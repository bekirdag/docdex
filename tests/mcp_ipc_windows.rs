mod common;

#[cfg(windows)]
mod windows_tests {
    use super::common;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::client::conn::http1;
    use hyper::header::CONTENT_TYPE;
    use hyper::{Method, Request, StatusCode};
    use hyper_util::rt::TokioIo;
    use serde_json::Value;
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fs;
    use std::path::Path;
    use std::process::{Child, Command};
    use tempfile::TempDir;
    use tokio::net::windows::named_pipe::ClientOptions;
    use uuid::Uuid;

    fn run_docdex<I, S>(
        state_root: &Path,
        home_dir: &Path,
        args: I,
    ) -> Result<Vec<u8>, Box<dyn Error>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = Command::new(common::docdex_bin())
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_STATE_DIR", state_root)
            .env("HOME", home_dir)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(format!(
                "docdexd exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )
            .into());
        }
        Ok(output.stdout)
    }

    fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
        fs::create_dir_all(repo_root.join("src"))?;
        fs::write(
            repo_root.join("src").join("note.md"),
            "Docdex test content\n",
        )?;
        Ok(())
    }

    struct ServerHarness {
        child: Child,
    }

    impl ServerHarness {
        fn spawn(
            state_root: &Path,
            home_dir: &Path,
            repo_root: &Path,
            host: &str,
            port: u16,
            pipe_name: &str,
        ) -> Result<Self, Box<dyn Error>> {
            let repo_str = repo_root.to_string_lossy().to_string();
            let child = Command::new(common::docdex_bin())
                .env("DOCDEX_WEB_ENABLED", "0")
                .env("DOCDEX_ENABLE_MEMORY", "0")
                .env("DOCDEX_STATE_DIR", state_root)
                .env("DOCDEX_ENABLE_MCP", "1")
                .env("HOME", home_dir)
                .args([
                    "serve",
                    "--repo",
                    repo_str.as_str(),
                    "--host",
                    host,
                    "--port",
                    &port.to_string(),
                    "--log",
                    "warn",
                    "--secure-mode=false",
                    "--enable-mcp",
                    "--mcp-ipc",
                    "auto",
                    "--mcp-pipe-name",
                    pipe_name,
                ])
                .spawn()?;
            common::wait_for_health(host, port)?;
            Ok(Self { child })
        }

        fn shutdown(&mut self) {
            self.child.kill().ok();
            self.child.wait().ok();
        }
    }

    async fn send_mcp_request(
        pipe_name: &str,
        payload: &Value,
    ) -> Result<(StatusCode, Value), Box<dyn Error>> {
        let body = serde_json::to_vec(payload)?;
        let stream = ClientOptions::new().open(pipe_name).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri("http://localhost/v1/mcp")
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        if status == StatusCode::NO_CONTENT {
            return Ok((status, serde_json::json!({})));
        }
        let bytes = response.into_body().collect().await?.to_bytes();
        let value: Value = serde_json::from_slice(&bytes)?;
        Ok((status, value))
    }

    #[test]
    fn mcp_ipc_windows_roundtrip() -> Result<(), Box<dyn Error>> {
        let repo = TempDir::new()?;
        write_repo(repo.path())?;

        let state_root = TempDir::new()?;
        let home_dir = TempDir::new()?;
        let pipe_name = format!("docdex-mcp-{}", Uuid::new_v4());
        let pipe_full = format!("\\\\.\\pipe\\{}", pipe_name);

        run_docdex(
            state_root.path(),
            home_dir.path(),
            ["index", "--repo", repo.path().to_string_lossy().as_ref()],
        )?;

        let Some(port) = common::pick_free_port() else {
            return Ok(());
        };
        let host = "127.0.0.1";
        let mut server = ServerHarness::spawn(
            state_root.path(),
            home_dir.path(),
            repo.path(),
            host,
            port,
            &pipe_name,
        )?;

        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let init_payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "rootUri": format!("file://{}", repo.path().display()) }
            });
            let (status, init_resp) = send_mcp_request(&pipe_full, &init_payload).await?;
            if !status.is_success() {
                return Err(format!("initialize failed: {status} {init_resp}").into());
            }
            if init_resp.get("result").is_none() {
                return Err(format!("initialize missing result: {init_resp}").into());
            }

            let tools_payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            });
            let (status, tools_resp) = send_mcp_request(&pipe_full, &tools_payload).await?;
            if !status.is_success() {
                return Err(format!("tools/list failed: {status} {tools_resp}").into());
            }
            if tools_resp.get("result").is_none() {
                return Err(format!("tools/list missing result: {tools_resp}").into());
            }

            let search_payload = serde_json::json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "docdex_search",
                    "arguments": { "query": "Docdex" }
                }
            });
            let (status, search_resp) = send_mcp_request(&pipe_full, &search_payload).await?;
            if !status.is_success() {
                return Err(format!("docdex_search failed: {status} {search_resp}").into());
            }
            if search_resp.get("result").is_none() {
                return Err(format!("docdex_search missing result: {search_resp}").into());
            }
            Ok::<(), Box<dyn Error>>(())
        })?;

        server.shutdown();
        Ok(())
    }
}
