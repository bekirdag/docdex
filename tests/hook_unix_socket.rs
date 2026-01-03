mod common;

#[cfg(unix)]
mod unix_tests {
    use docdexd::repo_manager::repo_fingerprint_sha256;
    use http_body_util::{BodyExt, Full};
    use hyper::body::Bytes;
    use hyper::client::conn::http1;
    use hyper::header::CONTENT_TYPE;
    use hyper::{Method, Request};
    use hyper_util::rt::TokioIo;
    use reqwest::blocking::Client;
    use serde_json::Value;
    use std::error::Error;
    use std::ffi::OsStr;
    use std::fs;
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command};
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;
    use tokio::net::UnixStream;

    fn docdex_bin() -> PathBuf {
        std::env::set_var("DOCDEX_CLI_LOCAL", "1");
        assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
    }

    fn run_docdex<I, S>(
        state_root: &Path,
        home_dir: &Path,
        args: I,
    ) -> Result<Vec<u8>, Box<dyn Error>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = Command::new(docdex_bin())
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

    fn pick_free_port() -> Option<u16> {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => Some(listener.local_addr().ok()?.port()),
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping hook unix socket test: TCP bind not permitted");
                None
            }
            Err(err) => panic!("bind ephemeral port: {err}"),
        }
    }

    fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
        let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
        let url = format!("http://{host}:{port}/healthz");
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match client.get(&url).send() {
                Ok(resp) if resp.status().is_success() => return Ok(()),
                _ => thread::sleep(Duration::from_millis(200)),
            }
        }
        Err("docdexd healthz endpoint did not respond in time".into())
    }

    fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
        let src_dir = repo_root.join("src");
        fs::create_dir_all(&src_dir)?;
        fs::write(src_dir.join("safe.ts"), "const ok = true;\n")?;
        Ok(())
    }

    fn write_config(
        home_dir: &Path,
        global_state_dir: &Path,
        hook_socket_path: &Path,
    ) -> Result<(), Box<dyn Error>> {
        let config_dir = home_dir.join(".docdex");
        fs::create_dir_all(&config_dir)?;
        let config_path = config_dir.join("config.toml");
        let payload = format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory.profile]\nembedding_dim = 4\nembedding_model = \"test-embed\"\n\n[server]\nhook_socket_path = \"{}\"\n",
            crate::common::toml_path(global_state_dir),
            crate::common::toml_path(hook_socket_path)
        );
        fs::write(config_path, payload)?;
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
        ) -> Result<Self, Box<dyn Error>> {
            let repo_str = repo_root.to_string_lossy().to_string();
            let child = Command::new(docdex_bin())
                .env("DOCDEX_ENABLE_MEMORY", "0")
                .env("DOCDEX_STATE_DIR", state_root)
                .env("DOCDEX_ENABLE_MCP", "0")
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
                ])
                .spawn()?;
            wait_for_health(host, port)?;
            Ok(Self { child })
        }

        fn shutdown(&mut self) {
            self.child.kill().ok();
            self.child.wait().ok();
        }
    }

    #[test]
    fn hook_validate_over_unix_socket() -> Result<(), Box<dyn Error>> {
        let repo = TempDir::new()?;
        write_repo(repo.path())?;

        let state_root = TempDir::new()?;
        let home_dir = TempDir::new()?;
        let global_state_dir = home_dir.path().join(".docdex").join("state");
        let hook_socket_path = home_dir.path().join(".docdex").join("hook.sock");
        write_config(home_dir.path(), &global_state_dir, &hook_socket_path)?;

        run_docdex(
            state_root.path(),
            home_dir.path(),
            ["index", "--repo", repo.path().to_string_lossy().as_ref()],
        )?;

        let Some(port) = pick_free_port() else {
            return Ok(());
        };
        let host = "127.0.0.1";
        let mut server =
            ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

        let repo_id = repo_fingerprint_sha256(repo.path())?;
        let payload = send_hook_over_unix(&hook_socket_path, &repo_id)?;
        assert_eq!(payload.get("status").and_then(|v| v.as_str()), Some("pass"));

        server.shutdown();
        Ok(())
    }

    fn send_hook_over_unix(socket_path: &Path, repo_id: &str) -> Result<Value, Box<dyn Error>> {
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let payload = serde_json::to_vec(&serde_json::json!({ "files": ["src/safe.ts"] }))?;
            let stream = UnixStream::connect(socket_path).await?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            let request = Request::builder()
                .method(Method::POST)
                .uri("http://localhost/v1/hooks/validate")
                .header(CONTENT_TYPE, "application/json")
                .header("x-docdex-repo-id", repo_id)
                .body(Full::new(Bytes::from(payload)))?;
            let response = sender.send_request(request).await?;
            let status = response.status();
            let body = response.into_body().collect().await?.to_bytes();
            if !status.is_success() {
                return Err(format!("hook unix request failed with status {status}").into());
            }
            let payload: Value = serde_json::from_slice(&body)?;
            Ok(payload)
        })
    }
}
