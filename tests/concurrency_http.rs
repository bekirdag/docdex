use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

type BoxError = Box<dyn Error + Send + Sync>;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_repo(repo_root: &Path) -> Result<(), BoxError> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("alpha.md"),
        r#"# Alpha

CONCURRENCY_ALPHA
"#,
    )?;
    std::fs::write(
        docs_dir.join("beta.md"),
        r#"# Beta

CONCURRENCY_BETA
"#,
    )?;
    Ok(())
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<(), BoxError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
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
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping concurrency_http: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn spawn_server(
    state_root: &Path,
    repo: &Path,
    host: &str,
    port: u16,
) -> Result<Child, BoxError> {
    let repo_str = repo.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
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
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_for_health(host: &str, port: u16) -> Result<(), BoxError> {
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

fn search(
    client: &Client,
    base_url: &str,
    query: &str,
) -> Result<Value, BoxError> {
    let resp = client
        .get(format!("{base_url}/search"))
        .query(&[("q", query), ("limit", "5")])
        .send()?;
    if !resp.status().is_success() {
        return Err(format!("search failed: HTTP {}", resp.status()).into());
    }
    Ok(resp.json()?)
}

fn assert_paths(payload: &Value, expected_suffix: &str) -> Result<(), BoxError> {
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .ok_or("search response missing hits array")?;
    assert!(!hits.is_empty(), "expected hits for {expected_suffix}");
    for hit in hits {
        let path = hit
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        if !path.ends_with(expected_suffix) {
            return Err(format!("unexpected hit path: {path}").into());
        }
    }
    Ok(())
}

#[test]
fn http_concurrency_is_isolated() -> Result<(), BoxError> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;

    run_docdex(state_root.path(), [
        "index",
        "--repo",
        repo.path().to_string_lossy().as_ref(),
    ])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let base_url = format!("http://{host}:{port}");
    let barrier = Arc::new(Barrier::new(3));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();

    let base_url_a = base_url.clone();
    let handle_a = thread::spawn(move || -> Result<(), BoxError> {
        barrier_a.wait();
        let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
        let payload = search(&client, &base_url_a, "CONCURRENCY_ALPHA")?;
        assert_paths(&payload, "docs/alpha.md")?;
        Ok(())
    });

    let base_url_b = base_url.clone();
    let handle_b = thread::spawn(move || -> Result<(), BoxError> {
        barrier_b.wait();
        let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
        let payload = search(&client, &base_url_b, "CONCURRENCY_BETA")?;
        assert_paths(&payload, "docs/beta.md")?;
        Ok(())
    });

    barrier.wait();

    handle_a.join().expect("alpha thread panicked")?;
    handle_b.join().expect("beta thread panicked")?;

    server.kill().ok();
    server.wait().ok();
    Ok(())
}
