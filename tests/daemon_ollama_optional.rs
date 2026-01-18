use std::error::Error;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::write(
        repo_root.join("README.md"),
        "# Docdex\n\nOllama optional.\n",
    )?;
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping ollama optional test: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn daemon_starts_without_ollama_configured() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let config_dir = TempDir::new()?;
    let config_path = config_dir.path().join("config.toml");
    fs::write(&config_path, "[llm]\nprovider = \"openai\"\n")?;
    let lock_path = config_dir.path().join("daemon.lock");

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let repo_arg = repo.path().to_string_lossy().to_string();
    let child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_ENABLE_MEMORY", "1")
        .env("DOCDEX_EMBEDDING_MODEL", " ")
        .env("DOCDEX_OLLAMA_BASE_URL", " ")
        .env("DOCDEX_CONFIG_PATH", &config_path)
        .env("DOCDEX_STATE_DIR", state_root.path())
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .args([
            "daemon",
            "--repo",
            repo_arg.as_str(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let _guard = ChildGuard(child);
    wait_for_health("127.0.0.1", port)?;
    Ok(())
}
