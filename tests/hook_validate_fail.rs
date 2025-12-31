use docdexd::profiles::{PreferenceCategory, ProfileManager};
use docdexd::repo_manager::repo_fingerprint_sha256;
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

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn run_docdex<I, S>(state_root: &Path, home_dir: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
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
            eprintln!("skipping hook test: TCP bind not permitted in this environment");
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
    fs::write(src_dir.join("unsafe.ts"), "const value: any = 42;\n")?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    embedding_dim: usize,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[memory.profile]\nembedding_dim = {}\nembedding_model = \"test-embed\"\n",
        global_state_dir.display(),
        embedding_dim
    );
    fs::write(config_path, payload)?;
    Ok(())
}

fn seed_constraint(global_state_dir: &Path, embedding_dim: usize) -> Result<(), Box<dyn Error>> {
    let manager = ProfileManager::new(global_state_dir, embedding_dim)?;
    let now_ms = 1_700_000_000_000i64;
    manager.create_agent("agent-test", "test", now_ms)?;
    let embedding = vec![0.1; embedding_dim];
    manager.add_preference(
        "agent-test",
        "No any types",
        &embedding,
        PreferenceCategory::Constraint,
        now_ms,
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
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[test]
fn hook_validate_fails_on_any_type() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    let embedding_dim = 4;
    write_config(home_dir.path(), &global_state_dir, embedding_dim)?;
    seed_constraint(&global_state_dir, embedding_dim)?;

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
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let repo_id = repo_fingerprint_sha256(repo.path())?;
    let url = format!("http://{host}:{port}/v1/hooks/validate");
    let resp = client
        .post(url)
        .header("x-docdex-repo-id", repo_id)
        .json(&serde_json::json!({ "files": ["src/unsafe.ts"] }))
        .send()?;
    assert!(resp.status().is_success());
    let payload: Value = resp.json()?;
    assert_eq!(payload.get("status").and_then(|v| v.as_str()), Some("fail"));
    let errors = payload
        .get("errors")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(!errors.is_empty(), "expected hook violations");

    server.shutdown();
    Ok(())
}
