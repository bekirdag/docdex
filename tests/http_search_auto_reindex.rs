use docdexd::index::IndexConfig;
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tantivy::schema::{Schema, STORED, TEXT};
use tantivy::{doc, Index};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::write(repo_root.join("doc.md"), "# Fixture\n\nSCHEMA_TOKEN\n")?;
    Ok(())
}

fn create_incompatible_index(index_dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(index_dir)?;
    let mut builder = Schema::builder();
    let title = builder.add_text_field("legacy_title", TEXT | STORED);
    let schema = builder.build();
    let index = Index::create_in_dir(index_dir, schema)?;
    let mut writer = index.writer(15_000_000)?;
    writer.add_document(doc!(title => "legacy"))?;
    writer.commit()?;
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping auto reindex HTTP test: TCP bind not permitted");
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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn http_search_auto_reindexes_stale_index() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let config = IndexConfig::with_overrides(
        repo.path(),
        Some(state_root.path().to_path_buf()),
        Vec::new(),
        Vec::new(),
        true,
    )?;
    create_incompatible_index(config.state_dir())?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let repo_arg = repo.path().to_string_lossy().to_string();
    let lock_path = state_root.path().join("daemon.lock");
    let child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_STATE_DIR", state_root.path())
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .args([
            "serve",
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
    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let url = format!("http://127.0.0.1:{port}/search?q=SCHEMA_TOKEN&limit=1");
    let resp = client.get(&url).send()?;
    assert!(
        resp.status().is_success(),
        "expected success, got {}",
        resp.status()
    );
    let payload: Value = resp.json()?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .ok_or("missing hits array")?;
    assert!(!hits.is_empty(), "expected hits after auto reindex");
    Ok(())
}
