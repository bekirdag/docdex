use reqwest::blocking::Client;
use rusqlite::{params, Connection};
use serde_json::Value;
use std::error::Error;
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

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping symbols tests: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let lock_path = state_root.join("daemon.lock");
    let config_path = state_root.join("config.toml");
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", lock_path)
        .env("DOCDEX_CONFIG_PATH", config_path)
        .env("DOCDEX_TEST_ALLOW_MULTI_DAEMON", "1")
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let timeout_secs = std::env::var("DOCDEX_TEST_HEALTH_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(60);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn inspect_repo_state(state_root: &Path, repo_root: &Path) -> Result<Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let config_path = state_root.join("config.toml");
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_CONFIG_PATH", config_path)
        .args([
            "repo",
            "inspect",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd repo inspect exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn resolve_repo_state_root(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    let root = payload
        .get("statePaths")
        .and_then(|value| value.get("repoStateRoot"))
        .and_then(|value| value.as_str())
        .ok_or("missing statePaths.repoStateRoot")?;
    Ok(PathBuf::from(root))
}

fn init_stale_symbols_db(path: &Path) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS symbols_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); \
         CREATE TABLE IF NOT EXISTS symbols_files ( \
             file_path TEXT PRIMARY KEY, \
             outcome_status TEXT, \
             outcome_reason TEXT, \
             outcome_error_summary TEXT, \
             file_lang TEXT \
         ); \
         CREATE TABLE IF NOT EXISTS symbols ( \
             id INTEGER PRIMARY KEY AUTOINCREMENT, \
             file_path TEXT NOT NULL, \
             symbol_id TEXT, \
             name TEXT NOT NULL, \
             kind TEXT NOT NULL, \
             line_start INTEGER NOT NULL, \
             start_col INTEGER NOT NULL, \
             line_end INTEGER NOT NULL, \
             end_col INTEGER NOT NULL, \
             signature TEXT \
         ); \
         CREATE TABLE IF NOT EXISTS ast_files ( \
             file_path TEXT PRIMARY KEY, \
             outcome_status TEXT, \
             outcome_reason TEXT, \
             outcome_error_summary TEXT, \
             node_count INT, \
             truncated INT, \
             file_lang TEXT \
         ); \
         CREATE TABLE IF NOT EXISTS ast_nodes ( \
             file_path TEXT, \
             node_id INT, \
             parent_id INT, \
             kind TEXT, \
             is_named INT, \
             line_start INT, \
             start_col INT, \
             line_end INT, \
             end_col INT \
         );",
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO symbols_meta (key, value) VALUES ('parser_versions', ?1)",
        params![r#"{"tree_sitter":"0.0.0"}"#],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO symbols_files (file_path, outcome_status) VALUES (?1, 'ok')",
        params!["src/lib.rs"],
    )?;
    conn.execute(
        "INSERT INTO symbols (file_path, symbol_id, name, kind, line_start, start_col, line_end, end_col) \
         VALUES (?1, ?2, ?3, ?4, 1, 1, 1, 3)",
        params!["src/lib.rs", "id", "demo", "function"],
    )?;
    Ok(())
}

fn write_index_ready_marker(index_dir: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(index_dir)?;
    let payload = serde_json::json!({
        "indexed_at_epoch_ms": 0u128,
        "docs_indexed": 1u64
    });
    std::fs::write(
        index_dir.join("index_ready.json"),
        serde_json::to_vec(&payload)?,
    )?;
    Ok(())
}

#[test]
fn symbols_status_cli_reports_fields() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    std::fs::create_dir_all(repo.path().join("src"))?;
    std::fs::write(repo.path().join("src").join("lib.rs"), "pub fn demo() {}\n")?;
    let state_root = TempDir::new()?;
    let config_path = state_root.path().join("config.toml");
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_CONFIG_PATH", config_path)
        .args([
            "symbols-status",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--state-dir",
            state_root.path().to_string_lossy().as_ref(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd symbols-status failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let schema = payload
        .get("schema")
        .and_then(|value| value.get("name"))
        .and_then(|value| value.as_str())
        .ok_or("symbols-status missing schema.name")?;
    if schema != "docdex.symbols_status" {
        return Err(format!("unexpected schema name: {schema}").into());
    }
    let requires_reindex = payload
        .get("requires_reindex")
        .and_then(|value| value.as_bool())
        .ok_or("symbols-status missing requires_reindex")?;
    if requires_reindex {
        return Err("expected requires_reindex=false for fresh store".into());
    }
    Ok(())
}

#[test]
fn symbols_endpoint_returns_stale_on_parser_drift() -> Result<(), Box<dyn Error>> {
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let repo = TempDir::new()?;
    std::fs::create_dir_all(repo.path().join("src"))?;
    std::fs::write(repo.path().join("src").join("lib.rs"), "pub fn demo() {}\n")?;
    let state_root = TempDir::new()?;
    let repo_state_root = resolve_repo_state_root(state_root.path(), repo.path())?;
    init_stale_symbols_db(&repo_state_root.join("symbols.db"))?;
    write_index_ready_marker(&repo_state_root.join("index"))?;

    let mut server = spawn_server(state_root.path(), repo.path(), "127.0.0.1", port)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        wait_for_health("127.0.0.1", port)?;
        let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
        let url = format!("http://127.0.0.1:{port}/v1/symbols?path=src/lib.rs");
        let resp = client.get(&url).send()?;
        if resp.status().as_u16() != 409 {
            return Err(format!("expected 409, got {}", resp.status()).into());
        }
        let body: Value = resp.json()?;
        let code = body
            .get("error")
            .and_then(|value| value.get("code"))
            .and_then(|value| value.as_str())
            .ok_or("missing error.code")?;
        if code != "stale_index" {
            return Err(format!("expected stale_index, got {code}").into());
        }
        Ok(())
    })();
    let _ = server.kill();
    let _ = server.wait();
    result
}
