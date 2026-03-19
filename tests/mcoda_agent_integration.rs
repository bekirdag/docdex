use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use rusqlite::Connection;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

use docdexd::llm::adapter::resolve_agent_adapter;
use docdexd::llm::adapter::LlmAdapter;
use docdexd::mcoda::registry::McodaAgent;
use docdexd::mcoda::registry::McodaRegistry;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(
        docs_dir.join("overview.md"),
        r#"
# Platform Overview

Our roadmap includes authentication and billing upgrades.
        "#,
    )?;
    Ok(())
}

fn encrypt_secret(key: &[u8], iv: &[u8; 12], plaintext: &str) -> String {
    let cipher = Aes256Gcm::new_from_slice(key).expect("valid key");
    let nonce = Nonce::from_slice(iv);
    let mut encrypted = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .expect("encrypt");
    let tag = encrypted.split_off(encrypted.len() - 16);
    let mut payload = Vec::new();
    payload.extend_from_slice(iv);
    payload.extend_from_slice(&tag);
    payload.extend_from_slice(&encrypted);
    Base64Engine.encode(payload)
}

fn create_mcoda_db(
    db_path: &Path,
    agent_id: &str,
    agent_slug: &str,
    adapter: &str,
    default_model: &str,
    config_json: &str,
    encrypted_secret: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        r#"
        CREATE TABLE agents (
          id TEXT PRIMARY KEY,
          slug TEXT UNIQUE NOT NULL,
          adapter TEXT NOT NULL,
          default_model TEXT,
          config_json TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE agent_auth (
          agent_id TEXT PRIMARY KEY,
          encrypted_secret TEXT NOT NULL,
          last_verified_at TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL
        );
        CREATE TABLE agent_models (
          agent_id TEXT NOT NULL,
          model_name TEXT NOT NULL,
          is_default INTEGER DEFAULT 0,
          config_json TEXT,
          PRIMARY KEY (agent_id, model_name)
        );
        CREATE TABLE agent_capabilities (
          agent_id TEXT NOT NULL,
          capability TEXT NOT NULL,
          PRIMARY KEY (agent_id, capability)
        );
        "#,
    )?;
    conn.execute(
        "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        (
            agent_id,
            agent_slug,
            adapter,
            default_model,
            config_json,
            "2024-01-01T00:00:00Z",
            "2024-01-01T00:00:00Z",
        ),
    )?;
    conn.execute(
        "INSERT INTO agent_models (agent_id, model_name, is_default, config_json)
         VALUES (?1, ?2, 1, NULL)",
        (agent_id, default_model),
    )?;
    conn.execute(
        "INSERT INTO agent_capabilities (agent_id, capability) VALUES (?1, ?2)",
        (agent_id, "chat"),
    )?;
    if let Some(secret) = encrypted_secret {
        conn.execute(
            "INSERT INTO agent_auth (agent_id, encrypted_secret, last_verified_at, created_at, updated_at)
             VALUES (?1, ?2, NULL, ?3, ?4)",
            (agent_id, secret, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"),
        )?;
    }
    Ok(())
}

fn start_stub_openai_server(
    response_body: String,
) -> std::io::Result<(
    SocketAddr,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
    thread::JoinHandle<()>,
)> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let count = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let count_clone = count.clone();
    let stop_clone = stop.clone();
    let handle = thread::spawn(move || {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        );
        while !stop_clone.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut buffer = [0u8; 4096];
                    let _ = stream.read(&mut buffer);
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                    count_clone.fetch_add(1, Ordering::SeqCst);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    Ok((addr, count, stop, handle))
}

#[test]
fn mcoda_registry_loads_and_decrypts() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let mcoda_dir = temp.path().join(".mcoda");
    fs::create_dir_all(&mcoda_dir)?;
    let key_path = mcoda_dir.join("mcoda.key");
    let key = vec![7u8; 32];
    fs::write(&key_path, &key)?;
    let db_path = mcoda_dir.join("mcoda.db");
    let iv = [3u8; 12];
    let encrypted_secret = encrypt_secret(&key, &iv, "secret-value");
    let config_json = r#"{"baseUrl":"http://localhost","headers":{"x-test":"1"}}"#;
    create_mcoda_db(
        &db_path,
        "agent-1",
        "agent-one",
        "openai-api",
        "gpt-test",
        config_json,
        Some(&encrypted_secret),
    )?;

    let registry = McodaRegistry::load_from_paths(&db_path, &key_path)?;
    assert_eq!(registry.agents.len(), 1);
    let agent = registry.agent_by_slug("agent-one").expect("agent");
    assert_eq!(agent.adapter, "openai-api");
    assert_eq!(agent.default_model.as_deref(), Some("gpt-test"));
    let config = agent.config.as_ref().expect("config");
    assert_eq!(
        config.get("baseUrl").and_then(|v| v.as_str()),
        Some("http://localhost")
    );
    let auth = agent.auth.as_ref().expect("auth");
    assert_eq!(auth.decrypted_secret.as_deref(), Some("secret-value"));
    assert_eq!(agent.capabilities, vec!["chat".to_string()]);
    Ok(())
}

#[test]
fn adapter_falls_back_to_cli_when_secret_missing() -> Result<(), Box<dyn Error>> {
    let agent = McodaAgent {
        id: "agent-1".to_string(),
        slug: "agent-one".to_string(),
        adapter: "openai-api".to_string(),
        default_model: Some("gpt-test".to_string()),
        config: None,
        created_at: None,
        updated_at: None,
        rating: None,
        cost_per_million: None,
        max_complexity: None,
        best_usage: None,
        reasoning_rating: None,
        health_status: None,
        cli_binary: None,
        capabilities: Vec::new(),
        models: Vec::new(),
        auth: None,
        usage_limits: Vec::new(),
    };
    let adapter = resolve_agent_adapter(&agent)?;
    assert!(matches!(adapter, LlmAdapter::CodexCli(_)));
    Ok(())
}

#[test]
fn chat_uses_agent_adapter() -> Result<(), Box<dyn Error>> {
    let response_body =
        r#"{"choices":[{"message":{"content":"{\"relevant\":true,\"score\":0.9}"}}]}"#;
    let (addr, count, stop, handle) = match start_stub_openai_server(response_body.to_string()) {
        Ok(parts) => parts,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            eprintln!("skipping chat_uses_agent_adapter: bind permission denied");
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };

    let temp = TempDir::new()?;
    let home_dir = temp.path().join("home");
    let repo_dir = temp.path().join("repo");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&home_dir)?;
    fs::create_dir_all(&repo_dir)?;
    fs::create_dir_all(&state_dir)?;
    write_fixture_repo(&repo_dir)?;

    let mcoda_dir = home_dir.join(".mcoda");
    fs::create_dir_all(&mcoda_dir)?;
    let key_path = mcoda_dir.join("mcoda.key");
    let key = vec![9u8; 32];
    fs::write(&key_path, &key)?;
    let db_path = mcoda_dir.join("mcoda.db");
    let iv = [8u8; 12];
    let encrypted_secret = encrypt_secret(&key, &iv, "stub-secret");
    let config_json = format!(r#"{{"baseUrl":"http://{}:{}/v1"}}"#, addr.ip(), addr.port());
    create_mcoda_db(
        &db_path,
        "agent-1",
        "stub-agent",
        "openai-api",
        "gpt-stub",
        &config_json,
        Some(&encrypted_secret),
    )?;

    let repo_str = repo_dir.to_string_lossy().to_string();
    let state_str = state_dir.to_string_lossy().to_string();
    let status = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", &home_dir)
        .env("DOCDEX_WEB_ENABLED", "0")
        .arg("index")
        .arg("--repo")
        .arg(repo_str.as_str())
        .arg("--state-dir")
        .arg(state_str.as_str())
        .status()?;
    assert!(status.success(), "docdexd index failed");

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", &home_dir)
        .env("DOCDEX_WEB_ENABLED", "0")
        .arg("chat")
        .arg("--repo")
        .arg(repo_str.as_str())
        .arg("--state-dir")
        .arg(state_str.as_str())
        .arg("--query")
        .arg("roadmap")
        .arg("--limit")
        .arg("1")
        .arg("--llm-filter-local-results")
        .arg("--agent")
        .arg("stub-agent")
        .output()?;
    assert!(output.status.success(), "docdexd chat failed");
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .expect("hits array missing");
    assert!(!hits.is_empty(), "expected at least one hit");

    stop.store(true, Ordering::SeqCst);
    handle.join().expect("join server thread");
    assert!(
        count.load(Ordering::SeqCst) > 0,
        "expected stub adapter to receive at least one request"
    );
    Ok(())
}
