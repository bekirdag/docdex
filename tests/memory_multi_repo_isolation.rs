mod common;

use common::{docdex_bin, pick_free_port, wait_for_health, MockOllama};
use reqwest::blocking::Client;
use serde_json::json;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use url::Url;

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn write_repo(repo_root: &Path, marker: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(docs_dir.join("readme.md"), format!("# Repo\n\n{marker}\n"))?;
    Ok(())
}

fn file_uri(path: &Path) -> String {
    Url::from_directory_path(path)
        .expect("file uri")
        .to_string()
}

fn run_docdex_ok<I, S>(state_root: &Path, args: I) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
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

fn start_daemon(
    state_root: &Path,
    repo_root: &Path,
    port: u16,
    lock_path: &Path,
    ollama_base_url: &str,
) -> Result<Daemon, Box<dyn Error>> {
    let child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", lock_path)
        .args([
            "daemon",
            "--repo",
            repo_root.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--enable-memory=true",
            "--ollama-base-url",
            ollama_base_url,
            "--embedding-model",
            "fake-embed",
            "--embedding-timeout-ms",
            "200",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(Daemon { child })
}

fn init_repo(client: &Client, port: u16, repo_root: &Path) -> Result<String, Box<dyn Error>> {
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/initialize"))
        .json(&json!({ "rootUri": file_uri(repo_root) }))
        .send()?;
    if !resp.status().is_success() {
        return Err(format!("initialize failed: {}", resp.status()).into());
    }
    let payload: serde_json::Value = resp.json()?;
    let repo_id = payload
        .get("repo_id")
        .and_then(|value| value.as_str())
        .ok_or("missing repo_id")?;
    Ok(repo_id.to_string())
}

#[test]
fn memory_isolation_multi_repo_requires_repo_id() -> Result<(), Box<dyn Error>> {
    let repo_one = TempDir::new()?;
    let repo_two = TempDir::new()?;
    write_repo(repo_one.path(), "alpha")?;
    write_repo(repo_two.path(), "bravo")?;

    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let state_dir = TempDir::new()?;
    run_docdex_ok(
        state_dir.path(),
        ["index", "--repo", repo_one.path().to_str().unwrap()],
    )?;
    run_docdex_ok(
        state_dir.path(),
        ["index", "--repo", repo_two.path().to_str().unwrap()],
    )?;

    let port = match pick_free_port() {
        Some(port) => port,
        None => return Ok(()),
    };
    let lock_path = state_dir.path().join("daemon.lock");
    let _daemon = start_daemon(
        state_dir.path(),
        repo_one.path(),
        port,
        &lock_path,
        &mock.base_url,
    )?;
    wait_for_health("127.0.0.1", port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let repo_one_id = init_repo(&client, port, repo_one.path())?;
    let repo_two_id = init_repo(&client, port, repo_two.path())?;

    let store_url = format!("http://127.0.0.1:{port}/v1/memory/store");
    let recall_url = format!("http://127.0.0.1:{port}/v1/memory/recall");

    let missing_store = client
        .post(&store_url)
        .json(&json!({ "text": "oops" }))
        .send()?;
    assert_eq!(missing_store.status(), reqwest::StatusCode::BAD_REQUEST);

    let store_one: serde_json::Value = client
        .post(&store_url)
        .header("x-docdex-repo-id", repo_one_id.clone())
        .json(&json!({ "text": "alpha memory" }))
        .send()?
        .json()?;
    let memory_one_id = store_one
        .get("id")
        .and_then(|value| value.as_str())
        .ok_or("missing memory id")?
        .to_string();
    let store_two = client
        .post(&store_url)
        .header("x-docdex-repo-id", repo_two_id.clone())
        .json(&json!({ "text": "bravo memory" }))
        .send()?;
    assert!(store_two.status().is_success());

    let recall_one: serde_json::Value = client
        .post(&recall_url)
        .header("x-docdex-repo-id", repo_one_id.clone())
        .json(&json!({ "query": "alpha", "top_k": 5 }))
        .send()?
        .json()?;
    let results_one = recall_one
        .get("results")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        results_one
            .iter()
            .any(|item| item.get("content") == Some(&json!("alpha memory"))),
        "repo one recall missing expected content: {recall_one}"
    );
    assert!(
        results_one
            .iter()
            .all(|item| item.get("content") != Some(&json!("bravo memory"))),
        "repo one recall leaked repo two content: {recall_one}"
    );

    let recall_two: serde_json::Value = client
        .post(&recall_url)
        .header("x-docdex-repo-id", repo_two_id)
        .json(&json!({ "query": "bravo", "top_k": 5 }))
        .send()?
        .json()?;
    let results_two = recall_two
        .get("results")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        results_two
            .iter()
            .any(|item| item.get("content") == Some(&json!("bravo memory"))),
        "repo two recall missing expected content: {recall_two}"
    );
    assert!(
        results_two
            .iter()
            .all(|item| item.get("content") != Some(&json!("alpha memory"))),
        "repo two recall leaked repo one content: {recall_two}"
    );

    let missing_recall = client
        .post(&recall_url)
        .json(&json!({ "query": "alpha", "top_k": 5 }))
        .send()?;
    assert_eq!(missing_recall.status(), reqwest::StatusCode::BAD_REQUEST);

    let delete_url = format!("http://127.0.0.1:{port}/v1/memory/delete");
    let deleted: serde_json::Value = client
        .post(&delete_url)
        .header("x-docdex-repo-id", repo_one_id.clone())
        .json(&json!({ "id": memory_one_id }))
        .send()?
        .json()?;
    assert_eq!(
        deleted.get("deleted").and_then(|value| value.as_bool()),
        Some(true)
    );

    let recall_after_delete: serde_json::Value = client
        .post(&recall_url)
        .header("x-docdex-repo-id", repo_one_id.clone())
        .json(&json!({ "query": "alpha", "top_k": 5 }))
        .send()?
        .json()?;
    let after_delete_results = recall_after_delete
        .get("results")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        after_delete_results
            .iter()
            .all(|item| item.get("content") != Some(&json!("alpha memory"))),
        "deleted memory still recalled: {recall_after_delete}"
    );

    let delete_alias_url = format!("http://127.0.0.1:{port}/v1/memory/repo/delete");
    let deleted_again: serde_json::Value = client
        .post(&delete_alias_url)
        .header("x-docdex-repo-id", repo_one_id)
        .json(&json!({ "memory_id": memory_one_id }))
        .send()?
        .json()?;
    assert_eq!(
        deleted_again
            .get("deleted")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    Ok(())
}
