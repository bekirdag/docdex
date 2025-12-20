use reqwest::blocking::Client;
use serde_json::{json, Value};
<<<<<<< HEAD
<<<<<<< HEAD
use std::collections::HashSet;
=======
use std::collections::BTreeSet;
>>>>>>> mcoda/task/bck-05-us-10-t23
=======
use std::collections::HashSet;
>>>>>>> mcoda/task/bck-05-us-09-t36
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const MAX_MCP_RATE_LIMIT_PAYLOAD_BYTES: usize = 2048;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

<<<<<<< HEAD
const MAX_MCP_ERROR_PAYLOAD_BYTES: usize = 2048;
=======
const MCP_RATE_LIMIT_PAYLOAD_MAX_BYTES: usize = 2048;
>>>>>>> mcoda/task/bck-05-us-09-t36

struct McpHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

const MAX_SNIPPET_CHARS: usize = 420;

impl McpHarness {
<<<<<<< HEAD
    fn spawn(repo: &Path, state_root: &Path) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_env(repo, state_root, &[])
=======
    fn spawn(repo: &Path) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_options(repo, &[], None, 4)
>>>>>>> mcoda/task/bck-05-us-08-t34
    }

    fn spawn_with_env(
        repo: &Path,
        state_root: &Path,
        envs: &[(&str, &str)],
    ) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_options(repo, envs, None, 4)
    }

    fn spawn_with_options(
        repo: &Path,
        envs: &[(&str, &str)],
        state_dir: Option<&Path>,
        max_results: usize,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo.to_string_lossy().to_string();
        let max_results = max_results.max(1).to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--log",
            "warn",
            "--max-results",
            max_results.as_str(),
        ]);
<<<<<<< HEAD
        cmd.env("DOCDEX_STATE_DIR", state_root);
=======
        if let Some(state_dir) = state_dir {
            let state_dir = state_dir.to_string_lossy().to_string();
            cmd.args(["--state-dir", state_dir.as_str()]);
        }
>>>>>>> mcoda/task/bck-05-us-08-t34
        for (key, value) in envs {
            cmd.env(key, value);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or("failed to take child stdin for MCP server")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to take child stdout for MCP server")?;
        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
        })
    }

    fn spawn_with_state_dir(repo: &Path, state_dir: &Path) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo.to_string_lossy().to_string();
        let state_dir_str = state_dir.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_dir_str.as_str(),
            "--log",
            "warn",
            "--max-results",
            "4",
        ]);
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or("failed to take child stdin for MCP server")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to take child stdout for MCP server")?;
        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
        })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("overview.md"),
        r#"# Overview

This repository contains the MCP_ROADMAP notes used for testing.
"#,
    )?;
    // Extra files so limit clamping is observable.
    for i in 0..8 {
        std::fs::write(
            docs_dir.join(format!("extra_{i}.md")),
            format!("# Extra {i}\n\nMCP_ROADMAP term appears here.\n"),
        )?;
    }
    let long_line = std::iter::repeat("LONG_TERM")
        .take(1000)
        .collect::<Vec<_>>()
        .join(" ");
    std::fs::write(docs_dir.join("long.md"), format!("# Long\n\n{long_line}\n"))?;
    Ok(())
}

fn write_repo_with_tokens(
    repo_root: &Path,
    unique_token: &str,
    common_token: &str,
    extra_common_files: usize,
) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("unique.md"),
        format!(
            "# Unique\n\n{unique_token}\n\n{common_token}\n",
            unique_token = unique_token,
            common_token = common_token
        ),
    )?;
    for i in 0..extra_common_files {
        std::fs::write(
            docs_dir.join(format!("common_{i}.md")),
            format!("# Common {i}\n\n{common_token}\n", common_token = common_token),
        )?;
    }
    Ok(())
}

fn write_repo_with_token(repo_root: &Path, token: &str) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("overview.md"),
        format!("# Overview\n\n{token}\n"),
    )?;
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

<<<<<<< HEAD
fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<std::process::Output, Box<dyn Error>>
=======
fn write_large_fixture_repo(
    repo_root: &Path,
    term: &str,
    file_count: usize,
    bytes_per_file: usize,
) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    let mut content = String::new();
    let chunk = format!("{term} concurrency test filler.\n");
    while content.len() < bytes_per_file {
        content.push_str(&chunk);
    }
    for i in 0..file_count {
        std::fs::write(docs_dir.join(format!("doc_{i}.md")), &content)?;
    }
    Ok(())
}

fn setup_large_repo(
    term: &str,
    file_count: usize,
    bytes_per_file: usize,
) -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_large_fixture_repo(temp.path(), term, file_count, bytes_per_file)?;
    Ok(temp)
}

fn wait_for_writer_lock(
    state_dir: &Path,
    child: &mut Child,
    timeout: Duration,
) -> Result<(), Box<dyn Error>> {
    let lock_path = state_dir.join(".tantivy-writer.lock");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            return Err(format!("index process exited early: {status}").into());
        }
        if lock_path.exists() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("timed out waiting for index writer lock".into())
}

fn run_docdex<I, S>(args: I) -> Result<std::process::Output, Box<dyn Error>>
>>>>>>> mcoda/task/bck-05-us-08-t13
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .args(args)
        .output()?)
}

fn index_repo_with_state(repo: &Path, state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let repo_str = repo.to_string_lossy().to_string();
    let state_str = state_dir.to_string_lossy().to_string();
    let out = run_docdex([
        "index",
        "--repo",
        repo_str.as_str(),
        "--state-dir",
        state_str.as_str(),
    ])?;
    if !out.status.success() {
        return Err(format!(
            "index failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(())
}

fn parse_cli_error(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("expected CLI error payload".into());
    }
    Ok(serde_json::from_str(trimmed)?)
}

fn send_line(
    stdin: &mut std::process::ChildStdin,
    payload: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_line(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("unexpected empty response line from MCP server".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn parse_tool_result(resp: &serde_json::Value) -> Result<serde_json::Value, Box<dyn Error>> {
    let content = resp
        .get("result")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_array())
        .ok_or("tool result missing content array")?;
    let first_text = content
        .first()
        .and_then(|v| v.get("text"))
        .and_then(|v| v.as_str())
        .ok_or("tool result missing text content")?;
    Ok(serde_json::from_str(first_text)?)
}

<<<<<<< HEAD
<<<<<<< HEAD
fn json_keys(value: &Value) -> Result<HashSet<String>, Box<dyn Error>> {
    let obj = value
        .as_object()
        .ok_or("expected JSON object for key extraction")?;
    Ok(obj.keys().cloned().collect())
}

fn assert_keys_subset(value: &Value, allowed: &[&str], context: &str) -> Result<(), Box<dyn Error>> {
    let obj = value
        .as_object()
        .ok_or_else(|| format!("{context} should be a JSON object"))?;
    for key in obj.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("{context} has unexpected key {key}").into());
=======
fn object_keys(value: &Value) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let obj = value.as_object().ok_or("expected JSON object")?;
    Ok(obj.keys().cloned().collect())
}

fn first_item_keys(value: &Value, field: &str) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let array = value
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or("expected JSON array field")?;
    let first = array.first().ok_or("expected non-empty array")?;
    object_keys(first)
}

fn assert_search_hit_schema(hit: &Value) -> Result<(), Box<dyn Error>> {
    let obj = hit.as_object().ok_or("search hit should be an object")?;
    if !obj.get("doc_id").and_then(|v| v.as_str()).is_some() {
        return Err("search hit missing doc_id".into());
    }
    if !obj.get("rel_path").and_then(|v| v.as_str()).is_some() {
        return Err("search hit missing rel_path".into());
    }
    if !obj.get("path").and_then(|v| v.as_str()).is_some() {
        return Err("search hit missing path".into());
    }
    if !obj.get("score").and_then(|v| v.as_f64()).is_some() {
        return Err("search hit missing score".into());
    }
    if !obj.get("summary").and_then(|v| v.as_str()).is_some() {
        return Err("search hit missing summary".into());
    }
    if !obj.get("snippet").and_then(|v| v.as_str()).is_some() {
        return Err("search hit missing snippet".into());
    }
    if !obj.get("token_estimate").and_then(|v| v.as_u64()).is_some() {
        return Err("search hit missing token_estimate".into());
    }
    if let Some(origin) = obj.get("snippet_origin") {
        if !origin.as_str().is_some() {
            return Err("search hit snippet_origin must be a string".into());
        }
    }
    if let Some(truncated) = obj.get("snippet_truncated") {
        if !truncated.is_boolean() {
            return Err("search hit snippet_truncated must be a boolean".into());
        }
    }
    if let Some(line_start) = obj.get("line_start") {
        if !line_start.is_number() {
            return Err("search hit line_start must be a number".into());
        }
    }
    if let Some(line_end) = obj.get("line_end") {
        if !line_end.is_number() {
            return Err("search hit line_end must be a number".into());
>>>>>>> mcoda/task/bck-05-us-10-t23
        }
    }
    Ok(())
}

<<<<<<< HEAD
=======
fn assert_doc_snapshot_schema(entry: &Value) -> Result<(), Box<dyn Error>> {
    let obj = entry.as_object().ok_or("doc snapshot should be an object")?;
    if !obj.get("doc_id").and_then(|v| v.as_str()).is_some() {
        return Err("doc snapshot missing doc_id".into());
    }
    if !obj.get("rel_path").and_then(|v| v.as_str()).is_some() {
        return Err("doc snapshot missing rel_path".into());
    }
    if !obj.get("summary").and_then(|v| v.as_str()).is_some() {
        return Err("doc snapshot missing summary".into());
    }
    if !obj.get("token_estimate").and_then(|v| v.as_u64()).is_some() {
        return Err("doc snapshot missing token_estimate".into());
    }
    Ok(())
}

>>>>>>> mcoda/task/bck-05-us-10-t23
=======
fn parse_cli_json(raw: &[u8]) -> Result<serde_json::Value, Box<dyn Error>> {
    let text = String::from_utf8_lossy(raw);
    let trimmed = text.trim();
    Ok(serde_json::from_str(trimmed)?)
}

fn parse_cli_error(raw: &[u8]) -> Result<serde_json::Value, Box<dyn Error>> {
    parse_cli_json(raw)
}

>>>>>>> mcoda/task/bck-05-us-08-t34
fn mcp_error_code(resp: &Value) -> Option<i64> {
    resp.get("error").and_then(|v| v.get("code")).and_then(|v| v.as_i64())
}

fn mcp_error_data_code(resp: &Value) -> Option<&str> {
    resp.get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
}

<<<<<<< HEAD
fn rate_limit_data_signature(data: &serde_json::Map<String, Value>) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = data
        .iter()
        .map(|(k, v)| {
            let kind = match v {
                Value::Null => "null",
                Value::Bool(_) => "bool",
                Value::Number(_) => "number",
                Value::String(_) => "string",
                Value::Array(_) => "array",
                Value::Object(_) => "object",
            };
            (k.clone(), kind)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
=======
fn search_hit_ids(
    mcp: &mut McpHarness,
    id: i64,
    query: &str,
    limit: usize,
) -> Result<Vec<String>, Box<dyn Error>> {
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": query, "limit": limit } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    if resp.get("error").is_some() {
        return Err(format!("search failed: {resp}").into());
    }
    let body = parse_tool_result(&resp)?;
    let hits = body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search response missing hits array")?;
    Ok(hits
        .iter()
        .filter_map(|hit| hit.get("doc_id").and_then(|v| v.as_str()))
        .map(|doc_id| doc_id.to_string())
        .collect())
>>>>>>> mcoda/task/bck-05-us-08-t22
}

#[test]
fn mcp_missing_index_returns_actionable_hint() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("missing_index"));
    let details = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("missing_index should include details")?;
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("missing_index details should include recoverySteps")?;
    assert!(
        steps
            .iter()
            .any(|v| v.as_str().unwrap_or_default().contains("docdexd index")),
        "expected recoverySteps to mention docdexd index; got: {details}"
    );
    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_stale_index_returns_actionable_hint() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let state_path = repo
        .path()
        .join(".docdex")
        .join("index")
        .join("index_state.json");
    let mut state: Value = serde_json::from_str(&std::fs::read_to_string(&state_path)?)?;
    state["status"] = Value::String("stale".to_string());
    std::fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("stale_index"));
    let details = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("stale_index should include details")?;
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("stale_index details should include recoverySteps")?;
    assert!(
        steps
            .iter()
            .any(|v| v.as_str().unwrap_or_default().contains("docdexd index")),
        "expected recoverySteps to mention docdexd index; got: {details}"
    );
    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_rate_limit_errors_include_retry_hints() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn_with_env(
        repo.path(),
        state_root.path(),
        &[
            // 1 request/sec refill + burst=1 lets us deterministically rate-limit
            // multiple tools within a short test window.
            ("DOCDEX_MCP_RATE_LIMIT_PER_MIN", "60"),
            ("DOCDEX_MCP_RATE_LIMIT_BURST", "1"),
        ],
    )?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let ok = read_line(&mut mcp.reader)?;
    assert!(ok.get("result").is_some(), "first tool call should succeed");

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": { "name": "docdex_files", "arguments": {} }
        }),
    )?;
    let limited_files = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&limited_files), Some(-32029));
    assert_eq!(mcp_error_data_code(&limited_files), Some("rate_limited"));
    let limited_files_bytes = serde_json::to_vec(&limited_files)?.len();
    assert!(
        limited_files_bytes <= MAX_MCP_ERROR_PAYLOAD_BYTES,
        "rate-limit payload should remain small (got {} bytes)",
        limited_files_bytes
    );

    let data_files = limited_files
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error.data object")?;
<<<<<<< HEAD
    assert!(
        data_files
            .get("message")
            .and_then(|v| v.as_str())
            .is_some(),
        "rate-limit error should include message"
=======
    let payload_bytes = serde_json::to_vec(&limited_files)?;
    assert!(
        payload_bytes.len() <= MAX_MCP_RATE_LIMIT_PAYLOAD_BYTES,
        "rate-limit payload should remain small (got {} bytes)",
        payload_bytes.len()
>>>>>>> mcoda/task/bck-05-us-09-t29
    );
    assert_eq!(
        data_files.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(
        data_files.get("scope").and_then(|v| v.as_str()),
        Some("global")
    );
    assert_eq!(
        data_files.get("resource_key").and_then(|v| v.as_str()),
        Some("global")
    );
    assert_eq!(
        data_files.get("limit_per_min").and_then(|v| v.as_u64()),
        Some(60)
    );
    assert_eq!(
        data_files.get("limit_burst").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert!(
        data_files
            .get("denied_total")
            .and_then(|v| v.as_u64())
            .is_some(),
        "denied_total must be an integer"
    );
    assert!(
        data_files
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "retry_after_ms must be an integer"
    );
<<<<<<< HEAD
    let envelope = data_files
        .get("error")
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error envelope")?;
    assert_eq!(
        envelope.get("code").and_then(|v| v.as_str()),
        Some("rate_limited")
    );
=======
    if let Some(retry_at) = data_files.get("retry_at") {
        assert!(
            retry_at.as_str().is_some(),
            "retry_at must be an RFC3339 string when present"
        );
    }
>>>>>>> mcoda/task/bck-05-us-09-t29
    assert!(
<<<<<<< HEAD
        envelope.get("message").and_then(|v| v.as_str()).is_some(),
        "rate-limit error envelope should include message"
    );
    let details = envelope
        .get("details")
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error envelope missing details")?;
    assert!(
        details
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "rate-limit error envelope should include retry_after_ms"
    );
    assert_eq!(
        details.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(
        details.get("scope").and_then(|v| v.as_str()),
        Some("global")
=======
        data_files.keys().all(|k| {
            matches!(
                k.as_str(),
                "code"
                    | "retry_after_ms"
                    | "retry_at"
                    | "limit_key"
                    | "scope"
                    | "resource_key"
                    | "limit_per_min"
                    | "limit_burst"
                    | "denied_total"
            )
        }),
        "error.data should only include stable keys"
>>>>>>> mcoda/task/bck-05-us-09-t05
    );

    // Wait long enough for the limiter to refill 1 token (per_minute=60).
    thread::sleep(Duration::from_millis(1100));

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "docdex_files", "arguments": {} }
        }),
    )?;
    let ok_files = read_line(&mut mcp.reader)?;
    assert!(
        ok_files.get("result").is_some(),
        "docdex_files should succeed after refill"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let limited_search = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&limited_search), Some(-32029));
    assert_eq!(mcp_error_data_code(&limited_search), Some("rate_limited"));
    let limited_search_bytes = serde_json::to_vec(&limited_search)?.len();
    assert!(
        limited_search_bytes <= MAX_MCP_ERROR_PAYLOAD_BYTES,
        "rate-limit payload should remain small (got {} bytes)",
        limited_search_bytes
    );

    let data_search = limited_search
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error.data object (docdex_search)")?;
<<<<<<< HEAD
    assert_eq!(
        data_search.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(
        data_search.get("scope").and_then(|v| v.as_str()),
        Some("global")
    );
=======
    let payload_bytes = serde_json::to_vec(&limited_search)?;
    assert!(
        payload_bytes.len() <= MAX_MCP_RATE_LIMIT_PAYLOAD_BYTES,
        "rate-limit payload should remain small (got {} bytes)",
        payload_bytes.len()
    );

    fn shape_signature(data: &serde_json::Map<String, Value>) -> Vec<(String, &'static str)> {
        let mut out: Vec<(String, &'static str)> = data
            .iter()
            .map(|(k, v)| {
                let kind = match v {
                    Value::Null => "null",
                    Value::Bool(_) => "bool",
                    Value::Number(_) => "number",
                    Value::String(_) => "string",
                    Value::Array(_) => "array",
                    Value::Object(_) => "object",
                };
                (k.clone(), kind)
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }
>>>>>>> mcoda/task/bck-05-us-09-t29

    assert_eq!(
        rate_limit_data_signature(data_files),
        rate_limit_data_signature(data_search),
        "rate-limit error schema should be identical across tools sharing the limiter"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
<<<<<<< HEAD
<<<<<<< HEAD
fn mcp_backoff_required_is_structured_and_bounded() -> Result<(), Box<dyn Error>> {
=======
fn mcp_rate_limit_schema_is_stable_under_concurrent_tool_bursts() -> Result<(), Box<dyn Error>> {
>>>>>>> mcoda/task/bck-05-us-09-t36
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

<<<<<<< HEAD
=======
fn mcp_backoff_required_errors_are_machine_coded() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
>>>>>>> mcoda/task/bck-05-us-09-t29
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
<<<<<<< HEAD
            "params": { "name": "docdex_index", "arguments": {} }
=======
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
>>>>>>> mcoda/task/bck-05-us-09-t29
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("backoff_required"));
<<<<<<< HEAD

=======
>>>>>>> mcoda/task/bck-05-us-09-t29
    let data = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("backoff error missing error.data object")?;
    assert_eq!(
        data.get("code").and_then(|v| v.as_str()),
        Some("backoff_required")
    );
    assert_eq!(
<<<<<<< HEAD
        data.get("tool").and_then(|v| v.as_str()),
        Some("docdex_index")
    );
    assert!(data
        .get("reason")
        .and_then(|v| v.as_str())
        .map(|value| !value.is_empty())
        .unwrap_or(false));
    assert_eq!(
=======
>>>>>>> mcoda/task/bck-05-us-09-t29
        data.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("backoff_required")
    );

<<<<<<< HEAD
    let payload_bytes = serde_json::to_vec(&resp)?.len();
    assert!(
        payload_bytes <= MAX_MCP_ERROR_PAYLOAD_BYTES,
        "backoff payload should remain small (got {} bytes)",
        payload_bytes
    );

    mcp.shutdown();
    server.kill().ok();
    server.wait().ok();
=======
    let McpHarness {
        mut child,
        stdin,
        mut reader,
    } = McpHarness::spawn_with_env(
        repo.path(),
        &[
            ("DOCDEX_MCP_RATE_LIMIT_PER_MIN", "60"),
            ("DOCDEX_MCP_RATE_LIMIT_BURST", "2"),
        ],
    )?;

    let threads = 32usize;
    let barrier = Arc::new(Barrier::new(threads));
    let stdin = Arc::new(Mutex::new(stdin));
    let mut handles = Vec::with_capacity(threads);

    for i in 0..threads {
        let barrier = barrier.clone();
        let stdin = stdin.clone();
        handles.push(thread::spawn(move || -> Result<(), String> {
            let id = (i + 1) as u64;
            let payload = match i % 4 {
                0 => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
                }),
                1 => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": "docdex_files", "arguments": {} }
                }),
                2 => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": "docdex_stats", "arguments": {} }
                }),
                _ => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": "docdex_open", "arguments": { "path": "docs/overview.md", "start_line": 1, "end_line": 3 } }
                }),
            };
            barrier.wait();
            let mut guard = stdin
                .lock()
                .map_err(|_| "stdin lock poisoned".to_string())?;
            send_line(&mut *guard, payload).map_err(|err| err.to_string())?;
            Ok(())
        }));
    }

    for handle in handles {
        handle.join().expect("thread panicked")?;
    }

    let allowed_keys: HashSet<&str> = [
        "code",
        "retry_after_ms",
        "retry_at",
        "limit_key",
        "scope",
    ]
    .into_iter()
    .collect();
    let mut rate_limited = 0usize;
    let mut schema_variants: HashSet<Vec<(String, &'static str)>> = HashSet::new();
    for _ in 0..threads {
        let resp = read_line(&mut reader)?;
        if mcp_error_code(&resp) == Some(-32029) {
            rate_limited += 1;
            assert_eq!(mcp_error_data_code(&resp), Some("rate_limited"));
            let data = resp
                .get("error")
                .and_then(|v| v.get("data"))
                .and_then(|v| v.as_object())
                .ok_or("rate-limit error missing error.data object")?;
            for key in data.keys() {
                if !allowed_keys.contains(key.as_str()) {
                    return Err(format!("unexpected rate-limit data field: {key}").into());
                }
            }
            assert_eq!(data.get("code").and_then(|v| v.as_str()), Some("rate_limited"));
            assert!(
                data.get("retry_after_ms").and_then(|v| v.as_u64()).is_some(),
                "retry_after_ms must be an integer"
            );
            if let Some(retry_at) = data.get("retry_at") {
                retry_at
                    .as_str()
                    .ok_or("retry_at must be a string when present")?;
            }
            assert_eq!(
                data.get("limit_key").and_then(|v| v.as_str()),
                Some("mcp_tools")
            );
            assert_eq!(data.get("scope").and_then(|v| v.as_str()), Some("global"));

            schema_variants.insert(rate_limit_data_signature(data));
            let payload_bytes = serde_json::to_vec(&resp)?;
            assert!(
                payload_bytes.len() <= MCP_RATE_LIMIT_PAYLOAD_MAX_BYTES,
                "rate-limit rpc payload should remain small (got {} bytes)",
                payload_bytes.len()
            );
        }
    }

    assert!(
        rate_limited >= threads / 2,
        "expected rate limiting under concurrency (got {rate_limited} out of {threads})"
    );
    assert_eq!(
        schema_variants.len(),
        1,
        "rate-limit error schema should not vary across concurrent tools"
    );

    child.kill().ok();
    child.wait().ok();
>>>>>>> mcoda/task/bck-05-us-09-t36
=======
    mcp.shutdown();
    server.kill().ok();
    server.wait().ok();
>>>>>>> mcoda/task/bck-05-us-09-t29
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping HTTP tests: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

<<<<<<< HEAD
fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
=======
fn spawn_server(repo_root: &Path, host: &str, port: u16) -> Result<Child, Box<dyn Error>> {
    spawn_server_with_options(repo_root, host, port, None, None)
}

fn spawn_server_with_options(
    repo_root: &Path,
    host: &str,
    port: u16,
    state_dir: Option<&Path>,
    max_limit: Option<usize>,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let mut cmd = Command::new(docdex_bin());
    cmd.args([
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
    ]);
    if let Some(state_dir) = state_dir {
        let state_dir = state_dir.to_string_lossy().to_string();
        cmd.args(["--state-dir", state_dir.as_str()]);
    }
    if let Some(max_limit) = max_limit {
        let max_limit = max_limit.max(1).to_string();
        cmd.args(["--max-limit", max_limit.as_str()]);
    }
    Ok(cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?)
>>>>>>> mcoda/task/bck-05-us-08-t34
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

#[test]
fn mcp_error_codes_match_http_invalid_query() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let http_err: Value = client
        .get(&url)
        .query(&[("q", ""), ("limit", "1")])
        .send()?
        .json()?;
    assert_eq!(
        http_err
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_query"),
        "HTTP invalid query should return machine code invalid_query"
    );

    let mut mcp = McpHarness::spawn(repo.path(), state_root.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "" } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&resp),
        Some("invalid_query"),
        "MCP invalid query should map to the same machine code as HTTP"
    );

    mcp.shutdown();
    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn mcp_validation_errors_have_consistent_envelope() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let mut mcp = McpHarness::spawn(repo.path(), state_root.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": { "name": "docdex_files", "arguments": { "limit": "not-a-number" } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("invalid_params"));
    assert_eq!(
        resp.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("tool"))
            .and_then(|v| v.as_str()),
        Some("docdex_files"),
        "validation errors should include tool name"
    );
    assert!(
        resp.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("invalid type"),
        "validation errors should include a reason string"
    );

    let other_repo = TempDir::new()?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "project_root": other_repo.path().to_string_lossy()
                }
            }
        }),
    )?;
    let mismatch = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&mismatch), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&mismatch),
        Some("unknown_repo"),
        "repo mismatches should be machine-coded as unknown_repo"
    );
    let details = mismatch
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("mismatch error should include details")?;
    let expected = repo
        .path()
        .canonicalize()
        .unwrap_or_else(|_| repo.path().to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(
        details.get("knownCanonicalPath").and_then(|v| v.as_str()),
        Some(expected.as_str()),
        "mismatch details should include known canonical path"
    );
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("mismatch details should include recoverySteps array")?;
    assert!(!steps.is_empty(), "mismatch details should include recovery steps");
    assert!(
        steps.iter().any(|v| v
            .as_str()
            .unwrap_or_default()
            .contains("docdexd mcp --repo")),
        "expected recoverySteps to mention restarting the MCP server with `docdexd mcp --repo`; got: {details}"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
<<<<<<< HEAD
fn mcp_schema_version_negotiation_rejects_unsupported_versions() -> Result<(), Box<dyn Error>> {
=======
fn mcp_invalid_argument_errors_are_machine_coded() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn_with_env(repo.path(), &[("DOCDEX_ENABLE_MEMORY", "1")])?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": { "name": "docdex_memory_store", "arguments": { "text": "" } }
        }),
    )?;
    let store_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&store_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&store_err), Some("invalid_argument"));
    assert_eq!(
        store_err
            .get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("tool"))
            .and_then(|v| v.as_str()),
        Some("docdex_memory_store")
    );
    assert!(
        store_err
            .get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("text must not be empty"),
        "memory store invalid_argument should include a reason"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": { "name": "docdex_memory_recall", "arguments": { "query": "   " } }
        }),
    )?;
    let recall_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&recall_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&recall_err), Some("invalid_argument"));
    assert_eq!(
        recall_err
            .get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("tool"))
            .and_then(|v| v.as_str()),
        Some("docdex_memory_recall")
    );
    assert!(
        recall_err
            .get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("reason"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("query must not be empty"),
        "memory recall invalid_argument should include a reason"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_missing_project_root_path_is_missing_repo_path() -> Result<(), Box<dyn Error>> {
>>>>>>> mcoda/task/bck-05-us-09-t29
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "schema_version": 99
                }
            }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("unsupported_version"));
    let details = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("unsupported version error should include details")?;
    let schema = details
        .get("schema")
        .ok_or("unsupported version details should include schema")?;
    assert_eq!(
        schema.get("name").and_then(|v| v.as_str()),
        Some("docdex_search")
    );
    assert_eq!(schema.get("requested").and_then(|v| v.as_u64()), Some(99));
    let supported = schema
        .get("supported")
        .ok_or("unsupported version details should include supported range")?;
    assert_eq!(supported.get("min").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(supported.get("max").and_then(|v| v.as_u64()), Some(1));

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_schema_version_negotiation_rejects_unsupported_versions() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "schema_version": 99
                }
            }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("unsupported_version"));
    let details = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("unsupported version error should include details")?;
    let schema = details
        .get("schema")
        .ok_or("unsupported version details should include schema")?;
    assert_eq!(
        schema.get("name").and_then(|v| v.as_str()),
        Some("docdex_search")
    );
    assert_eq!(schema.get("requested").and_then(|v| v.as_u64()), Some(99));
    let supported = schema
        .get("supported")
        .ok_or("unsupported version details should include supported range")?;
    assert_eq!(supported.get("min").and_then(|v| v.as_u64()), Some(1));
    assert_eq!(supported.get("max").and_then(|v| v.as_u64()), Some(1));

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_missing_project_root_path_is_missing_repo_path() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let mut mcp = McpHarness::spawn(repo.path(), state_root.path())?;

    let missing = repo.path().join("does-not-exist");
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "project_root": missing.to_string_lossy()
                }
            }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("missing_repo_path"));
    let details = resp
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("details"))
        .ok_or("missing repo path error should include details")?;
    let expected = missing.to_string_lossy().replace('\\', "/");
    assert_eq!(
        details.get("normalizedPath").and_then(|v| v.as_str()),
        Some(expected.as_str())
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_missing_and_stale_index_errors_are_distinct() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let missing = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&missing), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&missing),
        Some("missing_index"),
        "missing index should return missing_index code"
    );
    mcp.shutdown();

    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;
    thread::sleep(Duration::from_millis(1100));
    std::fs::write(repo.path().join("docs").join("overview.md"), "# Overview\n\nMCP_ROADMAP updated.\n")?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let stale = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&stale), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&stale),
        Some("stale_index"),
        "stale index should return stale_index code"
    );
    mcp.shutdown();

    Ok(())
}

#[test]
fn mcp_missing_and_stale_index_errors_are_distinct() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let missing = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&missing), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&missing),
        Some("missing_index"),
        "missing index should return missing_index code"
    );
    mcp.shutdown();

    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;
    thread::sleep(Duration::from_millis(1100));
    std::fs::write(repo.path().join("docs").join("overview.md"), "# Overview\n\nMCP_ROADMAP updated.\n")?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 14,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "query": "MCP_ROADMAP", "limit": 1 } }
        }),
    )?;
    let stale = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&stale), Some(-32602));
    assert_eq!(
        mcp_error_data_code(&stale),
        Some("stale_index"),
        "stale index should return stale_index code"
    );
    mcp.shutdown();

    Ok(())
}

#[test]
fn mcp_limit_and_max_content_enforcement_is_predictable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn(repo.path(), state_root.path())?;

    // Clamp docdex_search to max-results (4).
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "MCP_ROADMAP", "limit": 999 }
            }
        }),
    )?;
    let search_resp = read_line(&mut mcp.reader)?;
    let search_body = parse_tool_result(&search_resp)?;
    assert_eq!(
        search_body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should report the clamped limit"
    );
    let hits_len = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(hits_len <= 4, "docdex_search hits should not exceed max-results");
    let hits = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return hits array")?;
    let first_hit = hits.first().ok_or("docdex_search missing hit")?;
    assert_search_hit_schema(first_hit)?;

    // Clamp docdex_files to max (1000) even if request is larger.
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 5000, "offset": 0 }
            }
        }),
    )?;
    let files_resp = read_line(&mut mcp.reader)?;
    let files_body = parse_tool_result(&files_resp)?;
    assert_eq!(
        files_body.get("limit").and_then(|v| v.as_u64()),
        Some(1000),
        "docdex_files should report the clamped limit"
    );
    let files = files_body
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("docdex_files should return results array")?;
    let first_file = files.first().ok_or("docdex_files missing result")?;
    assert_doc_snapshot_schema(first_file)?;

    // docdex_open should fail with a structured max-content error.
    let big_path = repo.path().join("docs").join("big.md");
    let big_size = 2_000_000usize;
    std::fs::write(&big_path, "x".repeat(big_size))?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": { "name": "docdex_open", "arguments": { "path": "docs/big.md" } }
        }),
    )?;
    let open_resp = read_line(&mut mcp.reader)?;
    assert!(
        open_resp.get("error").is_none(),
        "docdex_open should clamp oversized content instead of erroring"
    );
    let open_body = parse_tool_result(&open_resp)?;
    let content = open_body
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or("docdex_open should return content")?;
    assert!(
        content.len() <= 512 * 1024,
        "docdex_open content should be bounded"
    );
    assert_eq!(
        open_err.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("details"))
            .and_then(|v| v.get("actual_bytes"))
            .and_then(|v| v.as_u64()),
        Some(big_size as u64),
        "actual_bytes should be reported"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_search_clamps_after_parser_sanitization() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "MCP_ROADMAP:\"", "limit": 999 }
            }
        }),
    )?;
    let search_resp = read_line(&mut mcp.reader)?;
    let search_body = parse_tool_result(&search_resp)?;
    assert_eq!(
        search_body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should report the clamped limit"
    );
    let hits_len = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(hits_len <= 4, "docdex_search hits should remain bounded");

    let meta_query = search_body
        .get("meta")
        .and_then(|v| v.get("query"))
        .ok_or("search response missing meta.query")?;
    assert_eq!(
        meta_query.get("rewrite").and_then(|v| v.as_str()),
        Some("sanitized"),
        "parser errors should surface sanitized query metadata"
    );
    assert_eq!(
        meta_query.get("effective").and_then(|v| v.as_str()),
        Some("MCP_ROADMAP"),
        "sanitized query should be reflected in metadata"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_search_snippet_and_summary_bounds_are_enforced() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let long_doc = repo.path().join("docs").join("long.md");
    let long_line = "LONGTERM ".repeat(200);
    std::fs::write(&long_doc, format!("# Long\n\n{long_line}\n"))?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "LONGTERM", "limit": 1 }
            }
        }),
    )?;
    let baseline_resp = read_line(&mut mcp.reader)?;
    let baseline_body = parse_tool_result(&baseline_resp)?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "LONGTERM", "limit": 999 }
            }
        }),
    )?;
    let clamped_resp = read_line(&mut mcp.reader)?;
    let clamped_body = parse_tool_result(&clamped_resp)?;

    assert_eq!(
        json_keys(&baseline_body)?,
        json_keys(&clamped_body)?,
        "clamped search responses should keep the same top-level schema"
    );
    assert_eq!(
        clamped_body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should report the clamped limit"
    );

    let hits = clamped_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return hits array")?;
    assert!(
        !hits.is_empty(),
        "expected at least one search hit for LONGTERM"
    );
    assert!(hits.len() <= 4, "hits should not exceed max-results");

    let allowed_hit_keys = [
        "doc_id",
        "rel_path",
        "path",
        "score",
        "summary",
        "snippet",
        "token_estimate",
        "snippet_origin",
        "snippet_truncated",
        "line_start",
        "line_end",
    ];
    for hit in hits {
        assert_keys_subset(hit, &allowed_hit_keys, "search hit")?;
        let summary = hit.get("summary").and_then(|v| v.as_str()).unwrap_or("");
        let snippet = hit.get("snippet").and_then(|v| v.as_str()).unwrap_or("");
        assert!(
            summary.chars().count() <= 360,
            "summary should be <= 360 chars (got {})",
            summary.chars().count()
        );
        assert!(
            snippet.chars().count() <= 420,
            "snippet should be <= 420 chars (got {})",
            snippet.chars().count()
        );
    }

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_files_clamp_and_schema_are_stable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 2, "offset": 0 }
            }
        }),
    )?;
    let baseline_resp = read_line(&mut mcp.reader)?;
    let baseline_body = parse_tool_result(&baseline_resp)?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 5000, "offset": 0 }
            }
        }),
    )?;
    let clamped_resp = read_line(&mut mcp.reader)?;
    let clamped_body = parse_tool_result(&clamped_resp)?;

    assert_eq!(
        json_keys(&baseline_body)?,
        json_keys(&clamped_body)?,
        "clamped files responses should keep the same top-level schema"
    );
    assert_eq!(
        clamped_body.get("limit").and_then(|v| v.as_u64()),
        Some(1000),
        "docdex_files should report the clamped limit"
    );

    let results = clamped_body
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("docdex_files should return results array")?;
    assert!(results.len() <= 1000, "results should be clamped to max limit");

    let allowed_doc_keys = ["doc_id", "rel_path", "summary", "token_estimate"];
    for doc in results {
        assert_keys_subset(doc, &allowed_doc_keys, "doc snapshot")?;
    }

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_search_aggregation_respects_max_results() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let docs_dir = repo.path().join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    for i in 0..2 {
        std::fs::write(
            docs_dir.join(format!("repo_{i}.md")),
            format!("# Repo {i}\n\nAGG_TERM appears here.\n"),
        )?;
    }

    let mut sources = Vec::new();
    for i in 0..5 {
        let lib_doc = repo
            .path()
            .join("vendor")
            .join(format!("lib{i}"))
            .join("README.md");
        std::fs::create_dir_all(lib_doc.parent().expect("parent"))?;
        std::fs::write(
            &lib_doc,
            format!("# Lib {i}\n\nAGG_TERM appears here too.\n"),
        )?;
        sources.push(json!({
            "library": format!("lib{i}"),
            "version": "1.0.0",
            "source": "local_file",
            "path": lib_doc.display().to_string(),
            "title": format!("Lib {i}")
        }));
    }
    let sources_path = repo.path().join("libs_sources.json");
    std::fs::write(&sources_path, serde_json::to_string_pretty(&json!({ "sources": sources }))?)?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );
    let ingest_out = run_docdex([
        "libs-ingest",
        "--repo",
        repo_str.as_str(),
        "--sources",
        sources_path.to_string_lossy().as_ref(),
    ])?;
    assert!(
        ingest_out.status.success(),
        "libs-ingest should succeed: {}",
        String::from_utf8_lossy(&ingest_out.stderr)
    );

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "AGG_TERM", "limit": 999 }
            }
        }),
    )?;
    let search_resp = read_line(&mut mcp.reader)?;
    let search_body = parse_tool_result(&search_resp)?;

    assert_eq!(
        search_body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should report the clamped limit"
    );
    let hits = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return hits array")?;
    assert!(
        hits.len() <= 4,
        "aggregated hits should not exceed max-results"
    );
    assert!(
        hits.iter().any(|hit| {
            hit.get("doc_id")
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with("libs:"))
                .unwrap_or(false)
                || hit.get("rel_path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.starts_with("libs/"))
                    .unwrap_or(false)
        }),
        "expected at least one libs hit when libs index is present"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_resource_read_enforces_max_content() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let big_path = repo.path().join("docs").join("big.md");
    std::fs::write(&big_path, "x".repeat(600_000))?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 60,
            "method": "resources/read",
            "params": { "uri": "docdex://docs/big.md" }
        }),
    )?;
    let open_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&open_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&open_err), Some("max_content_exceeded"));
    assert_eq!(
        open_err.get("error")
            .and_then(|v| v.get("data"))
            .and_then(|v| v.get("details"))
            .and_then(|v| v.get("max_bytes"))
            .and_then(|v| v.as_u64()),
        Some(512 * 1024),
        "max_bytes should be reported"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_schema_is_stable_when_clamped() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "MCP_ROADMAP", "limit": 2 }
            }
        }),
    )?;
    let search_ok = read_line(&mut mcp.reader)?;
    let search_ok_body = parse_tool_result(&search_ok)?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "MCP_ROADMAP", "limit": 999 }
            }
        }),
    )?;
    let search_clamped = read_line(&mut mcp.reader)?;
    let search_clamped_body = parse_tool_result(&search_clamped)?;

    assert_eq!(
        object_keys(&search_ok_body)?,
        object_keys(&search_clamped_body)?,
        "docdex_search schema should be stable when clamped"
    );
    assert_eq!(
        first_item_keys(&search_ok_body, "hits")?,
        first_item_keys(&search_clamped_body, "hits")?,
        "docdex_search hit schema should be stable when clamped"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 2, "offset": 0 }
            }
        }),
    )?;
    let files_ok = read_line(&mut mcp.reader)?;
    let files_ok_body = parse_tool_result(&files_ok)?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 5000, "offset": 0 }
            }
        }),
    )?;
    let files_clamped = read_line(&mut mcp.reader)?;
    let files_clamped_body = parse_tool_result(&files_clamped)?;

    assert_eq!(
        object_keys(&files_ok_body)?,
        object_keys(&files_clamped_body)?,
        "docdex_files schema should be stable when clamped"
    );
    assert_eq!(
        first_item_keys(&files_ok_body, "results")?,
        first_item_keys(&files_clamped_body, "results")?,
        "docdex_files item schema should be stable when clamped"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_search_snippet_size_is_bounded() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "LONG_TERM", "limit": 1 }
            }
        }),
    )?;
    let search_resp = read_line(&mut mcp.reader)?;
    let search_body = parse_tool_result(&search_resp)?;
    let hits = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return hits array")?;
    let first_hit = hits.first().ok_or("docdex_search missing hit")?;
    let snippet = first_hit
        .get("snippet")
        .and_then(|v| v.as_str())
        .ok_or("docdex_search hit missing snippet")?;
    let snippet_len = snippet.chars().count();
    assert!(
        snippet_len <= MAX_SNIPPET_CHARS,
        "snippet length should be <= {MAX_SNIPPET_CHARS}, got {snippet_len}"
    );
    let truncated = first_hit
        .get("snippet_truncated")
        .and_then(|v| v.as_bool())
        .ok_or("docdex_search hit missing snippet_truncated")?;
    if snippet_len == MAX_SNIPPET_CHARS {
        assert!(
            truncated,
            "snippet_truncated should be true when at max length"
        );
    }

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_max_results_are_repo_invariant_and_no_leakage() -> Result<(), Box<dyn Error>> {
    fn write_repo_with_prefix(repo_root: &Path, prefix: &str) -> Result<(), Box<dyn Error>> {
        let docs_dir = repo_root.join("docs");
        std::fs::create_dir_all(&docs_dir)?;
        for i in 0..6 {
            std::fs::write(
                docs_dir.join(format!("{prefix}_{i}.md")),
                format!("# {prefix} {i}\n\nshared_term\n"),
            )?;
        }
        Ok(())
    }

    let repo_a = TempDir::new()?;
    let repo_b = TempDir::new()?;
    write_repo_with_prefix(repo_a.path(), "a")?;
    write_repo_with_prefix(repo_b.path(), "b")?;

    let repo_a_str = repo_a.path().to_string_lossy().to_string();
    let repo_b_str = repo_b.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_a_str.as_str()])?;
    run_docdex(["index", "--repo", repo_b_str.as_str()])?;

    let mut mcp_a = McpHarness::spawn(repo_a.path())?;
    let mut mcp_b = McpHarness::spawn(repo_b.path())?;

    send_line(
        &mut mcp_a.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "shared_term", "limit": 999 }
            }
        }),
    )?;
    let resp_a = read_line(&mut mcp_a.reader)?;
    let body_a = parse_tool_result(&resp_a)?;

    send_line(
        &mut mcp_b.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "shared_term", "limit": 999 }
            }
        }),
    )?;
    let resp_b = read_line(&mut mcp_b.reader)?;
    let body_b = parse_tool_result(&resp_b)?;

    assert_eq!(
        body_a.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "repo A should clamp limit to max-results"
    );
    assert_eq!(
        body_b.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "repo B should clamp limit to max-results"
    );

    let hits_a = body_a
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("repo A missing hits array")?;
    let hits_b = body_b
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("repo B missing hits array")?;
    assert!(hits_a.len() <= 4, "repo A should respect max-results");
    assert!(hits_b.len() <= 4, "repo B should respect max-results");
    assert!(
        hits_a.iter().all(|hit| {
            hit.get("rel_path")
                .and_then(|v| v.as_str())
                .map(|path| path.starts_with("docs/a_"))
                .unwrap_or(false)
        }),
        "repo A results should not include repo B paths"
    );
    assert!(
        hits_b.iter().all(|hit| {
            hit.get("rel_path")
                .and_then(|v| v.as_str())
                .map(|path| path.starts_with("docs/b_"))
                .unwrap_or(false)
        }),
        "repo B results should not include repo A paths"
    );

    mcp_a.shutdown();
    mcp_b.shutdown();
    Ok(())
}

#[test]
fn cli_invalid_query_error_matches_machine_reason() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let query_out = run_docdex(state_root.path(), [
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "",
        "--limit",
        "1",
    ])?;
    assert!(
        !query_out.status.success(),
        "empty query should fail in CLI query command"
    );
    let stderr = String::from_utf8_lossy(&query_out.stderr);
    assert!(
        stderr.contains("invalid query"),
        "CLI should report invalid query: {stderr}"
    );
    Ok(())
}

#[test]
<<<<<<< HEAD
<<<<<<< HEAD
fn cli_missing_vs_stale_index_errors_are_distinct_and_actionable() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo_with_tokens(repo.path(), "repo_token", "COMMON_TERM", 1)?;
    let repo_str = repo.path().to_string_lossy().to_string();

    let missing_out = run_docdex([
=======
fn cli_missing_index_includes_hint_and_no_auto_state_dir() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let state_dir = repo.path().join(".docdex").join("index");

    let output = run_docdex([
>>>>>>> mcoda/task/bck-05-us-08-t22
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
<<<<<<< HEAD
        "COMMON_TERM",
=======
        "MCP_ROADMAP",
>>>>>>> mcoda/task/bck-05-us-08-t22
        "--limit",
        "1",
    ])?;
    assert!(
<<<<<<< HEAD
        !missing_out.status.success(),
        "missing index should fail"
    );
    let missing_payload = parse_cli_error(&missing_out.stderr)?;
    assert_eq!(
        missing_payload
=======
        !output.status.success(),
        "expected query to fail without an index"
    );
    let payload = parse_cli_error(&output.stderr)?;
    assert_eq!(
        payload
>>>>>>> mcoda/task/bck-05-us-08-t22
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("missing_index")
    );
<<<<<<< HEAD
    let missing_message = missing_payload
        .get("error")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        missing_message.contains("docdexd index") || missing_message.contains("docdex_index"),
        "missing index should include remediation hint: {missing_message}"
    );

    let state_dir = repo.path().join(".docdex").join("index");
    std::fs::create_dir_all(&state_dir)?;
    let stale_out = run_docdex([
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "COMMON_TERM",
        "--limit",
        "1",
    ])?;
    assert!(
        !stale_out.status.success(),
        "stale index should fail"
    );
    let stale_payload = parse_cli_error(&stale_out.stderr)?;
    assert_eq!(
        stale_payload
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("stale_index")
    );
    let stale_message = stale_payload
        .get("error")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_lowercase();
    assert!(
        stale_message.contains("docdexd index") || stale_message.contains("docdex_index"),
        "stale index should include remediation hint: {stale_message}"
    );

=======
    let message = payload
        .get("error")
        .and_then(|v| v.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("docdexd index"),
        "missing_index should include remediation hint; got: {message}"
    );
    assert!(
        !state_dir.exists(),
        "missing_index should not create state dir automatically"
    );
>>>>>>> mcoda/task/bck-05-us-08-t22
    Ok(())
}

#[test]
<<<<<<< HEAD
fn cli_search_is_repo_isolated_and_respects_limit() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo_with_tokens(&repo_a, "repo_a_token", "COMMON_TERM", 6)?;
    write_repo_with_tokens(&repo_b, "repo_b_token", "OTHER_TERM", 0)?;

    index_repo_with_state(&repo_a, state_root.path())?;
    index_repo_with_state(&repo_b, state_root.path())?;

    let repo_a_str = repo_a.to_string_lossy().to_string();
    let state_root_str = state_root.path().to_string_lossy().to_string();

    let isolate_out = run_docdex([
        "query",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        state_root_str.as_str(),
        "--query",
        "repo_b_token",
        "--limit",
        "5",
        "--repo-only",
    ])?;
    assert!(isolate_out.status.success(), "repo query should succeed");
    let isolate_payload = parse_cli_json(&isolate_out.stdout)?;
    let isolate_hits = isolate_payload
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("CLI search missing hits array")?;
    assert!(
        isolate_hits.is_empty(),
        "repo-scoped CLI query must not return cross-repo hits"
    );

    let limit_out = run_docdex([
        "query",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        state_root_str.as_str(),
        "--query",
        "COMMON_TERM",
        "--limit",
        "3",
        "--repo-only",
    ])?;
    assert!(limit_out.status.success(), "repo query should succeed");
    let limit_payload = parse_cli_json(&limit_out.stdout)?;
    let limit_hits_len = limit_payload
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        limit_hits_len <= 3,
        "CLI limit should cap results"
    );

    Ok(())
}

#[test]
fn mcp_search_is_repo_isolated_and_respects_max_results() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo_with_tokens(&repo_a, "repo_a_token", "COMMON_TERM", 6)?;
    write_repo_with_tokens(&repo_b, "repo_b_token", "OTHER_TERM", 0)?;

    index_repo_with_state(&repo_a, state_root.path())?;
    index_repo_with_state(&repo_b, state_root.path())?;

    let mut mcp =
        McpHarness::spawn_with_options(&repo_a, &[], Some(state_root.path()), 3)?;

=======
fn mcp_shared_state_dir_does_not_leak_cross_repo_hits() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let repo_a = TempDir::new()?;
    let repo_b = TempDir::new()?;
    write_repo_with_token(repo_a.path(), "REPO_A_ONLY_TOKEN")?;
    write_repo_with_token(repo_b.path(), "REPO_B_ONLY_TOKEN")?;

    let state_root_str = state_root.path().to_string_lossy().to_string();
    let repo_a_str = repo_a.path().to_string_lossy().to_string();
    run_docdex([
        "index",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        &state_root_str,
    ])?;

    let mut mcp = McpHarness::spawn_with_state_dir(repo_b.path(), state_root.path())?;
>>>>>>> mcoda/task/bck-05-us-08-t22
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
<<<<<<< HEAD
                "arguments": { "query": "repo_b_token", "limit": 5 }
            }
        }),
    )?;
    let isolate_resp = read_line(&mut mcp.reader)?;
    let isolate_body = parse_tool_result(&isolate_resp)?;
    let isolate_hits = isolate_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("MCP search missing hits array")?;
    assert!(
        isolate_hits.is_empty(),
        "repo-scoped MCP query must not return cross-repo hits"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": "COMMON_TERM", "limit": 999 }
            }
        }),
    )?;
    let limit_resp = read_line(&mut mcp.reader)?;
    let limit_body = parse_tool_result(&limit_resp)?;
    assert_eq!(
        limit_body.get("limit").and_then(|v| v.as_u64()),
        Some(3),
        "MCP should report the clamped limit"
    );
    let limit_hits_len = limit_body
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        limit_hits_len <= 3,
        "MCP max results should cap returned hits"
=======
                "arguments": { "query": "REPO_A_ONLY_TOKEN", "limit": 5 }
            }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert!(
        resp.get("result").is_some(),
        "expected search to return a result payload"
    );
    let body = parse_tool_result(&resp)?;
    let hits = body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("search response missing hits array")?;
    assert!(
        hits.is_empty(),
        "expected repo-b search to ignore repo-a index hits"
    );
    let expected_root = repo_b
        .path()
        .canonicalize()
        .unwrap_or_else(|_| repo_b.path().to_path_buf())
        .to_string_lossy()
        .to_string();
    assert_eq!(
        body.get("repo_root").and_then(|v| v.as_str()),
        Some(expected_root.as_str()),
        "search should report repo-b root"
>>>>>>> mcoda/task/bck-05-us-08-t22
    );

    mcp.shutdown();
    Ok(())
}

#[test]
<<<<<<< HEAD
fn http_search_is_repo_isolated_and_respects_max_limit() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo_with_tokens(&repo_a, "repo_a_token", "COMMON_TERM", 6)?;
    write_repo_with_tokens(&repo_b, "repo_b_token", "OTHER_TERM", 0)?;

    index_repo_with_state(&repo_a, state_root.path())?;
    index_repo_with_state(&repo_b, state_root.path())?;
=======
fn mcp_index_writer_backoff_is_machine_readable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;
>>>>>>> mcoda/task/bck-05-us-08-t22

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
<<<<<<< HEAD
    let mut server = spawn_server_with_options(
        &repo_a,
        host,
        port,
        Some(state_root.path()),
        Some(3),
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let isolate_resp: Value = client
        .get(&url)
        .query(&[("q", "repo_b_token"), ("limit", "5"), ("snippets", "false")])
        .send()?
        .json()?;
    let isolate_hits = isolate_resp
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("HTTP search missing hits array")?;
    assert!(
        isolate_hits.is_empty(),
        "repo-scoped HTTP query must not return cross-repo hits"
    );

    let limit_resp: Value = client
        .get(&url)
        .query(&[("q", "COMMON_TERM"), ("limit", "999"), ("snippets", "false")])
        .send()?
        .json()?;
    let limit_hits_len = limit_resp
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.len())
        .unwrap_or(0);
    assert!(
        limit_hits_len <= 3,
        "HTTP max_limit should cap results"
    );

=======
    let mut server = spawn_server(repo.path(), host, port)?;
    wait_for_health(host, port)?;
=======
fn mcp_search_remains_repo_scoped_during_concurrent_reindex() -> Result<(), Box<dyn Error>> {
    const TERM: &str = "CONCURRENCY_TERM";
    let repo = setup_large_repo(TERM, 120, 128 * 1024)?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let mut reindex = Command::new(docdex_bin())
        .args(["index", "--repo", repo_str.as_str()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let state_dir = repo.path().join(".docdex").join("index");
    wait_for_writer_lock(&state_dir, &mut reindex, Duration::from_secs(10))?;
>>>>>>> mcoda/task/bck-05-us-08-t13

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
<<<<<<< HEAD
            "id": 31,
=======
            "id": 301,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "query": TERM, "limit": 999 }
            }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    let body = parse_tool_result(&resp)?;
    let hits = body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return hits array")?;
    assert!(!hits.is_empty(), "expected search hits during reindex");
    assert!(
        hits.len() <= 4,
        "docdex_search should clamp to max-results (expected <= 4, got {})",
        hits.len()
    );
    assert_eq!(
        body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should report the clamped limit"
    );
    for hit in hits {
        let path = hit
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or("hit missing path")?;
        assert!(
            path.starts_with("docs/"),
            "expected repo-local path, got {path}"
        );
        assert!(
            repo.path().join(path).exists(),
            "hit path should exist in repo; got {path}"
        );
    }

    mcp.shutdown();
    reindex.kill().ok();
    reindex.wait().ok();
    Ok(())
}

#[test]
fn mcp_index_returns_backoff_required_during_concurrent_updates() -> Result<(), Box<dyn Error>> {
    const TERM: &str = "CONCURRENCY_TERM";
    let repo = setup_large_repo(TERM, 120, 128 * 1024)?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let mut reindex = Command::new(docdex_bin())
        .args(["index", "--repo", repo_str.as_str()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let state_dir = repo.path().join(".docdex").join("index");
    wait_for_writer_lock(&state_dir, &mut reindex, Duration::from_secs(10))?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 401,
>>>>>>> mcoda/task/bck-05-us-08-t13
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
        }),
    )?;
<<<<<<< HEAD
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("backoff_required"));
    let reason = resp
=======
    let full_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&full_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&full_err), Some("backoff_required"));
    let reason = full_err
>>>>>>> mcoda/task/bck-05-us-08-t13
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("reason"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
<<<<<<< HEAD
        reason.contains("retry"),
        "backoff_required should include retry guidance; got: {reason}"
    );

    mcp.shutdown();
>>>>>>> mcoda/task/bck-05-us-08-t22
    server.kill().ok();
    server.wait().ok();
    Ok(())
}
<<<<<<< HEAD
=======

#[test]
fn mcp_tool_failure_does_not_corrupt_search_state() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn(repo.path())?;
    let baseline = search_hit_ids(&mut mcp, 40, "MCP_ROADMAP", 3)?;
    assert!(
        !baseline.is_empty(),
        "expected search to return initial hits"
=======
        reason.contains("index writer unavailable") || reason.contains("retry later"),
        "backoff_required should include a retry hint; got: {reason}"
>>>>>>> mcoda/task/bck-05-us-08-t13
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
<<<<<<< HEAD
            "id": 41,
            "method": "tools/call",
            "params": { "name": "docdex_open", "arguments": { "path": "../secrets.md" } }
        }),
    )?;
    let open_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&open_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&open_err), Some("invalid_path"));

    let after = search_hit_ids(&mut mcp, 42, "MCP_ROADMAP", 3)?;
    assert_eq!(baseline, after, "search results should be deterministic");

    mcp.shutdown();
    Ok(())
}
>>>>>>> mcoda/task/bck-05-us-08-t22
=======
            "id": 402,
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": ["docs/doc_0.md"] } }
        }),
    )?;
    let incremental_err = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&incremental_err), Some(-32602));
    assert_eq!(mcp_error_data_code(&incremental_err), Some("backoff_required"));

    mcp.shutdown();
    reindex.kill().ok();
    reindex.wait().ok();
    Ok(())
}
>>>>>>> mcoda/task/bck-05-us-08-t13
