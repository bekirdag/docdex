use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

struct McpHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpHarness {
    fn spawn(repo: &Path, state_root: &Path) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_env(repo, state_root, &[])
    }

    fn spawn_with_env(
        repo: &Path,
        state_root: &Path,
        envs: &[(&str, &str)],
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--log",
            "warn",
            "--max-results",
            "4",
        ]);
        cmd.env("DOCDEX_STATE_DIR", state_root);
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
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .args(args)
        .output()?)
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
        }
    }
    Ok(())
}

fn mcp_error_code(resp: &Value) -> Option<i64> {
    resp.get("error").and_then(|v| v.get("code")).and_then(|v| v.as_i64())
}

fn mcp_error_data_code(resp: &Value) -> Option<&str> {
    resp.get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
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

    let data_files = limited_files
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error.data object")?;
    assert_eq!(
        data_files.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(
        data_files.get("scope").and_then(|v| v.as_str()),
        Some("global")
    );
    assert!(
        data_files
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .is_some(),
        "retry_after_ms must be an integer"
    );
    assert!(
        data_files.keys().all(|k| {
            matches!(
                k.as_str(),
                "code" | "retry_after_ms" | "retry_at" | "limit_key" | "scope"
            )
        }),
        "error.data should only include stable keys"
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

    let data_search = limited_search
        .get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or("rate-limit error missing error.data object (docdex_search)")?;

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

    assert_eq!(
        shape_signature(data_files),
        shape_signature(data_search),
        "rate-limit error schema should be identical across tools sharing the limiter"
    );

    mcp.shutdown();
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
