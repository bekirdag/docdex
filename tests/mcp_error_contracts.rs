use reqwest::blocking::Client;
use serde_json::{json, Value};
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
    fn spawn(repo: &Path) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_env(repo, &[])
    }

    fn spawn_with_env(
        repo: &Path,
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

fn run_docdex<I, S>(args: I) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin()).args(args).output()?)
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

fn mcp_error_code(resp: &Value) -> Option<i64> {
    resp.get("error").and_then(|v| v.get("code")).and_then(|v| v.as_i64())
}

fn mcp_error_data_code(resp: &Value) -> Option<&str> {
    resp.get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
}

fn error_data_map(resp: &Value) -> Result<&serde_json::Map<String, Value>, Box<dyn Error>> {
    resp.get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.as_object())
        .ok_or_else(|| "error response missing error.data object".into())
}

fn assert_enveloped_error(
    resp: &Value,
    expected_code: &str,
    expected_tool: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let data = error_data_map(resp)?;
    assert_eq!(
        data.get("code").and_then(|v| v.as_str()),
        Some(expected_code),
        "error.data.code should match expected code"
    );
    let message = data
        .get("message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !message.trim().is_empty(),
        "error.data.message should be non-empty"
    );
    let nested = data
        .get("error")
        .and_then(|v| v.as_object())
        .ok_or("error.data.error should be an object")?;
    assert_eq!(
        nested.get("code").and_then(|v| v.as_str()),
        Some(expected_code),
        "error.data.error.code should mirror error.data.code"
    );
    assert_eq!(
        nested.get("message").and_then(|v| v.as_str()),
        Some(message),
        "error.data.error.message should mirror error.data.message"
    );
    if let Some(tool) = expected_tool {
        assert_eq!(
            data.get("tool").and_then(|v| v.as_str()),
            Some(tool),
            "error.data.tool should match the tool name"
        );
        assert_eq!(
            nested.get("tool").and_then(|v| v.as_str()),
            Some(tool),
            "error.data.error.tool should match the tool name"
        );
    }
    Ok(())
}

fn assert_invalid_params(resp: &Value, expected_tool: &str) -> Result<(), Box<dyn Error>> {
    assert_eq!(mcp_error_code(resp), Some(-32602));
    assert_eq!(mcp_error_data_code(resp), Some("invalid_params"));
    assert_enveloped_error(resp, "invalid_params", Some(expected_tool))?;
    let data = error_data_map(resp)?;
    let details = data
        .get("details")
        .and_then(|v| v.as_object())
        .ok_or("invalid params error missing details")?;
    assert_eq!(
        details.get("validation").and_then(|v| v.as_str()),
        Some("serde")
    );
    assert_eq!(
        details.get("tool").and_then(|v| v.as_str()),
        Some(expected_tool)
    );
    let reason = data
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !reason.trim().is_empty(),
        "invalid params error should include a reason string"
    );
    Ok(())
}

fn sorted_keys(map: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut keys: Vec<String> = map.keys().cloned().collect();
    keys.sort();
    keys
}

fn parse_cli_error(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let trimmed = raw.trim();
    Ok(serde_json::from_str(trimmed)?)
}

#[test]
fn mcp_rate_limit_errors_include_retry_hints() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn_with_env(
        repo.path(),
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

fn spawn_server(repo_root: &Path, host: &str, port: u16) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
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
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(repo.path(), host, port)?;
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

    let mut mcp = McpHarness::spawn(repo.path())?;
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
    let mut mcp = McpHarness::spawn(repo.path())?;

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
    assert_invalid_params(&resp, "docdex_files")?;
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
    assert_enveloped_error(&mismatch, "unknown_repo", Some("docdex_search"))?;
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
fn mcp_validation_errors_share_envelope_across_tools() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    let cases = vec![
        (101, "docdex_search", json!({ "query": 123 })),
        (102, "docdex_index", json!({ "paths": "nope" })),
        (103, "docdex_files", json!({ "limit": "nope" })),
        (104, "docdex_open", json!({ "path": 5 })),
        (105, "docdex_stats", json!({ "project_root": 5 })),
        (106, "docdex_repo_inspect", json!({ "project_root": 5 })),
        (107, "docdex_symbols", json!({ "path": 5 })),
        (108, "docdex_memory_store", json!({ "text": 5 })),
        (109, "docdex_memory_recall", json!({ "query": 5 })),
    ];

    let mut data_keys: Option<Vec<String>> = None;
    let mut error_keys: Option<Vec<String>> = None;

    for (id, tool, args) in cases {
        send_line(
            &mut mcp.stdin,
            json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": { "name": tool, "arguments": args }
            }),
        )?;
        let resp = read_line(&mut mcp.reader)?;
        assert_invalid_params(&resp, tool)?;

        let data = error_data_map(&resp)?;
        let keys = sorted_keys(data);
        if let Some(ref baseline) = data_keys {
            assert_eq!(
                &keys, baseline,
                "error.data keys should be consistent across tools"
            );
        } else {
            data_keys = Some(keys);
        }
        let nested = data
            .get("error")
            .and_then(|v| v.as_object())
            .ok_or("invalid params error missing nested error")?;
        let nested_keys = sorted_keys(nested);
        if let Some(ref baseline) = error_keys {
            assert_eq!(
                &nested_keys, baseline,
                "error.data.error keys should be consistent across tools"
            );
        } else {
            error_keys = Some(nested_keys);
        }
    }

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_symbols_errors_cover_missing_dependency_and_index() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_root = repo.path();
    std::fs::write(repo_root.join("docs").join("symbols.md"), "# Title\n")?;

    let mut mcp = McpHarness::spawn(repo_root)?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 120,
            "method": "tools/call",
            "params": { "name": "docdex_symbols", "arguments": { "path": "docs/symbols.md" } }
        }),
    )?;
    let dep_resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&dep_resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&dep_resp), Some("missing_dependency"));
    assert_enveloped_error(&dep_resp, "missing_dependency", Some("docdex_symbols"))?;
    let dep_details = error_data_map(&dep_resp)?
        .get("details")
        .and_then(|v| v.as_object())
        .ok_or("missing dependency error missing details")?;
    assert_eq!(
        dep_details.get("dependency").and_then(|v| v.as_str()),
        Some("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
    );
    assert_eq!(
        dep_details.get("flag").and_then(|v| v.as_str()),
        Some("--enable-symbol-extraction=true")
    );
    mcp.shutdown();

    let mut mcp_symbols = McpHarness::spawn_with_env(
        repo_root,
        &[("DOCDEX_ENABLE_SYMBOL_EXTRACTION", "1")],
    )?;
    send_line(
        &mut mcp_symbols.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 121,
            "method": "tools/call",
            "params": { "name": "docdex_symbols", "arguments": { "path": "docs/symbols.md" } }
        }),
    )?;
    let index_resp = read_line(&mut mcp_symbols.reader)?;
    assert_eq!(mcp_error_code(&index_resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&index_resp), Some("missing_index"));
    assert_enveloped_error(&index_resp, "missing_index", Some("docdex_symbols"))?;
    let index_details = error_data_map(&index_resp)?
        .get("details")
        .and_then(|v| v.as_object())
        .ok_or("missing index error missing details")?;
    assert_eq!(
        index_details.get("resource").and_then(|v| v.as_str()),
        Some("symbols")
    );
    assert_eq!(
        index_details.get("path").and_then(|v| v.as_str()),
        Some("docs/symbols.md")
    );
    mcp_symbols.shutdown();

    Ok(())
}

#[test]
fn mcp_internal_errors_have_consistent_envelope() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 130,
            "method": "tools/call",
            "params": { "name": "docdex_open", "arguments": { "path": "docs/missing.md" } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("internal_error"));
    assert_enveloped_error(&resp, "internal_error", Some("docdex_open"))?;

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_backoff_required_when_index_writer_busy() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut primary = McpHarness::spawn(repo.path())?;
    send_line(
        &mut primary.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 140,
            "method": "initialize",
            "params": {}
        }),
    )?;
    let _ = read_line(&mut primary.reader)?;

    let mut secondary = McpHarness::spawn(repo.path())?;
    send_line(
        &mut secondary.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 141,
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
        }),
    )?;
    let resp = read_line(&mut secondary.reader)?;
    assert_eq!(mcp_error_code(&resp), Some(-32602));
    assert_eq!(mcp_error_data_code(&resp), Some("backoff_required"));
    assert_enveloped_error(&resp, "backoff_required", Some("docdex_index"))?;

    primary.shutdown();
    secondary.shutdown();
    Ok(())
}

#[test]
fn mcp_missing_project_root_path_is_missing_repo_path() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

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
    assert_enveloped_error(&resp, "missing_repo_path", Some("docdex_search"))?;
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
fn mcp_missing_repo_path_matches_cli_error_code() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut mcp = McpHarness::spawn(repo.path())?;

    let missing = repo.path().join("does-not-exist");
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 13,
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
    let mcp_code = mcp_error_data_code(&resp);
    assert_eq!(mcp_code, Some("missing_repo_path"));

    let cli_out = run_docdex([
        "query",
        "--repo",
        missing.to_string_lossy().as_ref(),
        "--query",
        "MCP_ROADMAP",
        "--limit",
        "1",
    ])?;
    assert!(
        !cli_out.status.success(),
        "CLI query should fail for missing repo path"
    );
    let cli_payload = parse_cli_error(&cli_out.stderr)?;
    let cli_code = cli_payload
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str());
    assert_eq!(
        cli_code,
        Some("missing_repo_path"),
        "CLI and MCP should share the missing_repo_path code"
    );

    mcp.shutdown();
    Ok(())
}

#[test]
fn mcp_limit_and_max_content_enforcement_is_predictable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let mut mcp = McpHarness::spawn(repo.path())?;

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
    assert_eq!(
        files_body.get("offset").and_then(|v| v.as_u64()),
        Some(0),
        "docdex_files should report the requested offset"
    );

    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 211,
            "method": "tools/call",
            "params": {
                "name": "docdex_files",
                "arguments": { "limit": 1, "offset": 999_999 }
            }
        }),
    )?;
    let files_offset_resp = read_line(&mut mcp.reader)?;
    let files_offset_body = parse_tool_result(&files_offset_resp)?;
    assert_eq!(
        files_offset_body.get("offset").and_then(|v| v.as_u64()),
        Some(50_000),
        "docdex_files should clamp offset to the max"
    );

    // docdex_open should fail with a structured max-content error.
    let big_path = repo.path().join("docs").join("big.md");
    std::fs::write(&big_path, "x".repeat(600_000))?;
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
    assert_enveloped_error(&open_err, "max_content_exceeded", Some("docdex_open"))?;
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
    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = run_docdex(["index", "--repo", repo_str.as_str()])?;
    assert!(
        index_out.status.success(),
        "index should succeed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let query_out = run_docdex([
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
