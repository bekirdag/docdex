use serde_json::json;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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
        let repo_str = repo.to_string_lossy().to_string();
        let mut child = Command::new(docdex_bin())
            .args([
                "mcp",
                "--repo",
                repo_str.as_str(),
                "--log",
                "warn",
                "--max-results",
                "4",
            ])
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
    fs::create_dir_all(&docs_dir)?;
    fs::write(
        docs_dir.join("overview.md"),
        r#"# Overview

This repository contains the MCP_ROADMAP notes used for testing.
"#,
    )?;
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
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
    let value: serde_json::Value = serde_json::from_str(&line)?;
    Ok(value)
}

#[test]
fn mcp_server_end_to_end() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    // initialize
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }),
    )?;
    let init_resp = read_line(&mut harness.reader)?;
    assert_eq!(
        init_resp.get("id").and_then(|v| v.as_i64()),
        Some(1),
        "initialize response should echo id"
    );
    assert_eq!(
        init_resp
            .get("result")
            .and_then(|v| v.get("capabilities"))
            .and_then(|v| v.get("tools"))
            .and_then(|v| v.as_bool()),
        Some(true),
        "initialize should advertise tools capability"
    );

    // tools/list
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
        }),
    )?;
    let list_resp = read_line(&mut harness.reader)?;
    let tools = list_resp
        .get("result")
        .and_then(|v| v.get("tools"))
        .and_then(|v| v.as_array())
        .ok_or("tools/list should return tools array")?;
    let tool_names: Vec<String> = tools
        .iter()
        .filter_map(|tool| {
            tool.get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    assert!(
        tool_names.contains(&"docdex.search".to_string()),
        "tools/list should include docdex.search"
    );
    assert!(
        tool_names.contains(&"docdex.index".to_string()),
        "tools/list should include docdex.index"
    );
    assert!(
        tool_names.contains(&"docdex.stats".to_string()),
        "tools/list should include docdex.stats"
    );

    // build index via tool
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex.index",
                "arguments": { "paths": [] }
            }
        }),
    )?;
    let index_resp = read_line(&mut harness.reader)?;
    assert_eq!(
        index_resp.get("id").and_then(|v| v.as_i64()),
        Some(3),
        "index response should echo id"
    );
    assert_eq!(
        index_resp
            .get("result")
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str()),
        Some("ok"),
        "docdex.index should return status ok"
    );

    // search for the test term
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "docdex.search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "limit": 5
                }
            }
        }),
    )?;
    let search_resp = read_line(&mut harness.reader)?;
    let results = search_resp
        .get("result")
        .and_then(|v| v.get("results"))
        .and_then(|v| v.as_array())
        .ok_or("docdex.search should return results array")?;
    assert!(
        !results.is_empty(),
        "docdex.search should return at least one hit for MCP_ROADMAP"
    );

    // stats should report doc count
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "docdex.stats",
                "arguments": {}
            }
        }),
    )?;
    let stats_resp = read_line(&mut harness.reader)?;
    let num_docs = stats_resp
        .get("result")
        .and_then(|v| v.get("num_docs"))
        .and_then(|v| v.as_u64())
        .ok_or("docdex.stats should include num_docs")?;
    assert!(num_docs > 0, "stats num_docs should be > 0");
    let segments = stats_resp
        .get("result")
        .and_then(|v| v.get("segments"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(segments > 0, "stats should report at least one segment");

    // files listing should include known docs and totals
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "docdex.files",
                "arguments": { "limit": 10, "offset": 0 }
            }
        }),
    )?;
    let files_resp = read_line(&mut harness.reader)?;
    let files = files_resp
        .get("result")
        .and_then(|v| v.get("results"))
        .and_then(|v| v.as_array())
        .ok_or("docdex.files should return results array")?;
    assert!(
        !files.is_empty(),
        "docdex.files should return at least one document entry"
    );
    let total = files_resp
        .get("result")
        .and_then(|v| v.get("total"))
        .and_then(|v| v.as_u64())
        .ok_or("docdex.files should return total")?;
    assert!(
        total >= files.len() as u64,
        "total should be >= returned rows"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_rejects_wrong_version() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "1.0",
            "id": 10,
            "method": "initialize",
            "params": {}
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let error_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        error_code,
        Some(-32600),
        "wrong jsonrpc version should return invalid request error"
    );
    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_unknown_tool_returns_error() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": { "name": "docdex.unknown", "arguments": {} }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let error_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        error_code,
        Some(-32601),
        "unknown tool should return method not found"
    );
    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_search_empty_query_errors() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    // index first
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": { "name": "docdex.index", "arguments": { "paths": [] } }
        }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    // search with empty query should error
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 13,
            "method": "tools/call",
            "params": { "name": "docdex.search", "arguments": { "query": "" } }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let error_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        error_code,
        Some(-32602),
        "empty query should return invalid params error"
    );
    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_files_pagination_and_invalid_params() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    // index first
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": { "name": "docdex.index", "arguments": { "paths": [] } }
        }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    // pagination with offset beyond total should return empty results but include total
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": { "name": "docdex.files", "arguments": { "limit": 5, "offset": 10_000 } }
        }),
    )?;
    let paged_resp = read_line(&mut harness.reader)?;
    let total = paged_resp
        .get("result")
        .and_then(|v| v.get("total"))
        .and_then(|v| v.as_u64())
        .ok_or("docdex.files should include total")?;
    let files = paged_resp
        .get("result")
        .and_then(|v| v.get("results"))
        .and_then(|v| v.as_array())
        .ok_or("docdex.files should include results array")?;
    assert_eq!(
        files.len(),
        0,
        "offset beyond total should return empty results"
    );
    assert!(
        total >= files.len() as u64,
        "total should be present even when results are empty"
    );

    // invalid params (wrong type) should return invalid params error code
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": { "name": "docdex.files", "arguments": { "limit": "not-a-number" } }
        }),
    )?;
    let invalid_resp = read_line(&mut harness.reader)?;
    let err_code = invalid_resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32602),
        "invalid params should return code -32602"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_open_respects_ranges_and_bounds() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_root = repo.path();
    let content = "\
Line1
Line2
Line3
Line4
Line5
";
    std::fs::write(repo_root.join("docs").join("open.md"), content)?;
    let mut harness = McpHarness::spawn(repo_root)?;

    // Full file
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "docdex.open",
                "arguments": { "path": "docs/open.md" }
            }
        }),
    )?;
    let full_resp = read_line(&mut harness.reader)?;
    let full_content = full_resp
        .get("result")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_str())
        .ok_or("docdex.open should return content")?;
    assert!(full_content.contains("Line1") && full_content.contains("Line5"));

    // Range (lines 2-3)
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex.open",
                "arguments": { "path": "docs/open.md", "start_line": 2, "end_line": 3 }
            }
        }),
    )?;
    let range_resp = read_line(&mut harness.reader)?;
    let range_content = range_resp
        .get("result")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_str())
        .ok_or("docdex.open range should return content")?;
    assert!(
        range_content.lines().count() == 2 && range_content.contains("Line2"),
        "range content should include only requested lines"
    );

    // Reject parent dirs
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "docdex.open",
                "arguments": { "path": "../open.md" }
            }
        }),
    )?;
    let bad_resp = read_line(&mut harness.reader)?;
    let err_code = bad_resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(err_code, Some(-32602), "parent dir should be rejected");

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_invalid_arg_shapes_return_errors() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    // search with missing query
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": { "name": "docdex.search", "arguments": { "limit": 2 } }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let err_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32602),
        "missing required field should return invalid params"
    );

    // open with absolute path should be rejected
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": { "name": "docdex.open", "arguments": { "path": "/etc/passwd" } }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let err_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32602),
        "absolute paths should be rejected with invalid params"
    );

    // open with start > end
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 52,
            "method": "tools/call",
            "params": { "name": "docdex.open", "arguments": { "path": "docs/overview.md", "start_line": 10, "end_line": 1 } }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let err_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32602),
        "start>end should be rejected with invalid params"
    );

    // open with start beyond file
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 53,
            "method": "tools/call",
            "params": { "name": "docdex.open", "arguments": { "path": "docs/overview.md", "start_line": 10_000 } }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let err_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32602),
        "start beyond file should be rejected with invalid params"
    );

    // oversized file
    let big_path = repo.path().join("docs").join("big.md");
    let big_content = "x".repeat(600_000);
    std::fs::write(&big_path, big_content)?;
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 54,
            "method": "tools/call",
            "params": { "name": "docdex.open", "arguments": { "path": "docs/big.md" } }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let err_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32602),
        "oversized file should be rejected with invalid params"
    );

    // resource templates list should return docdex.file
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 55,
            "method": "resources/templates/list"
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let templates = resp
        .get("result")
        .and_then(|v| v.get("resourceTemplates"))
        .and_then(|v| v.as_array())
        .ok_or("resources/templates/list should return array")?;
    let has_docdex = templates.iter().any(|tpl| {
        tpl.get("name")
            .and_then(|v| v.as_str())
            .map(|name| name == "docdex.file")
            .unwrap_or(false)
    });
    assert!(has_docdex, "resource templates should include docdex.file");

    // resources/read should resolve docdex.file
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 56,
            "method": "resources/read",
            "params": { "uri": "docdex://docs/overview.md" }
        }),
    )?;
    let read_resp = read_line(&mut harness.reader)?;
    let content = read_resp
        .get("result")
        .and_then(|v| v.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !content.is_empty(),
        "resources/read should return file content for docdex.file"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_initialize_rejects_wrong_workspace_root() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let mut harness = McpHarness::spawn(repo.path())?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 40,
            "method": "initialize",
            "params": { "workspace_root": "/tmp/not-the-repo" }
        }),
    )?;
    let resp = read_line(&mut harness.reader)?;
    let err_code = resp
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_i64());
    assert_eq!(
        err_code,
        Some(-32600),
        "workspace root mismatch should return invalid request"
    );
    harness.shutdown();
    Ok(())
}
