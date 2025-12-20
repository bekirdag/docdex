use serde_json::{json, Value};
use sha2::{Digest, Sha256};
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
    fn spawn(repo: &Path, state_root: &Path) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_symbols(repo, state_root, false)
    }

    fn spawn_with_symbols(
        repo: &Path,
        state_root: &Path,
        enable_symbols: bool,
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
        if enable_symbols {
            cmd.env("DOCDEX_ENABLE_SYMBOL_EXTRACTION", "1");
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

fn symbols_record_path(repo_state_root: &Path, rel_path: &str) -> PathBuf {
    let key = hex::encode(Sha256::digest(rel_path.as_bytes()));
    repo_state_root
        .join("symbols.db")
        .join("files")
        .join(format!("{key}.json"))
}

fn inspect_repo_state(state_root: &Path, repo_root: &Path) -> Result<Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
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
    let parsed: serde_json::Value = serde_json::from_str(first_text)?;
    Ok(parsed)
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
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

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
            .map(|v| v.is_object()),
        Some(true),
        "initialize should advertise tools capability"
    );
    let policy = init_resp
        .get("result")
        .and_then(|v| v.get("serverInfo"))
        .and_then(|v| v.get("docdex"))
        .and_then(|v| v.get("policy"))
        .ok_or("initialize should include serverInfo.docdex.policy")?;
    assert_eq!(
        policy.get("schema_version").and_then(|v| v.as_u64()),
        Some(1)
    );
    let rate_limit = policy
        .get("rate_limit")
        .and_then(|v| v.as_object())
        .ok_or("policy.rate_limit should be an object")?;
    assert_eq!(
        rate_limit.get("enabled").and_then(|v| v.as_bool()),
        Some(false)
    );
    assert_eq!(
        rate_limit.get("per_minute").and_then(|v| v.as_u64()),
        Some(0)
    );
    assert_eq!(rate_limit.get("burst").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        rate_limit.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(
        rate_limit.get("scope").and_then(|v| v.as_str()),
        Some("global")
    );
    let backoff = policy
        .get("backoff")
        .and_then(|v| v.as_array())
        .ok_or("policy.backoff should be an array")?;
    assert!(
        backoff.iter().any(|entry| {
            entry.get("code").and_then(|v| v.as_str()) == Some("backoff_required")
        }),
        "policy.backoff should advertise backoff_required"
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
        tool_names.contains(&"docdex_search".to_string()),
        "tools/list should include docdex_search"
    );
    assert!(
        tool_names.contains(&"docdex_index".to_string()),
        "tools/list should include docdex_index"
    );
    assert!(
        tool_names.contains(&"docdex_stats".to_string()),
        "tools/list should include docdex_stats"
    );

    // build index via tool
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex_index",
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
    let index_body = parse_tool_result(&index_resp)?;
    assert_eq!(
        index_body.get("status").and_then(|v| v.as_str()),
        Some("ok"),
        "docdex_index should return status ok"
    );

    // search for the test term
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "MCP_ROADMAP",
                    "limit": 5
                }
            }
        }),
    )?;
    let search_resp = read_line(&mut harness.reader)?;
    let search_body = parse_tool_result(&search_resp)?;
    let hits = search_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return hits array")?;
    let results = search_body
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search should return results array")?;
    assert_eq!(
        hits.len(),
        results.len(),
        "docdex_search hits/results should have same length"
    );
    assert!(
        !hits.is_empty(),
        "docdex_search should return at least one hit for MCP_ROADMAP"
    );
    let top_score = search_body.get("top_score").and_then(|v| v.as_f64());
    let top_score_camel = search_body.get("topScore").and_then(|v| v.as_f64());
    assert!(
        top_score.is_some(),
        "docdex_search should include top_score when results are returned"
    );
    assert!(
        top_score_camel.is_some(),
        "docdex_search should include topScore when results are returned"
    );
    let first = hits.first().ok_or("hit missing")?;
    assert!(
        first.get("path").and_then(|v| v.as_str()).is_some(),
        "docdex_search hits should include path"
    );
    assert!(
        first.get("snippet").and_then(|v| v.as_str()).is_some(),
        "docdex_search hits should include snippet"
    );
    let first_score = hits
        .first()
        .and_then(|hit| hit.get("score"))
        .and_then(|v| v.as_f64())
        .unwrap_or(-1.0);
    assert!(
        (top_score.unwrap_or(-1.0) - first_score).abs() < 1e-6,
        "docdex_search top_score should match the first result score"
    );
    assert!(
        (top_score.unwrap_or(-1.0) - top_score_camel.unwrap_or(-1.0)).abs() < 1e-6,
        "docdex_search topScore should match top_score"
    );

    assert_eq!(
        search_body.get("limit").and_then(|v| v.as_u64()),
        Some(4),
        "docdex_search should clamp limit to server --max-results"
    );
    let context = search_body
        .get("meta")
        .and_then(|v| v.get("context_assembly"))
        .ok_or("docdex_search meta.context_assembly should be present")?;
    assert_eq!(
        context.get("requested_limit").and_then(|v| v.as_u64()),
        Some(5),
        "context_assembly should record requested limit before clamp"
    );
    assert_eq!(
        context.get("effective_limit").and_then(|v| v.as_u64()),
        Some(4),
        "context_assembly should record effective limit after clamp"
    );
    assert_eq!(
        context
            .get("snippet_policy")
            .and_then(|v| v.as_str()),
        Some("full"),
        "context_assembly snippet_policy should be stable"
    );
    assert_eq!(
        context
            .get("token_budget_mode")
            .and_then(|v| v.as_str()),
        Some("per_hit_token_estimate"),
        "context_assembly token_budget_mode should be stable"
    );
    let token_sum: u64 = hits
        .iter()
        .map(|hit| hit.get("token_estimate").and_then(|v| v.as_u64()).unwrap_or(0))
        .sum();
    assert_eq!(
        context
            .get("token_estimate_sum_kept")
            .and_then(|v| v.as_u64()),
        Some(token_sum),
        "context_assembly token_estimate_sum_kept should match sum of returned hits"
    );
    assert_eq!(
        context
            .get("hits_before_pruning")
            .and_then(|v| v.as_u64()),
        Some(hits.len() as u64),
        "context_assembly hits_before_pruning should be bounded"
    );
    assert_eq!(
        context
            .get("hits_after_pruning")
            .and_then(|v| v.as_u64()),
        Some(hits.len() as u64),
        "context_assembly hits_after_pruning should be bounded"
    );
    let selected_sources = context
        .get("selected_sources")
        .and_then(|v| v.as_array())
        .ok_or("context_assembly selected_sources should be an array")?;
    assert_eq!(
        selected_sources.len(),
        hits.len(),
        "context_assembly selected_sources should track returned hits"
    );

    // no-match search should return empty results and a null top_score
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": {
                    "query": "NO_MATCH_TERM_123456",
                    "limit": 5
                }
            }
        }),
    )?;
    let no_match_resp = read_line(&mut harness.reader)?;
    let no_match_body = parse_tool_result(&no_match_resp)?;
    let no_match_hits = no_match_body
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search no-match should return hits array")?;
    let no_match_results = no_match_body
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("docdex_search no-match should return results array")?;
    assert!(
        no_match_hits.is_empty(),
        "no-match docdex_search should return empty results"
    );
    assert!(
        no_match_results.is_empty(),
        "no-match docdex_search should return empty results array"
    );
    assert!(
        no_match_body.get("top_score").map(|v| v.is_null()).unwrap_or(false),
        "no-match docdex_search should return top_score: null"
    );
    assert!(
        no_match_body.get("topScore").map(|v| v.is_null()).unwrap_or(false),
        "no-match docdex_search should return topScore: null"
    );

    // stats should report doc count
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "docdex_stats",
                "arguments": {}
            }
        }),
    )?;
    let stats_resp = read_line(&mut harness.reader)?;
    let stats_body = parse_tool_result(&stats_resp)?;
    let num_docs = stats_body
        .get("num_docs")
        .and_then(|v| v.as_u64())
        .ok_or("docdex_stats should include num_docs")?;
    assert!(num_docs > 0, "stats num_docs should be > 0");
    let segments = stats_body
        .get("segments")
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
                "name": "docdex_files",
                "arguments": { "limit": 10, "offset": 0 }
            }
        }),
    )?;
    let files_resp = read_line(&mut harness.reader)?;
    let files_body = parse_tool_result(&files_resp)?;
    let files = files_body
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("docdex_files should return results array")?;
    assert!(
        !files.is_empty(),
        "docdex_files should return at least one document entry"
    );
    let total = files_body
        .get("total")
        .and_then(|v| v.as_u64())
        .ok_or("docdex_files should return total")?;
    assert!(
        total >= files.len() as u64,
        "total should be >= returned rows"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_symbols_returns_outcome_and_symbols_when_enabled() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    fs::write(
        repo_root.join("docs").join("symbols.md"),
        "# Title\n\nIntro text.\n\n## Subsection\nMore.\n",
    )?;
    let mut harness = McpHarness::spawn_with_symbols(repo_root, state_root.path(), true)?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "initialize",
            "params": {}
        }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    // build index via tool
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "docdex_index",
                "arguments": { "paths": [] }
            }
        }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    // fetch symbols for a known file
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 102,
            "method": "tools/call",
            "params": {
                "name": "docdex_symbols",
                "arguments": { "path": "docs/symbols.md" }
            }
        }),
    )?;
    let symbols_resp = read_line(&mut harness.reader)?;
    let payload = parse_tool_result(&symbols_resp)?;

    assert_eq!(
        payload.get("schema").and_then(|v| v.get("name")).and_then(|v| v.as_str()),
        Some("docdex.symbols"),
        "symbols payload should include schema name"
    );
    let schema = payload
        .get("schema")
        .and_then(|v| v.as_object())
        .ok_or("symbols payload missing schema object")?;
    let version = schema
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or("symbols payload missing schema.version")?;
    let compatible = schema
        .get("compatible")
        .and_then(|v| v.as_object())
        .ok_or("symbols payload missing schema.compatible")?;
    let min = compatible
        .get("min")
        .and_then(|v| v.as_u64())
        .ok_or("symbols payload missing schema.compatible.min")?;
    let max = compatible
        .get("max")
        .and_then(|v| v.as_u64())
        .ok_or("symbols payload missing schema.compatible.max")?;
    assert!(
        min <= version && version <= max,
        "symbols schema version should be within compatible range"
    );
    assert_eq!(
        payload.get("file").and_then(|v| v.as_str()),
        Some("docs/symbols.md"),
        "symbols payload should identify the file"
    );
    let repo_id = payload
        .get("repo_id")
        .and_then(|v| v.as_str())
        .ok_or("symbols payload missing repo_id")?;
    assert_eq!(repo_id.len(), 64, "repo_id should be a sha256 hex string");

    let status = payload
        .get("outcome")
        .and_then(|v| v.get("status"))
        .and_then(|v| v.as_str())
        .ok_or("symbols payload missing outcome.status")?;
    assert_eq!(status, "ok", "markdown symbol extraction should be ok");

    let symbols = payload
        .get("symbols")
        .and_then(|v| v.as_array())
        .ok_or("symbols payload missing symbols array")?;
    assert!(
        symbols.len() >= 2,
        "markdown file should yield at least two heading symbols"
    );
    let first_id = symbols
        .first()
        .and_then(|v| v.get("symbol_id"))
        .and_then(|v| v.as_str())
        .ok_or("symbol missing symbol_id")?;
    assert!(
        first_id.starts_with(&format!("{repo_id}:docs/symbols.md#")),
        "symbol_id should include repo_id and file prefix"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_symbols_backfills_missing_symbol_ids_and_stays_deterministic() -> Result<(), Box<dyn Error>>
{
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let rel_path = "docs/symbols.md";
    fs::write(
        repo_root.join(rel_path),
        "# Title\n\nIntro text.\n\n## Subsection\nMore.\n",
    )?;
    let mut harness = McpHarness::spawn_with_symbols(repo_root, state_root.path(), true)?;

    send_line(
        &mut harness.stdin,
        json!({ "jsonrpc": "2.0", "id": 200, "method": "initialize", "params": {} }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 201,
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
        }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    let repo_state_root = resolve_repo_state_root(state_root.path(), repo_root)?;
    let record_path = symbols_record_path(&repo_state_root, rel_path);
    let raw = fs::read_to_string(&record_path)?;
    let mut value: serde_json::Value = serde_json::from_str(&raw)?;
    let symbols = value
        .get_mut("symbols")
        .and_then(|v| v.as_array_mut())
        .ok_or("expected symbols store record to contain a symbols array")?;
    for symbol in symbols {
        if let Some(obj) = symbol.as_object_mut() {
            obj.remove("symbol_id");
        }
    }
    fs::write(&record_path, serde_json::to_string_pretty(&value)?)?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 202,
            "method": "tools/call",
            "params": { "name": "docdex_symbols", "arguments": { "path": rel_path } }
        }),
    )?;
    let first_resp = read_line(&mut harness.reader)?;
    let first_payload = parse_tool_result(&first_resp)?;
    let ids_first: Vec<String> = first_payload
        .get("symbols")
        .and_then(|v| v.as_array())
        .ok_or("symbols payload missing symbols array")?
        .iter()
        .filter_map(|v| v.get("symbol_id").and_then(|id| id.as_str()).map(|s| s.to_string()))
        .collect();
    assert!(
        !ids_first.is_empty(),
        "expected symbols response to return at least one symbol"
    );
    assert!(
        ids_first.iter().all(|id| !id.trim().is_empty()),
        "expected all returned symbols to include symbol_id"
    );

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 203,
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
        }),
    )?;
    let _ = read_line(&mut harness.reader)?;

    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 204,
            "method": "tools/call",
            "params": { "name": "docdex_symbols", "arguments": { "path": rel_path } }
        }),
    )?;
    let second_resp = read_line(&mut harness.reader)?;
    let second_payload = parse_tool_result(&second_resp)?;
    let ids_second: Vec<String> = second_payload
        .get("symbols")
        .and_then(|v| v.as_array())
        .ok_or("symbols payload missing symbols array")?
        .iter()
        .filter_map(|v| v.get("symbol_id").and_then(|id| id.as_str()).map(|s| s.to_string()))
        .collect();
    assert_eq!(
        ids_first, ids_second,
        "symbol identifiers should remain stable across repeated indexing runs"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_rejects_wrong_version() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

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
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

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
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

    // index first
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
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
            "params": { "name": "docdex_search", "arguments": { "query": "" } }
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
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

    // index first
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": { "name": "docdex_index", "arguments": { "paths": [] } }
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
            "params": { "name": "docdex_files", "arguments": { "limit": 5, "offset": 10_000 } }
        }),
    )?;
    let paged_resp = read_line(&mut harness.reader)?;
    let paged_body = parse_tool_result(&paged_resp)?;
    let total = paged_body
        .get("total")
        .and_then(|v| v.as_u64())
        .ok_or("docdex_files should include total")?;
    let files = paged_body
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("docdex_files should include results array")?;
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
            "params": { "name": "docdex_files", "arguments": { "limit": "not-a-number" } }
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
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let content = "\
Line1
Line2
Line3
Line4
Line5
";
    std::fs::write(repo_root.join("docs").join("open.md"), content)?;
    let mut harness = McpHarness::spawn(repo_root, state_root.path())?;

    // Full file
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "docdex_open",
                "arguments": { "path": "docs/open.md" }
            }
        }),
    )?;
    let full_resp = read_line(&mut harness.reader)?;
    let full_body = parse_tool_result(&full_resp)?;
    let full_content = full_body
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or("docdex_open should return content")?;
    assert!(full_content.contains("Line1") && full_content.contains("Line5"));

    // Range (lines 2-3)
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex_open",
                "arguments": { "path": "docs/open.md", "start_line": 2, "end_line": 3 }
            }
        }),
    )?;
    let range_resp = read_line(&mut harness.reader)?;
    let range_body = parse_tool_result(&range_resp)?;
    let range_content = range_body
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or("docdex_open range should return content")?;
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
                "name": "docdex_open",
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
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

    // search with missing query
    send_line(
        &mut harness.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": { "name": "docdex_search", "arguments": { "limit": 2 } }
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
            "params": { "name": "docdex_open", "arguments": { "path": "/etc/passwd" } }
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
            "params": { "name": "docdex_open", "arguments": { "path": "docs/overview.md", "start_line": 10, "end_line": 1 } }
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
            "params": { "name": "docdex_open", "arguments": { "path": "docs/overview.md", "start_line": 10_000 } }
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
            "params": { "name": "docdex_open", "arguments": { "path": "docs/big.md" } }
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

    // resource templates list should return docdex_file
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
            .map(|name| name == "docdex_file")
            .unwrap_or(false)
    });
    assert!(has_docdex, "resource templates should include docdex_file");

    // resources/read should resolve docdex_file
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
        "resources/read should return file content for docdex_file"
    );

    harness.shutdown();
    Ok(())
}

#[test]
fn mcp_initialize_rejects_wrong_workspace_root() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let mut harness = McpHarness::spawn(repo.path(), state_root.path())?;

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
