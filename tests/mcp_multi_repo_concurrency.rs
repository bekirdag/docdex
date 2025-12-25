use serde_json::{json, Value};
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use tempfile::TempDir;

type BoxError = Box<dyn Error + Send + Sync>;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

struct McpHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpHarness {
    fn spawn(repo: &Path) -> Result<Self, BoxError> {
        let repo_str = repo.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args(["mcp", "--repo", repo_str.as_str(), "--log", "warn"]);
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

fn run_docdex<I, S>(args: I) -> Result<(), BoxError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin()).args(args).output()?;
    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "docdexd failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        )
        .into());
    }
    Ok(())
}

fn write_repo(repo_root: &Path, filename: &str, token: &str) -> Result<(), BoxError> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join(filename),
        format!(
            r#"# Fixture

shared_term
{token}
"#
        ),
    )?;
    Ok(())
}

fn setup_repo(filename: &str, token: &str) -> Result<TempDir, BoxError> {
    let temp = TempDir::new()?;
    write_repo(temp.path(), filename, token)?;
    Ok(temp)
}

fn send_line(
    stdin: &mut std::process::ChildStdin,
    payload: serde_json::Value,
) -> Result<(), BoxError> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_line(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<serde_json::Value, BoxError> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("unexpected empty response line from MCP server".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn parse_tool_result(resp: &Value) -> Result<Value, BoxError> {
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

fn run_search_and_open(
    mut harness: McpHarness,
    project_root: &str,
    expected_path: &str,
    expected_token: &str,
) -> Result<(), BoxError> {
    let result = (|| -> Result<(), BoxError> {
        send_line(
            &mut harness.stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "docdex_search",
                    "arguments": { "query": "shared_term", "limit": 5, "project_root": project_root }
                }
            }),
        )?;
        let search_resp = read_line(&mut harness.reader)?;
        let search_body = parse_tool_result(&search_resp)?;
        let hits = search_body
            .get("hits")
            .and_then(|v| v.as_array())
            .ok_or("docdex_search missing hits array")?;
        assert!(!hits.is_empty(), "expected at least one hit");
        let paths: Vec<String> = hits
            .iter()
            .filter_map(|hit| {
                hit.get("path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        assert!(
            !paths.is_empty(),
            "expected docdex_search hits to include paths"
        );
        assert!(
            paths.iter().all(|path| path == expected_path),
            "expected all hits to resolve to {expected_path}; got {paths:?}"
        );

        send_line(
            &mut harness.stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "docdex_open",
                    "arguments": { "path": expected_path, "project_root": project_root }
                }
            }),
        )?;
        let open_resp = read_line(&mut harness.reader)?;
        let open_body = parse_tool_result(&open_resp)?;
        let content = open_body
            .get("content")
            .and_then(|v| v.as_str())
            .ok_or("docdex_open missing content")?;
        assert!(
            content.contains(expected_token),
            "expected docdex_open content to include token {expected_token}"
        );
        Ok(())
    })();

    harness.shutdown();
    result
}

#[test]
fn mcp_multi_repo_concurrency_is_isolated() -> Result<(), BoxError> {
    let repo_a = setup_repo("a-only.md", "REPO_A_TOKEN")?;
    let repo_b = setup_repo("b-only.md", "REPO_B_TOKEN")?;

    let repo_a_root = repo_a.path().to_string_lossy().to_string();
    let repo_b_root = repo_b.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_a_root.as_str()])?;
    run_docdex(["index", "--repo", repo_b_root.as_str()])?;

    let harness_a = McpHarness::spawn(repo_a.path())?;
    let harness_b = McpHarness::spawn(repo_b.path())?;

    let barrier = Arc::new(Barrier::new(3));
    let barrier_a = barrier.clone();
    let barrier_b = barrier.clone();

    let repo_a_project_root = repo_a_root.clone();
    let handle_a = thread::spawn(move || -> Result<(), BoxError> {
        barrier_a.wait();
        run_search_and_open(
            harness_a,
            repo_a_project_root.as_str(),
            "docs/a-only.md",
            "REPO_A_TOKEN",
        )
    });
    let repo_b_project_root = repo_b_root.clone();
    let handle_b = thread::spawn(move || -> Result<(), BoxError> {
        barrier_b.wait();
        run_search_and_open(
            harness_b,
            repo_b_project_root.as_str(),
            "docs/b-only.md",
            "REPO_B_TOKEN",
        )
    });

    barrier.wait();

    handle_a.join().expect("repo-a thread panicked")?;
    handle_b.join().expect("repo-b thread panicked")?;
    Ok(())
}
