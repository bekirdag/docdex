use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
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

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MEMORY", "0")
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
    Ok(output.stdout)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping HTTP determinism tests: TCP bind not permitted in this environment"
            );
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_arg = repo_root.to_string_lossy().to_string();
    let port_string = port.to_string();
    let lock_path = state_root.join("daemon.lock");
    let args = vec![
        "serve",
        "--repo",
        repo_arg.as_str(),
        "--host",
        host,
        "--port",
        &port_string,
        "--log",
        "warn",
        "--secure-mode=false",
    ];
    let child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env(
            "DOCDEX_DAEMON_LOCK_PATH",
            lock_path.to_string_lossy().as_ref(),
        )
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_for_health(host, port)?;
    Ok(child)
}

fn setup_determinism_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    let repo_root = temp.path();
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;

    fs::write(
        docs_dir.join("a.md"),
        r#"# A

commonterm commonterm
prune_term prune_term
"#,
    )?;
    fs::write(
        docs_dir.join("b.md"),
        r#"# B

commonterm commonterm
prune_term prune_term
"#,
    )?;

    let huge_tokens = 200usize;
    let huge_body = std::iter::repeat("prune_term")
        .take(huge_tokens)
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(
        docs_dir.join("huge.md"),
        format!("# Huge\n\n{huge_body}\n\ncommonterm\n"),
    )?;

    let chunk_line = std::iter::repeat("chunk_term")
        .take(1200)
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(
        docs_dir.join("chunk.md"),
        format!("# Chunk\n\n{chunk_line}\n"),
    )?;

    Ok(temp)
}

fn search_signature(payload: &Value) -> Value {
    let empty: Vec<Value> = Vec::new();
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);

    let hits_sig = hits
        .iter()
        .map(|hit| {
            json!({
                "doc_id": hit.get("doc_id"),
                "rel_path": hit.get("rel_path"),
                "token_estimate": hit.get("token_estimate"),
                "snippet_origin": hit.get("snippet_origin"),
                "snippet_truncated": hit.get("snippet_truncated"),
                "line_start": hit.get("line_start"),
                "line_end": hit.get("line_end"),
            })
        })
        .collect::<Vec<_>>();

    let context_assembly = payload
        .get("meta")
        .and_then(|v| v.get("context_assembly"))
        .cloned()
        .unwrap_or(Value::Null);

    json!({
        "hits": hits_sig,
        "context_assembly": context_assembly,
    })
}

fn snippet_signature(payload: &Value) -> Value {
    let snippet = payload.get("snippet").cloned().unwrap_or(Value::Null);
    if snippet.is_null() {
        return json!({ "snippet": null });
    }
    json!({
        "snippet": {
            "text": snippet.get("text"),
            "truncated": snippet.get("truncated"),
            "origin": snippet.get("origin"),
            "line_start": snippet.get("line_start"),
            "line_end": snippet.get("line_end"),
        }
    })
}

fn capture_determinism_signatures(
    client: &Client,
    host: &str,
    port: u16,
) -> Result<Value, Box<dyn Error>> {
    let search_url = format!("http://{host}:{port}/search");

    let ordering_payload: Value = client
        .get(&search_url)
        .query(&[("q", "commonterm"), ("limit", "10"), ("snippets", "false")])
        .send()?
        .error_for_status()?
        .json()?;
    let ordering = search_signature(&ordering_payload);

    let pruning_payload: Value = client
        .get(&search_url)
        .query(&[
            ("q", "prune_term"),
            ("limit", "10"),
            ("snippets", "false"),
            ("max_tokens", "50"),
        ])
        .send()?
        .error_for_status()?
        .json()?;
    let pruning = search_signature(&pruning_payload);

    let empty_array: Vec<Value> = Vec::new();
    let pruned = pruning_payload
        .get("meta")
        .and_then(|v| v.get("context_assembly"))
        .and_then(|v| v.get("pruned"))
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_array)
        .iter()
        .filter_map(|entry| entry.get("rel_path").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    assert!(
        pruned.iter().any(|path| path.ends_with("docs/huge.md")),
        "expected docs/huge.md to be pruned under max_tokens=50"
    );

    let snippet_url = format!("http://{host}:{port}/snippet/docs/chunk.md");
    let chunk_payload: Value = client
        .get(&snippet_url)
        .query(&[("window", "20"), ("text_only", "true")])
        .send()?
        .error_for_status()?
        .json()?;
    let chunk = snippet_signature(&chunk_payload);

    let snippet = chunk_payload.get("snippet").cloned().unwrap_or(Value::Null);
    assert!(
        snippet
            .get("truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "expected preview snippet to be truncated for docs/chunk.md"
    );
    let text = snippet
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        text.ends_with('…'),
        "expected truncated preview snippet text to end with ellipsis"
    );

    let chunk_too_small_payload: Value = client
        .get(&snippet_url)
        .query(&[("window", "20"), ("text_only", "true"), ("max_tokens", "5")])
        .send()?
        .error_for_status()?
        .json()?;
    let chunk_too_small = snippet_signature(&chunk_too_small_payload);
    assert!(
        chunk_too_small_payload.get("snippet").is_none()
            || chunk_too_small_payload.get("snippet").unwrap().is_null(),
        "expected snippet to be omitted when doc token_estimate exceeds max_tokens"
    );

    Ok(json!({
        "ordering": ordering,
        "pruning": pruning,
        "chunk": chunk,
        "chunk_too_small": chunk_too_small,
    }))
}

#[test]
fn e2e_context_assembly_ordering_is_deterministic() -> Result<(), Box<dyn Error>> {
    let repo = setup_determinism_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let search_url = format!("http://{host}:{port}/search");

    let baseline: Value = client
        .get(&search_url)
        .query(&[("q", "commonterm"), ("limit", "10"), ("snippets", "false")])
        .send()?
        .json()?;
    let expected = search_signature(&baseline);
    for _ in 0..10 {
        let payload: Value = client
            .get(&search_url)
            .query(&[("q", "commonterm"), ("limit", "10"), ("snippets", "false")])
            .send()?
            .json()?;
        assert_eq!(search_signature(&payload), expected);
    }

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn e2e_context_assembly_is_deterministic_across_reindex_and_restart() -> Result<(), Box<dyn Error>>
{
    let repo = setup_determinism_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let baseline = capture_determinism_signatures(&client, host, port)?;

    child.kill().ok();
    child.wait().ok();

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let after = capture_determinism_signatures(&client, host, port)?;

    child.kill().ok();
    child.wait().ok();

    assert_eq!(after, baseline);
    Ok(())
}

#[test]
fn e2e_context_assembly_pruning_is_deterministic() -> Result<(), Box<dyn Error>> {
    let repo = setup_determinism_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let search_url = format!("http://{host}:{port}/search");

    let baseline: Value = client
        .get(&search_url)
        .query(&[
            ("q", "prune_term"),
            ("limit", "10"),
            ("snippets", "false"),
            ("max_tokens", "50"),
        ])
        .send()?
        .json()?;
    let expected = search_signature(&baseline);

    let empty_array: Vec<Value> = Vec::new();
    let pruned = baseline
        .get("meta")
        .and_then(|v| v.get("context_assembly"))
        .and_then(|v| v.get("pruned"))
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_array)
        .iter()
        .filter_map(|entry| entry.get("rel_path").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    assert!(
        pruned.iter().any(|path| path.ends_with("docs/huge.md")),
        "expected docs/huge.md to be pruned under max_tokens=50"
    );

    for _ in 0..10 {
        let payload: Value = client
            .get(&search_url)
            .query(&[
                ("q", "prune_term"),
                ("limit", "10"),
                ("snippets", "false"),
                ("max_tokens", "50"),
            ])
            .send()?
            .json()?;
        assert_eq!(search_signature(&payload), expected);
    }

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn e2e_context_assembly_chunking_is_deterministic() -> Result<(), Box<dyn Error>> {
    let repo = setup_determinism_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;

    let snippet_url = format!("http://{host}:{port}/snippet/docs/chunk.md");
    let baseline: Value = client
        .get(&snippet_url)
        .query(&[("window", "20"), ("text_only", "true")])
        .send()?
        .error_for_status()?
        .json()?;
    let expected = snippet_signature(&baseline);
    for _ in 0..10 {
        let payload: Value = client
            .get(&snippet_url)
            .query(&[("window", "20"), ("text_only", "true")])
            .send()?
            .error_for_status()?
            .json()?;
        assert_eq!(snippet_signature(&payload), expected);
    }

    let snippet = baseline.get("snippet").cloned().unwrap_or(Value::Null);
    assert!(
        snippet
            .get("truncated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        "expected preview snippet to be truncated for docs/chunk.md"
    );
    let text = snippet
        .get("text")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        text.ends_with('…'),
        "expected truncated preview snippet text to end with ellipsis"
    );

    let too_small: Value = client
        .get(&snippet_url)
        .query(&[("window", "20"), ("text_only", "true"), ("max_tokens", "5")])
        .send()?
        .error_for_status()?
        .json()?;
    for _ in 0..5 {
        let payload: Value = client
            .get(&snippet_url)
            .query(&[("window", "20"), ("text_only", "true"), ("max_tokens", "5")])
            .send()?
            .error_for_status()?
            .json()?;
        assert_eq!(snippet_signature(&payload), snippet_signature(&too_small));
    }
    assert!(
        too_small.get("snippet").is_none() || too_small.get("snippet").unwrap().is_null(),
        "expected snippet to be omitted when doc token_estimate exceeds max_tokens"
    );

    child.kill().ok();
    child.wait().ok();
    Ok(())
}
