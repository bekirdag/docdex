use reqwest::blocking::Client;
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
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    std::fs::write(temp.path().join("a.ts"), "export const A = 1;\n")?;
    std::fs::write(temp.path().join("b.ts"), "export const B = 2;\n")?;
    std::fs::write(temp.path().join("c.ts"), "export const C = 3;\n")?;
    std::fs::write(temp.path().join("d.ts"), "export const D = 4;\n")?;
    std::fs::write(temp.path().join("x.ts"), "export const X = 5;\n")?;
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

fn resolve_index_dir(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    if let Some(resolved) = payload
        .get("statePaths")
        .and_then(|value| value.get("repoStateRoot"))
        .and_then(|value| value.as_str())
    {
        return Ok(PathBuf::from(resolved));
    }
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|value| value.as_str())
        .ok_or("missing resolvedIndexStateDir")?;
    Ok(PathBuf::from(resolved))
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping impact tests: TCP bind not permitted in this environment");
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
        .env("DOCDEX_ENABLE_MCP", "0")
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

fn write_impact_graph(state_dir: &Path) -> Result<(), Box<dyn Error>> {
    write_impact_graph_payload(
        state_dir,
        serde_json::json!({
            "edges": [
                { "source": "a.ts", "target": "b.ts", "kind": "import" },
                { "source": "b.ts", "target": "c.ts", "kind": "import" },
                { "source": "c.ts", "target": "d.ts", "kind": "require" },
                { "source": "x.ts", "target": "a.ts", "kind": "include" },
                { "source": "a.ts", "target": "z.ts" }
            ]
        }),
    )
}

fn write_impact_graph_payload(
    state_dir: &Path,
    payload: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(state_dir)?;
    std::fs::write(
        state_dir.join("impact_graph.json"),
        serde_json::to_vec_pretty(&payload)?,
    )?;
    Ok(())
}

fn issue_fields(body: &Value) -> Result<Vec<String>, Box<dyn Error>> {
    let issues = body
        .get("error")
        .and_then(|v| v.get("details"))
        .and_then(|v| v.get("issues"))
        .and_then(|v| v.as_array())
        .ok_or("missing error.details.issues")?;
    let mut fields = issues
        .iter()
        .filter_map(|issue| {
            issue
                .get("field")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect::<Vec<_>>();
    fields.sort();
    fields.dedup();
    Ok(fields)
}

fn field_error_codes(body: &Value, field: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let errors = body
        .get("error")
        .and_then(|v| v.get("details"))
        .and_then(|v| v.get("fieldErrors"))
        .and_then(|v| v.get(field))
        .and_then(|v| v.as_array())
        .ok_or("missing error.details.fieldErrors.<field> array")?;
    let mut codes = errors
        .iter()
        .filter_map(|err| {
            err.get("code")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    Ok(codes)
}

fn assert_schema_signal(body: &Value, expected_name: &str) -> Result<(), Box<dyn Error>> {
    let schema = body
        .get("schema")
        .and_then(|v| v.as_object())
        .ok_or("impact graph response missing schema object")?;
    let name = schema
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or("impact graph response missing schema.name")?;
    if name != expected_name {
        return Err(format!("schema.name mismatch: {name}").into());
    }
    let version = schema
        .get("version")
        .and_then(|v| v.as_u64())
        .ok_or("impact graph response missing schema.version")?;
    let compatible = schema
        .get("compatible")
        .and_then(|v| v.as_object())
        .ok_or("impact graph response missing schema.compatible")?;
    let min = compatible
        .get("min")
        .and_then(|v| v.as_u64())
        .ok_or("impact graph response missing schema.compatible.min")?;
    let max = compatible
        .get("max")
        .and_then(|v| v.as_u64())
        .ok_or("impact graph response missing schema.compatible.max")?;
    if !(min <= version && version <= max) {
        return Err("schema.version not within compatible range".into());
    }
    Ok(())
}

#[test]
fn impact_enforces_max_edges_and_sets_truncated() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client
        .get(&url)
        .query(&[("file", "a.ts"), ("maxEdges", "1"), ("maxDepth", "10")])
        .send()?
        .json()?;
    let edges = resp
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("missing edges array")?;
    assert!(edges.len() <= 1);
    assert_eq!(resp.get("truncated").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxEdges"))
            .and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxDepth"))
            .and_then(|v| v.as_u64()),
        Some(10)
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_max_edges_zero_returns_empty_and_truncated() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client
        .get(&url)
        .query(&[("file", "a.ts"), ("maxEdges", "0"), ("maxDepth", "10")])
        .send()?
        .json()?;
    let edges = resp
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("missing edges array")?;
    assert!(edges.is_empty());
    assert_eq!(resp.get("truncated").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxEdges"))
            .and_then(|v| v.as_u64()),
        Some(0)
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_enforces_max_depth() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client
        .get(&url)
        .query(&[("file", "a.ts"), ("maxEdges", "100"), ("maxDepth", "1")])
        .send()?
        .json()?;
    let edges = resp
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("missing edges array")?;
    assert!(
        !edges.iter().any(|edge| {
            edge.get("source").and_then(|v| v.as_str()) == Some("b.ts")
                && edge.get("target").and_then(|v| v.as_str()) == Some("c.ts")
        }),
        "maxDepth=1 should not traverse to b.ts -> c.ts"
    );
    assert_eq!(
        resp.get("truncated").and_then(|v| v.as_bool()),
        Some(true),
        "maxDepth=1 should mark response as truncated"
    );
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxEdges"))
            .and_then(|v| v.as_u64()),
        Some(100)
    );
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxDepth"))
            .and_then(|v| v.as_u64()),
        Some(1)
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_max_depth_zero_returns_empty_and_truncated() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client
        .get(&url)
        .query(&[("file", "a.ts"), ("maxEdges", "100"), ("maxDepth", "0")])
        .send()?
        .json()?;
    let edges = resp
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("missing edges array")?;
    assert!(edges.is_empty());
    assert_eq!(resp.get("truncated").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxDepth"))
            .and_then(|v| v.as_u64()),
        Some(0)
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_filters_edge_types() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client
        .get(&url)
        .query(&[
            ("file", "a.ts"),
            ("maxEdges", "100"),
            ("maxDepth", "10"),
            ("edgeTypes", "include"),
        ])
        .send()?
        .json()?;
    let edges = resp
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("missing edges array")?;
    assert_eq!(edges.len(), 1);
    assert_eq!(
        edges[0].get("kind").and_then(|v| v.as_str()),
        Some("include")
    );
    let applied_edge_types = resp
        .get("appliedLimits")
        .and_then(|v| v.get("edgeTypes"))
        .and_then(|v| v.as_array())
        .ok_or("missing appliedLimits.edgeTypes array")?;
    assert_eq!(
        applied_edge_types
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>(),
        vec!["include"]
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_reports_applied_limits_and_not_truncated_by_default() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client.get(&url).query(&[("file", "a.ts")]).send()?.json()?;
    assert_schema_signal(&resp, "docdex.impact_graph")?;
    assert_eq!(resp.get("truncated").and_then(|v| v.as_bool()), Some(false));
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxEdges"))
            .and_then(|v| v.as_u64()),
        Some(1000)
    );
    assert_eq!(
        resp.get("appliedLimits")
            .and_then(|v| v.get("maxDepth"))
            .and_then(|v| v.as_u64()),
        Some(10)
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_edge_types_does_not_expand_through_excluded_edges() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph_payload(
        &state_dir,
        serde_json::json!({
            "edges": [
                { "source": "a.ts", "target": "b.ts", "kind": "include" },
                { "source": "b.ts", "target": "c.ts", "kind": "require" },
                { "source": "c.ts", "target": "d.ts", "kind": "include" }
            ]
        }),
    )?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp: Value = client
        .get(&url)
        .query(&[
            ("file", "a.ts"),
            ("maxEdges", "100"),
            ("maxDepth", "10"),
            ("edgeTypes", "include"),
        ])
        .send()?
        .json()?;
    let edges = resp
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("missing edges array")?;

    assert_eq!(
        edges.len(),
        1,
        "should not reach c.ts without traversing require edges"
    );
    assert!(
        !edges.iter().any(|edge| {
            edge.get("source").and_then(|v| v.as_str()) == Some("c.ts")
                && edge.get("target").and_then(|v| v.as_str()) == Some("d.ts")
        }),
        "should not expand traversal via excluded edge types"
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_diagnostics_lists_entries() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph_payload(
        &state_dir,
        serde_json::json!({
            "graphs": [
                {
                    "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
                    "repo_id": "test-repo",
                    "source": "a.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": [],
                    "diagnostics": {
                        "unresolvedImportsTotal": 2,
                        "unresolvedImportsSample": ["./dynamic.js", "./other.js"]
                    }
                },
                {
                    "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
                    "repo_id": "test-repo",
                    "source": "b.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": [],
                    "diagnostics": {
                        "unresolvedImportsTotal": 1,
                        "unresolvedImportsSample": ["./dyn.ts"]
                    }
                }
            ]
        }),
    )?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact/diagnostics");
    let resp: Value = client.get(&url).send()?.json()?;
    let schema_name = resp
        .get("schema")
        .and_then(|v| v.get("name"))
        .and_then(|v| v.as_str())
        .ok_or("impact diagnostics response missing schema.name")?;
    assert_eq!(schema_name, "docdex.impact_diagnostics");
    assert_eq!(resp.get("total").and_then(|v| v.as_u64()), Some(2));
    assert_eq!(resp.get("limit").and_then(|v| v.as_u64()), Some(200));
    assert_eq!(resp.get("offset").and_then(|v| v.as_u64()), Some(0));

    let diagnostics = resp
        .get("diagnostics")
        .and_then(|v| v.as_array())
        .ok_or("missing diagnostics array")?;
    let mut files = diagnostics
        .iter()
        .filter_map(|entry| entry.get("file").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    files.sort();
    assert_eq!(files, vec!["a.ts", "b.ts"]);

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_diagnostics_filters_by_file() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph_payload(
        &state_dir,
        serde_json::json!({
            "graphs": [
                {
                    "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
                    "repo_id": "test-repo",
                    "source": "a.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": [],
                    "diagnostics": {
                        "unresolvedImportsTotal": 2,
                        "unresolvedImportsSample": ["./dynamic.js"]
                    }
                }
            ]
        }),
    )?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact/diagnostics");
    let resp: Value = client.get(&url).query(&[("file", "a.ts")]).send()?.json()?;
    let diagnostics = resp
        .get("diagnostics")
        .and_then(|v| v.as_array())
        .ok_or("missing diagnostics array")?;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(
        diagnostics[0].get("file").and_then(|v| v.as_str()),
        Some("a.ts")
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_invalid_params_return_invalid_argument_with_field_details() -> Result<(), Box<dyn Error>>
{
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp = client
        .get(&url)
        .query(&[("file", "a.ts"), ("maxEdges", "-1"), ("maxDepth", "-2")])
        .send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json()?;
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_argument")
    );
    assert_eq!(issue_fields(&body)?, vec!["maxDepth", "maxEdges"]);
    assert_eq!(
        field_error_codes(&body, "maxEdges")?,
        vec!["must_be_non_negative"]
    );
    assert_eq!(
        field_error_codes(&body, "maxDepth")?,
        vec!["must_be_non_negative"]
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_non_integer_params_return_invalid_argument_with_field_details(
) -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp = client
        .get(&url)
        .query(&[("file", "a.ts"), ("maxEdges", "nope"), ("maxDepth", "10")])
        .send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json()?;
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_argument")
    );
    assert_eq!(issue_fields(&body)?, vec!["maxEdges"]);
    assert_eq!(
        field_error_codes(&body, "maxEdges")?,
        vec!["must_be_integer"]
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_missing_file_returns_invalid_argument_with_field_details() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp = client.get(&url).send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json()?;
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_argument")
    );
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str()),
        Some("file must not be empty")
    );
    assert_eq!(issue_fields(&body)?, vec!["file"]);
    assert_eq!(field_error_codes(&body, "file")?, vec!["must_be_non_empty"]);

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn impact_edge_types_empty_returns_invalid_argument_with_field_details(
) -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    write_impact_graph(&state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/graph/impact");
    let resp = client
        .get(&url)
        .query(&[("file", "a.ts"), ("edgeTypes", ",")])
        .send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json()?;
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_argument")
    );
    assert_eq!(issue_fields(&body)?, vec!["edgeTypes"]);
    assert_eq!(
        field_error_codes(&body, "edgeTypes")?,
        vec!["must_be_non_empty_string"]
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}
