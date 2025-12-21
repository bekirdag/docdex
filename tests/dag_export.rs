use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    fs::write(temp.path().join("README.md"), "# Fixture\n")?;
    Ok(temp)
}

fn run_docdex<I, S>(args: I) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin()).args(args).output()?)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping dag export tests: TCP bind not permitted in this environment");
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

#[derive(Serialize)]
struct DagRecord {
    id: String,
    session_id: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    payload: Value,
    created_at: i64,
}

fn write_dag_records(state_dir: &Path, records: &[DagRecord]) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(state_dir)?;
    let mut file = fs::File::create(state_dir.join("dag.jsonl"))?;
    for record in records {
        let line = serde_json::to_string(record)?;
        writeln!(file, "{line}")?;
    }
    Ok(())
}

fn cli_export(
    repo_root: &Path,
    session_id: &str,
    max_nodes: Option<usize>,
) -> Result<Value, Box<dyn Error>> {
    let mut args = vec![
        "dag".to_string(),
        "view".to_string(),
        "--repo".to_string(),
        repo_root.to_string_lossy().to_string(),
        session_id.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if let Some(max_nodes) = max_nodes {
        args.push("--max-nodes".to_string());
        args.push(max_nodes.to_string());
    }
    let output = Command::new(docdex_bin()).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "dag view failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn http_export(
    host: &str,
    port: u16,
    session_id: &str,
    max_nodes: Option<usize>,
) -> Result<Value, Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/dag/export");
    let mut params: Vec<(&str, String)> = vec![
        ("session_id", session_id.to_string()),
        ("format", "json".to_string()),
    ];
    if let Some(max_nodes) = max_nodes {
        params.push(("max_nodes", max_nodes.to_string()));
    }
    Ok(client.get(url).query(&params).send()?.json()?)
}

#[test]
fn dag_export_cli_matches_http_json() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let state_dir = repo.path().join(".docdex").join("index");
    write_dag_records(
        &state_dir,
        &[
            DagRecord {
                id: "n2".to_string(),
                session_id: "sess-1".to_string(),
                kind: "Observation".to_string(),
                payload: serde_json::json!({}),
                created_at: 200,
            },
            DagRecord {
                id: "n1".to_string(),
                session_id: "sess-1".to_string(),
                kind: "UserRequest".to_string(),
                payload: serde_json::json!({"text": "hi"}),
                created_at: 100,
            },
            DagRecord {
                id: "n3".to_string(),
                session_id: "sess-2".to_string(),
                kind: "Thought".to_string(),
                payload: serde_json::json!({}),
                created_at: 300,
            },
        ],
    )?;

    let cli_payload = cli_export(repo.path(), "sess-1", None)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let http_payload = http_export(host, port, "sess-1", None)?;
    server.kill().ok();
    server.wait().ok();

    assert_eq!(cli_payload, http_payload);
    let nodes = cli_payload
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or("nodes missing")?;
    assert_eq!(nodes.len(), 2);
    assert_eq!(
        nodes
            .first()
            .and_then(|v| v.get("id"))
            .and_then(|v| v.as_str()),
        Some("n1")
    );
    Ok(())
}

#[test]
fn dag_export_respects_max_nodes() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_str.as_str()])?;

    let state_dir = repo.path().join(".docdex").join("index");
    write_dag_records(
        &state_dir,
        &[
            DagRecord {
                id: "n1".to_string(),
                session_id: "sess-3".to_string(),
                kind: "UserRequest".to_string(),
                payload: serde_json::json!({}),
                created_at: 100,
            },
            DagRecord {
                id: "n2".to_string(),
                session_id: "sess-3".to_string(),
                kind: "Observation".to_string(),
                payload: serde_json::json!({}),
                created_at: 200,
            },
            DagRecord {
                id: "n3".to_string(),
                session_id: "sess-3".to_string(),
                kind: "Decision".to_string(),
                payload: serde_json::json!({}),
                created_at: 300,
            },
        ],
    )?;

    let cli_payload = cli_export(repo.path(), "sess-3", Some(2))?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(repo.path(), host, port)?;
    wait_for_health(host, port)?;
    let http_payload = http_export(host, port, "sess-3", Some(2))?;
    server.kill().ok();
    server.wait().ok();

    assert_eq!(cli_payload, http_payload);
    let nodes = cli_payload
        .get("nodes")
        .and_then(|v| v.as_array())
        .ok_or("nodes missing")?;
    let edges = cli_payload
        .get("edges")
        .and_then(|v| v.as_array())
        .ok_or("edges missing")?;
    assert_eq!(nodes.len(), 2);
    assert_eq!(edges.len(), 1);
    assert_eq!(
        cli_payload.get("truncated").and_then(|v| v.as_bool()),
        Some(true)
    );
    assert_eq!(
        cli_payload
            .get("appliedLimits")
            .and_then(|v| v.get("maxNodes"))
            .and_then(|v| v.as_u64()),
        Some(2)
    );
    Ok(())
}
