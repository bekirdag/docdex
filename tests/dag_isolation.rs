use docdexd::dag::{load_session_dag, logging as dag_logging, DagStatus};
use docdexd::state_layout::resolve_state_paths;
use serde_json::json;
use std::error::Error;
use std::path::Path;
use tempfile::TempDir;

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(docs_dir.join("overview.md"), "# Overview\n\nHello.\n")?;
    Ok(())
}

#[test]
fn dag_isolation_between_repos() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let repo_a = TempDir::new()?;
    let repo_b = TempDir::new()?;
    write_fixture_repo(repo_a.path())?;
    write_fixture_repo(repo_b.path())?;

    let state_a = resolve_state_paths(repo_a.path(), Some(state_root.path().to_path_buf()))?;
    let state_b = resolve_state_paths(repo_b.path(), Some(state_root.path().to_path_buf()))?;

    let session_id = "session-1";
    dag_logging::log_node(
        state_a.repo_root(),
        session_id,
        "UserRequest",
        &json!({ "repo": "a" }),
    )?;
    dag_logging::log_node(
        state_b.repo_root(),
        session_id,
        "UserRequest",
        &json!({ "repo": "b" }),
    )?;

    let dag_a = load_session_dag(repo_a.path(), session_id, Some(state_root.path().to_path_buf()))?;
    let dag_b = load_session_dag(repo_b.path(), session_id, Some(state_root.path().to_path_buf()))?;

    assert_eq!(dag_a.status, DagStatus::Found);
    assert_eq!(dag_b.status, DagStatus::Found);
    assert!(dag_a
        .nodes
        .iter()
        .all(|node| node.payload.get("repo") == Some(&json!("a"))));
    assert!(dag_b
        .nodes
        .iter()
        .all(|node| node.payload.get("repo") == Some(&json!("b"))));
    Ok(())
}
