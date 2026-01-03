use docdexd::dag::{logging as dag_logging, view as dag_view};
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
fn dag_view_renders_persisted_nodes() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_fixture_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let state_paths = resolve_state_paths(repo.path(), Some(state_root.path().to_path_buf()))?;
    let repo_state_root = state_paths.repo_root().to_path_buf();

    let session_id = "session-1";
    dag_logging::log_node(
        &repo_state_root,
        session_id,
        "UserRequest",
        &json!({ "query": "hello" }),
    )?;
    dag_logging::log_node(
        &repo_state_root,
        session_id,
        "Decision",
        &json!({ "answer": "ok" }),
    )?;

    let text = dag_view::render_session_as_text(
        repo.path(),
        session_id,
        Some(state_root.path().to_path_buf()),
        None,
    )?;
    assert!(text.contains("UserRequest"));
    assert!(text.contains("Decision"));

    let dot = dag_view::render_session_as_dot(
        repo.path(),
        session_id,
        Some(state_root.path().to_path_buf()),
        None,
    )?;
    assert!(dot.contains("digraph dag"));
    assert!(dot.contains("UserRequest"));
    assert!(dot.contains("->"));
    Ok(())
}
