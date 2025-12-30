use super::{project_map_path, render_project_map, ProjectMap, ProjectMapNode};
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn project_map_path_resolves_repo_root() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let repo_root = temp.path().join("repo");
    let index_dir = repo_root.join("index");
    std::fs::create_dir_all(&index_dir)?;

    let path = project_map_path(&index_dir, "agent-1");
    let expected = PathBuf::from(&repo_root).join("maps").join("agent-1.json");
    assert_eq!(path, expected);
    Ok(())
}

#[test]
fn render_project_map_outputs_tree() {
    let map = ProjectMap {
        agent_id: "agent".to_string(),
        keywords: vec!["rust".to_string()],
        generated_at_ms: 0,
        nodes: vec![ProjectMapNode {
            name: "src".to_string(),
            children: vec![ProjectMapNode {
                name: "main.rs".to_string(),
                children: Vec::new(),
                hidden: None,
            }],
            hidden: Some(1),
        }],
    };
    let rendered = render_project_map(&map);
    assert!(rendered.contains("Project map:"));
    assert!(rendered.contains("- src (+1 hidden)"));
    assert!(rendered.contains("- main.rs"));
}
