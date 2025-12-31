use docdexd::repo_manager;
use rusqlite::Connection;
use serde_json::Value;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn run_index(state_root: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "index",
            "--repo",
            repo_root.to_string_lossy().as_ref(),
            "--state-dir",
            state_root.to_string_lossy().as_ref(),
            "--enable-symbol-extraction=true",
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn repo_state_root(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let fingerprint = repo_manager::repo_fingerprint_sha256(repo_root)?;
    Ok(state_root.join("repos").join(fingerprint))
}

fn read_symbol_files(db_path: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare("SELECT file_path FROM symbols_files")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut files = BTreeSet::new();
    for row in rows {
        files.insert(row?);
    }
    Ok(files)
}

fn read_ast_files(db_path: &Path) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare("SELECT file_path FROM ast_files")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut files = BTreeSet::new();
    for row in rows {
        files.insert(row?);
    }
    Ok(files)
}

fn read_impact_edges(path: &Path) -> Result<BTreeSet<(String, String)>, Box<dyn Error>> {
    let raw = fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&raw)?;
    let mut edge_values: Vec<Value> = Vec::new();
    if value.is_array() {
        if let Some(edges) = value.as_array() {
            if edges.first().and_then(|item| item.get("source")).is_some() {
                edge_values.extend(edges.iter().cloned());
            } else {
                for entry in edges {
                    if let Some(edges_value) = entry.get("edges") {
                        if let Some(list) = edges_value.as_array() {
                            edge_values.extend(list.iter().cloned());
                        }
                    }
                }
            }
        }
    } else if let Some(edges_value) = value.get("edges") {
        if let Some(list) = edges_value.as_array() {
            edge_values.extend(list.iter().cloned());
        }
    } else if let Some(graphs_value) = value.get("graphs") {
        if let Some(list) = graphs_value.as_array() {
            for entry in list {
                if let Some(edges_value) = entry.get("edges") {
                    if let Some(edges) = edges_value.as_array() {
                        edge_values.extend(edges.iter().cloned());
                    }
                }
            }
        }
    }
    if edge_values.is_empty() {
        return Err("impact_graph.json missing edges".into());
    }
    let mut pairs = BTreeSet::new();
    for edge in edge_values {
        let source = edge
            .get("source")
            .and_then(|v| v.as_str())
            .ok_or("impact edge missing source")?;
        let target = edge
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or("impact edge missing target")?;
        pairs.insert((source.to_string(), target.to_string()));
    }
    Ok(pairs)
}

fn write_repo_a(root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(root.join("src"))?;
    fs::write(
        root.join("src").join("lib.rs"),
        "mod util;\npub fn alpha() {}\n",
    )?;
    fs::write(root.join("src").join("util.rs"), "pub fn util() {}\n")?;
    Ok(())
}

fn write_repo_b(root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(root.join("pkg"))?;
    fs::write(root.join("pkg").join("main.py"), "import pkg.util\n")?;
    fs::write(
        root.join("pkg").join("util.py"),
        "def beta():\n    return 1\n",
    )?;
    Ok(())
}

#[test]
fn repo_isolation_for_symbols_and_impact_graph() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let repo_a = TempDir::new()?;
    let repo_b = TempDir::new()?;
    write_repo_a(repo_a.path())?;
    write_repo_b(repo_b.path())?;

    run_index(state_root.path(), repo_a.path())?;
    run_index(state_root.path(), repo_b.path())?;

    let repo_a_state = repo_state_root(state_root.path(), repo_a.path())?;
    let repo_b_state = repo_state_root(state_root.path(), repo_b.path())?;

    let repo_a_symbols = read_symbol_files(&repo_a_state.join("symbols.db"))?;
    let repo_b_symbols = read_symbol_files(&repo_b_state.join("symbols.db"))?;
    let repo_a_ast = read_ast_files(&repo_a_state.join("symbols.db"))?;
    let repo_b_ast = read_ast_files(&repo_b_state.join("symbols.db"))?;

    assert!(repo_a_symbols.contains("src/lib.rs"));
    assert!(repo_a_symbols.contains("src/util.rs"));
    assert!(!repo_a_symbols.contains("pkg/main.py"));
    assert!(!repo_a_symbols.contains("pkg/util.py"));
    assert!(repo_a_ast.contains("src/lib.rs"));
    assert!(repo_a_ast.contains("src/util.rs"));
    assert!(!repo_a_ast.contains("pkg/main.py"));
    assert!(!repo_a_ast.contains("pkg/util.py"));

    assert!(repo_b_symbols.contains("pkg/main.py"));
    assert!(repo_b_symbols.contains("pkg/util.py"));
    assert!(!repo_b_symbols.contains("src/lib.rs"));
    assert!(!repo_b_symbols.contains("src/util.rs"));
    assert!(repo_b_ast.contains("pkg/main.py"));
    assert!(repo_b_ast.contains("pkg/util.py"));
    assert!(!repo_b_ast.contains("src/lib.rs"));
    assert!(!repo_b_ast.contains("src/util.rs"));

    let repo_a_edges = read_impact_edges(&repo_a_state.join("impact_graph.json"))?;
    let repo_b_edges = read_impact_edges(&repo_b_state.join("impact_graph.json"))?;

    assert!(repo_a_edges.contains(&("src/lib.rs".to_string(), "src/util.rs".to_string())));
    assert!(!repo_a_edges.contains(&("pkg/main.py".to_string(), "pkg/util.py".to_string())));

    assert!(repo_b_edges.contains(&("pkg/main.py".to_string(), "pkg/util.py".to_string())));
    assert!(!repo_b_edges.contains(&("src/lib.rs".to_string(), "src/util.rs".to_string())));

    Ok(())
}
