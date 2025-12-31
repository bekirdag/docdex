use rusqlite::{params, Connection, OptionalExtension};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("src"))?;
    fs::create_dir_all(repo_root.join("pkg"))?;
    fs::create_dir_all(repo_root.join("web"))?;
    fs::create_dir_all(repo_root.join("cmd"))?;

    fs::write(
        repo_root.join("src").join("lib.rs"),
        r#"
pub struct Widget;
pub enum Mode { A }
pub trait Runner { fn run(&self); }
pub fn build() -> Widget { Widget }
"#,
    )?;

    fs::write(
        repo_root.join("pkg").join("mod.py"),
        r#"
class Greeter:
    def hello(self):
        return "hi"

def util(x):
    return x
"#,
    )?;

    fs::write(
        repo_root.join("web").join("app.js"),
        r#"
export function greet() {}
export class Greeter {}
"#,
    )?;

    fs::write(
        repo_root.join("web").join("types.ts"),
        r#"
export interface Config { name: string }
export type ID = string
export enum Kind { A, B }
"#,
    )?;

    fs::write(
        repo_root.join("cmd").join("main.go"),
        r#"
package main

type Widget struct {}

func Run() {}
"#,
    )?;

    Ok(())
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .env("DOCDEX_STATE_DIR", state_root)
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

fn inspect_repo_state(
    state_root: &Path,
    repo_root: &Path,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
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

fn assert_symbol(
    conn: &Connection,
    rel_path: &str,
    name: &str,
    kind: &str,
) -> Result<(), Box<dyn Error>> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM symbols WHERE file_path = ?1 AND name = ?2 AND kind = ?3",
        params![rel_path, name, kind],
        |row| row.get(0),
    )?;
    if count < 1 {
        return Err(format!("missing symbol {name} ({kind}) in {rel_path}").into());
    }
    Ok(())
}

fn assert_outcome_ok(conn: &Connection, rel_path: &str) -> Result<(), Box<dyn Error>> {
    let status: Option<String> = conn
        .query_row(
            "SELECT outcome_status FROM symbols_files WHERE file_path = ?1",
            params![rel_path],
            |row| row.get(0),
        )
        .optional()?;
    if status.as_deref() != Some("ok") {
        return Err(format!("expected outcome ok for {rel_path}, got {status:?}").into());
    }
    Ok(())
}

fn assert_ast_nodes(conn: &Connection, rel_path: &str) -> Result<(), Box<dyn Error>> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM ast_nodes WHERE file_path = ?1",
        params![rel_path],
        |row| row.get(0),
    )?;
    if count < 1 {
        return Err(format!("missing ast nodes for {rel_path}").into());
    }
    let status: Option<String> = conn
        .query_row(
            "SELECT outcome_status FROM ast_files WHERE file_path = ?1",
            params![rel_path],
            |row| row.get(0),
        )
        .optional()?;
    if status.as_deref() != Some("ok") {
        return Err(format!("expected ast outcome ok for {rel_path}, got {status:?}").into());
    }
    Ok(())
}

#[test]
fn symbols_tree_sitter_extracts_across_languages() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_fixture_repo(repo.path())?;

    run_docdex(
        state_root.path(),
        [
            "index",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--enable-symbol-extraction=true",
        ],
    )?;

    let repo_state_root = resolve_repo_state_root(state_root.path(), repo.path())?;
    let symbols_db = repo_state_root.join("symbols.db");
    let conn = Connection::open(symbols_db)?;

    assert_symbol(&conn, "src/lib.rs", "Widget", "struct")?;
    assert_symbol(&conn, "src/lib.rs", "build", "function")?;
    assert_outcome_ok(&conn, "src/lib.rs")?;
    assert_ast_nodes(&conn, "src/lib.rs")?;

    assert_symbol(&conn, "pkg/mod.py", "Greeter", "class")?;
    assert_symbol(&conn, "pkg/mod.py", "util", "function")?;
    assert_outcome_ok(&conn, "pkg/mod.py")?;
    assert_ast_nodes(&conn, "pkg/mod.py")?;

    assert_symbol(&conn, "web/app.js", "greet", "function")?;
    assert_symbol(&conn, "web/app.js", "Greeter", "class")?;
    assert_outcome_ok(&conn, "web/app.js")?;
    assert_ast_nodes(&conn, "web/app.js")?;

    assert_symbol(&conn, "web/types.ts", "Config", "interface")?;
    assert_symbol(&conn, "web/types.ts", "ID", "type")?;
    assert_symbol(&conn, "web/types.ts", "Kind", "enum")?;
    assert_outcome_ok(&conn, "web/types.ts")?;
    assert_ast_nodes(&conn, "web/types.ts")?;

    assert_symbol(&conn, "cmd/main.go", "Widget", "struct")?;
    assert_symbol(&conn, "cmd/main.go", "Run", "function")?;
    assert_outcome_ok(&conn, "cmd/main.go")?;
    assert_ast_nodes(&conn, "cmd/main.go")?;

    Ok(())
}
