use serde_json::Value;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn run_docdex<I, S>(
    state_root: &Path,
    home: &Path,
    args: I,
) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("HOME", home)
        .env("DOCDEX_ENABLE_SYMBOL_RANKING", "1")
        .env("DOCDEX_ENABLE_AST_RANKING", "1")
        .args(args)
        .output()?)
}

fn index_repo(state_root: &Path, home: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let output = run_docdex(
        state_root,
        home,
        [
            "index",
            "--repo",
            repo_str.as_str(),
            "--enable-symbol-extraction=true",
        ],
    )?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[test]
fn symbol_ranking_prefers_struct_over_const() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home = TempDir::new()?;
    let src_dir = repo.path().join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("struct.rs"), "struct Config { value: i32 }\n")?;
    std::fs::write(src_dir.join("const.rs"), "const Config: i32 = 1;\n")?;

    index_repo(state_root.path(), home.path(), repo.path())?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let output = run_docdex(
        state_root.path(),
        home.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--query",
            "Config",
            "--limit",
            "5",
        ],
    )?;
    if !output.status.success() {
        return Err(format!(
            "docdexd query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("query response missing hits array")?;
    if hits.len() < 2 {
        return Err("expected at least two hits for Config query".into());
    }
    let first_path = hits
        .first()
        .and_then(|hit| hit.get("path").and_then(|v| v.as_str()))
        .ok_or("missing path in first hit")?;
    if first_path != "src/struct.rs" {
        return Err(format!("expected struct.rs to rank first, got {first_path}").into());
    }
    Ok(())
}

#[test]
fn ast_ranking_prefers_function_over_class() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home = TempDir::new()?;
    let src_dir = repo.path().join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("func.rs"), "// function class\nfn run() {}\n")?;
    std::fs::write(
        src_dir.join("class.ts"),
        "// function class\nclass Widget {}\n",
    )?;

    index_repo(state_root.path(), home.path(), repo.path())?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let output = run_docdex(
        state_root.path(),
        home.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--query",
            "function class",
            "--limit",
            "5",
        ],
    )?;
    if !output.status.success() {
        return Err(format!(
            "docdexd query failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("query response missing hits array")?;
    if hits.len() < 2 {
        return Err("expected at least two hits for function/class query".into());
    }
    let first_path = hits
        .first()
        .and_then(|hit| hit.get("path").and_then(|v| v.as_str()))
        .ok_or("missing path in first hit")?;
    if first_path != "src/func.rs" {
        return Err(format!("expected func.rs to rank first, got {first_path}").into());
    }
    Ok(())
}
