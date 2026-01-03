use serde_json::Value;
use std::error::Error;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn run_docdex<I, S>(
    state_root: &std::path::Path,
    args: I,
) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args(args)
        .output()?)
}

#[test]
fn ast_query_returns_function_files() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let src_dir = repo.path().join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("lib.rs"), "fn greet() { println!(\"hi\"); }\n")?;
    std::fs::write(src_dir.join("consts.rs"), "const VALUE: i32 = 1;\n")?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let index_output = run_docdex(
        state_root.path(),
        [
            "index",
            "--repo",
            repo_str.as_str(),
            "--enable-symbol-extraction=true",
        ],
    )?;
    if !index_output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&index_output.stderr)
        )
        .into());
    }

    let query_output = run_docdex(
        state_root.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--query",
            "function",
            "--limit",
            "5",
        ],
    )?;
    if !query_output.status.success() {
        return Err(format!(
            "docdexd query failed: {}",
            String::from_utf8_lossy(&query_output.stderr)
        )
        .into());
    }

    let payload: Value = serde_json::from_slice(&query_output.stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("query response missing hits array")?;
    if hits.is_empty() {
        return Err("expected AST-backed search hit for function query".into());
    }
    let mut has_lib = false;
    for hit in hits {
        if hit.get("path").and_then(|v| v.as_str()) == Some("src/lib.rs") {
            has_lib = true;
            break;
        }
    }
    if !has_lib {
        return Err("expected src/lib.rs to appear in AST-backed query results".into());
    }

    Ok(())
}
