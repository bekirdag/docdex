use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

const SOAK_TOKEN: &str = "SOAK_REPO_TOKEN";

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_large_repo(repo_root: &Path, file_count: usize) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    let src_root = repo_root.join("src");
    fs::create_dir_all(&src_root)?;
    for idx in 0..file_count {
        let bucket = idx % 20;
        let dir = src_root.join(format!("mod_{bucket}"));
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("file_{idx}.rs"));
        fs::write(
            path,
            format!(
                "pub fn f_{idx}() -> usize {{ {idx} }}\nconst MARKER: &str = \"{SOAK_TOKEN}\";\n"
            ),
        )?;
    }
    Ok(())
}

fn run_docdex<I, S>(args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
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

/// Soak test for large repo indexing + repeated queries.
#[test]
#[ignore]
fn soak_large_repo_index_and_query() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_dir = TempDir::new()?;
    write_large_repo(repo.path(), 1200)?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let state_str = state_dir.path().to_string_lossy().to_string();

    run_docdex([
        "index",
        "--repo",
        repo_str.as_str(),
        "--state-dir",
        state_str.as_str(),
        "--log",
        "warn",
    ])?;

    for _ in 0..20 {
        run_docdex([
            "query",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_str.as_str(),
            "--query",
            SOAK_TOKEN,
            "--limit",
            "5",
            "--repo-only",
        ])?;
    }

    Ok(())
}
