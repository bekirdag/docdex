use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(
        docs_dir.join("overview.md"),
        r#"# Overview

This repository contains REPL_NEEDLE used for testing.
"#,
    )?;
    Ok(())
}

fn run_docdex<I, S>(args: I) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
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
    Ok(())
}

#[test]
fn chat_repl_accepts_queries() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_dir = TempDir::new()?;
    write_fixture_repo(repo.path())?;

    run_docdex([
        "index",
        "--repo",
        repo.path().to_string_lossy().as_ref(),
        "--state-dir",
        state_dir.path().to_string_lossy().as_ref(),
    ])?;

    let mut child = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "chat",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--state-dir",
            state_dir.path().to_string_lossy().as_ref(),
            "--limit",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("failed to take docdexd chat stdin")?;
    stdin.write_all(b"REPL_NEEDLE\nexit\n")?;
    stdin.flush()?;
    drop(stdin);

    let output = child.wait_with_output()?;
    assert!(
        output.status.success(),
        "docdexd chat repl exited with {}",
        output.status
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("docdex> "),
        "expected REPL prompt in stdout"
    );
    assert!(
        stdout.contains("\"hits\""),
        "expected JSON output from chat REPL"
    );
    Ok(())
}
