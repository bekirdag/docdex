mod common;

use common::{docdex_bin, MockOllama};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\n\n[memory.profile]\nembedding_dim = 4\nembedding_model = \"fake-embed\"\n",
        global_state_dir.display(),
        llm_base_url
    );
    fs::write(config_path, payload)?;
    Ok(())
}

fn run_docdex<I, S>(home_dir: &Path, args: I) -> Result<Value, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("HOME", home_dir)
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
    Ok(serde_json::from_slice(&output.stdout)?)
}

#[test]
fn cli_profile_add_and_search() -> Result<(), Box<dyn Error>> {
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;

    let _add_resp = run_docdex(
        home_dir.path(),
        [
            "profile",
            "add",
            "--agent-id",
            "agent-cli",
            "--category",
            "style",
            "--content",
            "Use tabs",
        ],
    )?;

    let search_resp = run_docdex(
        home_dir.path(),
        [
            "profile",
            "search",
            "--agent-id",
            "agent-cli",
            "--query",
            "tabs",
            "--top-k",
            "3",
        ],
    )?;
    let results = search_resp
        .get("results")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new());
    assert!(!results.is_empty(), "expected search results");
    Ok(())
}
