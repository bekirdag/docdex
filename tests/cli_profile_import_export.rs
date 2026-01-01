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
        crate::common::toml_path(global_state_dir),
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
        .env("DOCDEX_ENABLE_MEMORY", "0")
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
fn cli_profile_export_and_import() -> Result<(), Box<dyn Error>> {
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let home_src = TempDir::new()?;
    let state_src = home_src.path().join(".docdex").join("state");
    write_config(home_src.path(), &state_src, &mock.base_url)?;

    let _add_resp = run_docdex(
        home_src.path(),
        [
            "profile",
            "add",
            "--agent-id",
            "agent-export",
            "--category",
            "tooling",
            "--content",
            "Use Docdex",
        ],
    )?;

    let export_path = home_src.path().join("profile_export.json");
    let _export_resp = run_docdex(
        home_src.path(),
        [
            "profile",
            "export",
            "--out",
            export_path.to_string_lossy().as_ref(),
        ],
    )?;

    let home_dst = TempDir::new()?;
    let state_dst = home_dst.path().join(".docdex").join("state");
    write_config(home_dst.path(), &state_dst, &mock.base_url)?;

    let import_resp = run_docdex(
        home_dst.path(),
        ["profile", "import", export_path.to_string_lossy().as_ref()],
    )?;
    let inserted = import_resp
        .get("inserted")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(inserted >= 1);
    Ok(())
}
