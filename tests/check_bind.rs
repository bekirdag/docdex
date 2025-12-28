use serde_json::Value;
use std::error::Error;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_config(home: &Path, state_root: &Path, bind_addr: &str) -> Result<(), Box<dyn Error>> {
    let config_dir = home.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let payload = format!(
        r#"[core]
global_state_dir = "{}"

[llm]
provider = "noop"
default_model = "noop"
embedding_model = "noop"
max_answer_tokens = 128

[memory]
enabled = false

[server]
enable_mcp = false
http_bind_addr = "{}"
"#,
        state_root.display(),
        bind_addr
    );
    fs::write(config_dir.join("config.toml"), payload)?;
    Ok(())
}

fn parse_report(output: &[u8]) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(output)?)
}

fn find_check<'a>(report: &'a Value, name: &str) -> Option<&'a Value> {
    report
        .get("checks")
        .and_then(|v| v.as_array())
        .and_then(|checks| {
            checks
                .iter()
                .find(|item| item.get("name").and_then(|v| v.as_str()) == Some(name))
        })
}

#[test]
fn check_fails_when_bind_in_use() -> Result<(), Box<dyn Error>> {
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    write_config(
        home.path(),
        state_root.path(),
        &format!("127.0.0.1:{port}"),
    )?;

    let output = Command::new(docdex_bin())
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MCP", "0")
        .arg("check")
        .output()?;

    assert!(
        !output.status.success(),
        "docdexd check should fail when bind is in use"
    );
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "bind_available").ok_or("missing bind_available check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("fail"));
    let error_kind = check
        .get("details")
        .and_then(|v| v.get("error_kind"))
        .and_then(|v| v.as_str());
    assert_eq!(error_kind, Some("addr_in_use"));
    drop(listener);
    Ok(())
}

#[cfg(unix)]
#[test]
fn check_reports_permission_denied_on_privileged_port() -> Result<(), Box<dyn Error>> {
    if nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping permission denied check: running as root");
        return Ok(());
    }
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), state_root.path(), "127.0.0.1:1")?;

    let output = Command::new(docdex_bin())
        .env("HOME", home.path())
        .env("DOCDEX_LLM_AGENT", "test")
        .env("DOCDEX_ENABLE_MCP", "0")
        .arg("check")
        .output()?;

    assert!(
        !output.status.success(),
        "docdexd check should fail when bind is not permitted"
    );
    let report = parse_report(&output.stdout)?;
    let check = find_check(&report, "bind_available").ok_or("missing bind_available check")?;
    assert_eq!(check.get("status").and_then(|v| v.as_str()), Some("fail"));
    let error_kind = check
        .get("details")
        .and_then(|v| v.get("error_kind"))
        .and_then(|v| v.as_str());
    if error_kind == Some("addr_in_use") {
        eprintln!("skipping permission denied check: port 1 already in use");
        return Ok(());
    }
    assert_eq!(error_kind, Some("permission_denied"));
    Ok(())
}
