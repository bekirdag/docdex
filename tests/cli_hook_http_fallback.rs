mod common;

use common::{docdex_bin, pick_free_port, wait_for_health};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(repo_root.join("docs").join("readme.md"), "# Repo\n")?;
    Command::new("git")
        .current_dir(repo_root)
        .args(["init", "-q"])
        .status()?;
    Command::new("git")
        .current_dir(repo_root)
        .args(["add", "."])
        .status()?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    socket_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[server]\nhook_socket_path = \"{}\"\n\n[memory.profile]\nembedding_dim = 4\nembedding_model = \"fake-embed\"\n",
        global_state_dir.display(),
        socket_path.display()
    );
    fs::write(config_path, payload)?;
    Ok(())
}

struct ServerHarness {
    child: Child,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_ENABLE_MCP", "0")
            .env("HOME", home_dir)
            .args([
                "serve",
                "--repo",
                repo_str.as_str(),
                "--host",
                host,
                "--port",
                &port.to_string(),
                "--log",
                "warn",
                "--secure-mode=false",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[test]
fn cli_hook_falls_back_to_http_when_socket_missing() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;

    let socket_path = home_dir.path().join("missing.sock");
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &socket_path)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let status = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("HOME", home_dir.path())
        .env("DOCDEX_HTTP_BASE_URL", base_url)
        .args([
            "hook",
            "pre-commit",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
        ])
        .status()?;
    assert!(
        status.success(),
        "expected hook to succeed via HTTP fallback"
    );

    server.shutdown();
    Ok(())
}
