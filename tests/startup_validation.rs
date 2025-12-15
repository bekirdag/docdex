use reqwest::blocking::Client;
use std::error::Error;
use std::fs;
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(docs_dir.join("overview.md"), "# Overview\n\nTesting.\n")?;
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping startup validation tests: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn spawn_server_default_host(repo_root: &Path, port: u16) -> Result<Child, Box<dyn Error>> {
    let repo_arg = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.0.kill().ok();
        self.0.wait().ok();
    }
}

#[test]
fn daemon_refuses_requests_until_state_validation_completes() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };

    let state_dir = repo.path().join(".docdex").join("index");
    let repo_arg = repo.path().to_string_lossy().to_string();
    let child = Command::new(docdex_bin())
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .env("DOCDEX_TEST_HOLD_AFTER_STATE_DIR_CREATED_MS", "1500")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let guard = ChildGuard(child);

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !state_dir.exists() {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        state_dir.exists(),
        "expected state dir to be created during startup validation at {}",
        state_dir.display()
    );
    #[cfg(unix)]
    {
        let mode = fs::metadata(&state_dir)?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "state dir should be chmod 700 on unix");
    }

    let client = Client::builder().timeout(Duration::from_millis(200)).build()?;
    let url = format!("http://127.0.0.1:{port}/healthz");
    let early = client.get(&url).send();
    assert!(
        early.is_err(),
        "expected connection failure before startup validation completes"
    );

    wait_for_health("127.0.0.1", port)?;
    drop(guard);
    Ok(())
}

#[test]
fn daemon_defaults_to_loopback_binding() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };

    let child = spawn_server_default_host(repo.path(), port)?;
    let guard = ChildGuard(child);
    wait_for_health("127.0.0.1", port)?;

    match TcpListener::bind(format!("127.0.0.2:{port}")) {
        Ok(listener) => drop(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrNotAvailable => {
            eprintln!("skipping 127.0.0.2 bind assertion: {err}");
        }
        Err(err) => {
            assert_ne!(
                err.kind(),
                std::io::ErrorKind::AddrInUse,
                "port should not be occupied on other loopback addresses; server should default-bind to 127.0.0.1"
            );
        }
    }

    drop(guard);
    Ok(())
}

