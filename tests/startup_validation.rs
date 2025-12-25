use reqwest::blocking::Client;
use serde_json::Value;
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

fn inspect_repo_state(state_root: &Path, repo_root: &Path) -> Result<Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
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

fn resolve_index_dir(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|value| value.as_str())
        .ok_or("missing resolvedIndexStateDir")?;
    Ok(PathBuf::from(resolved))
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping startup validation tests: TCP bind not permitted in this environment"
            );
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

fn spawn_server_default_host(
    state_root: &Path,
    repo_root: &Path,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_arg = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
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

fn parse_single_error_envelope(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let trimmed = raw.trim();
    assert!(
        !trimmed.contains('\n'),
        "expected a single-line JSON error envelope; got:\n{trimmed}"
    );
    Ok(serde_json::from_str(trimmed)?)
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
    let state_root = TempDir::new()?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };

    let state_dir = resolve_index_dir(state_root.path(), repo.path())?;
    let repo_arg = repo.path().to_string_lossy().to_string();
    let child = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
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

    let client = Client::builder()
        .timeout(Duration::from_millis(200))
        .build()?;
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
    let state_root = TempDir::new()?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };

    let child = spawn_server_default_host(state_root.path(), repo.path(), port)?;
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

#[test]
fn startup_failure_emits_single_error_envelope_for_auth() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_arg = repo.path().to_string_lossy().to_string();
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let port_str = port.to_string();
    let output = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--host",
            "0.0.0.0",
            "--port",
            port_str.as_str(),
            "--expose",
            "--log",
            "warn",
            // exposed binds require an auth token; omit --auth-token to force startup failure
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "expected non-zero exit when exposed bind has no auth token"
    );
    let payload = parse_single_error_envelope(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str()),
        Some("startup_auth_required")
    );
    assert!(
        payload
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|m| m.as_str())
            .unwrap_or_default()
            .to_lowercase()
            .contains("auth token"),
        "expected message to mention auth token requirement; got: {payload}"
    );
    Ok(())
}

#[test]
fn startup_failure_emits_single_error_envelope_for_bind() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_arg = repo.path().to_string_lossy().to_string();
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping bind failure test: TCP bind not permitted in this environment");
            return Ok(());
        }
        Err(err) => return Err(format!("bind ephemeral port: {err}").into()),
    };
    let port = listener.local_addr()?.port();

    let output = Command::new(docdex_bin())
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
        .output()?;
    assert!(
        !output.status.success(),
        "expected non-zero exit when port is already in use"
    );
    let payload = parse_single_error_envelope(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str()),
        Some("startup_bind_failed")
    );
    drop(listener);
    Ok(())
}

#[test]
fn startup_failure_emits_single_error_envelope_for_config_parse() -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .args(["serve", "--this-flag-does-not-exist"])
        .output()?;
    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid flags"
    );
    let payload = parse_single_error_envelope(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str()),
        Some("startup_config_invalid")
    );
    Ok(())
}

#[test]
fn startup_failure_emits_single_error_envelope_for_rate_limit_config() -> Result<(), Box<dyn Error>>
{
    let repo = setup_repo()?;
    let repo_arg = repo.path().to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--rate-limit-burst",
            "10",
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid rate limit config"
    );
    let payload = parse_single_error_envelope(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str()),
        Some("startup_config_invalid")
    );
    let message = payload
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_lowercase();
    assert!(
        message.contains("rate limit"),
        "expected message to mention rate limit config; got: {payload}"
    );
    Ok(())
}

#[test]
fn startup_failure_emits_single_error_envelope_for_rate_limit_config() -> Result<(), Box<dyn Error>>
{
    let repo = setup_repo()?;
    let repo_arg = repo.path().to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--rate-limit-burst",
            "10",
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "expected non-zero exit for invalid rate limit config"
    );
    let payload = parse_single_error_envelope(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|c| c.as_str()),
        Some("startup_config_invalid")
    );
    let message = payload
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .unwrap_or("")
        .to_lowercase();
    assert!(
        message.contains("rate limit"),
        "expected message to mention rate limit config; got: {payload}"
    );
    Ok(())
}
