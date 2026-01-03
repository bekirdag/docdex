use crate::config::RepoArgs;
use crate::error::{
    repo_resolution_details, AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_REPO_PATH,
};
use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::env;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Instant;

const RUN_TESTS_CONFIG_PATH: &str = ".docdex/run-tests.json";
const MAX_CAPTURE_BYTES: usize = 200_000;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

#[derive(Debug)]
struct RunTestsConfig {
    command: String,
    args: Vec<String>,
    env: HashMap<String, String>,
}

#[derive(Serialize)]
struct RunTestsReport {
    status: &'static str,
    success: bool,
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
    duration_ms: u64,
    command: String,
    args: Vec<String>,
    cwd: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
}

#[derive(serde::Deserialize)]
struct RunTestsConfigFile {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
}

pub fn run(repo: RepoArgs, target: Option<PathBuf>) -> Result<()> {
    let repo_root = repo.repo_root();
    if !repo_root.exists() {
        let details = repo_resolution_details(
            repo_root.to_string_lossy().replace('\\', "/"),
            None,
            None,
            vec![
                "Verify the repo path exists on disk.".to_string(),
                "Pass the correct path with --repo.".to_string(),
            ],
        );
        return Err(AppError::new(ERR_MISSING_REPO_PATH, "repo path not found")
            .with_details(details)
            .into());
    }

    let config = load_run_tests_config(&repo_root)?;
    let target_arg = target
        .as_ref()
        .map(|path| resolve_target(&repo_root, path))
        .transpose()?;
    let target_value = target_arg
        .as_ref()
        .map(|path| path.to_string_lossy().replace('\\', "/"));
    let args = apply_target(config.args.clone(), target_value.as_deref());

    let mut cmd = Command::new(&config.command);
    cmd.args(&args);
    cmd.current_dir(&repo_root);
    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.envs(&config.env);
    cmd.env("DOCDEX_REPO_ROOT", repo_root.to_string_lossy().to_string());
    if let Some(target_value) = target_value.as_deref() {
        cmd.env("DOCDEX_TEST_TARGET", target_value);
    }

    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .with_context(|| format!("run test command `{}`", config.command))?;
    let stdout_reader = child.stdout.take().context("capture run-tests stdout")?;
    let stderr_reader = child.stderr.take().context("capture run-tests stderr")?;

    let stdout_handle = thread::spawn(move || read_limited(stdout_reader, MAX_CAPTURE_BYTES));
    let stderr_handle = thread::spawn(move || read_limited(stderr_reader, MAX_CAPTURE_BYTES));

    let status = child.wait().context("wait for run-tests command")?;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    let (stdout, stdout_truncated) = stdout_handle
        .join()
        .unwrap_or_else(|_| (String::new(), false));
    let (stderr, stderr_truncated) = stderr_handle
        .join()
        .unwrap_or_else(|_| (String::new(), false));

    let exit_code = status.code();
    #[cfg(unix)]
    let signal = status.signal();
    #[cfg(not(unix))]
    let signal = None;

    let success = status.success();
    let status = if success { "ok" } else { "failed" };
    let report = RunTestsReport {
        status,
        success,
        exit_code,
        signal,
        duration_ms,
        command: config.command,
        args,
        cwd: repo_root.to_string_lossy().replace('\\', "/"),
        target: target_value.map(|value| value.to_string()),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
    };

    let payload = serde_json::to_string(&report).context("serialize run-tests report")?;
    println!("{payload}");

    if success {
        return Ok(());
    }

    if let Some(code) = exit_code {
        std::process::exit(code);
    }
    #[cfg(unix)]
    if let Some(sig) = signal {
        std::process::exit(128 + sig);
    }
    std::process::exit(1);
}

fn load_run_tests_config(repo_root: &Path) -> Result<RunTestsConfig> {
    if let Ok(command) = env::var("DOCDEX_RUN_TESTS_CMD") {
        let command = command.trim().to_string();
        if !command.is_empty() {
            let args = env::var("DOCDEX_RUN_TESTS_ARGS")
                .ok()
                .map(|value| parse_args_env(value.trim()))
                .unwrap_or_default();
            return Ok(RunTestsConfig {
                command,
                args,
                env: HashMap::new(),
            });
        }
    }

    let config_path = repo_root.join(RUN_TESTS_CONFIG_PATH);
    if config_path.exists() {
        let raw = std::fs::read_to_string(&config_path).with_context(|| {
            format!("read run-tests config at {}", config_path.to_string_lossy())
        })?;
        let parsed: RunTestsConfigFile = serde_json::from_str(&raw).with_context(|| {
            format!(
                "parse run-tests config at {}",
                config_path.to_string_lossy()
            )
        })?;
        let command = parsed.command.trim().to_string();
        if command.is_empty() {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "run-tests config missing command")
                    .with_details(json!({ "config_path": config_path }))
                    .into(),
            );
        }
        return Ok(RunTestsConfig {
            command,
            args: parsed.args,
            env: parsed.env,
        });
    }

    Err(AppError::new(
        ERR_INVALID_ARGUMENT,
        "run-tests is not configured for this repo",
    )
    .with_details(json!({
        "recoverySteps": [
            format!("Set DOCDEX_RUN_TESTS_CMD and (optionally) DOCDEX_RUN_TESTS_ARGS for {}", repo_root.to_string_lossy()),
            format!("Or create {} with {{\"command\": \"...\", \"args\": [\"...\"] }}", config_path.to_string_lossy())
        ]
    }))
    .into())
}

fn parse_args_env(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() {
        return Vec::new();
    }
    if raw.trim_start().starts_with('[') {
        if let Ok(args) = serde_json::from_str::<Vec<String>>(raw) {
            return args;
        }
    }
    raw.split_whitespace()
        .map(|part| part.to_string())
        .collect()
}

fn resolve_target(repo_root: &Path, target: &Path) -> Result<PathBuf> {
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        repo_root.join(target)
    };
    let canonical_repo = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let canonical_target = resolved
        .canonicalize()
        .with_context(|| format!("resolve target {}", resolved.display()))?;
    if !canonical_target.starts_with(&canonical_repo) {
        return Err(
            AppError::new(ERR_INVALID_ARGUMENT, "target must be within repo")
                .with_details(json!({
                    "repo_root": canonical_repo.to_string_lossy(),
                    "target": canonical_target.to_string_lossy()
                }))
                .into(),
        );
    }
    let rel = canonical_target
        .strip_prefix(&canonical_repo)
        .unwrap_or(canonical_target.as_path());
    if rel.as_os_str().is_empty() {
        return Ok(PathBuf::from("."));
    }
    Ok(rel.to_path_buf())
}

fn apply_target(mut args: Vec<String>, target: Option<&str>) -> Vec<String> {
    let mut replaced = false;
    if let Some(target) = target {
        for arg in &mut args {
            if arg.contains("{target}") {
                *arg = arg.replace("{target}", target);
                replaced = true;
            }
        }
        args.retain(|arg| !arg.trim().is_empty());
        if !replaced {
            args.push(target.to_string());
        }
    } else {
        for arg in &mut args {
            if arg.contains("{target}") {
                *arg = arg.replace("{target}", "");
            }
        }
        args.retain(|arg| !arg.trim().is_empty());
    }
    args
}

fn read_limited<R: Read>(mut reader: R, max_bytes: usize) -> (String, bool) {
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < max_bytes {
                    let remaining = max_bytes - buf.len();
                    let take = remaining.min(n);
                    buf.extend_from_slice(&chunk[..take]);
                    if take < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    let mut out = String::from_utf8_lossy(&buf).to_string();
    if truncated {
        out.push_str("...");
    }
    (out, truncated)
}
