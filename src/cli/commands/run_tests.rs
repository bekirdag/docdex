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
    let args = apply_target(
        &repo_root,
        &config.command,
        config.args.clone(),
        target_arg.as_deref(),
    )?;

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

fn apply_target(
    repo_root: &Path,
    command: &str,
    mut args: Vec<String>,
    target: Option<&Path>,
) -> Result<Vec<String>> {
    let mut replaced = false;
    if let Some(target) = target {
        let target_value = target.to_string_lossy().replace('\\', "/");
        for arg in &mut args {
            if arg.contains("{target}") {
                *arg = arg.replace("{target}", &target_value);
                replaced = true;
            }
        }
        args.retain(|arg| !arg.trim().is_empty());
        if replaced {
            return Ok(args);
        }

        if target == Path::new(".") {
            return Ok(args);
        }

        if is_cargo_command(command) {
            if let Some(extra_args) = cargo_target_args(repo_root, target)? {
                insert_before_passthrough(&mut args, extra_args);
                return Ok(args);
            }
            return Err(unsupported_cargo_target_error(&target_value).into());
        }

        insert_before_passthrough(&mut args, [target_value]);
        return Ok(args);
    }

    for arg in &mut args {
        if arg.contains("{target}") {
            *arg = arg.replace("{target}", "");
        }
    }
    args.retain(|arg| !arg.trim().is_empty());
    Ok(args)
}

fn is_cargo_command(command: &str) -> bool {
    let program = Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(command);
    let program = program.strip_suffix(".exe").unwrap_or(program);
    program.eq_ignore_ascii_case("cargo")
}

fn cargo_target_args(repo_root: &Path, target: &Path) -> Result<Option<Vec<String>>> {
    let Some(root) = target.components().next() else {
        return Ok(None);
    };
    let Some(root) = root.as_os_str().to_str() else {
        return Ok(None);
    };
    match root {
        "tests" => cargo_named_target_args(repo_root, target, "test"),
        "benches" => cargo_named_target_args(repo_root, target, "bench"),
        _ => Ok(None),
    }
}

fn unsupported_cargo_target_error(target: &str) -> AppError {
    AppError::new(
        ERR_INVALID_ARGUMENT,
        "unsupported Cargo test target for run-tests",
    )
    .with_details(json!({
        "target": target,
        "recoverySteps": [
            "Use a top-level integration test file like tests/<name>.rs.",
            "Use a top-level tests/ or benches/ directory to run named targets.",
            "Or add a `{target}` placeholder in .docdex/run-tests.json if this repo needs custom target mapping."
        ]
    }))
}

fn cargo_named_target_args(
    repo_root: &Path,
    target: &Path,
    flag: &str,
) -> Result<Option<Vec<String>>> {
    if target.extension().and_then(|value| value.to_str()) == Some("rs") {
        if let Some(name) = target.file_stem().and_then(|value| value.to_str()) {
            return Ok(Some(vec![format!("--{flag}"), name.to_string()]));
        }
    }

    if target.components().count() != 1 {
        return Ok(None);
    }

    let names = collect_direct_rust_target_names(&repo_root.join(target))?;
    if names.is_empty() {
        return Ok(None);
    }

    let mut args = Vec::with_capacity(names.len() * 2);
    for name in names {
        args.push(format!("--{flag}"));
        args.push(name);
    }
    Ok(Some(args))
}

fn collect_direct_rust_target_names(dir: &Path) -> Result<Vec<String>> {
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)
        .with_context(|| format!("read target directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("rs") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        if name == "mod" {
            continue;
        }
        names.push(name.to_string());
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn insert_before_passthrough<I>(args: &mut Vec<String>, extras: I)
where
    I: IntoIterator<Item = String>,
{
    let index = args
        .iter()
        .position(|arg| arg == "--")
        .unwrap_or(args.len());
    args.splice(index..index, extras);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn apply_target_preserves_explicit_placeholder_configs() -> Result<()> {
        let args = apply_target(
            Path::new("."),
            "cargo",
            vec!["test".to_string(), "{target}".to_string()],
            Some(Path::new("tests/conversation_memory_http.rs")),
        )?;
        assert_eq!(args, vec!["test", "tests/conversation_memory_http.rs"]);
        Ok(())
    }

    #[test]
    fn apply_target_maps_cargo_integration_test_files() -> Result<()> {
        let args = apply_target(
            Path::new("."),
            "cargo",
            vec!["test".to_string()],
            Some(Path::new("tests/conversation_memory_http.rs")),
        )?;
        assert_eq!(args, vec!["test", "--test", "conversation_memory_http"]);
        Ok(())
    }

    #[test]
    fn apply_target_inserts_cargo_targets_before_passthrough_args() -> Result<()> {
        let args = apply_target(
            Path::new("."),
            "cargo",
            vec![
                "test".to_string(),
                "--".to_string(),
                "--nocapture".to_string(),
            ],
            Some(Path::new("tests/conversation_memory_http.rs")),
        )?;
        assert_eq!(
            args,
            vec![
                "test",
                "--test",
                "conversation_memory_http",
                "--",
                "--nocapture"
            ]
        );
        Ok(())
    }

    #[test]
    fn apply_target_maps_top_level_tests_directory_to_named_targets() -> Result<()> {
        let dir = tempdir()?;
        let tests_dir = dir.path().join("tests");
        std::fs::create_dir_all(tests_dir.join("common"))?;
        std::fs::write(tests_dir.join("alpha.rs"), "fn main() {}\n")?;
        std::fs::write(tests_dir.join("beta.rs"), "fn main() {}\n")?;
        std::fs::write(
            tests_dir.join("common").join("mod.rs"),
            "pub fn helper() {}\n",
        )?;

        let args = apply_target(
            dir.path(),
            "cargo",
            vec!["test".to_string()],
            Some(Path::new("tests")),
        )?;
        assert_eq!(args, vec!["test", "--test", "alpha", "--test", "beta"]);
        Ok(())
    }

    #[test]
    fn apply_target_rejects_unsupported_cargo_source_file_targets() {
        let err = apply_target(
            Path::new("."),
            "cargo",
            vec!["test".to_string()],
            Some(Path::new("src/cli/commands/run_tests.rs")),
        )
        .expect_err("src paths should not be forwarded as cargo filters");
        let message = format!("{err:#}");
        assert!(message.contains("unsupported Cargo test target"));
    }
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
