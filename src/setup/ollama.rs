use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use which::which;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Mac,
    Linux,
    Windows,
    Other,
}

impl Platform {
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::Mac
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Other
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tooling {
    pub has_brew: bool,
    pub has_curl: bool,
    pub has_wget: bool,
    pub has_winget: bool,
}

impl Tooling {
    pub fn detect() -> Self {
        Self {
            has_brew: which("brew").is_ok(),
            has_curl: which("curl").is_ok(),
            has_wget: which("wget").is_ok(),
            has_winget: which("winget").is_ok(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallCommand {
    pub program: String,
    pub args: Vec<String>,
}

pub fn resolve_ollama_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    if let Some(path) = explicit {
        if path.is_file() {
            return Some(path);
        }
    }
    which("ollama").ok()
}

pub fn list_models(bin: &Path) -> Result<Vec<String>> {
    match list_models_once(bin) {
        Ok(models) => Ok(models),
        Err(err) => {
            if is_connect_error(&err) && start_server(bin).is_ok() {
                if let Ok(models) = wait_for_models(bin) {
                    return Ok(models);
                }
            }
            Err(err)
        }
    }
}

pub fn pull_model(bin: &Path, model: &str) -> Result<()> {
    match pull_model_once(bin, model) {
        Ok(()) => Ok(()),
        Err(err) => {
            if is_connect_error(&err) && start_server(bin).is_ok() {
                if wait_for_ready(bin) {
                    return pull_model_once(bin, model);
                }
            }
            Err(err)
        }
    }
}

fn list_models_once(bin: &Path) -> Result<Vec<String>> {
    let output = Command::new(bin).arg("list").output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "ollama list failed: {}",
            normalize_command_error(&output)
        ));
    }
    Ok(parse_models(&output.stdout))
}

fn pull_model_once(bin: &Path, model: &str) -> Result<()> {
    let output = Command::new(bin)
        .arg("pull")
        .arg(model)
        .output()
        .with_context(|| format!("run ollama pull {model}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "ollama pull {model} failed (stdout: {}, stderr: {})",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn parse_models(stdout: &[u8]) -> Vec<String> {
    let stdout = String::from_utf8_lossy(stdout);
    let mut models = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("NAME") {
            continue;
        }
        if let Some(name) = trimmed.split_whitespace().next() {
            models.push(name.to_string());
        }
    }
    models
}

fn normalize_command_error(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stderr.is_empty() {
        stdout
    } else if stdout.is_empty() {
        stderr
    } else {
        format!("{stderr} {stdout}")
    }
}

fn is_connect_error(err: &anyhow::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    text.contains("could not connect")
        || text.contains("connection refused")
        || text.contains("connection error")
        || text.contains("connect to")
}

fn start_server(bin: &Path) -> Result<()> {
    let mut cmd = Command::new(bin);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const DETACHED_PROCESS: u32 = 0x00000008;
        cmd.creation_flags(DETACHED_PROCESS);
    }
    cmd.spawn().context("spawn ollama serve")?;
    Ok(())
}

fn wait_for_ready(bin: &Path) -> bool {
    for _ in 0..15 {
        if list_models_once(bin).is_ok() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    false
}

fn wait_for_models(bin: &Path) -> Result<Vec<String>> {
    for _ in 0..15 {
        if let Ok(models) = list_models_once(bin) {
            return Ok(models);
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
    }
    Err(anyhow!("ollama server did not become ready in time"))
}

pub fn install_ollama() -> Result<()> {
    let plan = install_plan(Platform::current(), Tooling::detect())?;
    let status = Command::new(&plan.program).args(&plan.args).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!("ollama install command failed: {}", plan.program))
    }
}

pub fn install_plan(platform: Platform, tooling: Tooling) -> Result<InstallCommand> {
    match platform {
        Platform::Mac => {
            if !tooling.has_brew {
                return Err(anyhow!(
                    "Homebrew not found; install Ollama from https://ollama.com/download"
                ));
            }
            Ok(InstallCommand {
                program: "brew".to_string(),
                args: vec!["install".to_string(), "ollama".to_string()],
            })
        }
        Platform::Linux => {
            if tooling.has_curl {
                return Ok(InstallCommand {
                    program: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "curl -fsSL https://ollama.com/install.sh | sh".to_string(),
                    ],
                });
            }
            if tooling.has_wget {
                return Ok(InstallCommand {
                    program: "sh".to_string(),
                    args: vec![
                        "-c".to_string(),
                        "wget -qO- https://ollama.com/install.sh | sh".to_string(),
                    ],
                });
            }
            Err(anyhow!(
                "curl or wget missing; install Ollama from https://ollama.com/download"
            ))
        }
        Platform::Windows => {
            if !tooling.has_winget {
                return Err(anyhow!(
                    "winget not found; install Ollama from https://ollama.com/download"
                ));
            }
            Ok(InstallCommand {
                program: "winget".to_string(),
                args: vec![
                    "install".to_string(),
                    "-e".to_string(),
                    "--id".to_string(),
                    "Ollama.Ollama".to_string(),
                    "--accept-package-agreements".to_string(),
                    "--accept-source-agreements".to_string(),
                ],
            })
        }
        Platform::Other => Err(anyhow!(
            "unsupported platform; install Ollama from https://ollama.com/download"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_plan_mac_uses_brew() {
        let plan = install_plan(
            Platform::Mac,
            Tooling {
                has_brew: true,
                has_curl: false,
                has_wget: false,
                has_winget: false,
            },
        )
        .unwrap();
        assert_eq!(plan.program, "brew");
        assert_eq!(plan.args, vec!["install", "ollama"]);
    }

    #[test]
    fn install_plan_linux_prefers_curl() {
        let plan = install_plan(
            Platform::Linux,
            Tooling {
                has_brew: false,
                has_curl: true,
                has_wget: true,
                has_winget: false,
            },
        )
        .unwrap();
        assert_eq!(plan.program, "sh");
        assert_eq!(plan.args[0], "-c");
        assert!(plan.args[1].contains("curl"));
    }

    #[test]
    fn install_plan_linux_falls_back_to_wget() {
        let plan = install_plan(
            Platform::Linux,
            Tooling {
                has_brew: false,
                has_curl: false,
                has_wget: true,
                has_winget: false,
            },
        )
        .unwrap();
        assert!(plan.args[1].contains("wget"));
    }

    #[test]
    fn install_plan_windows_uses_winget() {
        let plan = install_plan(
            Platform::Windows,
            Tooling {
                has_brew: false,
                has_curl: false,
                has_wget: false,
                has_winget: true,
            },
        )
        .unwrap();
        assert_eq!(plan.program, "winget");
    }

    #[test]
    fn install_plan_errors_when_missing_tools() {
        let err = install_plan(
            Platform::Linux,
            Tooling {
                has_brew: false,
                has_curl: false,
                has_wget: false,
                has_winget: false,
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("curl or wget missing"));
    }

    #[test]
    fn connect_error_detection_matches_common_messages() {
        let err = anyhow!("could not connect to a running Ollama instance");
        assert!(is_connect_error(&err));
        let err = anyhow!("Connection refused");
        assert!(is_connect_error(&err));
    }

    #[test]
    fn parse_models_filters_header_and_empty_lines() {
        let input = b"NAME\tSIZE\nnomic-embed-text\t123MB\n\nphi3.5:3.8b\t2GB\n";
        let parsed = parse_models(input);
        assert_eq!(parsed, vec!["nomic-embed-text", "phi3.5:3.8b"]);
    }
}
