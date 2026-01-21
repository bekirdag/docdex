#[path = "../src/cli/commands/agents_apply.rs"]
mod agents_apply;

use anyhow::Result;
use once_cell::sync::Lazy;
use serde_json::Value;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    home: Option<OsString>,
    userprofile: Option<OsString>,
    appdata: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn new(temp: &Path) -> Self {
        let lock = ENV_LOCK.lock().expect("env lock");
        let home = std::env::var_os("HOME");
        let userprofile = std::env::var_os("USERPROFILE");
        let appdata = std::env::var_os("APPDATA");
        let app_data_dir = temp.join("AppData").join("Roaming");
        std::env::set_var("HOME", temp);
        std::env::set_var("USERPROFILE", temp);
        std::env::set_var("APPDATA", &app_data_dir);
        Self {
            home,
            userprofile,
            appdata,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        restore_env("HOME", self.home.take());
        restore_env("USERPROFILE", self.userprofile.take());
        restore_env("APPDATA", self.appdata.take());
    }
}

fn restore_env(key: &str, value: Option<OsString>) {
    if let Some(value) = value {
        std::env::set_var(key, value);
    } else {
        std::env::remove_var(key);
    }
}

fn vscode_settings_path(home: &Path, app_data: &Path) -> PathBuf {
    if cfg!(windows) {
        return app_data.join("Code").join("User").join("settings.json");
    }
    if cfg!(target_os = "macos") {
        return home
            .join("Library")
            .join("Application Support")
            .join("Code")
            .join("User")
            .join("settings.json");
    }
    home.join(".config")
        .join("Code")
        .join("User")
        .join("settings.json")
}

#[test]
fn agents_apply_round_trip() -> Result<()> {
    let temp = TempDir::new()?;
    let app_data = temp.path().join("AppData").join("Roaming");
    let _env = EnvGuard::new(temp.path());
    let cursor_legacy = temp.path().join(".cursor").join("agents.md");
    let cursor_legacy_upper = temp.path().join(".cursor").join("AGENTS.md");
    let legacy_block =
        "---- START OF DOCDEX INFO V0.0.1 ----\nLEGACY DOCDEX\n---- END OF DOCDEX INFO -----\n";
    fs::create_dir_all(cursor_legacy.parent().expect("cursor dir"))?;
    fs::write(&cursor_legacy, legacy_block)?;
    fs::write(&cursor_legacy_upper, legacy_block)?;

    agents_apply::run(false)?;

    let vscode_global = temp.path().join(".vscode").join("global_instructions.md");
    let vscode_instructions_file = temp
        .path()
        .join(".vscode")
        .join("instructions")
        .join("docdex.md");
    let codex_agents = temp.path().join(".codex").join("AGENTS.md");
    let claude_instructions = temp.path().join(".claude").join("CLAUDE.md");
    let gemini_instructions = temp.path().join(".gemini").join("GEMINI.md");
    let settings_path = vscode_settings_path(temp.path(), &app_data);

    assert!(!vscode_global.exists());
    assert!(!vscode_instructions_file.exists());
    assert!(!cursor_legacy.exists());
    assert!(!cursor_legacy_upper.exists());

    let codex_text = fs::read_to_string(&codex_agents)?;
    assert!(codex_text.contains("---- START OF DOCDEX INFO V"));
    assert!(codex_text.contains("---- END OF DOCDEX INFO -----"));

    let claude_text = fs::read_to_string(&claude_instructions)?;
    assert!(claude_text.contains("---- START OF DOCDEX INFO V"));
    assert!(claude_text.contains("---- END OF DOCDEX INFO -----"));

    let gemini_text = fs::read_to_string(&gemini_instructions)?;
    assert!(gemini_text.contains("---- START OF DOCDEX INFO V"));
    assert!(gemini_text.contains("---- END OF DOCDEX INFO -----"));

    let settings_text = fs::read_to_string(&settings_path)?;
    let settings_json: Value = serde_json::from_str(&settings_text)?;
    let instructions = settings_json
        .get("chat.instructions")
        .and_then(|value| value.as_str())
        .expect("expected VS Code instructions setting");
    assert!(instructions.contains("---- START OF DOCDEX INFO V"));
    assert!(instructions.contains("---- END OF DOCDEX INFO -----"));
    assert!(settings_json
        .get("github.copilot.chat.codeGeneration.instructions")
        .is_none());
    assert!(settings_json
        .get("copilot.chat.codeGeneration.instructions")
        .is_none());
    assert!(settings_json
        .get("chat.instructionsFilesLocations")
        .is_none());

    agents_apply::run(true)?;

    assert!(!vscode_global.exists());
    assert!(!vscode_instructions_file.exists());
    assert!(!codex_agents.exists());
    assert!(!claude_instructions.exists());
    assert!(!gemini_instructions.exists());
    assert!(!cursor_legacy.exists());
    assert!(!cursor_legacy_upper.exists());

    let settings_text = fs::read_to_string(&settings_path)?;
    let settings_json: Value = serde_json::from_str(&settings_text)?;
    assert!(settings_json.get("chat.instructions").is_none());
    assert!(settings_json
        .get("copilot.chat.codeGeneration.instructions")
        .is_none());
    assert!(settings_json
        .get("github.copilot.chat.codeGeneration.instructions")
        .is_none());
    assert!(settings_json
        .get("chat.instructionsFilesLocations")
        .is_none());

    Ok(())
}
