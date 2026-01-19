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

    agents_apply::run(false)?;

    let vscode_global = temp.path().join(".vscode").join("global_instructions.md");
    let vscode_instructions_dir = temp.path().join(".vscode").join("instructions");
    let vscode_instructions_file = vscode_instructions_dir.join("docdex.md");
    let codex_agents = temp.path().join(".codex").join("AGENTS.md");
    let settings_path = vscode_settings_path(temp.path(), &app_data);

    let global_text = fs::read_to_string(&vscode_global)?;
    assert!(global_text.contains("---- START OF DOCDEX INFO V"));
    assert!(global_text.contains("---- END OF DOCDEX INFO -----"));

    let codex_text = fs::read_to_string(&codex_agents)?;
    assert!(codex_text.contains("---- START OF DOCDEX INFO V"));
    assert!(codex_text.contains("---- END OF DOCDEX INFO -----"));

    let instructions_text = fs::read_to_string(&vscode_instructions_file)?;
    assert!(instructions_text.contains("---- START OF DOCDEX INFO V"));
    assert!(instructions_text.contains("---- END OF DOCDEX INFO -----"));

    let settings_text = fs::read_to_string(&settings_path)?;
    let settings_json: Value = serde_json::from_str(&settings_text)?;
    let instructions = settings_json
        .get("github.copilot.chat.codeGeneration.instructions")
        .and_then(|value| value.as_str())
        .expect("expected VS Code instructions setting");
    assert!(instructions.contains("---- START OF DOCDEX INFO V"));
    assert!(instructions.contains("---- END OF DOCDEX INFO -----"));
    let legacy_instructions = settings_json
        .get("copilot.chat.codeGeneration.instructions")
        .and_then(|value| value.as_str())
        .expect("expected legacy VS Code instructions setting");
    assert!(legacy_instructions.contains("---- START OF DOCDEX INFO V"));
    assert!(legacy_instructions.contains("---- END OF DOCDEX INFO -----"));
    assert_eq!(
        settings_json
            .get("github.copilot.chat.codeGeneration.useInstructionFiles")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    let instructions_locations = settings_json
        .get("chat.instructionsFilesLocations")
        .expect("expected VS Code instructions file locations");
    let expected_location = vscode_instructions_dir.to_string_lossy().to_string();
    let has_location = match instructions_locations {
        Value::Object(map) => map.get(&expected_location) == Some(&Value::Bool(true)),
        Value::Array(list) => list
            .iter()
            .any(|value| value.as_str() == Some(expected_location.as_str())),
        Value::String(value) => value == &expected_location,
        _ => false,
    };
    assert!(has_location);

    agents_apply::run(true)?;

    assert!(!vscode_global.exists());
    assert!(!vscode_instructions_file.exists());
    assert!(!codex_agents.exists());

    let settings_text = fs::read_to_string(&settings_path)?;
    let settings_json: Value = serde_json::from_str(&settings_text)?;
    assert!(settings_json
        .get("copilot.chat.codeGeneration.instructions")
        .is_none());
    assert!(settings_json
        .get("github.copilot.chat.codeGeneration.instructions")
        .is_none());
    if let Some(locations) = settings_json.get("chat.instructionsFilesLocations") {
        let expected_location = vscode_instructions_dir.to_string_lossy().to_string();
        let still_present = match locations {
            Value::Object(map) => map.get(&expected_location) == Some(&Value::Bool(true)),
            Value::Array(list) => list
                .iter()
                .any(|value| value.as_str() == Some(expected_location.as_str())),
            Value::String(value) => value == &expected_location,
            _ => false,
        };
        assert!(!still_present);
    }

    Ok(())
}
