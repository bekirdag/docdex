use std::process::Command;

mod common;

#[test]
fn setup_help_is_provider_neutral() {
    let output = Command::new(common::docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .arg("setup")
        .arg("--help")
        .output()
        .expect("run docdex setup --help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("local LLM services"));
    assert!(stdout.contains("optional fallbacks"));
    assert!(!stdout.contains("wizard for Ollama and models"));
}

#[test]
fn setup_non_interactive_prints_hint() {
    let output = Command::new(common::docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .arg("setup")
        .arg("--non-interactive")
        .output()
        .expect("run docdex setup");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("docdex setup"));
    assert!(stdout.contains("local LLM service"));
    assert!(stdout.contains("optional Ollama fallback"));
}
