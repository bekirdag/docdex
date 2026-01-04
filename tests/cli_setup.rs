use std::process::Command;

mod common;

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
}
