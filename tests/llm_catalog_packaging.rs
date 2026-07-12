use std::process::Command;

use tempfile::TempDir;

#[test]
fn llm_list_uses_embedded_catalog_from_an_empty_runtime_directory() {
    let runtime_dir = TempDir::new().expect("create empty runtime directory");
    let home_dir = runtime_dir.path().join("home");
    std::fs::create_dir(&home_dir).expect("create isolated home directory");
    assert!(!runtime_dir.path().join("docs/llm_list.json").exists());

    let output = Command::new(assert_cmd::cargo::cargo_bin!("docdexd"))
        .current_dir(runtime_dir.path())
        .env_clear()
        .env("HOME", &home_dir)
        .env("USERPROFILE", &home_dir)
        .arg("llm-list")
        .output()
        .expect("run packaged-style docdexd binary");

    assert!(
        output.status.success(),
        "llm-list failed without repository runtime files: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("llm-list output is UTF-8");
    assert!(stdout.contains("available models (hardware filtered):"));
    assert!(stdout.contains("Ultra-light (local-friendly)"));
}
