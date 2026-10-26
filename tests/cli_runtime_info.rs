use std::fs;
use std::process::Command;

#[test]
fn runtime_info_works_without_configuration_state_or_a_daemon() {
    let temp = tempfile::tempdir().expect("tempdir");
    let invalid_config = temp.path().join("invalid.toml");
    fs::write(&invalid_config, "not valid [[[ toml").expect("invalid config");
    let home = temp.path().join("absent-home");
    let output = Command::new(env!("CARGO_BIN_EXE_docdexd"))
        .arg("runtime-info")
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("DOCDEX_CONFIG_PATH", &invalid_config)
        .env("DOCDEX_HTTP_BASE_URL", "http://127.0.0.1:1")
        .current_dir(temp.path())
        .output()
        .expect("runtime-info");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    assert_eq!(info["schema_version"], 1);
    assert_eq!(info["version"], env!("CARGO_PKG_VERSION"));
    for feature in [
        "workspace_metadata_control",
        "embedding_input_type",
        "strict_repo_embeddings",
        "deterministic_profile_embeddings",
    ] {
        assert_eq!(info["managed_clients"][feature], true, "{feature}");
    }
    assert!(!home.exists(), "runtime probe must not create global state");
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}
