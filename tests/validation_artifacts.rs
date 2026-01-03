use std::path::Path;

#[test]
fn load_and_soak_scripts_exist() {
    assert!(Path::new("scripts/load_test_http.sh").exists());
    assert!(Path::new("scripts/load_test_mcp.sh").exists());
    assert!(Path::new("tests/soak_large_repo.rs").exists());
}

#[test]
fn bench_script_and_bench_exist() {
    assert!(Path::new("scripts/bench_indexing.sh").exists());
    assert!(Path::new("benches/indexing_bench.rs").exists());
}

#[test]
fn security_audit_assets_exist() {
    assert!(Path::new("scripts/security_audit.sh").exists());
    assert!(Path::new("docs/security/threat_model.md").exists());
}

#[test]
fn fuzz_targets_exist() {
    assert!(Path::new("fuzz/Cargo.toml").exists());
    assert!(Path::new("fuzz/fuzz_targets/libs_request.rs").exists());
    assert!(Path::new("fuzz/fuzz_targets/hook_validate_request.rs").exists());
    assert!(Path::new("fuzz/fuzz_targets/profile_sync_manifest.rs").exists());
    assert!(Path::new("fuzz/fuzz_targets/mcp_payload.rs").exists());
}
