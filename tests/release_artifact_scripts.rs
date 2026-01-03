use std::fs;

#[test]
fn release_artifact_scripts_exist() {
    for path in [
        "scripts/test_release_artifacts.sh",
        "scripts/test_npm_install_matrix.sh",
    ] {
        let contents = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("{path} must exist for release validation"));
        assert!(contents.contains("set -euo pipefail"));
    }
}
