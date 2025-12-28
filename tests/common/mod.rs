use std::path::PathBuf;
use std::process::Command;
use std::sync::Once;

static BUILD_MCP_SERVER: Once = Once::new();

pub fn mcp_server_bin() -> PathBuf {
    if let Ok(path) = std::env::var("DOCDEX_MCP_SERVER_BIN") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_docdex-mcp-server") {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("target"));
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let exe_name = format!("docdex-mcp-server{}", std::env::consts::EXE_SUFFIX);
    let candidate = target_dir.join(&profile).join(&exe_name);
    if candidate.exists() {
        return candidate;
    }
    BUILD_MCP_SERVER.call_once(|| {
        let status = Command::new("cargo")
            .args(["build", "-p", "docdex-mcp-server"])
            .status()
            .expect("failed to run cargo build -p docdex-mcp-server");
        assert!(
            status.success(),
            "cargo build -p docdex-mcp-server failed"
        );
    });
    if candidate.exists() {
        return candidate;
    }
    panic!(
        "docdex-mcp-server binary not found at {}",
        candidate.display()
    );
}
