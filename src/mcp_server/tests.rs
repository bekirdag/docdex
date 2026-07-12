use super::*;
use chrono::Utc;
use parking_lot::ReentrantMutexGuard;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

use crate::setup::test_support::ENV_LOCK;

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
    _lock: ReentrantMutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let lock = ENV_LOCK.lock();
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.as_ref() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn rate_limited_rpc_has_stable_data_shape() {
    let err = RateLimited::new(
        Duration::from_millis(0),
        "mcp_tools".to_string(),
        "global".to_string(),
    );
    let rpc = rpc_rate_limited(&err);
    assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
    let data = rpc.data.expect("rate limited rpc should include data");
    let obj = data
        .as_object()
        .expect("rate limited data should be object");
    assert_eq!(
        obj.get("code").and_then(|v| v.as_str()),
        Some(ERR_RATE_LIMITED)
    );
    assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(0));
    assert_eq!(
        obj.get("limit_key").and_then(|v| v.as_str()),
        Some("mcp_tools")
    );
    assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));
    assert!(
        obj.get("retry_at").is_none(),
        "retry_at should be omitted when unset"
    );
}

#[test]
fn rate_limited_rpc_truncates_long_message_and_allows_retry_at() {
    let err = RateLimited::new(
        Duration::from_millis(1234),
        "bucket".to_string(),
        "global".to_string(),
    )
    .with_message("x".repeat(10_000))
    .with_retry_at(Utc::now());
    let rpc = rpc_rate_limited(&err);
    assert!(
        rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
        "rpc error message should be bounded"
    );
    let data = rpc.data.expect("rate limited rpc should include data");
    let obj = data
        .as_object()
        .expect("rate limited data should be object");
    assert!(obj.get("retry_at").and_then(|v| v.as_str()).is_some());
    assert_eq!(
        obj.get("retry_after_ms").and_then(|v| v.as_u64()),
        Some(1234)
    );
}

#[test]
fn rate_limited_rpc_schema_is_stable_under_concurrency() {
    let limiter = RateLimiter::<()>::new(6, 1);
    let threads = 48usize;
    let barrier = Arc::new(Barrier::new(threads));

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let limiter = limiter.clone();
        let barrier = barrier.clone();
        handles.push(thread::spawn(move || {
            barrier.wait();
            limiter.check_or_rate_limited((), "mcp_tools", "global")
        }));
    }

    let mut rate_limited_count = 0usize;
    let mut schema_variants: HashSet<Vec<String>> = HashSet::new();
    for handle in handles {
        match handle.join().expect("thread panicked") {
            Ok(()) => {}
            Err(err) => {
                rate_limited_count += 1;
                let rpc = rpc_rate_limited(&err);
                assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
                assert!(
                    rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
                    "rpc error message should remain bounded"
                );
                let data = rpc
                    .data
                    .as_ref()
                    .expect("rate limited rpc should include data");
                let obj = data
                    .as_object()
                    .expect("rate limited data should be object");
                let mut keys: Vec<String> = obj.keys().cloned().collect();
                keys.sort();
                schema_variants.insert(keys);

                assert_eq!(
                    obj.get("code").and_then(|v| v.as_str()),
                    Some(ERR_RATE_LIMITED)
                );
                assert!(
                    obj.get("retry_after_ms").and_then(|v| v.as_u64()).is_some(),
                    "retry_after_ms must be an integer"
                );
                assert_eq!(
                    obj.get("limit_key").and_then(|v| v.as_str()),
                    Some("mcp_tools")
                );
                assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));

                let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
                assert!(
                    payload_bytes.len() <= 2048,
                    "rpc rate-limit payload should remain small (got {} bytes)",
                    payload_bytes.len()
                );
            }
        }
    }

    assert!(
            rate_limited_count >= threads / 2,
            "expected most concurrent calls to be rate limited (got {rate_limited_count} out of {threads})"
        );
    assert_eq!(
        schema_variants.len(),
        1,
        "rate-limit data schema should not vary under concurrency"
    );
}

#[test]
fn open_range_clamps_end_when_enabled() {
    let (start, end) =
        resolve_open_range(10, Some(1), Some(25), None, true).expect("clamped range");
    assert_eq!(start, 1);
    assert_eq!(end, 10);
}

#[test]
fn open_range_head_clamps_to_file() {
    let (start, end) = resolve_open_range(5, None, None, Some(20), false).expect("head range");
    assert_eq!(start, 1);
    assert_eq!(end, 5);
}

#[test]
fn open_range_errors_without_clamp() {
    let err =
        resolve_open_range(5, Some(1), Some(10), None, false).expect_err("expected invalid range");
    assert_eq!(err.start_line, 1);
    assert_eq!(err.end_line, 10);
    assert_eq!(err.total_lines, 5);
}

#[test]
fn initialize_params_accept_agent_model_aliases() {
    let params: InitializeParams = serde_json::from_value(serde_json::json!({
        "agentId": "codex",
        "agentModel": "gpt-5.2-codex"
    }))
    .expect("initialize params should parse");
    assert_eq!(params.agent_id.as_deref(), Some("codex"));
    assert_eq!(params.agent_model.as_deref(), Some("gpt-5.2-codex"));

    let snake_case: InitializeParams = serde_json::from_value(serde_json::json!({
        "agent_id": "codex",
        "agent_model": "gpt-5.2-codex"
    }))
    .expect("snake_case initialize params should parse");
    assert_eq!(snake_case.agent_model.as_deref(), Some("gpt-5.2-codex"));
}

#[tokio::test]
async fn same_repo_sessions_isolate_auth_and_agent_context(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let repo_root = temp.path().join("repo");
    let state_root = temp.path().join("state");
    fs::create_dir_all(&repo_root)?;
    fs::create_dir_all(&state_root)?;
    fs::write(repo_root.join("README.md"), "# test\n")?;
    let config_path = temp.path().join("config.toml");
    let escaped_state_root = state_root.to_string_lossy().replace('\\', "\\\\");
    fs::write(
        &config_path,
        format!("[core]\nglobal_state_dir = \"{escaped_state_root}\"\n[memory]\nenabled = false\n"),
    )?;

    let index_config = IndexConfig::with_overrides(
        &repo_root,
        Some(state_root.join("repo-state")),
        Vec::new(),
        Vec::new(),
        true,
    )?;
    let config_guard = EnvGuard::set("DOCDEX_CONFIG_PATH", &config_path);
    let service = McpService::new(
        repo_root,
        index_config,
        8,
        0,
        0,
        McpRuntimeOptions {
            memory_enabled: false,
            embedding_base_url: None,
            embedding_model: None,
            embedding_timeout_ms: Some(5_000),
            docdex_http_base_url: None,
            global_state_dir: None,
            personal_preferences_config: Some(crate::config::MemoryPersonalPreferencesConfig {
                enabled: false,
                ..Default::default()
            }),
        },
        Some("secret-token".to_string()),
        Arc::new(DelegationMetrics::default()),
    )?;
    drop(config_guard);

    let valid_init = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "auth_token": "secret-token",
            "agent_id": "agent-a",
            "agent_model": "model-a"
        }
    });
    let valid_response = service
        .handle_json_for_session("session-a", valid_init)
        .await?
        .expect("initialize response");
    assert!(valid_response.get("result").is_some());

    let invalid_init = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": { "auth_token": "wrong-token", "agent_id": "agent-b" }
    });
    let invalid_response = service
        .handle_json_for_session("session-b", invalid_init)
        .await?
        .expect("unauthorized initialize response");
    assert_eq!(
        invalid_response
            .pointer("/error/data/code")
            .and_then(Value::as_str),
        Some(ERR_UNAUTHORIZED)
    );

    let tools_list = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/list",
        "params": {}
    });
    let session_b_tools = service
        .handle_json_for_session("session-b", tools_list.clone())
        .await?
        .expect("session-b tools response");
    assert_eq!(
        session_b_tools
            .pointer("/error/data/code")
            .and_then(Value::as_str),
        Some(ERR_UNAUTHORIZED)
    );
    let session_a_tools = service
        .handle_json_for_session("session-a", tools_list)
        .await?
        .expect("session-a tools response");
    assert!(session_a_tools.pointer("/result/tools").is_some());

    let other_repo = temp.path().join("other-repo");
    fs::create_dir_all(&other_repo)?;
    let wrong_repo_response = service
        .handle_json_for_session(
            "session-c",
            json!({
                "jsonrpc": "2.0",
                "id": 30,
                "method": "initialize",
                "params": {
                    "auth_token": "secret-token",
                    "project_root": other_repo
                }
            }),
        )
        .await?
        .expect("wrong-repo initialize response");
    assert_eq!(
        wrong_repo_response
            .pointer("/error/data/code")
            .and_then(Value::as_str),
        Some(ERR_UNKNOWN_REPO)
    );
    let session_c_tools = service
        .handle_json_for_session(
            "session-c",
            json!({
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/list",
                "params": {}
            }),
        )
        .await?
        .expect("session-c tools response");
    assert_eq!(
        session_c_tools
            .pointer("/error/data/code")
            .and_then(Value::as_str),
        Some(ERR_UNAUTHORIZED),
        "a failed initialize must not partially authorize the session"
    );

    let (session_a, session_b) = {
        let sessions = service.sessions.read().await;
        (
            sessions.get("session-a").cloned().expect("session-a state"),
            sessions.get("session-b").cloned().expect("session-b state"),
        )
    };
    let session_a = session_a.lock().await;
    let session_b = session_b.lock().await;
    assert!(session_a.authorized);
    assert!(!session_b.authorized);
    assert_eq!(session_a.default_agent_id.as_deref(), Some("agent-a"));
    assert_eq!(session_a.default_agent_model.as_deref(), Some("model-a"));
    assert_eq!(session_b.default_agent_id, None);
    drop(session_a);
    drop(session_b);

    let held_session = service.server_for_session("session-a").await;
    let _held_session_guard = held_session.lock().await;
    let session_b_response = tokio::time::timeout(
        Duration::from_secs(1),
        service.handle_json_for_session(
            "session-b",
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/list",
                "params": {}
            }),
        ),
    )
    .await
    .expect("one busy MCP session must not block another")?
    .expect("session-b response");
    assert_eq!(
        session_b_response
            .pointer("/error/data/code")
            .and_then(Value::as_str),
        Some(ERR_UNAUTHORIZED)
    );
    Ok(())
}
