use super::*;
use chrono::Utc;
use std::collections::HashSet;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

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
