use super::*;
use tempfile::TempDir;

fn sample_capture_request() -> PersonalPreferencesCaptureRequest {
    PersonalPreferencesCaptureRequest {
        source: "chat_completion".to_string(),
        source_session_id: Some("session-1".to_string()),
        capture_kind: Some("chat_completion".to_string()),
        title: Some("Docdex planning".to_string()),
        agent_id: Some("codex".to_string()),
        transport: Some("http".to_string()),
        repo_id: Some("repo-1".to_string()),
        repo_root: Some("/tmp/repo-one".to_string()),
        scope_id: Some("repo-1".to_string()),
        scope_label: Some("/tmp/repo-one".to_string()),
        started_at_ms: Some(10),
        ended_at_ms: Some(20),
        messages: vec![
            PersonalPreferencesMessage {
                role: "user".to_string(),
                content: "I prefer Rust, local-first tools, and comprehensive tests.".to_string(),
                created_at_ms: Some(10),
                metadata: Value::Null,
            },
            PersonalPreferencesMessage {
                role: "assistant".to_string(),
                content: "Noted.".to_string(),
                created_at_ms: Some(20),
                metadata: Value::Null,
            },
        ],
        transcript_text: None,
        summary_text: None,
        metadata: serde_json::json!({ "source": "test" }),
    }
}

#[path = "tests/capture.rs"]
mod capture;
#[path = "tests/clone.rs"]
mod clone;
#[path = "tests/digest.rs"]
mod digest;
#[path = "tests/generated_skills.rs"]
mod generated_skills;
#[path = "tests/governance.rs"]
mod governance;
#[path = "tests/migrations.rs"]
mod migrations;
#[path = "tests/operator_events.rs"]
mod operator_events;
#[path = "tests/routines.rs"]
mod routines;
