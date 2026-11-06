use super::*;
use tempfile::TempDir;

#[test]
fn transcript_scan_caches_before_reading_and_preserves_cache_across_reopen() -> Result<()> {
    let temp = TempDir::new()?;
    let root = temp.path().join("codex/sessions");
    fs::create_dir_all(&root)?;
    let path = root.join("example.txt");
    fs::write(&path, "user: use local tools\nassistant: understood\n")?;
    let config = MemoryPersonalPreferencesConfig {
        capture_supported_client_transcripts: true,
        client_transcript_roots: vec![root.display().to_string()],
        archive_raw_conversations: false,
        digest_enabled: false,
        ..MemoryPersonalPreferencesConfig::default()
    };
    let store = PersonalPreferencesStore::new(temp.path())?;
    let first = store.scan_supported_client_transcripts(&config, Some(4))?;
    assert_eq!(first.captures_created, 1);
    assert!(first.bytes_read > 0);
    drop(store);
    let reopened = PersonalPreferencesStore::new(temp.path())?;
    let second = reopened.scan_supported_client_transcripts(&config, Some(4))?;
    assert_eq!(second.cached_files, 1);
    assert_eq!(second.bytes_read, 0);
    fs::write(&path, "user: use local tools and validate changes\n")?;
    assert!(
        reopened
            .scan_supported_client_transcripts(&config, Some(4))?
            .bytes_read
            > 0
    );
    Ok(())
}

#[test]
fn transcript_scan_defers_oversized_original_without_reading_or_removing_it() -> Result<()> {
    let temp = TempDir::new()?;
    let root = temp.path().join("codex/sessions");
    fs::create_dir_all(&root)?;
    let path = root.join("large.jsonl");
    fs::File::create(&path)?.set_len(MAX_AUTO_TRANSCRIPT_BYTES + 1)?;
    let config = MemoryPersonalPreferencesConfig {
        capture_supported_client_transcripts: true,
        client_transcript_roots: vec![root.display().to_string()],
        ..MemoryPersonalPreferencesConfig::default()
    };
    let store = PersonalPreferencesStore::new(temp.path())?;
    let scan = store.scan_supported_client_transcripts(&config, None)?;
    assert_eq!(scan.deferred_large_files, 1);
    assert_eq!(scan.bytes_read, 0);
    assert_eq!(scan.captures_created, 0);
    assert_eq!(fs::metadata(path)?.len(), MAX_AUTO_TRANSCRIPT_BYTES + 1);
    Ok(())
}

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
