use docdexd::api::v1::chat::resolve_profile_agent_id;

#[test]
fn header_overrides_body_agent_id() {
    let resolved = resolve_profile_agent_id(Some(" header-id "), Some("body-id"));
    assert_eq!(resolved.as_deref(), Some("header-id"));
}

#[test]
fn body_agent_id_used_when_header_empty() {
    let resolved = resolve_profile_agent_id(Some("   "), Some("body-id"));
    assert_eq!(resolved.as_deref(), Some("body-id"));
}

#[test]
fn missing_agent_id_returns_none() {
    let resolved = resolve_profile_agent_id(None, Some("  "));
    assert!(resolved.is_none());
}
