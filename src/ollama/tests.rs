use super::{ollama_error_message, parse_authority, parse_http_response, redact_embedding_prompt};

#[test]
fn parse_authority_defaults_port_when_missing() -> Result<(), Box<dyn std::error::Error>> {
    let (host, connect) = parse_authority("localhost")?;
    assert_eq!(host, "localhost:80");
    assert_eq!(connect, "localhost:80");
    Ok(())
}

#[test]
fn parse_authority_ipv6_with_port() -> Result<(), Box<dyn std::error::Error>> {
    let (host, connect) = parse_authority("[::1]:11434")?;
    assert_eq!(host, "[::1]:11434");
    assert_eq!(connect, "[::1]:11434");
    Ok(())
}

#[test]
fn parse_http_response_decodes_chunked_body() -> Result<(), Box<dyn std::error::Error>> {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    let (status, body) = parse_http_response(raw)?;
    assert_eq!(status, 200);
    assert_eq!(body, b"hello");
    Ok(())
}

#[test]
fn parse_http_response_rejects_missing_headers() {
    let raw = b"HTTP/1.1 200 OK\n";
    let err = parse_http_response(raw).expect_err("expected missing header delimiter error");
    let message = err.to_string();
    assert!(message.contains("missing header delimiter"));
}

#[test]
fn ollama_error_message_prefers_error_field() {
    let body = br#"{"error": "model not found"}"#;
    let message = ollama_error_message(body).expect("expected message");
    assert_eq!(message, "model not found");
}

#[test]
fn redact_embedding_prompt_scrubs_prompt() {
    let message = "failure: prompt secret".to_string();
    let redacted = redact_embedding_prompt(message, "prompt secret");
    assert!(redacted.contains("<redacted>"));
}
