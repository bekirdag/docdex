use std::fs;

#[test]
fn rate_limit_contract_doc_defines_shapes_and_bounds() {
    let text = fs::read_to_string("docs/contracts/rate_limit_error_contract_v1.md")
        .expect("expected docs/contracts/rate_limit_error_contract_v1.md to exist");
    assert!(
        text.contains("Rate-Limit Error Contract (v1)"),
        "contract doc should define the rate-limit contract version"
    );
    assert!(
        text.contains("MCP JSON-RPC error.data"),
        "contract doc should describe MCP rate-limit data"
    );
    assert!(
        text.contains("HTTP rate limits return status `429`"),
        "contract doc should describe HTTP rate-limit behavior"
    );
    assert!(
        text.contains("retry_after_ms") && text.contains("limit_key") && text.contains("scope"),
        "contract doc should list required retry fields"
    );
    assert!(
        text.contains("max 2048 bytes") && text.contains("max 1024 bytes"),
        "contract doc should define payload bounds"
    );
}
