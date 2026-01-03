use std::fs;

fn read_text(path: &str, message: &str) -> String {
    fs::read_to_string(path)
        .expect(message)
        .replace("\r\n", "\n")
}

#[test]
fn contract_docs_exist_and_define_edge_direction() {
    let text = read_text(
        "docs/contracts/code_intelligence_schema_v1.md",
        "expected docs/contracts/code_intelligence_schema_v1.md to exist",
    );
    assert!(
        text.contains("\"name\": \"docdex.impact_graph\""),
        "contract doc should define the impact graph schema name"
    );
    assert!(
        text.contains("`outcome`") && text.contains("ok") && text.contains("skipped"),
        "contract doc should describe per-file symbols outcomes"
    );
    assert!(
        text.contains("Edge direction semantics"),
        "contract doc should define edge direction semantics"
    );
    assert!(
        text.contains("importer / depender") && text.contains("imported / dependee"),
        "contract doc should describe source/target meaning"
    );
}

#[test]
fn openapi_impact_graph_requires_schema_and_exposes_edges() {
    let text = read_text("openapi/mcoda.yaml", "expected openapi/mcoda.yaml");
    assert!(
        text.contains("DocdexSchemaInfo"),
        "OpenAPI should define DocdexSchemaInfo for schema compatibility signaling"
    );
    assert!(
        text.contains("ImpactGraphEdge"),
        "OpenAPI should define ImpactGraphEdge for directed edges"
    );
    assert!(
        text.contains("required:\n+                  - schema")
            || text.contains("required:\n                  - schema"),
        "OpenAPI ImpactGraphResponse should require a top-level schema field"
    );
    assert!(
        text.contains("Edge direction semantics:"),
        "OpenAPI should document edge direction semantics"
    );
}

#[test]
fn contract_docs_define_impact_diagnostics() {
    let text = read_text(
        "docs/contracts/code_intelligence_schema_v1.md",
        "expected docs/contracts/code_intelligence_schema_v1.md to exist",
    );
    assert!(
        text.contains("\"name\": \"docdex.impact_diagnostics\""),
        "contract doc should define the impact diagnostics schema name"
    );
    assert!(
        text.contains("Impact diagnostics response"),
        "contract doc should describe impact diagnostics response fields"
    );
}

#[test]
fn openapi_includes_impact_diagnostics_endpoint() {
    let text = read_text("openapi/mcoda.yaml", "expected openapi/mcoda.yaml");
    assert!(
        text.contains("/v1/graph/impact/diagnostics"),
        "OpenAPI should define the impact diagnostics endpoint"
    );
    assert!(
        text.contains("ImpactDiagnosticsResponse"),
        "OpenAPI should define ImpactDiagnosticsResponse schema"
    );
}
