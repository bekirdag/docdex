use std::fs;

#[test]
fn contract_docs_exist_and_define_edge_direction() {
    let text = fs::read_to_string("docs/contracts/code_intelligence_schema_v1.md")
        .expect("expected docs/contracts/code_intelligence_schema_v1.md to exist");
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
    let text = fs::read_to_string("openapi/mcoda.yaml").expect("expected openapi/mcoda.yaml");
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
