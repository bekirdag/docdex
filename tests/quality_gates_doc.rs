use std::fs;

#[test]
fn quality_gates_doc_has_required_sections() {
    let contents = fs::read_to_string("docs/quality_gates.md")
        .expect("docs/quality_gates.md must exist for release gates");
    assert!(contents.contains("Release Targets (Global)"));
    assert!(contents.contains("Phase Gate Criteria"));
    assert!(contents.contains("v2.1-Specific Gates"));
    assert!(contents.contains("Partitioned Token Budget"));
}
