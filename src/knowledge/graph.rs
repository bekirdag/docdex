use crate::knowledge::types::KnowledgeFactRecord;

pub fn score_fact_match(fact: &KnowledgeFactRecord, normalized_query: &str) -> i64 {
    if normalized_query.is_empty() {
        return 0;
    }
    let mut score = 0i64;
    let subject = fact.subject.to_ascii_lowercase();
    let relation = fact.relation.to_ascii_lowercase();
    let object_text = fact.object_text.to_ascii_lowercase();
    let object_entity = fact
        .object_entity
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let summary = fact.summary.to_ascii_lowercase();

    if subject == normalized_query {
        score += 500;
    } else if subject.contains(normalized_query) {
        score += 240;
    }
    if object_entity == normalized_query {
        score += 400;
    } else if object_entity.contains(normalized_query) {
        score += 220;
    }
    if relation == normalized_query {
        score += 180;
    }
    if summary.contains(normalized_query) {
        score += 160;
    }
    if object_text.contains(normalized_query) {
        score += 140;
    }
    if fact
        .subject_aliases
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(normalized_query))
    {
        score += 180;
    }
    if fact
        .object_aliases
        .iter()
        .any(|alias| alias.eq_ignore_ascii_case(normalized_query))
    {
        score += 160;
    }
    if fact
        .entity_hints
        .iter()
        .any(|hint| hint.to_ascii_lowercase().contains(normalized_query))
    {
        score += 120;
    }
    score
}
