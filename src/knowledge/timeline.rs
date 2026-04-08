use crate::knowledge::types::KnowledgeFactRecord;

pub fn fact_timeline_ts(fact: &KnowledgeFactRecord) -> i64 {
    fact.valid_from_ms.unwrap_or(fact.created_at_ms)
}
