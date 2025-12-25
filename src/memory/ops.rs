use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone)]
pub struct MemoryCandidate {
    pub id: String,
    pub created_at_ms: i64,
    pub content: String,
    pub score: f32,
    pub metadata: Value,
}

#[derive(Debug, Clone)]
pub struct MemoryItem {
    pub content: String,
    pub score: f32,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryContextItem {
    pub id: String,
    pub created_at_ms: i64,
    pub score: f32,
    pub token_estimate: usize,
    pub truncated: bool,
    pub content: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryContextDropped {
    pub id: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemoryContextPruneTrace {
    pub budget_tokens: usize,
    pub max_items: usize,
    pub candidates: usize,
    pub kept: usize,
    pub dropped: Vec<MemoryContextDropped>,
}

pub fn prune_and_truncate_memory_context(
    candidates: &[MemoryCandidate],
    max_items: usize,
    budget_tokens: usize,
) -> (Vec<MemoryContextItem>, MemoryContextPruneTrace) {
    let mut ordered: Vec<MemoryCandidate> = candidates.to_vec();
    ordered.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.created_at_ms.cmp(&a.created_at_ms))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut remaining = budget_tokens;
    let mut kept: Vec<MemoryContextItem> = Vec::new();
    let mut dropped: Vec<MemoryContextDropped> = Vec::new();

    for (idx, candidate) in ordered.into_iter().enumerate() {
        if idx >= max_items {
            dropped.push(MemoryContextDropped {
                id: candidate.id,
                reason: "max_items",
            });
            continue;
        }
        if remaining == 0 {
            dropped.push(MemoryContextDropped {
                id: candidate.id,
                reason: "budget_exhausted",
            });
            continue;
        }

        let token_estimate = estimate_tokens(&candidate.content);
        let (content, truncated, used_tokens) = if token_estimate <= remaining {
            let used = token_estimate;
            (candidate.content, false, used)
        } else {
            let (truncated_content, was_truncated) =
                truncate_to_tokens(&candidate.content, remaining);
            let used = estimate_tokens(&truncated_content);
            (truncated_content, was_truncated, used)
        };

        remaining = remaining.saturating_sub(used_tokens);
        kept.push(MemoryContextItem {
            id: candidate.id,
            created_at_ms: candidate.created_at_ms,
            score: candidate.score,
            token_estimate: used_tokens,
            truncated,
            content,
            metadata: candidate.metadata,
        });
    }

    let trace = MemoryContextPruneTrace {
        budget_tokens,
        max_items,
        candidates: candidates.len(),
        kept: kept.len(),
        dropped,
    };
    (kept, trace)
}

pub fn inject_embedding_metadata(
    user: Option<Value>,
    embedding_provider: &str,
    embedding_model: &str,
) -> Value {
    let mut value = match user {
        Some(Value::Object(map)) => Value::Object(map),
        Some(_) => json!({}),
        None => json!({}),
    };
    let obj = value
        .as_object_mut()
        .expect("json!({}) always produces object");
    obj.insert(
        "embeddingProvider".to_string(),
        Value::String(embedding_provider.to_string()),
    );
    obj.insert(
        "embeddingModel".to_string(),
        Value::String(embedding_model.to_string()),
    );
    value
}

fn estimate_tokens(text: &str) -> usize {
    text.split_whitespace().count()
}

fn truncate_to_tokens(text: &str, max_tokens: usize) -> (String, bool) {
    if max_tokens == 0 {
        return (String::new(), !text.trim().is_empty());
    }
    let mut iter = text.split_whitespace();
    let mut out = String::new();
    let mut remaining = max_tokens;
    while remaining > 0 {
        let Some(token) = iter.next() else {
            break;
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
        remaining -= 1;
    }
    let truncated = iter.next().is_some();
    if truncated && !out.is_empty() {
        out.push('…');
    }
    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn candidate(id: &str, created_at_ms: i64, score: f32, content: &str) -> MemoryCandidate {
        MemoryCandidate {
            id: id.to_string(),
            created_at_ms,
            content: content.to_string(),
            score,
            metadata: json!({"k":"v"}),
        }
    }

    #[test]
    fn truncation_is_token_based_and_does_not_add_extra_tokens() {
        let (truncated, was_truncated) = truncate_to_tokens("one two three four", 3);
        assert!(was_truncated);
        assert_eq!(truncated, "one two three…");
        assert_eq!(estimate_tokens(&truncated), 3);
    }

    #[test]
    fn pruning_is_deterministic_regardless_of_input_order() {
        let a = candidate("a", 10, 0.5, "alpha beta gamma");
        let b = candidate("b", 11, 0.5, "delta epsilon");
        let c = candidate("c", 9, 0.9, "zeta eta theta iota");

        let inputs1 = vec![a.clone(), b.clone(), c.clone()];
        let inputs2 = vec![b, c, a];

        let (kept1, trace1) = prune_and_truncate_memory_context(&inputs1, 2, 10);
        let (kept2, trace2) = prune_and_truncate_memory_context(&inputs2, 2, 10);

        let ids1 = kept1.iter().map(|i| i.id.as_str()).collect::<Vec<_>>();
        let ids2 = kept2.iter().map(|i| i.id.as_str()).collect::<Vec<_>>();
        assert_eq!(ids1, ids2);
        assert_eq!(trace1.kept, trace2.kept);
        assert_eq!(trace1.dropped.len(), trace2.dropped.len());
    }

    #[test]
    fn budget_exhaustion_truncates_then_drops_in_order() {
        let c1 = candidate("c1", 1, 0.9, "one two three four five");
        let c2 = candidate("c2", 2, 0.8, "six seven eight");
        let c3 = candidate("c3", 3, 0.7, "nine ten");

        let (kept, trace) = prune_and_truncate_memory_context(&[c1, c2, c3], 3, 4);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, "c1");
        assert_eq!(kept[0].content, "one two three four…");
        assert!(kept[0].truncated);

        assert_eq!(trace.dropped.len(), 2);
        assert_eq!(trace.dropped[0].id, "c2");
        assert_eq!(trace.dropped[0].reason, "budget_exhausted");
        assert_eq!(trace.dropped[1].id, "c3");
        assert_eq!(trace.dropped[1].reason, "budget_exhausted");
    }
}
