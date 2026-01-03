use docdexd::memory::{prune_and_truncate_memory_context, MemoryCandidate};
use proptest::prelude::*;
use serde_json::json;

fn candidate_strategy() -> impl Strategy<Value = MemoryCandidate> {
    let content = prop::collection::vec("[a-z]{1,8}", 0..12).prop_map(|parts| parts.join(" "));
    (any::<u32>(), content, 0.0f32..1.0f32, any::<i64>()).prop_map(
        |(id, content, score, created_at_ms)| MemoryCandidate {
            id: id.to_string(),
            created_at_ms,
            content,
            score,
            metadata: json!({}),
        },
    )
}

proptest! {
    #[test]
    fn memory_pruning_respects_limits(
        candidates in prop::collection::vec(candidate_strategy(), 0..40),
        max_items in 0usize..10,
        budget_tokens in 0usize..40,
    ) {
        let (kept, trace) = prune_and_truncate_memory_context(&candidates, max_items, budget_tokens);
        let used_tokens: usize = kept.iter().map(|item| item.token_estimate).sum();

        prop_assert!(kept.len() <= max_items);
        prop_assert!(used_tokens <= budget_tokens);
        prop_assert_eq!(trace.candidates, candidates.len());
        prop_assert_eq!(trace.kept, kept.len());
        prop_assert_eq!(trace.dropped.len(), candidates.len() - kept.len());
    }
}
