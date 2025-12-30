use docdexd::profiles::{prune_and_truncate_profile_context, PreferenceCategory, ProfileCandidate};
use proptest::prelude::*;

fn candidate_strategy() -> impl Strategy<Value = ProfileCandidate> {
    let content = prop::collection::vec("[a-z]{1,8}", 0..12)
        .prop_map(|parts| parts.join(" "));
    let category = prop_oneof![
        Just(PreferenceCategory::Style),
        Just(PreferenceCategory::Tooling),
        Just(PreferenceCategory::Constraint),
        Just(PreferenceCategory::Workflow),
    ];
    (any::<u32>(), any::<u32>(), content, 0.0f32..1.0f32, any::<i64>(), category).prop_map(
        |(id, agent, content, score, last_updated, category)| ProfileCandidate {
            id: id.to_string(),
            agent_id: agent.to_string(),
            content,
            category,
            score,
            last_updated,
        },
    )
}

proptest! {
    #[test]
    fn profile_pruning_respects_limits(
        candidates in prop::collection::vec(candidate_strategy(), 0..40),
        max_items in 0usize..10,
        budget_tokens in 0usize..40,
    ) {
        let (kept, trace) = prune_and_truncate_profile_context(&candidates, max_items, budget_tokens);
        let used_tokens: usize = kept.iter().map(|item| item.token_estimate).sum();

        prop_assert!(kept.len() <= max_items);
        prop_assert!(used_tokens <= budget_tokens);
        prop_assert_eq!(trace.candidates, candidates.len());
        prop_assert_eq!(trace.kept, kept.len());
        prop_assert_eq!(trace.dropped.len(), candidates.len() - kept.len());
    }
}
