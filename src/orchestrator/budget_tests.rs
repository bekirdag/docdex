use super::budget::{memory_budget_from_max_answer_tokens, MemoryBudget, ProfileBudget};

#[test]
fn memory_budget_from_answer_tokens_has_floor() {
    let budget = memory_budget_from_max_answer_tokens(0);
    assert_eq!(budget.max_items, 5);
    assert!(budget.token_budget >= 1);
    assert_eq!(budget.recall_candidates, 20);
}

#[test]
fn memory_budget_scales_with_answer_tokens() {
    let small = memory_budget_from_max_answer_tokens(10);
    let large = memory_budget_from_max_answer_tokens(1000);
    assert!(large.token_budget >= small.token_budget);
}

#[test]
fn profile_budget_defaults_are_nonzero() {
    let budget = ProfileBudget::default();
    assert!(budget.max_items > 0);
    assert!(budget.token_budget > 0);
    assert!(budget.recall_candidates > 0);
}

#[test]
fn memory_budget_default_matches_function() {
    let budget = MemoryBudget::default();
    let expected = memory_budget_from_max_answer_tokens(1024);
    assert_eq!(budget.max_items, expected.max_items);
    assert_eq!(budget.token_budget, expected.token_budget);
    assert_eq!(budget.recall_candidates, expected.recall_candidates);
}
