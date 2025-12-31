use super::{MemoryBudget, ProfileBudget, Tier2Config, WaterfallPlan, WebGateConfig};

#[test]
fn waterfall_plan_stores_inputs() {
    let web_gate = WebGateConfig {
        enabled: true,
        trigger_threshold: 0.3,
        min_local_match_ratio: 0.2,
        browser_hint: Some("chrome".to_string()),
        browser_available: false,
    };
    let tier2 = Tier2Config::enabled();
    let memory_budget = MemoryBudget {
        max_items: 3,
        token_budget: 120,
        recall_candidates: 10,
    };
    let profile_budget = ProfileBudget {
        max_items: 4,
        token_budget: 220,
        recall_candidates: 8,
    };

    let plan = WaterfallPlan::new(
        web_gate.clone(),
        tier2.clone(),
        memory_budget.clone(),
        profile_budget.clone(),
    );

    assert_eq!(plan.web_gate.enabled, web_gate.enabled);
    assert_eq!(plan.web_gate.trigger_threshold, web_gate.trigger_threshold);
    assert_eq!(plan.tier2_config.enabled, tier2.enabled);
    assert_eq!(plan.memory_budget.max_items, memory_budget.max_items);
    assert_eq!(
        plan.profile_budget.token_budget,
        profile_budget.token_budget
    );
}
