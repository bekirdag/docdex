use crate::orchestrator::budget::MemoryBudget;
use crate::orchestrator::web::WebGateConfig;
use crate::tier2::Tier2Config;

#[derive(Clone, Debug)]
pub struct WaterfallPlan {
    pub web_gate: WebGateConfig,
    pub tier2_config: Tier2Config,
    pub memory_budget: MemoryBudget,
}

impl WaterfallPlan {
    pub fn new(
        web_gate: WebGateConfig,
        tier2_config: Tier2Config,
        memory_budget: MemoryBudget,
    ) -> Self {
        Self {
            web_gate,
            tier2_config,
            memory_budget,
        }
    }
}
