#[derive(Clone, Debug)]
pub struct MemoryBudget {
    pub max_items: usize,
    pub token_budget: usize,
    pub recall_candidates: usize,
}

#[derive(Clone, Debug)]
pub struct ProfileBudget {
    pub max_items: usize,
    pub token_budget: usize,
    pub recall_candidates: usize,
}

const DEFAULT_MAX_ANSWER_TOKENS: u32 = 1024;
const DEFAULT_PROFILE_TOKEN_BUDGET: usize = 1000;
const DEFAULT_PROFILE_MAX_ITEMS: usize = 8;
const DEFAULT_PROFILE_RECALL_CANDIDATES: usize = 24;

pub fn memory_budget_from_max_answer_tokens(max_answer_tokens: u32) -> MemoryBudget {
    let generation_tokens = max_answer_tokens.max(1) as usize;
    let total_tokens = generation_tokens.saturating_mul(5);
    let memory_tokens = (total_tokens / 5).max(1);
    MemoryBudget {
        max_items: 5,
        token_budget: memory_tokens,
        recall_candidates: 20,
    }
}

impl Default for MemoryBudget {
    fn default() -> Self {
        memory_budget_from_max_answer_tokens(DEFAULT_MAX_ANSWER_TOKENS)
    }
}

impl Default for ProfileBudget {
    fn default() -> Self {
        ProfileBudget {
            max_items: DEFAULT_PROFILE_MAX_ITEMS,
            token_budget: DEFAULT_PROFILE_TOKEN_BUDGET,
            recall_candidates: DEFAULT_PROFILE_RECALL_CANDIDATES,
        }
    }
}
