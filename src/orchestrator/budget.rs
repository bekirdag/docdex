#[derive(Clone, Debug)]
pub struct MemoryBudget {
    pub max_items: usize,
    pub token_budget: usize,
    pub recall_candidates: usize,
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self {
            max_items: 5,
            token_budget: 350,
            recall_candidates: 20,
        }
    }
}
