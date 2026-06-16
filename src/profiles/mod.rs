use serde::{Deserialize, Serialize};

pub mod constraints;
pub mod db;
pub mod embedder;
pub mod evolution;
pub mod manager;
pub mod ops;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Agent {
    pub id: String,
    pub role: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreferenceCategory {
    Style,
    Tooling,
    Constraint,
    Workflow,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Preference {
    pub id: String,
    pub agent_id: String,
    pub content: String,
    pub embedding: Option<Vec<f32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<usize>,
    pub category: PreferenceCategory,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ProfileMeta {
    pub embedding_dim: usize,
    pub schema_version: u32,
}

pub use constraints::{
    check_any_type_usage, check_circular_dependencies, match_constraint_rules, ConstraintRule,
    ConstraintViolation,
};
pub use embedder::{ProfileEmbedder, ProfileEmbedding};
pub use evolution::{EvolutionAction, EvolutionDecision, EvolutionOutcome};
pub use manager::ProfileExportManifest;
pub use manager::ProfileImportSummary;
pub use manager::ProfileManager;
pub use ops::{
    prune_and_truncate_profile_context, ProfileCandidate, ProfileContextDropped,
    ProfileContextItem, ProfileContextPruneTrace,
};
