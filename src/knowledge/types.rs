use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntityRecord {
    pub entity_id: String,
    pub canonical_name: String,
    pub entity_type: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntityLinkRecord {
    pub link_id: String,
    pub entity_id: String,
    pub entity_name: String,
    pub entity_type: String,
    pub link_type: String,
    pub target: String,
    #[serde(default)]
    pub metadata: Value,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEntityLinksResult {
    pub entity: String,
    pub total: usize,
    pub limit: usize,
    #[serde(default)]
    pub matched_entities: Vec<KnowledgeEntityRecord>,
    #[serde(default)]
    pub links: Vec<KnowledgeEntityLinkRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNodeSearchResult {
    pub query: String,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub nodes: Vec<KnowledgeEntityRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdgeEvidenceRecord {
    pub evidence_id: String,
    pub edge_id: String,
    pub episode_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub source_role: Option<String>,
    #[serde(default)]
    pub source_ordinal: Option<usize>,
    pub snippet: String,
    #[serde(default)]
    pub metadata: Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdgeSearchResult {
    pub query: String,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub edges: Vec<KnowledgeGraphEdgeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeFactCandidate {
    pub subject: String,
    #[serde(default)]
    pub subject_type_hint: Option<String>,
    #[serde(default)]
    pub subject_aliases: Vec<String>,
    pub relation: String,
    pub object_text: String,
    #[serde(default)]
    pub object_entity: Option<String>,
    #[serde(default)]
    pub object_type_hint: Option<String>,
    #[serde(default)]
    pub object_aliases: Vec<String>,
    pub category: String,
    pub confidence: String,
    pub source_role: String,
    pub source_ordinal: usize,
    pub summary: String,
    #[serde(default)]
    pub entity_hints: Vec<String>,
    #[serde(default)]
    pub valid_from_ms: Option<i64>,
    #[serde(default)]
    pub valid_to_ms: Option<i64>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub source_id: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub evidence_snippet: Option<String>,
    #[serde(default)]
    pub source_metadata: Value,
}

impl Default for KnowledgeFactCandidate {
    fn default() -> Self {
        Self {
            subject: String::new(),
            subject_type_hint: None,
            subject_aliases: Vec::new(),
            relation: String::new(),
            object_text: String::new(),
            object_entity: None,
            object_type_hint: None,
            object_aliases: Vec::new(),
            category: String::new(),
            confidence: String::new(),
            source_role: String::new(),
            source_ordinal: 0,
            summary: String::new(),
            entity_hints: Vec::new(),
            valid_from_ms: None,
            valid_to_ms: None,
            source_type: None,
            source_id: None,
            source_session_id: None,
            evidence_snippet: None,
            source_metadata: Value::Object(Default::default()),
        }
    }
}

pub type KnowledgeGraphCandidate = KnowledgeFactCandidate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEpisodeRecord {
    pub episode_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub source_type: String,
    pub source_id: String,
    pub summary: String,
    pub happened_at_ms: i64,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEpisodeSearchResult {
    pub query: String,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub episodes: Vec<KnowledgeEpisodeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEpisodeDetailResult {
    pub episode: KnowledgeEpisodeRecord,
    pub total_edges: usize,
    pub limit: usize,
    #[serde(default)]
    pub edges: Vec<KnowledgeGraphEdgeRecord>,
    #[serde(default)]
    pub evidence: Vec<KnowledgeEdgeEvidenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeGraphEdgeRecord {
    pub edge_id: String,
    #[serde(default)]
    pub fact_id: Option<String>,
    #[serde(default)]
    pub episode_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub subject_entity_id: Option<String>,
    pub subject: String,
    pub relation: String,
    #[serde(default)]
    pub object_entity_id: Option<String>,
    #[serde(default)]
    pub object_entity: Option<String>,
    pub object_text: String,
    pub category: String,
    pub confidence: String,
    pub summary: String,
    #[serde(default)]
    pub valid_from_ms: Option<i64>,
    #[serde(default)]
    pub valid_to_ms: Option<i64>,
    #[serde(default)]
    pub invalidated_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeNeighborhoodResult {
    pub entity: String,
    pub total: usize,
    pub limit: usize,
    #[serde(default)]
    pub matched_entities: Vec<KnowledgeEntityRecord>,
    #[serde(default)]
    pub edges: Vec<KnowledgeGraphEdgeRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeFactRecord {
    pub fact_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub subject_entity_id: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub subject_aliases: Vec<String>,
    pub relation: String,
    pub object_text: String,
    #[serde(default)]
    pub object_entity: Option<String>,
    #[serde(default)]
    pub object_aliases: Vec<String>,
    pub category: String,
    pub confidence: String,
    pub summary: String,
    #[serde(default)]
    pub entity_hints: Vec<String>,
    #[serde(default)]
    pub valid_from_ms: Option<i64>,
    #[serde(default)]
    pub valid_to_ms: Option<i64>,
    #[serde(default)]
    pub invalidated_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub source_role: Option<String>,
    #[serde(default)]
    pub source_ordinal: Option<usize>,
    #[serde(default)]
    pub episode_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeQueryResult {
    pub query: String,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub matched_entities: Vec<KnowledgeEntityRecord>,
    #[serde(default)]
    pub facts: Vec<KnowledgeFactRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeTimelineEvent {
    pub fact_id: String,
    #[serde(default)]
    pub session_id: Option<String>,
    pub subject: String,
    pub relation: String,
    pub object_text: String,
    pub summary: String,
    pub occurred_at_ms: i64,
    #[serde(default)]
    pub valid_from_ms: Option<i64>,
    #[serde(default)]
    pub valid_to_ms: Option<i64>,
    #[serde(default)]
    pub invalidated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeTimelineResult {
    pub entity: String,
    pub total: usize,
    pub limit: usize,
    #[serde(default)]
    pub matched_entities: Vec<KnowledgeEntityRecord>,
    #[serde(default)]
    pub events: Vec<KnowledgeTimelineEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEdgeDeleteResult {
    pub edge_id: String,
    pub deleted: bool,
    pub deleted_evidence: usize,
    pub deleted_invalidations: usize,
    pub deleted_entity_links: usize,
    #[serde(default)]
    pub deleted_fact_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeEpisodeDeleteResult {
    pub episode_id: String,
    pub deleted: bool,
    pub deleted_edges: usize,
    pub deleted_facts: usize,
    pub deleted_evidence: usize,
    pub deleted_invalidations: usize,
    pub deleted_entity_links: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeRebuildResult {
    pub rebuilt: bool,
    pub entity_self_links_projected: usize,
    pub relation_links_projected: usize,
    pub orphan_links_deleted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnowledgeClearResult {
    pub cleared: bool,
    pub deleted_entities: usize,
    pub deleted_aliases: usize,
    pub deleted_facts: usize,
    pub deleted_episodes: usize,
    pub deleted_edges: usize,
    pub deleted_evidence: usize,
    pub deleted_invalidations: usize,
    pub deleted_links: usize,
}
