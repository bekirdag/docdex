mod db;
mod entity_registry;
mod graph;
mod ontology;
mod repo;
mod timeline;
mod types;

pub use db::KnowledgeStore;
pub use entity_registry::{
    extract_entity_hints, infer_fact_shape, normalize_entity_name, normalize_relation_name,
    RelationInference,
};
pub use graph::score_fact_match;
pub use ontology::{
    KnowledgeEntityType, KnowledgeOntology, KnowledgeRelationType, RelationCardinality,
    ValidatedKnowledgeCandidate,
};
pub use repo::{
    knowledge_lock_path, knowledge_namespace_lock_path, knowledge_namespace_path, knowledge_path,
};
pub use timeline::fact_timeline_ts;
pub use types::{
    KnowledgeClearResult, KnowledgeEdgeDeleteResult, KnowledgeEdgeEvidenceRecord,
    KnowledgeEdgeSearchResult, KnowledgeEntityLinkRecord, KnowledgeEntityLinksResult,
    KnowledgeEntityRecord, KnowledgeEpisodeDeleteResult, KnowledgeEpisodeDetailResult,
    KnowledgeEpisodeRecord, KnowledgeEpisodeSearchResult, KnowledgeFactCandidate,
    KnowledgeFactRecord, KnowledgeGraphCandidate, KnowledgeGraphEdgeRecord,
    KnowledgeNeighborhoodResult, KnowledgeNodeSearchResult, KnowledgeQueryResult,
    KnowledgeRebuildResult, KnowledgeTimelineEvent, KnowledgeTimelineResult,
};
