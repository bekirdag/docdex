use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationRole {
    System,
    User,
    Assistant,
    Tool,
    Developer,
    Other,
}

impl ConversationRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
            Self::Tool => "tool",
            Self::Developer => "developer",
            Self::Other => "other",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "system" => Self::System,
            "user" => Self::User,
            "assistant" => Self::Assistant,
            "tool" => Self::Tool,
            "developer" => Self::Developer,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationMessage {
    pub role: ConversationRole,
    pub content: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub created_at_ms: Option<i64>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationImport {
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub ended_at_ms: Option<i64>,
    pub messages: Vec<ConversationMessage>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummaryRecord {
    pub session_id: String,
    #[serde(default)]
    pub title: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub open_loops: Vec<String>,
    #[serde(default)]
    pub participants: Vec<String>,
    #[serde(default)]
    pub latest_user_goal: Option<String>,
    #[serde(default)]
    pub latest_assistant_reply: Option<String>,
    pub last_message_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkingMemoryRecord {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub active_objective: Option<String>,
    #[serde(default)]
    pub next_step: Option<String>,
    #[serde(default)]
    pub open_loops: Vec<String>,
    pub source_session_id: String,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TranscriptSnippet {
    pub session_id: String,
    pub message_id: String,
    pub role: String,
    pub content: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WakeupTrace {
    pub working_memory_found: bool,
    pub summary_candidates: usize,
    pub kg_candidates: usize,
    pub graph_edge_candidates: usize,
    pub graph_episode_candidates: usize,
    pub graph_link_candidates: usize,
    pub snippet_candidates: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WakeupBundle {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub working_memory: Option<WorkingMemoryRecord>,
    #[serde(default)]
    pub episodic_summaries: Vec<SessionSummaryRecord>,
    #[serde(default)]
    pub knowledge_facts: Vec<crate::knowledge::KnowledgeFactRecord>,
    #[serde(default)]
    pub knowledge_edges: Vec<crate::knowledge::KnowledgeGraphEdgeRecord>,
    #[serde(default)]
    pub knowledge_episodes: Vec<crate::knowledge::KnowledgeEpisodeRecord>,
    #[serde(default)]
    pub knowledge_entity_links: Vec<crate::knowledge::KnowledgeEntityLinkRecord>,
    #[serde(default)]
    pub transcript_snippets: Vec<TranscriptSnippet>,
    #[serde(default)]
    pub trace: WakeupTrace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportedConversationSession {
    pub session_id: String,
    pub deduplicated: bool,
    pub message_count: usize,
    pub capture_kind: ConversationCaptureKind,
    pub raw_messages_stored: bool,
    pub summary: SessionSummaryRecord,
    #[serde(default)]
    pub working_memory: Option<WorkingMemoryRecord>,
    #[serde(default)]
    pub durable_memories: Vec<ConversationDurableMemoryRouteRecord>,
    #[serde(default)]
    pub knowledge_facts: Vec<crate::knowledge::KnowledgeFactRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationCaptureKind {
    Manual,
    Auto,
}

impl ConversationCaptureKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Auto => "auto",
        }
    }

    pub fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "auto" => Self::Auto,
            _ => Self::Manual,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationImportOptions {
    pub capture_kind: ConversationCaptureKind,
    pub store_raw_messages: bool,
}

impl Default for ConversationImportOptions {
    fn default() -> Self {
        Self {
            capture_kind: ConversationCaptureKind::Manual,
            store_raw_messages: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationDurableMemoryTarget {
    RepoMemory,
    ProfileMemory,
}

impl ConversationDurableMemoryTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RepoMemory => "repo_memory",
            Self::ProfileMemory => "profile_memory",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationDurableMemoryCategory {
    RepoFact,
    Decision,
    Style,
    Tooling,
    Constraint,
    Workflow,
}

impl ConversationDurableMemoryCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RepoFact => "repo_fact",
            Self::Decision => "decision",
            Self::Style => "style",
            Self::Tooling => "tooling",
            Self::Constraint => "constraint",
            Self::Workflow => "workflow",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationDurableMemoryStatus {
    Stored,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationDurableMemoryCandidate {
    pub target: ConversationDurableMemoryTarget,
    pub category: ConversationDurableMemoryCategory,
    pub content: String,
    pub source_role: String,
    pub source_ordinal: usize,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationDurableMemoryRouteRecord {
    pub target: ConversationDurableMemoryTarget,
    pub category: ConversationDurableMemoryCategory,
    pub status: ConversationDurableMemoryStatus,
    pub content: String,
    pub source_role: String,
    pub source_ordinal: usize,
    pub confidence: String,
    #[serde(default)]
    pub stored_id: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSessionList {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub sessions: Vec<ConversationSessionListItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSessionListItem {
    pub session_id: String,
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub imported_at_ms: i64,
    pub message_count: usize,
    pub capture_kind: ConversationCaptureKind,
    pub raw_messages_stored: bool,
    #[serde(default)]
    pub redacted_at_ms: Option<i64>,
    #[serde(default)]
    pub metadata: Value,
    pub summary: SessionSummaryRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationStoredMessage {
    pub message_id: String,
    pub ordinal: usize,
    pub role: String,
    #[serde(default)]
    pub author: Option<String>,
    pub content: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSessionRecord {
    pub session_id: String,
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub imported_at_ms: i64,
    pub message_count: usize,
    pub capture_kind: ConversationCaptureKind,
    pub raw_messages_stored: bool,
    #[serde(default)]
    pub redacted_at_ms: Option<i64>,
    #[serde(default)]
    pub metadata: Value,
    pub summary: SessionSummaryRecord,
    #[serde(default)]
    pub working_memory: Option<WorkingMemoryRecord>,
    #[serde(default)]
    pub messages: Vec<ConversationStoredMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSearchResult {
    pub query: String,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub hits: Vec<ConversationSearchHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationSearchHit {
    pub session_id: String,
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub ended_at_ms: i64,
    pub imported_at_ms: i64,
    pub summary: SessionSummaryRecord,
    pub matched_field: String,
    pub snippet: String,
    pub score: i64,
    #[serde(default)]
    pub message_id: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaryEntryRecord {
    pub entry_id: String,
    #[serde(default)]
    pub agent_id: Option<String>,
    pub entry_type: String,
    pub content: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    pub created_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiaryReadResult {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    #[serde(default)]
    pub entries: Vec<DiaryEntryRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationHookAction {
    PeriodicMemorySave,
    PreCompactionSummarization,
    SessionCloseSummarization,
}

impl ConversationHookAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PeriodicMemorySave => "periodic_memory_save",
            Self::PreCompactionSummarization => "pre_compaction_summarization",
            Self::SessionCloseSummarization => "session_close_summarization",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationHookPayload {
    pub action: ConversationHookAction,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub ended_at_ms: Option<i64>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub messages: Option<Vec<ConversationMessage>>,
    #[serde(default)]
    pub transcript_text: Option<String>,
    #[serde(default)]
    pub summary_text: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationHookEnqueueResult {
    pub event_id: String,
    pub action: ConversationHookAction,
    pub status: String,
    pub queued_at_ms: i64,
    #[serde(default)]
    pub processed_at_ms: Option<i64>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub deduplicated: Option<bool>,
    #[serde(default)]
    pub summary: Option<SessionSummaryRecord>,
    #[serde(default)]
    pub working_memory: Option<WorkingMemoryRecord>,
    #[serde(default)]
    pub diary_entry: Option<DiaryEntryRecord>,
    #[serde(default)]
    pub durable_memories: Vec<ConversationDurableMemoryRouteRecord>,
    #[serde(default)]
    pub knowledge_facts: Vec<crate::knowledge::KnowledgeFactRecord>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationExportRecord {
    pub session: ConversationSessionRecord,
    #[serde(default)]
    pub related_diary_entries: Vec<DiaryEntryRecord>,
    #[serde(default)]
    pub knowledge_facts: Vec<crate::knowledge::KnowledgeFactRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationRedactResult {
    pub session_id: String,
    pub redacted: bool,
    #[serde(default)]
    pub redacted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationRetentionPolicy {
    pub manual_retention_days: u32,
    pub auto_capture_retention_days: u32,
    pub diary_retention_days: u32,
    pub hook_event_retention_days: u32,
    pub working_memory_retention_days: u32,
    pub episodic_rollup_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationPruneResult {
    pub applied: bool,
    pub deleted_manual_sessions: usize,
    pub deleted_auto_sessions: usize,
    pub deleted_diary_entries: usize,
    pub deleted_hook_events: usize,
    #[serde(default)]
    pub deleted_working_memory_records: usize,
    #[serde(default)]
    pub deleted_rollups: usize,
    #[serde(default)]
    pub created_rollups: usize,
    #[serde(default)]
    pub deleted_knowledge_facts: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deleted_session_ids: Vec<String>,
}

impl ConversationPruneResult {
    pub fn empty(applied: bool) -> Self {
        Self {
            applied,
            deleted_manual_sessions: 0,
            deleted_auto_sessions: 0,
            deleted_diary_entries: 0,
            deleted_hook_events: 0,
            deleted_working_memory_records: 0,
            deleted_rollups: 0,
            created_rollups: 0,
            deleted_knowledge_facts: 0,
            deleted_session_ids: Vec::new(),
        }
    }

    pub fn absorb(&mut self, other: Self) {
        self.applied |= other.applied;
        self.deleted_manual_sessions += other.deleted_manual_sessions;
        self.deleted_auto_sessions += other.deleted_auto_sessions;
        self.deleted_diary_entries += other.deleted_diary_entries;
        self.deleted_hook_events += other.deleted_hook_events;
        self.deleted_working_memory_records += other.deleted_working_memory_records;
        self.deleted_rollups += other.deleted_rollups;
        self.created_rollups += other.created_rollups;
        self.deleted_knowledge_facts += other.deleted_knowledge_facts;
        self.deleted_session_ids.extend(other.deleted_session_ids);
    }

    pub fn deleted_sessions_total(&self) -> usize {
        self.deleted_manual_sessions + self.deleted_auto_sessions
    }

    pub fn has_deletions(&self) -> bool {
        self.deleted_sessions_total() > 0
            || self.deleted_diary_entries > 0
            || self.deleted_hook_events > 0
            || self.deleted_working_memory_records > 0
            || self.deleted_rollups > 0
            || self.created_rollups > 0
            || self.deleted_knowledge_facts > 0
    }
}
