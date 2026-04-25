use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use chrono::DateTime;
use once_cell::sync::Lazy;
use regex::Regex;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tracing::warn;
use uuid::Uuid;
use walkdir::WalkDir;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use crate::config::{LlmConfig, MemoryPersonalPreferencesConfig};
use crate::conversations::{
    normalize_import_request, ConversationImport, ConversationImportEnvelope,
    ConversationImportFormat, ConversationMessage,
};
use crate::llm::delegation::{
    build_local_target_candidates_with_config, run_delegation_flow_with_failure_history,
    DelegationFailureHistoryContext, DelegationMode, LocalTarget, TaskType,
};
use crate::llm::local_library::{
    load_local_library, local_agent_is_cloud, refresh_local_library_if_stale,
};
use crate::profiles::{PreferenceCategory, ProfileEmbedder, ProfileManager};
use crate::state_layout::ensure_state_dir_secure;

const DB_FILE: &str = "personal_preferences.db";
const SCHEMA_VERSION: u32 = 6;
const DIGEST_STATUS_PENDING: &str = "pending";
const DIGEST_STATUS_PROCESSING: &str = "processing";
const DIGEST_STATUS_COMPLETED: &str = "completed";
const DIGEST_STATUS_FAILED: &str = "failed";
const DIGEST_STATUS_CAPTURED: &str = "captured";
const REDACTED_TEXT: &str = "[redacted]";
const ENCRYPTED_UNAVAILABLE_TEXT: &str = "[encrypted: unavailable]";
const ENCRYPTED_UNREADABLE_TEXT: &str = "[encrypted: unreadable]";
const ENCRYPTED_PREFIX: &str = "enc:v1:";
const MAX_DIGEST_RECORDS_PER_CAPTURE: usize = 16;
const MAX_DIGEST_EVIDENCE_CHARS: usize = 240;
const MAX_PROJECTABLE_RECORDS: usize = 24;
const DEFAULT_TRANSCRIPT_SCAN_LIMIT: usize = 12;
const SNAPSHOT_SUMMARY_LIMIT: usize = 8;

const REVIEW_STATUS_APPROVED: &str = "approved";
const REVIEW_STATUS_PENDING: &str = "pending_review";
const REVIEW_STATUS_REJECTED: &str = "rejected";

const CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT: &str = "explicit_user_statement";
const CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION: &str = "explicit_user_correction";
const CLAIM_ORIGIN_OBSERVED_BEHAVIOR: &str = "observed_behavior";
const CLAIM_ORIGIN_ENVIRONMENTAL_INFERENCE: &str = "environmental_inference";
const CLAIM_ORIGIN_CROSS_SESSION_INFERENCE: &str = "cross_session_inference";
const CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY: &str = "manual_review_entry";

const TRUTH_STATUS_CANDIDATE: &str = "candidate";
const TRUTH_STATUS_INFERRED: &str = "inferred";
const TRUTH_STATUS_CONFIRMED: &str = "confirmed";
const TRUTH_STATUS_REJECTED: &str = "rejected";
const TRUTH_STATUS_SUPERSEDED: &str = "superseded";
const TRUTH_STATUS_EXPIRED: &str = "expired";

const STABILITY_CLASS_EPHEMERAL: &str = "ephemeral";
const STABILITY_CLASS_SESSIONAL: &str = "sessional";
const STABILITY_CLASS_CURRENT: &str = "current";
const STABILITY_CLASS_STABLE: &str = "stable";
const STABILITY_CLASS_FOUNDATIONAL: &str = "foundational";

const CLONE_MODE_ADAPTIVE: &str = "adaptive";
const CLONE_MODE_PROJECT_BUILD: &str = "project_build";
const CLONE_MODE_REVIEW: &str = "review";
const CLONE_MODE_RELEASE: &str = "release";
const CLONE_MODE_SIMULATE_USER_PREFERENCE: &str = "simulate_user_preference";

const FEEDBACK_EVENT_ACCEPT_OUTPUT: &str = "accept_output";
const FEEDBACK_EVENT_REJECT_OUTPUT: &str = "reject_output";
const FEEDBACK_EVENT_CORRECT_OUTPUT: &str = "correct_output";
const FEEDBACK_EVENT_REWRITE_OUTPUT: &str = "rewrite_output";
const FEEDBACK_EVENT_OVERRIDE_PREFERENCE: &str = "override_preference";
const FEEDBACK_EVENT_DOWNGRADE_INFERENCE: &str = "downgrade_inference";
const FEEDBACK_EVENT_CONFIRM_INFERENCE: &str = "confirm_inference";
const PERSONAL_PREFERENCES_DIGEST_TIMEOUT_CAP_MS: u64 = 600_000;

static TRANSCRIPT_SECRET_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)\b(bearer)\s+[A-Za-z0-9\-._~+/]+=*").expect("bearer regex"),
        Regex::new(r"(?i)\b(sk-[A-Za-z0-9]{10,})\b").expect("api key regex"),
        Regex::new(r"(?i)\b(AKIA[0-9A-Z]{16})\b").expect("aws access key regex"),
        Regex::new(
            r#"(?i)\b(api[_-]?key|token|secret|password|passwd)\b\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{6,})["']?"#,
        )
        .expect("secret assignment regex"),
        Regex::new(r"(?s)-----BEGIN [A-Z ]+ PRIVATE KEY-----.*?-----END [A-Z ]+ PRIVATE KEY-----")
            .expect("pem regex"),
    ]
});

#[derive(Clone, Copy)]
struct CategoryPolicySeed {
    category: &'static str,
    description: &'static str,
    context_section: Option<&'static str>,
    context_allowed_default: bool,
    requires_review_for_sensitive: bool,
}

const DEFAULT_CATEGORY_POLICIES: &[CategoryPolicySeed] = &[
    CategoryPolicySeed {
        category: "communication_style",
        description: "How the user prefers to communicate and structure replies.",
        context_section: Some("communication_and_collaboration_style"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "workflow_method",
        description: "How the user prefers to work, sequence tasks, and review changes.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "coding_preference",
        description: "Coding-language, framework, and code-quality preferences.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "tooling_preference",
        description: "Preferred tools, CLIs, editors, and local-first constraints.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "architecture_preference",
        description: "Architectural patterns and design tradeoffs the user prefers.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "delivery_preference",
        description: "Preferences for release flow, validation, and delivery cadence.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "quality_bar",
        description: "How strict the user is on tests, review, performance, and correctness.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "decision_style",
        description: "How the user evaluates tradeoffs and makes decisions.",
        context_section: Some("communication_and_collaboration_style"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "learning_style",
        description: "How the user prefers to learn and receive explanations.",
        context_section: Some("communication_and_collaboration_style"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "collaboration_style",
        description: "How the user prefers agents and teammates to collaborate.",
        context_section: Some("communication_and_collaboration_style"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "current_projects",
        description: "Projects, products, and tools the user is actively building.",
        context_section: Some("current_projects_and_goals"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "product_goals",
        description: "The user’s stated product, business, or implementation goals.",
        context_section: Some("current_projects_and_goals"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "business_context",
        description: "Business facts, priorities, and operating context.",
        context_section: Some("current_projects_and_goals"),
        context_allowed_default: false,
        requires_review_for_sensitive: true,
    },
    CategoryPolicySeed {
        category: "personal_context",
        description: "Personal-life context that the user explicitly shares.",
        context_section: None,
        context_allowed_default: false,
        requires_review_for_sensitive: true,
    },
    CategoryPolicySeed {
        category: "identity_context",
        description: "Identity, demographic, or self-description facts the user shares.",
        context_section: None,
        context_allowed_default: false,
        requires_review_for_sensitive: true,
    },
    CategoryPolicySeed {
        category: "health_context",
        description: "Health-related context the user explicitly shares.",
        context_section: None,
        context_allowed_default: false,
        requires_review_for_sensitive: true,
    },
    CategoryPolicySeed {
        category: "likes",
        description: "Things the user likes, values, or explicitly wants.",
        context_section: Some("stable_preferences"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "dislikes",
        description: "Things the user dislikes, avoids, or explicitly rejects.",
        context_section: Some("avoidances_and_dislikes"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "strengths",
        description: "Skills, strengths, and reliable capabilities the user demonstrates.",
        context_section: Some("known_capabilities_and_history"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "limitations",
        description: "Constraints, gaps, or areas the user says they struggle with.",
        context_section: Some("known_capabilities_and_history"),
        context_allowed_default: true,
        requires_review_for_sensitive: true,
    },
    CategoryPolicySeed {
        category: "personality",
        description: "Durable personality traits and working temperament.",
        context_section: Some("communication_and_collaboration_style"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "cross_project_bridge",
        description: "Reusable tools, methods, or patterns that bridge work across repositories.",
        context_section: Some("cross_project_bridges"),
        context_allowed_default: true,
        requires_review_for_sensitive: false,
    },
    CategoryPolicySeed {
        category: "other",
        description: "Durable user-specific facts that do not fit another category.",
        context_section: None,
        context_allowed_default: false,
        requires_review_for_sensitive: false,
    },
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesMessage {
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub created_at_ms: Option<i64>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesCaptureRequest {
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub capture_kind: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub ended_at_ms: Option<i64>,
    #[serde(default)]
    pub messages: Vec<PersonalPreferencesMessage>,
    #[serde(default)]
    pub transcript_text: Option<String>,
    #[serde(default)]
    pub summary_text: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesCaptureRecord {
    pub id: String,
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub capture_kind: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub scope_id: Option<String>,
    #[serde(default)]
    pub scope_label: Option<String>,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub ended_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub digest_status: String,
    #[serde(default)]
    pub transcript_text: String,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub archive_path: Option<String>,
    #[serde(default)]
    pub raw_message_count: usize,
    #[serde(default)]
    pub archive_redacted_at_ms: Option<i64>,
    #[serde(default)]
    pub last_digest_error: Option<String>,
    #[serde(default)]
    pub messages: Vec<PersonalPreferencesMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceRecord {
    pub id: String,
    pub capture_id: String,
    pub record_type: String,
    pub category: String,
    #[serde(default)]
    pub subcategory: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub attribute: Option<String>,
    pub value: String,
    pub confidence: f32,
    pub sensitivity: String,
    #[serde(default)]
    pub evidence: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub projected_to_profile_at_ms: Option<i64>,
    pub review_status: String,
    #[serde(default)]
    pub review_updated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceStatus {
    pub storage_root: String,
    pub captures_total: usize,
    pub pending_captures: usize,
    pub processing_captures: usize,
    pub completed_captures: usize,
    pub failed_captures: usize,
    pub derived_records_total: usize,
    pub sources_total: usize,
    pub digest_runs_total: usize,
    pub snapshot_summaries_total: usize,
    pub claims_total: usize,
    pub feedback_events_total: usize,
    pub identity_snapshots_total: usize,
    pub decision_patterns_total: usize,
    pub style_signals_total: usize,
    pub clone_profiles_total: usize,
    pub clone_context_packs_total: usize,
    pub clone_evaluations_total: usize,
    pub claim_evidence_total: usize,
    pub claim_links_total: usize,
    pub project_timelines_total: usize,
    pub goal_graph_total: usize,
    pub override_rules_total: usize,
    pub redaction_spans_total: usize,
    pub retention_policies_total: usize,
    pub archive_files_total: usize,
    pub export_files_total: usize,
    #[serde(default)]
    pub last_capture_at_ms: Option<i64>,
    #[serde(default)]
    pub last_processed_at_ms: Option<i64>,
    #[serde(default)]
    pub last_scan_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesCaptureList {
    pub total: usize,
    pub items: Vec<PersonalPreferencesCaptureRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceClaim {
    pub id: String,
    #[serde(default)]
    pub record_id: Option<String>,
    #[serde(default)]
    pub capture_id: Option<String>,
    pub category: String,
    #[serde(default)]
    pub subcategory: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub attribute: Option<String>,
    pub value: String,
    pub claim_origin: String,
    pub truth_status: String,
    pub stability_class: String,
    pub sensitivity: String,
    pub confidence: f32,
    pub review_status: String,
    #[serde(default)]
    pub evidence_summary: Option<String>,
    #[serde(default)]
    pub valid_from_ms: Option<i64>,
    #[serde(default)]
    pub valid_to_ms: Option<i64>,
    #[serde(default)]
    pub supersedes_claim_id: Option<String>,
    #[serde(default)]
    pub contradicted_by_claim_id: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceClaimList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceClaimReviewSummary {
    pub claim_id: String,
    pub review_status: String,
    pub truth_status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceFeedbackEvent {
    pub id: String,
    pub event_type: String,
    #[serde(default)]
    pub claim_id: Option<String>,
    #[serde(default)]
    pub capture_id: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceFeedbackSummary {
    pub event_id: String,
    pub event_type: String,
    #[serde(default)]
    pub affected_claim_id: Option<String>,
    #[serde(default)]
    pub created_claim_id: Option<String>,
    #[serde(default)]
    pub created_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceSnapshot {
    pub id: String,
    pub snapshot_kind: String,
    pub summary: String,
    #[serde(default)]
    pub stable_summary: Option<String>,
    #[serde(default)]
    pub changed_summary: Option<String>,
    #[serde(default)]
    pub active_projects_summary: Option<String>,
    pub created_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceSnapshotList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceSnapshotRebuildSummary {
    pub created: usize,
    #[serde(default)]
    pub latest_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneTraceItem {
    pub claim_id: String,
    pub section: String,
    pub reason: String,
    pub score: f32,
    pub claim_origin: String,
    pub truth_status: String,
    pub confidence: f32,
    #[serde(default)]
    pub sensitive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneContextPack {
    pub mode: String,
    pub query: String,
    pub summary: String,
    pub items: Vec<PersonalPreferencesContextItem>,
    pub trace: Vec<PersonalPreferenceCloneTraceItem>,
    #[serde(default)]
    pub excluded_by_policy: usize,
    #[serde(default)]
    pub truncated_items: usize,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneExplanationRecord {
    pub claim_id: String,
    pub section: String,
    pub content: String,
    pub reason: String,
    pub score: f32,
    pub claim_origin: String,
    pub truth_status: String,
    pub confidence: f32,
    #[serde(default)]
    pub sensitive: bool,
    #[serde(default)]
    pub source_repo_root: Option<String>,
    #[serde(default)]
    pub evidence_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneExplanation {
    pub pack: PersonalPreferenceCloneContextPack,
    pub included_claims: Vec<PersonalPreferenceCloneExplanationRecord>,
    pub ranking_factors: Vec<String>,
    pub policy_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneEvaluation {
    pub mode: String,
    pub query: String,
    pub overall_score: f32,
    pub explicit_selected: usize,
    pub inferred_selected: usize,
    pub confirmed_selected: usize,
    pub current_selected: usize,
    pub bridge_selected: usize,
    pub style_selected: usize,
    pub decision_patterns_selected: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesSearchResponse {
    pub query: String,
    pub items: Vec<PersonalPreferenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCategory {
    pub category: String,
    pub description: String,
    #[serde(default)]
    pub context_section: Option<String>,
    pub context_allowed_default: bool,
    pub requires_review_for_sensitive: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceReview {
    pub id: String,
    pub record_id: String,
    pub verdict: String,
    #[serde(default)]
    pub notes: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesReviewList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceReview>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesReviewQueue {
    pub total: usize,
    pub items: Vec<PersonalPreferenceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesReviewSummary {
    pub record_id: String,
    pub review_status: String,
    pub review_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesContextItem {
    pub section: String,
    pub content: String,
    pub category: String,
    pub record_type: String,
    pub confidence: f32,
    #[serde(default)]
    pub claim_id: Option<String>,
    #[serde(default)]
    pub claim_origin: Option<String>,
    #[serde(default)]
    pub truth_status: Option<String>,
    #[serde(default)]
    pub source_repo_root: Option<String>,
    pub token_estimate: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferencesContextTrace {
    pub available: usize,
    pub selected: usize,
    pub truncated: usize,
    pub budget_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferencesContextAssembly {
    pub items: Vec<PersonalPreferencesContextItem>,
    pub trace: PersonalPreferencesContextTrace,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesContextOptions {
    pub max_records: usize,
    pub budget_tokens: usize,
    #[serde(default)]
    pub allow_sensitive: bool,
    #[serde(default)]
    pub current_repo_root: Option<String>,
}

impl Default for PersonalPreferencesContextOptions {
    fn default() -> Self {
        Self {
            max_records: 8,
            budget_tokens: 240,
            allow_sensitive: false,
            current_repo_root: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesClaimsQuery {
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub truth_status: Option<String>,
    #[serde(default)]
    pub claim_origin: Option<String>,
    #[serde(default)]
    pub include_sensitive: bool,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesCloneOptions {
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub allow_sensitive: bool,
    #[serde(default)]
    pub current_repo_root: Option<String>,
    #[serde(default)]
    pub max_records: Option<usize>,
    #[serde(default)]
    pub budget_tokens: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceDigestInput {
    pub capture: PersonalPreferencesCaptureRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceDigestRecord {
    pub record_type: String,
    pub category: String,
    #[serde(default)]
    pub subcategory: Option<String>,
    pub subject: String,
    #[serde(default)]
    pub attribute: Option<String>,
    pub value: String,
    #[serde(default)]
    pub confidence: Option<f32>,
    #[serde(default)]
    pub sensitivity: Option<String>,
    #[serde(default)]
    pub evidence: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferenceDigestOutput {
    #[serde(default)]
    pub records: Vec<PersonalPreferenceDigestRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferencesProcessingSummary {
    pub requeued_captures: usize,
    pub processed_captures: usize,
    pub completed_captures: usize,
    pub deferred_captures: usize,
    pub failed_captures: usize,
    pub records_written: usize,
    pub projected_profile_preferences: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesExportSummary {
    pub path: String,
    pub captures: usize,
    pub derived_records: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceClaimForgetSummary {
    pub claim_id: String,
    pub forgotten: bool,
    #[serde(default)]
    pub affected_record_id: Option<String>,
    #[serde(default)]
    pub tombstone_id: Option<String>,
    #[serde(default)]
    pub created_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesDeleteSummary {
    pub capture_id: String,
    pub deleted: bool,
    pub archive_deleted: bool,
    pub records_deleted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesRedactionSummary {
    pub capture_id: String,
    pub redacted: bool,
    pub archive_redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesPurgeSummary {
    pub captures_deleted: usize,
    pub derived_records_deleted: usize,
    pub archives_deleted: usize,
    pub queue_entries_deleted: usize,
    pub exports_deleted: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferencesPruneSummary {
    pub applied: bool,
    pub raw_candidates: usize,
    pub raw_redacted: usize,
    pub derived_candidates: usize,
    pub derived_deleted: usize,
    #[serde(default)]
    pub claim_candidates: usize,
    #[serde(default)]
    pub claims_deleted: usize,
    #[serde(default)]
    pub snapshot_candidates: usize,
    #[serde(default)]
    pub snapshots_deleted: usize,
    #[serde(default)]
    pub clone_artifact_candidates: usize,
    #[serde(default)]
    pub clone_artifacts_deleted: usize,
    #[serde(default)]
    pub exports_candidates: usize,
    #[serde(default)]
    pub exports_deleted: usize,
    #[serde(default)]
    pub retention_policies_updated: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceRetentionPolicy {
    pub policy_key: String,
    pub lane: String,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub raw_retention_days: Option<u32>,
    #[serde(default)]
    pub derived_retention_days: Option<u32>,
    #[serde(default)]
    pub claim_retention_days: Option<u32>,
    #[serde(default)]
    pub snapshot_retention_days: Option<u32>,
    #[serde(default)]
    pub export_retention_days: Option<u32>,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferencesCaptureOptions {
    pub queue_for_processing: bool,
    pub archive_raw_conversations: bool,
    pub secret_scrubber_enabled: bool,
    #[serde(default)]
    pub content_encryption_key_env: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferencesTranscriptSourceSummary {
    pub source: String,
    pub scanned_files: usize,
    pub sessions_detected: usize,
    pub captures_created: usize,
    pub skipped_existing: usize,
    pub parse_errors: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferencesTranscriptScanSummary {
    pub scanned_files: usize,
    pub sessions_detected: usize,
    pub captures_created: usize,
    pub skipped_existing: usize,
    pub parse_errors: usize,
    #[serde(default)]
    pub last_scan_at_ms: Option<i64>,
    #[serde(default)]
    pub sources: Vec<PersonalPreferencesTranscriptSourceSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersonalPreferencesArchiveEnvelope {
    capture_id: String,
    created_at_ms: i64,
    request: PersonalPreferencesCaptureRequest,
}

#[derive(Debug, Clone)]
struct ContentCipher {
    env_name: String,
    key_id: String,
    key_bytes: [u8; 32],
}

#[derive(Debug, Clone)]
struct ClientTranscriptCandidate {
    source: String,
    adapter_kind: String,
    path: PathBuf,
    format: Option<ConversationImportFormat>,
}

#[derive(Debug, Clone)]
struct CloneContextCandidate {
    claim: PersonalPreferenceClaim,
    section: String,
    content: String,
    record_type: String,
    source_repo_root: Option<String>,
    allowed: bool,
    reason: String,
    score: f32,
}

#[derive(Debug, Clone)]
struct CategoryPolicy {
    category: String,
    description: String,
    context_section: Option<String>,
    context_allowed_default: bool,
    requires_review_for_sensitive: bool,
}

#[derive(Clone)]
pub struct PersonalPreferencesStore {
    root_dir: PathBuf,
    archive_dir: PathBuf,
    queue_dir: PathBuf,
    exports_dir: PathBuf,
    redactions_dir: PathBuf,
    locks_dir: PathBuf,
    db_path: PathBuf,
}

impl PersonalPreferencesStore {
    pub fn new(root_dir: &Path) -> Result<Self> {
        ensure_state_dir_secure(root_dir)?;
        let archive_dir = root_dir.join("archive");
        let queue_dir = root_dir.join("queue");
        let exports_dir = root_dir.join("exports");
        let redactions_dir = root_dir.join("redactions");
        let locks_dir = root_dir.join("locks");
        ensure_state_dir_secure(&archive_dir)?;
        ensure_state_dir_secure(&queue_dir)?;
        ensure_state_dir_secure(&exports_dir)?;
        ensure_state_dir_secure(&redactions_dir)?;
        ensure_state_dir_secure(&locks_dir)?;
        let db_path = root_dir.join(DB_FILE);
        init_db(&db_path)?;
        Ok(Self {
            root_dir: root_dir.to_path_buf(),
            archive_dir,
            queue_dir,
            exports_dir,
            redactions_dir,
            locks_dir,
            db_path,
        })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn archive_dir(&self) -> &Path {
        &self.archive_dir
    }

    pub fn exports_dir(&self) -> &Path {
        &self.exports_dir
    }

    pub fn locks_dir(&self) -> &Path {
        &self.locks_dir
    }

    pub fn capture_conversation(
        &self,
        request: PersonalPreferencesCaptureRequest,
        queue_for_processing: bool,
        archive_raw_conversations: bool,
    ) -> Result<PersonalPreferencesCaptureRecord> {
        self.capture_conversation_with_options(
            request,
            PersonalPreferencesCaptureOptions {
                queue_for_processing,
                archive_raw_conversations,
                ..PersonalPreferencesCaptureOptions::default()
            },
        )
    }

    pub fn capture_conversation_with_options(
        &self,
        request: PersonalPreferencesCaptureRequest,
        options: PersonalPreferencesCaptureOptions,
    ) -> Result<PersonalPreferencesCaptureRecord> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let now = now_ms();
        let capture_id = Uuid::new_v4().to_string();
        let cipher = resolve_content_cipher(options.content_encryption_key_env.as_deref());
        let prepared_request = prepare_capture_request_for_storage(
            request,
            options.secret_scrubber_enabled,
            cipher.as_ref(),
        );
        let transcript_text = normalize_capture_text(&prepared_request);
        let digest_status = if options.queue_for_processing {
            DIGEST_STATUS_PENDING
        } else {
            DIGEST_STATUS_CAPTURED
        };
        let archive_path = if options.archive_raw_conversations {
            Some(self.write_archive_envelope(
                &capture_id,
                now,
                &prepared_request,
                cipher.as_ref(),
            )?)
        } else {
            None
        };
        tx.execute(
            "INSERT INTO captured_conversations(
                id, source, source_session_id, capture_kind, title, agent_id, transport,
                repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, NULL, NULL)",
            params![
                capture_id,
                prepared_request.source,
                prepared_request.source_session_id,
                prepared_request.capture_kind,
                prepared_request.title,
                prepared_request.agent_id,
                prepared_request.transport,
                prepared_request.repo_id,
                prepared_request.repo_root,
                prepared_request.scope_id,
                prepared_request.scope_label,
                prepared_request.started_at_ms,
                prepared_request.ended_at_ms,
                now,
                now,
                digest_status,
                protect_text_for_storage(&transcript_text, cipher.as_ref()),
                serde_json::to_string(&prepared_request.metadata)?,
                archive_path.clone().map(|value| value.display().to_string()),
                prepared_request.messages.len() as i64,
            ],
        )?;
        upsert_source_and_session_lineage(&tx, &capture_id, &prepared_request, digest_status, now)?;
        for (ordinal, message) in prepared_request.messages.iter().enumerate() {
            let message_id = Uuid::new_v4().to_string();
            let protected_content =
                protect_text_for_storage(message.content.trim(), cipher.as_ref());
            let metadata_json = serde_json::to_string(&message.metadata)?;
            tx.execute(
                "INSERT INTO captured_messages(
                    id, capture_id, ordinal, role, content, created_at_ms, metadata_json
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    message_id,
                    capture_id,
                    ordinal as i64,
                    normalize_text(&message.role),
                    protected_content,
                    message.created_at_ms,
                    metadata_json,
                ],
            )?;
            tx.execute(
                "INSERT INTO pp_messages(
                    id, capture_id, message_id, ordinal, role, content, created_at_ms, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    format!("ppmsg_{message_id}"),
                    capture_id,
                    message_id,
                    ordinal as i64,
                    normalize_text(&message.role),
                    protected_content,
                    message.created_at_ms,
                    metadata_json,
                ],
            )?;
        }
        tx.commit()?;
        self.sync_queue_marker(&capture_id, digest_status)?;
        self.read_capture(&capture_id)?
            .ok_or_else(|| anyhow!("captured conversation missing after insert"))
    }

    pub fn list_captures(
        &self,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferencesCaptureList> {
        let conn = open_db(&self.db_path)?;
        let status = status
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let total = if let Some(ref status) = status {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = ?1",
                params![status],
            )?
        } else {
            count_query(&conn, "SELECT COUNT(*) FROM captured_conversations")?
        };
        let sql = if status.is_some() {
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             WHERE digest_status = ?1
             ORDER BY created_at_ms DESC
             LIMIT ?2 OFFSET ?3"
        } else {
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             ORDER BY created_at_ms DESC
             LIMIT ?1 OFFSET ?2"
        };
        let mut stmt = conn.prepare(sql)?;
        let mut rows = if let Some(ref status) = status {
            stmt.query(params![status, limit.max(1) as i64, offset as i64])?
        } else {
            stmt.query(params![limit.max(1) as i64, offset as i64])?
        };
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            let mut capture = row_to_capture(row)?;
            hydrate_capture_content(&mut capture);
            items.push(capture);
        }
        Ok(PersonalPreferencesCaptureList { total, items })
    }

    pub fn read_capture(
        &self,
        capture_id: &str,
    ) -> Result<Option<PersonalPreferencesCaptureRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             WHERE id = ?1",
        )?;
        let capture = stmt
            .query_row(params![capture_id], row_to_capture)
            .optional()?;
        let Some(mut capture) = capture else {
            return Ok(None);
        };
        hydrate_capture_content(&mut capture);
        capture.messages = self.messages_for_capture(capture_id, &capture.metadata)?;
        if capture.messages.is_empty() {
            if let Some(path) = capture.archive_path.as_deref() {
                if let Ok(envelope) = self.read_archive_envelope(Path::new(path)) {
                    capture.messages = envelope.request.messages;
                    if capture.transcript_text.trim().is_empty() {
                        capture.transcript_text =
                            envelope.request.transcript_text.unwrap_or_default();
                    }
                }
            }
        }
        Ok(Some(capture))
    }

    pub fn status(&self) -> Result<PersonalPreferenceStatus> {
        let conn = open_db(&self.db_path)?;
        let captures_total = count_query(&conn, "SELECT COUNT(*) FROM captured_conversations")?;
        let pending_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'pending'",
        )?;
        let processing_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'processing'",
        )?;
        let completed_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'completed'",
        )?;
        let failed_captures = count_query(
            &conn,
            "SELECT COUNT(*) FROM captured_conversations WHERE digest_status = 'failed'",
        )?;
        let derived_records_total = count_query(&conn, "SELECT COUNT(*) FROM derived_records")?;
        let sources_total = count_query(&conn, "SELECT COUNT(*) FROM pp_sources")?;
        let digest_runs_total = count_query(&conn, "SELECT COUNT(*) FROM pp_digest_runs")?;
        let snapshot_summaries_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_snapshot_summaries")?;
        let claims_total = count_query(&conn, "SELECT COUNT(*) FROM pp_claims")?;
        let feedback_events_total = count_query(&conn, "SELECT COUNT(*) FROM pp_feedback_events")?;
        let identity_snapshots_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_identity_snapshots")?;
        let decision_patterns_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_decision_patterns")?;
        let style_signals_total = count_query(&conn, "SELECT COUNT(*) FROM pp_style_signals")?;
        let clone_profiles_total = count_query(&conn, "SELECT COUNT(*) FROM pp_clone_profiles")?;
        let clone_context_packs_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_clone_context_packs")?;
        let clone_evaluations_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_clone_evaluations")?;
        let claim_evidence_total = count_query(&conn, "SELECT COUNT(*) FROM pp_claim_evidence")?;
        let claim_links_total = count_query(&conn, "SELECT COUNT(*) FROM pp_claim_links")?;
        let project_timelines_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_project_timelines")?;
        let goal_graph_total = count_query(&conn, "SELECT COUNT(*) FROM pp_goal_graph")?;
        let override_rules_total = count_query(&conn, "SELECT COUNT(*) FROM pp_override_rules")?;
        let redaction_spans_total = count_query(&conn, "SELECT COUNT(*) FROM pp_redaction_spans")?;
        let retention_policies_total =
            count_query(&conn, "SELECT COUNT(*) FROM pp_retention_policies")?;
        let last_capture_at_ms = conn
            .query_row(
                "SELECT MAX(created_at_ms) FROM captured_conversations",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        let last_processed_at_ms = conn
            .query_row(
                "SELECT MAX(updated_at_ms) FROM captured_conversations WHERE digest_status = 'completed'",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        let last_scan_at_ms = conn
            .query_row(
                "SELECT MAX(created_at_ms) FROM pp_sessions WHERE capture_kind = 'client_transcript_scan'",
                [],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten();
        Ok(PersonalPreferenceStatus {
            storage_root: self.root_dir.display().to_string(),
            captures_total,
            pending_captures,
            processing_captures,
            completed_captures,
            failed_captures,
            derived_records_total,
            sources_total,
            digest_runs_total,
            snapshot_summaries_total,
            claims_total,
            feedback_events_total,
            identity_snapshots_total,
            decision_patterns_total,
            style_signals_total,
            clone_profiles_total,
            clone_context_packs_total,
            clone_evaluations_total,
            claim_evidence_total,
            claim_links_total,
            project_timelines_total,
            goal_graph_total,
            override_rules_total,
            redaction_spans_total,
            retention_policies_total,
            archive_files_total: count_files(&self.archive_dir)?,
            export_files_total: count_files(&self.exports_dir)?,
            last_capture_at_ms,
            last_processed_at_ms,
            last_scan_at_ms,
        })
    }

    pub fn list_categories(&self) -> Result<Vec<PersonalPreferenceCategory>> {
        let conn = open_db(&self.db_path)?;
        load_category_rows(&conn)
    }

    pub fn scan_supported_client_transcripts(
        &self,
        config: &MemoryPersonalPreferencesConfig,
        limit: Option<usize>,
    ) -> Result<PersonalPreferencesTranscriptScanSummary> {
        if !config.capture_enabled || !config.capture_supported_client_transcripts {
            return Ok(PersonalPreferencesTranscriptScanSummary::default());
        }
        let limit = limit.unwrap_or(DEFAULT_TRANSCRIPT_SCAN_LIMIT).clamp(1, 256);
        let candidates = collect_client_transcript_candidates(config, limit.saturating_mul(6))?;
        let mut summary = PersonalPreferencesTranscriptScanSummary::default();
        let mut per_source = BTreeMap::<String, PersonalPreferencesTranscriptSourceSummary>::new();
        let mut seen_paths = HashSet::<PathBuf>::new();
        let capture_options = PersonalPreferencesCaptureOptions {
            queue_for_processing: config.digest_enabled,
            archive_raw_conversations: config.archive_raw_conversations,
            secret_scrubber_enabled: config.transcript_secret_scrubber_enabled,
            content_encryption_key_env: config.content_encryption_key_env.clone(),
        };
        for candidate in candidates {
            let source_key = candidate.source.clone();
            let source_summary = per_source.entry(source_key.clone()).or_insert_with(|| {
                PersonalPreferencesTranscriptSourceSummary {
                    source: source_key.clone(),
                    ..PersonalPreferencesTranscriptSourceSummary::default()
                }
            });
            if seen_paths.insert(candidate.path.clone()) {
                summary.scanned_files += 1;
                source_summary.scanned_files += 1;
            }
            let imports = match load_transcript_candidate_imports(&candidate) {
                Ok(imports) => imports,
                Err(_) => {
                    summary.parse_errors += 1;
                    source_summary.parse_errors += 1;
                    continue;
                }
            };
            for import in imports {
                if summary.sessions_detected >= limit {
                    break;
                }
                summary.sessions_detected += 1;
                source_summary.sessions_detected += 1;
                let request = capture_request_from_import(&candidate, import);
                let external_ref = external_ref_for_capture_request(&request);
                if let Some(ref value) = external_ref {
                    if self.has_external_session_ref(value)? {
                        summary.skipped_existing += 1;
                        source_summary.skipped_existing += 1;
                        continue;
                    }
                }
                self.capture_conversation_with_options(request, capture_options.clone())?;
                summary.captures_created += 1;
                source_summary.captures_created += 1;
                summary.last_scan_at_ms = Some(now_ms());
            }
            if summary.sessions_detected >= limit {
                break;
            }
        }
        summary.sources = per_source.into_values().collect();
        Ok(summary)
    }

    pub fn list_review_records(
        &self,
        status: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferencesReviewQueue> {
        let conn = open_db(&self.db_path)?;
        let mut records = load_all_records(&conn)?;
        let normalized_status = status
            .and_then(normalize_review_status)
            .map(ToOwned::to_owned);
        if let Some(status) = normalized_status.as_deref() {
            records.retain(|record| record.review_status == status);
        }
        records.sort_by(|left, right| {
            right.updated_at_ms.cmp(&left.updated_at_ms).then_with(|| {
                right
                    .confidence
                    .partial_cmp(&left.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
        });
        let total = records.len();
        let items = records
            .into_iter()
            .skip(offset)
            .take(limit.max(1))
            .collect::<Vec<_>>();
        Ok(PersonalPreferencesReviewQueue { total, items })
    }

    pub fn list_reviews_for_record(
        &self,
        record_id: &str,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferencesReviewList> {
        let record_id = record_id.trim();
        if record_id.is_empty() {
            return Err(anyhow!("record_id must not be empty"));
        }
        let conn = open_db(&self.db_path)?;
        let total = count_query_with_param(
            &conn,
            "SELECT COUNT(*) FROM pp_reviews WHERE record_id = ?1",
            params![record_id],
        )?;
        let mut stmt = conn.prepare(
            "SELECT id, record_id, verdict, notes, created_at_ms
             FROM pp_reviews
             WHERE record_id = ?1
             ORDER BY created_at_ms DESC
             LIMIT ?2 OFFSET ?3",
        )?;
        let mut rows = stmt.query(params![record_id, limit.max(1) as i64, offset as i64])?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            items.push(PersonalPreferenceReview {
                id: row.get(0)?,
                record_id: row.get(1)?,
                verdict: row.get(2)?,
                notes: row.get(3)?,
                created_at_ms: row.get(4)?,
            });
        }
        Ok(PersonalPreferencesReviewList { total, items })
    }

    pub fn review_record(
        &self,
        record_id: &str,
        verdict: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferencesReviewSummary> {
        let record_id = record_id.trim();
        if record_id.is_empty() {
            return Err(anyhow!("record_id must not be empty"));
        }
        let verdict = normalize_review_status(verdict)
            .ok_or_else(|| anyhow!("verdict must be approved, pending_review, or rejected"))?;
        let note_text = notes
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let now = now_ms();
        let updated = tx.execute(
            "UPDATE derived_records
             SET review_status = ?2, review_updated_at_ms = ?3, updated_at_ms = ?3
             WHERE id = ?1",
            params![record_id, verdict, now],
        )?;
        if updated == 0 {
            return Err(anyhow!("record not found"));
        }
        sync_materialized_record_status(&tx, record_id, verdict, now)?;
        let review_id = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO pp_reviews(id, record_id, verdict, notes, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![review_id, record_id, verdict, note_text, now],
        )?;
        tx.commit()?;
        Ok(PersonalPreferencesReviewSummary {
            record_id: record_id.to_string(),
            review_status: verdict.to_string(),
            review_id,
        })
    }

    pub fn prune_retention(
        &self,
        raw_retention_days: u32,
        derived_retention_days: u32,
        apply: bool,
    ) -> Result<PersonalPreferencesPruneSummary> {
        let conn = open_db(&self.db_path)?;
        let raw_cutoff = retention_cutoff_ms(raw_retention_days);
        let derived_cutoff = retention_cutoff_ms(derived_retention_days);

        let raw_candidates = if let Some(cutoff_ms) = raw_cutoff {
            let mut stmt = conn.prepare(
                "SELECT id
                 FROM captured_conversations
                 WHERE created_at_ms < ?1
                   AND archive_redacted_at_ms IS NULL
                   AND (raw_message_count > 0 OR trim(transcript_text) != '')",
            )?;
            let mut rows = stmt.query(params![cutoff_ms])?;
            let mut ids = Vec::new();
            while let Some(row) = rows.next()? {
                ids.push(row.get::<_, String>(0)?);
            }
            ids
        } else {
            Vec::new()
        };

        let derived_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM derived_records WHERE updated_at_ms < ?1",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let claim_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_claims
                 WHERE updated_at_ms < ?1
                   AND (record_id IS NULL
                        OR truth_status IN ('rejected', 'superseded', 'expired'))",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let snapshot_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_identity_snapshots WHERE created_at_ms < ?1",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let clone_candidates = if let Some(cutoff_ms) = derived_cutoff {
            count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_clone_context_packs WHERE created_at_ms < ?1",
                params![cutoff_ms],
            )? + count_query_with_param(
                &conn,
                "SELECT COUNT(*) FROM pp_clone_evaluations WHERE created_at_ms < ?1",
                params![cutoff_ms],
            )?
        } else {
            0
        };
        let export_candidates = if let Some(cutoff_ms) = raw_cutoff {
            count_files_older_than(&self.exports_dir, cutoff_ms)?
        } else {
            0
        };

        let mut raw_redacted = 0usize;
        if apply {
            for capture_id in &raw_candidates {
                let summary = self.redact_capture(capture_id)?;
                if summary.redacted {
                    raw_redacted += 1;
                }
            }
        }

        let mut derived_deleted = 0usize;
        let mut claims_deleted = 0usize;
        let mut snapshots_deleted = 0usize;
        let mut clone_artifacts_deleted = 0usize;
        let mut exports_deleted = 0usize;
        let mut retention_policies_updated = 0usize;
        if apply {
            if let Some(cutoff_ms) = derived_cutoff {
                derived_deleted = conn.execute(
                    "DELETE FROM derived_records WHERE updated_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                claims_deleted = conn.execute(
                    "DELETE FROM pp_claims
                     WHERE updated_at_ms < ?1
                       AND (record_id IS NULL
                            OR truth_status IN ('rejected', 'superseded', 'expired'))",
                    params![cutoff_ms],
                )?;
                snapshots_deleted = conn.execute(
                    "DELETE FROM pp_identity_snapshots WHERE created_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                clone_artifacts_deleted += conn.execute(
                    "DELETE FROM pp_clone_context_packs WHERE created_at_ms < ?1",
                    params![cutoff_ms],
                )?;
                clone_artifacts_deleted += conn.execute(
                    "DELETE FROM pp_clone_evaluations WHERE created_at_ms < ?1",
                    params![cutoff_ms],
                )?;
            }
            if let Some(cutoff_ms) = raw_cutoff {
                exports_deleted = prune_files_older_than(&self.exports_dir, cutoff_ms)?;
            }
            upsert_retention_policy(
                &conn,
                "raw_archive",
                "raw_archive",
                Some(raw_retention_days),
                None,
                None,
                None,
                Some(raw_retention_days),
                &json!({ "updated_from": "prune_retention" }),
            )?;
            upsert_retention_policy(
                &conn,
                "derived_memory",
                "derived_memory",
                None,
                Some(derived_retention_days),
                Some(derived_retention_days),
                Some(derived_retention_days),
                None,
                &json!({ "updated_from": "prune_retention" }),
            )?;
            upsert_retention_policy(
                &conn,
                "clone_artifacts",
                "clone_artifacts",
                None,
                None,
                Some(derived_retention_days),
                Some(derived_retention_days),
                Some(raw_retention_days),
                &json!({ "updated_from": "prune_retention" }),
            )?;
            retention_policies_updated = 3;
        }

        Ok(PersonalPreferencesPruneSummary {
            applied: apply,
            raw_candidates: raw_candidates.len(),
            raw_redacted,
            derived_candidates,
            derived_deleted,
            claim_candidates,
            claims_deleted,
            snapshot_candidates,
            snapshots_deleted,
            clone_artifact_candidates: clone_candidates,
            clone_artifacts_deleted,
            exports_candidates: export_candidates,
            exports_deleted,
            retention_policies_updated,
        })
    }

    pub fn search_records(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<Vec<PersonalPreferenceRecord>> {
        self.search_records_with_policy(query, limit, true)
    }

    pub fn search_records_with_policy(
        &self,
        query: &str,
        limit: usize,
        include_sensitive: bool,
    ) -> Result<Vec<PersonalPreferenceRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut records = load_all_records(&conn)?;
        if !include_sensitive {
            records.retain(|record| !is_sensitive_level(&record.sensitivity));
        }
        rank_records(query, &mut records);
        records.truncate(limit.max(1));
        Ok(records)
    }

    pub fn list_claims(
        &self,
        query: PersonalPreferencesClaimsQuery,
    ) -> Result<PersonalPreferenceClaimList> {
        let conn = open_db(&self.db_path)?;
        let mut claims = load_all_claims(&conn)?;
        claims.retain(|claim| !claim_is_forgotten(claim));
        if !query.include_sensitive {
            claims.retain(|claim| !is_sensitive_level(&claim.sensitivity));
        }
        if let Some(status) = query
            .truth_status
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            claims.retain(|claim| claim.truth_status == status);
        }
        if let Some(origin) = query
            .claim_origin
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            claims.retain(|claim| claim.claim_origin == origin);
        }
        let query_text = query.query.unwrap_or_default();
        rank_claims(&query_text, &mut claims);
        let total = claims.len();
        let offset = query.offset.unwrap_or(0);
        let limit = query.limit.unwrap_or(20).clamp(1, 200);
        let items = claims.into_iter().skip(offset).take(limit).collect();
        Ok(PersonalPreferenceClaimList { total, items })
    }

    pub fn read_claim(&self, claim_id: &str) -> Result<Option<PersonalPreferenceClaim>> {
        let conn = open_db(&self.db_path)?;
        load_claim_by_id(&conn, claim_id)
    }

    pub fn forget_claim(
        &self,
        claim_id: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferenceClaimForgetSummary> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let claim = load_claim_by_id(&tx, claim_id)?
            .ok_or_else(|| anyhow!("personal preference claim not found"))?;
        let now = now_ms();
        let note_text = notes
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let mut claim_metadata = claim.metadata.as_object().cloned().unwrap_or_default();
        claim_metadata.insert("forgotten".to_string(), json!(true));
        claim_metadata.insert("forgotten_at_ms".to_string(), json!(now));
        if let Some(notes) = note_text.as_ref() {
            claim_metadata.insert("forgotten_notes".to_string(), json!(notes));
        }
        tx.execute(
            "UPDATE pp_claims
             SET value = ?2,
                 evidence_summary = ?2,
                 truth_status = ?3,
                 review_status = ?4,
                 valid_to_ms = ?5,
                 updated_at_ms = ?5,
                 metadata_json = ?6
             WHERE id = ?1",
            params![
                claim_id,
                REDACTED_TEXT,
                TRUTH_STATUS_EXPIRED,
                REVIEW_STATUS_REJECTED,
                now,
                serde_json::to_string(&Value::Object(claim_metadata.clone()))?,
            ],
        )?;
        if let Some(record_id) = claim.record_id.as_deref() {
            tx.execute(
                "UPDATE derived_records
                 SET value = ?2,
                     evidence = ?2,
                     review_status = ?3,
                     review_updated_at_ms = ?4,
                     updated_at_ms = ?4,
                     metadata_json = ?5
                 WHERE id = ?1",
                params![
                    record_id,
                    REDACTED_TEXT,
                    REVIEW_STATUS_REJECTED,
                    now,
                    serde_json::to_string(&Value::Object(claim_metadata.clone()))?,
                ],
            )?;
            sync_materialized_record_status(&tx, record_id, REVIEW_STATUS_REJECTED, now)?;
        }
        replace_claim_evidence(
            &tx,
            claim_id,
            claim.capture_id.as_deref(),
            None,
            &Value::Object(claim_metadata.clone()),
            now,
        )?;
        if let Some(capture_id) = claim.capture_id.as_deref() {
            write_redaction_span(
                &tx,
                capture_id,
                Some(claim_id),
                "claim_forget",
                None,
                None,
                REDACTED_TEXT,
                note_text.as_deref().unwrap_or("claim forgotten"),
                &json!({ "claim_id": claim_id }),
                now,
            )?;
        }
        write_claim_version(
            &tx,
            claim_id,
            &json!({
                "action": "forget",
                "notes": note_text,
            }),
            now,
        )?;
        let tombstone_id = format!("tombstone_{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO pp_tombstones(id, capture_id, action, details_json, created_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                tombstone_id,
                claim
                    .capture_id
                    .clone()
                    .unwrap_or_else(|| format!("claim:{claim_id}")),
                "forget_claim",
                serde_json::to_string(&json!({
                    "claim_id": claim_id,
                    "record_id": claim.record_id,
                    "notes": note_text,
                }))?,
                now,
            ],
        )?;
        let snapshot_id =
            rebuild_identity_snapshots_tx(&tx, claim.capture_id.as_deref(), "forget")?;
        tx.commit()?;
        Ok(PersonalPreferenceClaimForgetSummary {
            claim_id: claim_id.to_string(),
            forgotten: true,
            affected_record_id: claim.record_id,
            tombstone_id: Some(tombstone_id),
            created_snapshot_id: snapshot_id,
        })
    }

    pub fn list_retention_policies(&self) -> Result<Vec<PersonalPreferenceRetentionPolicy>> {
        let conn = open_db(&self.db_path)?;
        load_retention_policies(&conn)
    }

    pub fn review_claim(
        &self,
        claim_id: &str,
        verdict: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferenceClaimReviewSummary> {
        let verdict = normalize_review_status(verdict)
            .ok_or_else(|| anyhow!("verdict must be approved, pending_review, or rejected"))?;
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let claim = load_claim_by_id(&tx, claim_id)?
            .ok_or_else(|| anyhow!("personal preference claim not found"))?;
        let truth_status = match verdict {
            REVIEW_STATUS_APPROVED => {
                if claim.claim_origin == CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT
                    || claim.claim_origin == CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION
                    || claim.claim_origin == CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY
                {
                    TRUTH_STATUS_CONFIRMED
                } else {
                    TRUTH_STATUS_INFERRED
                }
            }
            REVIEW_STATUS_REJECTED => TRUTH_STATUS_REJECTED,
            _ => TRUTH_STATUS_CANDIDATE,
        };
        let now = now_ms();
        tx.execute(
            "UPDATE pp_claims
             SET review_status = ?2, truth_status = ?3, updated_at_ms = ?4
             WHERE id = ?1",
            params![claim_id, verdict, truth_status, now],
        )?;
        write_claim_version(
            &tx,
            claim_id,
            &json!({
                "action": "review",
                "review_status": verdict,
                "truth_status": truth_status,
                "notes": notes,
            }),
            now,
        )?;
        if let Some(record_id) = claim.record_id.as_deref() {
            tx.execute(
                "UPDATE derived_records
                 SET review_status = ?2, review_updated_at_ms = ?3, updated_at_ms = ?3
                 WHERE id = ?1",
                params![record_id, verdict, now],
            )?;
            sync_materialized_record_status(&tx, record_id, verdict, now)?;
            tx.execute(
                "INSERT INTO pp_reviews(id, record_id, verdict, notes, created_at_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![Uuid::new_v4().to_string(), record_id, verdict, notes, now],
            )?;
        }
        tx.commit()?;
        Ok(PersonalPreferenceClaimReviewSummary {
            claim_id: claim_id.to_string(),
            review_status: verdict.to_string(),
            truth_status: truth_status.to_string(),
        })
    }

    pub fn override_claim(
        &self,
        claim_id: &str,
        value: &str,
        notes: Option<&str>,
    ) -> Result<PersonalPreferenceFeedbackSummary> {
        self.add_feedback_event(
            FEEDBACK_EVENT_OVERRIDE_PREFERENCE,
            Some(claim_id),
            None,
            None,
            None,
            Some(value),
            notes,
            json!({}),
        )
    }

    pub fn add_feedback_event(
        &self,
        event_type: &str,
        claim_id: Option<&str>,
        capture_id: Option<&str>,
        category: Option<&str>,
        attribute: Option<&str>,
        value: Option<&str>,
        notes: Option<&str>,
        metadata: Value,
    ) -> Result<PersonalPreferenceFeedbackSummary> {
        let event_type = normalize_feedback_event_type(event_type)
            .ok_or_else(|| anyhow!("unsupported feedback event type"))?;
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let now = now_ms();
        let event_id = Uuid::new_v4().to_string();
        let base_claim = match claim_id {
            Some(id) => load_claim_by_id(&tx, id)?,
            None => None,
        };
        tx.execute(
            "INSERT INTO pp_feedback_events(
                id, claim_id, capture_id, event_type, notes, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                event_id,
                claim_id,
                capture_id,
                event_type,
                notes,
                now,
                serde_json::to_string(&metadata)?,
            ],
        )?;
        let mut affected_claim_id = claim_id.map(ToOwned::to_owned);
        let mut created_claim_id = None;
        if let Some(claim) = base_claim.as_ref() {
            let (next_confidence, next_truth_status) =
                apply_feedback_to_claim(claim, event_type, value);
            tx.execute(
                "UPDATE pp_claims
                 SET confidence = ?2, truth_status = ?3, updated_at_ms = ?4
                 WHERE id = ?1",
                params![claim.id, next_confidence, next_truth_status, now],
            )?;
            write_claim_version(
                &tx,
                &claim.id,
                &json!({
                    "action": "feedback",
                    "event_type": event_type,
                    "next_confidence": next_confidence,
                    "next_truth_status": next_truth_status,
                    "notes": notes,
                }),
                now,
            )?;
            if matches!(
                event_type,
                FEEDBACK_EVENT_CORRECT_OUTPUT
                    | FEEDBACK_EVENT_REWRITE_OUTPUT
                    | FEEDBACK_EVENT_OVERRIDE_PREFERENCE
            ) {
                if let Some(override_value) = value.map(str::trim).filter(|value| !value.is_empty())
                {
                    let override_claim = create_override_claim_from_claim(
                        &tx,
                        claim,
                        category,
                        attribute,
                        override_value,
                        notes,
                        now,
                    )?;
                    tx.execute(
                        "UPDATE pp_claims
                         SET truth_status = ?2, contradicted_by_claim_id = ?3, updated_at_ms = ?4
                         WHERE id = ?1",
                        params![claim.id, TRUTH_STATUS_SUPERSEDED, override_claim.id, now],
                    )?;
                    created_claim_id = Some(override_claim.id.clone());
                    affected_claim_id = Some(claim.id.clone());
                }
            }
        } else if let Some(new_value) = value.map(str::trim).filter(|value| !value.is_empty()) {
            let claim = create_manual_feedback_claim(
                &tx, event_type, capture_id, category, attribute, new_value, notes, now,
            )?;
            created_claim_id = Some(claim.id.clone());
            affected_claim_id = Some(claim.id);
        }
        let snapshot_id = rebuild_identity_snapshots_tx(&tx, None, "feedback")?;
        tx.commit()?;
        Ok(PersonalPreferenceFeedbackSummary {
            event_id,
            event_type: event_type.to_string(),
            affected_claim_id,
            created_claim_id,
            created_snapshot_id: snapshot_id,
        })
    }

    pub fn list_feedback_events(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PersonalPreferenceFeedbackEvent>> {
        let conn = open_db(&self.db_path)?;
        load_feedback_events(&conn, limit, offset)
    }

    pub fn list_snapshots(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferenceSnapshotList> {
        let conn = open_db(&self.db_path)?;
        let snapshots = load_snapshots(&conn, limit, offset)?;
        let total = count_query(&conn, "SELECT COUNT(*) FROM pp_identity_snapshots")?;
        Ok(PersonalPreferenceSnapshotList {
            total,
            items: snapshots,
        })
    }

    pub fn read_snapshot(&self, snapshot_id: &str) -> Result<Option<PersonalPreferenceSnapshot>> {
        let conn = open_db(&self.db_path)?;
        load_snapshot_by_id(&conn, snapshot_id)
    }

    pub fn rebuild_snapshots(&self) -> Result<PersonalPreferenceSnapshotRebuildSummary> {
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        let latest_snapshot_id = rebuild_identity_snapshots_tx(&tx, None, "manual_rebuild")?;
        tx.commit()?;
        Ok(PersonalPreferenceSnapshotRebuildSummary {
            created: usize::from(latest_snapshot_id.is_some()),
            latest_snapshot_id,
        })
    }

    pub fn build_context(
        &self,
        query: &str,
        options: PersonalPreferencesContextOptions,
    ) -> Result<PersonalPreferencesContextAssembly> {
        let pack = self.build_clone_context_pack(
            query,
            PersonalPreferencesCloneOptions {
                mode: Some(CLONE_MODE_ADAPTIVE.to_string()),
                allow_sensitive: options.allow_sensitive,
                current_repo_root: options.current_repo_root,
                max_records: Some(options.max_records),
                budget_tokens: Some(options.budget_tokens),
            },
        )?;
        Ok(PersonalPreferencesContextAssembly {
            trace: PersonalPreferencesContextTrace {
                available: pack.trace.len(),
                selected: pack.items.len(),
                truncated: pack.truncated_items,
                budget_tokens: options.budget_tokens,
            },
            items: pack.items,
        })
    }

    pub fn build_clone_context_pack(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneContextPack> {
        let conn = open_db(&self.db_path)?;
        let policies = load_category_policy_map(&conn)?;
        let mode = normalize_clone_mode(options.mode.as_deref().unwrap_or(CLONE_MODE_ADAPTIVE));
        let max_records = options.max_records.unwrap_or(8).clamp(1, 64);
        let budget_tokens = options.budget_tokens.unwrap_or(600).clamp(32, 4096);
        let current_repo_root = options.current_repo_root.clone();
        let mut candidates =
            load_clone_context_candidates(&conn, query, &mode, options.allow_sensitive)?;
        let available = candidates.len();
        if let Some(current_repo_root) = current_repo_root.as_deref() {
            for bridge in load_claim_bridge_candidates(
                &conn,
                current_repo_root,
                options.allow_sensitive,
                &policies,
            )? {
                candidates.push(bridge);
            }
        }
        candidates.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| {
                    right
                        .claim
                        .confidence
                        .partial_cmp(&left.claim.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .then_with(|| right.claim.updated_at_ms.cmp(&left.claim.updated_at_ms))
        });
        let mut used = 0usize;
        let mut truncated = 0usize;
        let mut excluded_by_policy = 0usize;
        let mut items = Vec::new();
        let mut trace = Vec::new();
        for candidate in candidates {
            if items.len() >= max_records || used >= budget_tokens {
                truncated += 1;
                continue;
            }
            if !candidate.allowed {
                excluded_by_policy += 1;
                continue;
            }
            let token_estimate = estimate_tokens(&candidate.content);
            let remaining = budget_tokens.saturating_sub(used);
            let rendered = if token_estimate > remaining {
                let snippet = truncate_to_tokens(&candidate.content, remaining);
                if snippet.is_empty() {
                    truncated += 1;
                    continue;
                }
                truncated += 1;
                snippet
            } else {
                candidate.content.clone()
            };
            let rendered_tokens = estimate_tokens(&rendered);
            used = used.saturating_add(rendered_tokens);
            items.push(PersonalPreferencesContextItem {
                section: candidate.section.clone(),
                content: rendered,
                category: candidate.claim.category.clone(),
                record_type: candidate.record_type.clone(),
                confidence: candidate.claim.confidence,
                claim_id: Some(candidate.claim.id.clone()),
                claim_origin: Some(candidate.claim.claim_origin.clone()),
                truth_status: Some(candidate.claim.truth_status.clone()),
                source_repo_root: candidate.source_repo_root.clone(),
                token_estimate: rendered_tokens,
            });
            trace.push(PersonalPreferenceCloneTraceItem {
                claim_id: candidate.claim.id.clone(),
                section: candidate.section,
                reason: candidate.reason,
                score: candidate.score,
                claim_origin: candidate.claim.claim_origin.clone(),
                truth_status: candidate.claim.truth_status.clone(),
                confidence: candidate.claim.confidence,
                sensitive: is_sensitive_level(&candidate.claim.sensitivity),
            });
        }
        let summary = render_clone_context_summary(&items);
        let created_at_ms = now_ms();
        let pack_id = format!("clone_pack_{}", Uuid::new_v4());
        conn.execute(
            "INSERT INTO pp_clone_context_packs(
                id, mode, query, query_hash, current_repo_root, summary, explanation_json, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                pack_id,
                mode,
                query,
                sha256_hex(query),
                current_repo_root,
                summary,
                serde_json::to_string(&trace)?,
                created_at_ms,
                serde_json::to_string(&json!({
                    "selected": items.len(),
                    "available": available,
                    "excluded_by_policy": excluded_by_policy,
                    "truncated_items": truncated,
                }))?,
            ],
        )?;
        upsert_clone_profile(&conn, &mode, &summary, created_at_ms)?;
        Ok(PersonalPreferenceCloneContextPack {
            mode,
            query: query.to_string(),
            summary,
            items,
            trace,
            excluded_by_policy,
            truncated_items: truncated,
            created_at_ms,
        })
    }

    pub fn explain_clone_context(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneExplanation> {
        let pack = self.build_clone_context_pack(query, options)?;
        let conn = open_db(&self.db_path)?;
        let included_claims = pack
            .trace
            .iter()
            .filter_map(|trace| {
                let claim = load_claim_by_id(&conn, &trace.claim_id).ok().flatten()?;
                let content = pack
                    .items
                    .iter()
                    .find(|item| item.claim_id.as_deref() == Some(trace.claim_id.as_str()))
                    .map(|item| item.content.clone())
                    .unwrap_or_else(|| render_claim_content(&claim));
                let source_repo_root = pack
                    .items
                    .iter()
                    .find(|item| item.claim_id.as_deref() == Some(trace.claim_id.as_str()))
                    .and_then(|item| item.source_repo_root.clone());
                Some(PersonalPreferenceCloneExplanationRecord {
                    claim_id: trace.claim_id.clone(),
                    section: trace.section.clone(),
                    content,
                    reason: trace.reason.clone(),
                    score: trace.score,
                    claim_origin: trace.claim_origin.clone(),
                    truth_status: trace.truth_status.clone(),
                    confidence: trace.confidence,
                    sensitive: trace.sensitive,
                    source_repo_root,
                    evidence_summary: claim.evidence_summary.clone(),
                })
            })
            .collect::<Vec<_>>();
        Ok(PersonalPreferenceCloneExplanation {
            pack,
            included_claims,
            ranking_factors: vec![
                "Ranking prefers explicit/confirmed/high-stability claims before weaker inferences."
                    .to_string(),
                "Scores combine confidence, truth status, stability, query term match, and mode-specific section boosts."
                    .to_string(),
                "Explicit user corrections receive an additional priority boost during clone-pack selection."
                    .to_string(),
            ],
            policy_notes: vec![
                "Repo truth still outranks clone inference; clone packs only shape preference-sensitive behavior."
                    .to_string(),
                "Sensitive claims are omitted unless allow_sensitive is enabled and policy allows them."
                    .to_string(),
                "Excluded-by-policy and truncated counts reflect pack-level filtering, not hidden inclusion."
                    .to_string(),
            ],
        })
    }

    pub fn evaluate_clone_context(
        &self,
        query: &str,
        options: PersonalPreferencesCloneOptions,
    ) -> Result<PersonalPreferenceCloneEvaluation> {
        let pack = self.build_clone_context_pack(query, options.clone())?;
        let explicit_selected = pack
            .trace
            .iter()
            .filter(|item| {
                matches!(
                    item.claim_origin.as_str(),
                    CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT
                        | CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION
                        | CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY
                )
            })
            .count();
        let inferred_selected = pack
            .trace
            .iter()
            .filter(|item| {
                matches!(
                    item.claim_origin.as_str(),
                    CLAIM_ORIGIN_CROSS_SESSION_INFERENCE | CLAIM_ORIGIN_ENVIRONMENTAL_INFERENCE
                )
            })
            .count();
        let confirmed_selected = pack
            .trace
            .iter()
            .filter(|item| item.truth_status == TRUTH_STATUS_CONFIRMED)
            .count();
        let current_selected = pack
            .items
            .iter()
            .filter(|item| {
                matches!(
                    item.section.as_str(),
                    "active_project_and_strategic_context"
                        | "current_workflow_and_quality_expectations"
                )
            })
            .count();
        let bridge_selected = pack
            .items
            .iter()
            .filter(|item| item.section == "relevant_cross_project_bridges")
            .count();
        let style_selected = pack
            .items
            .iter()
            .filter(|item| item.section == "relevant_communication_style_expectations")
            .count();
        let decision_patterns_selected = pack
            .items
            .iter()
            .filter(|item| item.record_type == "decision_pattern")
            .count();
        let overall_score =
            (((explicit_selected * 4 + confirmed_selected * 3 + bridge_selected * 2) as f32)
                / ((pack.items.len().max(1) * 4) as f32))
                .clamp(0.0, 1.0);
        let mut notes = Vec::new();
        if explicit_selected == 0 {
            notes.push("No explicit user statements were selected.".to_string());
        }
        if style_selected == 0 {
            notes.push("No communication-style expectations were selected.".to_string());
        }
        if bridge_selected == 0 {
            notes.push("No cross-project bridge hints were selected.".to_string());
        }
        let created_at_ms = now_ms();
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "INSERT INTO pp_clone_evaluations(
                id, mode, score, query, notes, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("clone_eval_{}", Uuid::new_v4()),
                pack.mode,
                overall_score,
                pack.query,
                notes.join(" "),
                created_at_ms,
                serde_json::to_string(&json!({
                    "explicit_selected": explicit_selected,
                    "inferred_selected": inferred_selected,
                    "confirmed_selected": confirmed_selected,
                    "current_selected": current_selected,
                    "bridge_selected": bridge_selected,
                    "style_selected": style_selected,
                    "decision_patterns_selected": decision_patterns_selected,
                }))?,
            ],
        )?;
        Ok(PersonalPreferenceCloneEvaluation {
            mode: pack.mode,
            query: pack.query,
            overall_score,
            explicit_selected,
            inferred_selected,
            confirmed_selected,
            current_selected,
            bridge_selected,
            style_selected,
            decision_patterns_selected,
            notes,
        })
    }

    pub fn export_bundle(
        &self,
        capture_id: Option<&str>,
    ) -> Result<PersonalPreferencesExportSummary> {
        let conn = open_db(&self.db_path)?;
        let captures = if let Some(capture_id) = capture_id {
            self.read_capture(capture_id)?
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            let mut list = self.list_captures(None, 10_000, 0)?.items;
            for capture in &mut list {
                capture.messages = self.messages_for_capture(&capture.id, &capture.metadata)?;
            }
            list
        };
        let capture_ids = captures
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        let records = if capture_ids.is_empty() {
            Vec::new()
        } else {
            load_records_for_capture_ids(&conn, &capture_ids)?
        };
        let payload = json!({
            "exported_at_ms": now_ms(),
            "storage_root": self.root_dir.display().to_string(),
            "captures": captures,
            "records": records,
        });
        let file_name = match capture_id {
            Some(id) => format!("personal-preferences-{id}-{}.json", now_ms()),
            None => format!("personal-preferences-export-{}.json", now_ms()),
        };
        let path = self.exports_dir.join(file_name);
        fs::write(&path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(PersonalPreferencesExportSummary {
            path: path.display().to_string(),
            captures: payload
                .get("captures")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0),
            derived_records: payload
                .get("records")
                .and_then(Value::as_array)
                .map(|items| items.len())
                .unwrap_or(0),
        })
    }

    pub fn redact_capture(&self, capture_id: &str) -> Result<PersonalPreferencesRedactionSummary> {
        let capture = self
            .read_capture(capture_id)?
            .ok_or_else(|| anyhow!("capture not found"))?;
        let now = now_ms();
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "UPDATE captured_conversations
             SET transcript_text = ?2, archive_redacted_at_ms = ?3, updated_at_ms = ?3
             WHERE id = ?1",
            params![capture_id, REDACTED_TEXT, now],
        )?;
        conn.execute(
            "UPDATE captured_messages
             SET content = ?2
             WHERE capture_id = ?1",
            params![capture_id, REDACTED_TEXT],
        )?;
        conn.execute(
            "UPDATE pp_messages
             SET content = ?2
             WHERE capture_id = ?1",
            params![capture_id, REDACTED_TEXT],
        )?;
        let mut archive_redacted = false;
        if let Some(path) = capture.archive_path.as_deref() {
            let archive_path = Path::new(path);
            if archive_path.exists() {
                let mut envelope = self.read_archive_envelope(archive_path)?;
                for message in &mut envelope.request.messages {
                    message.content = REDACTED_TEXT.to_string();
                }
                envelope.request.transcript_text = Some(REDACTED_TEXT.to_string());
                envelope.request.summary_text = Some(REDACTED_TEXT.to_string());
                let cipher = resolve_cipher_from_metadata(&envelope.request.metadata);
                let protected = PersonalPreferencesArchiveEnvelope {
                    request: protect_capture_request_payload(&envelope.request, cipher.as_ref()),
                    ..envelope
                };
                fs::write(archive_path, serde_json::to_vec_pretty(&protected)?)
                    .with_context(|| format!("write {}", archive_path.display()))?;
                archive_redacted = true;
            }
        }
        write_redaction_span(
            &conn,
            capture_id,
            None,
            "capture_redact",
            None,
            None,
            REDACTED_TEXT,
            "capture redacted",
            &json!({ "archive_redacted": archive_redacted }),
            now,
        )?;
        self.write_tombstone(
            capture_id,
            "redact",
            json!({ "archive_redacted": archive_redacted }),
        )?;
        Ok(PersonalPreferencesRedactionSummary {
            capture_id: capture_id.to_string(),
            redacted: true,
            archive_redacted,
        })
    }

    pub fn delete_capture(&self, capture_id: &str) -> Result<PersonalPreferencesDeleteSummary> {
        let capture = self.read_capture(capture_id)?;
        let Some(capture) = capture else {
            return Ok(PersonalPreferencesDeleteSummary {
                capture_id: capture_id.to_string(),
                deleted: false,
                archive_deleted: false,
                records_deleted: 0,
            });
        };
        let conn = open_db(&self.db_path)?;
        let records_deleted = count_query_with_param(
            &conn,
            "SELECT COUNT(*) FROM derived_records WHERE capture_id = ?1",
            params![capture_id],
        )?;
        conn.execute(
            "DELETE FROM captured_conversations WHERE id = ?1",
            params![capture_id],
        )?;
        self.delete_queue_marker(capture_id)?;
        let archive_deleted = if let Some(path) = capture.archive_path.as_deref() {
            delete_if_exists(Path::new(path))?
        } else {
            false
        };
        self.write_tombstone(
            capture_id,
            "delete",
            json!({ "archive_deleted": archive_deleted, "records_deleted": records_deleted }),
        )?;
        Ok(PersonalPreferencesDeleteSummary {
            capture_id: capture_id.to_string(),
            deleted: true,
            archive_deleted,
            records_deleted,
        })
    }

    pub fn purge_all(&self, include_exports: bool) -> Result<PersonalPreferencesPurgeSummary> {
        let conn = open_db(&self.db_path)?;
        let captures_deleted = count_query(&conn, "SELECT COUNT(*) FROM captured_conversations")?;
        let derived_records_deleted = count_query(&conn, "SELECT COUNT(*) FROM derived_records")?;
        conn.execute("DELETE FROM captured_conversations", [])?;
        conn.execute("DELETE FROM derived_records", [])?;
        conn.execute("DELETE FROM pp_sources", [])?;
        conn.execute("DELETE FROM pp_entities", [])?;
        let archives_deleted = remove_dir_contents(&self.archive_dir)?;
        let queue_entries_deleted = remove_dir_contents(&self.queue_dir)?;
        let exports_deleted = if include_exports {
            remove_dir_contents(&self.exports_dir)?
        } else {
            0
        };
        self.write_tombstone(
            "all",
            "purge",
            json!({
                "captures_deleted": captures_deleted,
                "derived_records_deleted": derived_records_deleted,
                "archives_deleted": archives_deleted,
                "queue_entries_deleted": queue_entries_deleted,
                "exports_deleted": exports_deleted,
            }),
        )?;
        Ok(PersonalPreferencesPurgeSummary {
            captures_deleted,
            derived_records_deleted,
            archives_deleted,
            queue_entries_deleted,
            exports_deleted,
        })
    }

    pub async fn process_pending_with_runner<F, Fut>(
        &self,
        limit: usize,
        mut runner: F,
    ) -> Result<PersonalPreferencesProcessingSummary>
    where
        F: FnMut(PersonalPreferenceDigestInput) -> Fut,
        Fut: Future<Output = Result<Option<PersonalPreferenceDigestOutput>>>,
    {
        let pending = self.list_pending_captures(limit.max(1))?;
        let mut summary = PersonalPreferencesProcessingSummary::default();
        for capture in pending {
            if !self.try_mark_capture_processing(&capture.id)? {
                continue;
            }
            summary.processed_captures += 1;
            let digest_job_id = self.create_digest_job(&capture.id)?;
            let input = PersonalPreferenceDigestInput {
                capture: capture.clone(),
            };
            match runner(input).await {
                Ok(Some(output)) => {
                    let written =
                        self.complete_capture(&capture.id, Some(&digest_job_id), &output.records)?;
                    self.complete_digest_job(
                        &digest_job_id,
                        DIGEST_STATUS_COMPLETED,
                        None,
                        json!({ "records_written": written }),
                    )?;
                    summary.records_written += written;
                    summary.completed_captures += 1;
                }
                Ok(None) => {
                    self.mark_capture_status(
                        &capture.id,
                        DIGEST_STATUS_PENDING,
                        Some("waiting_for_local_mcoda_agent"),
                    )?;
                    self.complete_digest_job(
                        &digest_job_id,
                        DIGEST_STATUS_PENDING,
                        Some("waiting_for_local_mcoda_agent"),
                        json!({}),
                    )?;
                    summary.deferred_captures += 1;
                }
                Err(err) => {
                    self.mark_capture_status(
                        &capture.id,
                        DIGEST_STATUS_FAILED,
                        Some(&err.to_string()),
                    )?;
                    self.complete_digest_job(
                        &digest_job_id,
                        DIGEST_STATUS_FAILED,
                        Some(&err.to_string()),
                        json!({}),
                    )?;
                    summary.failed_captures += 1;
                }
            }
        }
        Ok(summary)
    }

    pub fn requeue_captures_for_processing(
        &self,
        retry_failed: bool,
        retry_stale_processing_ms: Option<i64>,
        limit: Option<usize>,
    ) -> Result<usize> {
        if !retry_failed && retry_stale_processing_ms.is_none() {
            return Ok(0);
        }
        let limit = limit.unwrap_or(usize::MAX);
        if limit == 0 {
            return Ok(0);
        }
        let now = now_ms();
        let stale_before_ms =
            retry_stale_processing_ms.map(|value| now.saturating_sub(value.max(0)));
        let mut capture_ids = Vec::new();
        {
            let conn = open_db(&self.db_path)?;
            if retry_failed {
                let remaining = limit.saturating_sub(capture_ids.len());
                if remaining > 0 {
                    let mut stmt = conn.prepare(
                        "SELECT id
                         FROM captured_conversations
                         WHERE digest_status = ?1
                         ORDER BY updated_at_ms ASC, created_at_ms ASC
                         LIMIT ?2",
                    )?;
                    let mut rows = stmt.query(params![DIGEST_STATUS_FAILED, remaining as i64])?;
                    while let Some(row) = rows.next()? {
                        capture_ids.push(row.get::<_, String>(0)?);
                    }
                }
            }
            if let Some(stale_before_ms) = stale_before_ms {
                let remaining = limit.saturating_sub(capture_ids.len());
                if remaining > 0 {
                    let mut stmt = conn.prepare(
                        "SELECT id
                         FROM captured_conversations
                         WHERE digest_status = ?1 AND updated_at_ms <= ?2
                         ORDER BY updated_at_ms ASC, created_at_ms ASC
                         LIMIT ?3",
                    )?;
                    let mut rows = stmt.query(params![
                        DIGEST_STATUS_PROCESSING,
                        stale_before_ms,
                        remaining as i64
                    ])?;
                    while let Some(row) = rows.next()? {
                        capture_ids.push(row.get::<_, String>(0)?);
                    }
                }
            }
            for capture_id in &capture_ids {
                conn.execute(
                    "UPDATE captured_conversations
                     SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = NULL
                     WHERE id = ?1
                       AND digest_status IN (?4, ?5)",
                    params![
                        capture_id,
                        DIGEST_STATUS_PENDING,
                        now,
                        DIGEST_STATUS_FAILED,
                        DIGEST_STATUS_PROCESSING
                    ],
                )?;
            }
        }
        for capture_id in &capture_ids {
            self.sync_queue_marker(capture_id, DIGEST_STATUS_PENDING)?;
        }
        Ok(capture_ids.len())
    }

    pub fn list_projectable_records(&self, limit: usize) -> Result<Vec<PersonalPreferenceRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut records = load_all_records(&conn)?;
        records.retain(|record| {
            record.projected_to_profile_at_ms.is_none()
                && record.confidence >= 0.78
                && record.sensitivity == "low"
                && record.review_status == REVIEW_STATUS_APPROVED
                && map_record_to_profile_category(record).is_some()
        });
        records.sort_by(|left, right| {
            right
                .confidence
                .partial_cmp(&left.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
        });
        records.truncate(limit.max(1));
        Ok(records)
    }

    pub fn mark_records_projected(&self, record_ids: &[String]) -> Result<()> {
        if record_ids.is_empty() {
            return Ok(());
        }
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        for record_id in record_ids {
            conn.execute(
                "UPDATE derived_records
                 SET projected_to_profile_at_ms = ?2
                 WHERE id = ?1",
                params![record_id, now],
            )?;
        }
        Ok(())
    }

    fn list_pending_captures(&self, limit: usize) -> Result<Vec<PersonalPreferencesCaptureRecord>> {
        let conn = open_db(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                    repo_id, repo_root, scope_id, scope_label, started_at_ms, ended_at_ms,
                    created_at_ms, updated_at_ms, digest_status, transcript_text, metadata_json,
                    archive_path, raw_message_count, archive_redacted_at_ms, last_digest_error
             FROM captured_conversations
             WHERE digest_status = 'pending'
             ORDER BY created_at_ms ASC
             LIMIT ?1",
        )?;
        let mut rows = stmt.query(params![limit as i64])?;
        let mut captures = Vec::new();
        while let Some(row) = rows.next()? {
            let mut capture = row_to_capture(row)?;
            hydrate_capture_content(&mut capture);
            capture.messages = self.messages_for_capture(&capture.id, &capture.metadata)?;
            captures.push(capture);
        }
        Ok(captures)
    }

    fn messages_for_capture(
        &self,
        capture_id: &str,
        capture_metadata: &Value,
    ) -> Result<Vec<PersonalPreferencesMessage>> {
        let conn = open_db(&self.db_path)?;
        let cipher = resolve_cipher_from_metadata(capture_metadata);
        let mut stmt = conn.prepare(
            "SELECT role, content, created_at_ms, metadata_json
             FROM captured_messages
             WHERE capture_id = ?1
             ORDER BY ordinal ASC",
        )?;
        let mut rows = stmt.query(params![capture_id])?;
        let mut messages = Vec::new();
        while let Some(row) = rows.next()? {
            messages.push(PersonalPreferencesMessage {
                role: row.get::<_, String>(0)?,
                content: unprotect_text_for_reading(&row.get::<_, String>(1)?, cipher.as_ref()),
                created_at_ms: row.get(2)?,
                metadata: parse_json_value(&row.get::<_, String>(3)?),
            });
        }
        Ok(messages)
    }

    fn try_mark_capture_processing(&self, capture_id: &str) -> Result<bool> {
        let conn = open_db(&self.db_path)?;
        let updated = conn.execute(
            "UPDATE captured_conversations
             SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = NULL
             WHERE id = ?1 AND digest_status = ?4",
            params![
                capture_id,
                DIGEST_STATUS_PROCESSING,
                now_ms(),
                DIGEST_STATUS_PENDING
            ],
        )?;
        if updated > 0 {
            self.sync_queue_marker(capture_id, DIGEST_STATUS_PROCESSING)?;
        }
        Ok(updated > 0)
    }

    fn mark_capture_status(
        &self,
        capture_id: &str,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        let conn = open_db(&self.db_path)?;
        conn.execute(
            "UPDATE captured_conversations
             SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = ?4
             WHERE id = ?1",
            params![capture_id, status, now_ms(), error],
        )?;
        self.sync_queue_marker(capture_id, status)?;
        Ok(())
    }

    fn complete_capture(
        &self,
        capture_id: &str,
        digest_job_id: Option<&str>,
        records: &[PersonalPreferenceDigestRecord],
    ) -> Result<usize> {
        let capture = self
            .read_capture(capture_id)?
            .ok_or_else(|| anyhow!("capture not found"))?;
        let mut conn = open_db(&self.db_path)?;
        let tx = conn.transaction()?;
        tx.execute(
            "DELETE FROM derived_records WHERE capture_id = ?1",
            params![capture_id],
        )?;
        tx.execute(
            "DELETE FROM pp_snapshot_summaries WHERE capture_id = ?1",
            params![capture_id],
        )?;
        let now = now_ms();
        let mut inserted = 0usize;
        let mut seen = HashSet::new();
        let digest_run_id = format!("digest_run_{}", Uuid::new_v4());
        tx.execute(
            "INSERT INTO pp_digest_runs(
                id, job_id, capture_id, agent_id, model_hint, prompt_version, outcome_status,
                input_records, output_records, started_at_ms, finished_at_ms, error_text, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7, 0, ?8, NULL, NULL, ?9)",
            params![
                digest_run_id,
                digest_job_id,
                capture_id,
                capture.agent_id,
                "personal_preferences_v1",
                DIGEST_STATUS_PROCESSING,
                records.len() as i64,
                now,
                serde_json::to_string(&json!({
                    "capture_kind": capture.capture_kind,
                    "source": capture.source,
                }))?,
            ],
        )?;
        let mut snapshot_lines = Vec::new();
        for record in records.iter().take(MAX_DIGEST_RECORDS_PER_CAPTURE) {
            let normalized = normalize_digest_record(record, &capture);
            if normalized.value.is_empty() {
                continue;
            }
            let dedupe_key = format!(
                "{}|{}|{}|{}|{}",
                normalized.record_type,
                normalized.category,
                normalized.subject,
                normalized.attribute.clone().unwrap_or_default(),
                normalized.value
            );
            if !seen.insert(dedupe_key) {
                continue;
            }
            let policy = ensure_category_policy_for_record(&tx, &normalized)?;
            let review_status = default_review_status_for_record(&normalized, &policy);
            let record_id = Uuid::new_v4().to_string();
            tx.execute(
                "INSERT INTO derived_records(
                    id, capture_id, record_type, category, subcategory, subject,
                    attribute, value, confidence, sensitivity, evidence,
                    created_at_ms, updated_at_ms, metadata_json, projected_to_profile_at_ms,
                    review_status, review_updated_at_ms
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, NULL, ?15, ?16)",
                params![
                    record_id,
                    capture_id,
                    normalized.record_type,
                    normalized.category,
                    normalized.subcategory,
                    normalized.subject,
                    normalized.attribute,
                    normalized.value,
                    normalized.confidence,
                    normalized.sensitivity,
                    normalized.evidence,
                    now,
                    now,
                    serde_json::to_string(&normalized.metadata)?,
                    review_status,
                    now,
                ],
            )?;
            if let Some(evidence) = normalized.evidence.as_deref() {
                tx.execute(
                    "INSERT INTO pp_evidence(
                        id, record_id, capture_id, evidence_text, metadata_json, created_at_ms
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        Uuid::new_v4().to_string(),
                        record_id,
                        capture_id,
                        evidence,
                        serde_json::to_string(&normalized.metadata)?,
                        now,
                    ],
                )?;
            }
            let materialized = BackfillRecord {
                id: record_id.clone(),
                capture_id: capture_id.to_string(),
                record_type: normalized.record_type.clone(),
                category: normalized.category.clone(),
                subcategory: normalized.subcategory.clone(),
                subject: normalized.subject.clone(),
                attribute: normalized.attribute.clone(),
                value: normalized.value.clone(),
                confidence: normalized.confidence.unwrap_or(0.5),
                sensitivity: normalized
                    .sensitivity
                    .clone()
                    .unwrap_or_else(|| "private".to_string()),
                evidence: normalized.evidence.clone(),
                created_at_ms: now,
                updated_at_ms: now,
                metadata: normalized.metadata.clone(),
                review_status: review_status.to_string(),
            };
            materialize_record_views(&tx, &materialized)?;
            upsert_claim_from_backfill_record(&tx, &materialized, "capture_digest")?;
            if let Some(repo_root) = capture
                .repo_root
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                if should_materialize_bridge(&normalized) {
                    tx.execute(
                        "INSERT INTO pp_cross_project_bridges(
                            id, record_id, source_repo_root, target_repo_root, bridge_key, summary,
                            created_at_ms
                        ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6)",
                        params![
                            Uuid::new_v4().to_string(),
                            record_id,
                            repo_root,
                            bridge_key_for_record(&normalized),
                            render_digest_record(&normalized),
                            now,
                        ],
                    )?;
                }
            }
            if snapshot_lines.len() < SNAPSHOT_SUMMARY_LIMIT {
                snapshot_lines.push(render_digest_record(&normalized));
            }
            inserted += 1;
        }
        tx.execute(
            "UPDATE pp_digest_runs
             SET outcome_status = ?2, output_records = ?3, finished_at_ms = ?4
             WHERE id = ?1",
            params![digest_run_id, DIGEST_STATUS_COMPLETED, inserted as i64, now],
        )?;
        tx.execute(
            "INSERT INTO pp_snapshot_summaries(
                id, capture_id, digest_run_id, summary, record_count, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                format!("snapshot_{}_{}", capture_id, now),
                capture_id,
                digest_run_id,
                truncate_chars(&snapshot_lines.join(" | "), 640),
                inserted as i64,
                now,
                serde_json::to_string(&json!({
                    "capture_kind": capture.capture_kind,
                    "repo_root": capture.repo_root,
                }))?,
            ],
        )?;
        tx.execute(
            "UPDATE captured_conversations
             SET digest_status = ?2, updated_at_ms = ?3, last_digest_error = NULL
             WHERE id = ?1",
            params![capture_id, DIGEST_STATUS_COMPLETED, now],
        )?;
        let _ = rebuild_identity_snapshots_tx(&tx, Some(capture_id), "capture_complete")?;
        cleanup_orphan_entities(&tx)?;
        tx.commit()?;
        self.sync_queue_marker(capture_id, DIGEST_STATUS_COMPLETED)?;
        Ok(inserted)
    }

    fn write_archive_envelope(
        &self,
        capture_id: &str,
        created_at_ms: i64,
        request: &PersonalPreferencesCaptureRequest,
        cipher: Option<&ContentCipher>,
    ) -> Result<PathBuf> {
        let path = self.archive_dir.join(format!("{capture_id}.json"));
        let envelope = PersonalPreferencesArchiveEnvelope {
            capture_id: capture_id.to_string(),
            created_at_ms,
            request: protect_capture_request_payload(request, cipher),
        };
        fs::write(&path, serde_json::to_vec_pretty(&envelope)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(path)
    }

    fn read_archive_envelope(&self, path: &Path) -> Result<PersonalPreferencesArchiveEnvelope> {
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        let mut envelope: PersonalPreferencesArchiveEnvelope =
            serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
        let cipher = resolve_cipher_from_metadata(&envelope.request.metadata);
        envelope.request.transcript_text = envelope
            .request
            .transcript_text
            .map(|value| unprotect_text_for_reading(&value, cipher.as_ref()));
        envelope.request.summary_text = envelope
            .request
            .summary_text
            .map(|value| unprotect_text_for_reading(&value, cipher.as_ref()));
        envelope.request.messages = envelope
            .request
            .messages
            .into_iter()
            .map(|mut message| {
                message.content = unprotect_text_for_reading(&message.content, cipher.as_ref());
                message
            })
            .collect();
        Ok(envelope)
    }

    fn write_queue_marker(&self, capture: &PersonalPreferencesCaptureRecord) -> Result<()> {
        let path = self.queue_dir.join(format!("{}.json", capture.id));
        let payload = json!({
            "capture_id": capture.id,
            "source": capture.source,
            "repo_root": capture.repo_root,
            "created_at_ms": capture.created_at_ms,
            "digest_status": capture.digest_status,
        });
        fs::write(&path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    fn delete_queue_marker(&self, capture_id: &str) -> Result<()> {
        let path = self.queue_dir.join(format!("{capture_id}.json"));
        let _ = delete_if_exists(&path)?;
        Ok(())
    }

    fn sync_queue_marker(&self, capture_id: &str, status: &str) -> Result<()> {
        if status == DIGEST_STATUS_PENDING {
            if let Some(capture) = self.read_capture(capture_id)? {
                return self.write_queue_marker(&capture);
            }
            return Ok(());
        }
        self.delete_queue_marker(capture_id)
    }

    fn create_digest_job(&self, capture_id: &str) -> Result<String> {
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        let job_id = Uuid::new_v4().to_string();
        conn.execute(
            "INSERT INTO pp_digest_jobs(
                id, capture_id, status, error_text, started_at_ms, finished_at_ms,
                created_at_ms, updated_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, NULL, ?4, NULL, ?4, ?4, ?5)",
            params![
                job_id,
                capture_id,
                DIGEST_STATUS_PROCESSING,
                now,
                serde_json::to_string(&json!({}))?,
            ],
        )?;
        Ok(job_id)
    }

    fn complete_digest_job(
        &self,
        job_id: &str,
        status: &str,
        error: Option<&str>,
        metadata: Value,
    ) -> Result<()> {
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        conn.execute(
            "UPDATE pp_digest_jobs
             SET status = ?2,
                 error_text = ?3,
                 finished_at_ms = ?4,
                 updated_at_ms = ?4,
                 metadata_json = ?5
             WHERE id = ?1",
            params![
                job_id,
                status,
                error,
                now,
                serde_json::to_string(&metadata)?
            ],
        )?;
        Ok(())
    }

    fn write_tombstone(&self, capture_id: &str, action: &str, details: Value) -> Result<()> {
        let path = self
            .redactions_dir
            .join(format!("{}-{capture_id}-{action}.json", now_ms()));
        let payload = json!({
            "capture_id": capture_id,
            "action": action,
            "created_at_ms": now_ms(),
            "details": details,
        });
        fs::write(&path, serde_json::to_vec_pretty(&payload)?)
            .with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    fn has_external_session_ref(&self, external_ref: &str) -> Result<bool> {
        let external_ref = external_ref.trim();
        if external_ref.is_empty() {
            return Ok(false);
        }
        let conn = open_db(&self.db_path)?;
        let hash = sha256_hex(external_ref);
        Ok(conn
            .query_row(
                "SELECT 1 FROM pp_sessions WHERE external_ref_hash = ?1 LIMIT 1",
                params![hash],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }
}

fn resolve_content_cipher(env_name: Option<&str>) -> Option<ContentCipher> {
    let env_name = env_name
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let raw_secret = std::env::var(&env_name).ok()?;
    let key_bytes = derive_cipher_key(&raw_secret);
    Some(ContentCipher {
        key_id: sha256_hex(&raw_secret)[..16].to_string(),
        env_name,
        key_bytes,
    })
}

fn derive_cipher_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

fn prepare_capture_request_for_storage(
    mut request: PersonalPreferencesCaptureRequest,
    secret_scrubber_enabled: bool,
    cipher: Option<&ContentCipher>,
) -> PersonalPreferencesCaptureRequest {
    let transcript_text = request
        .transcript_text
        .take()
        .map(|value| maybe_scrub_secret_text(value, secret_scrubber_enabled));
    let summary_text = request
        .summary_text
        .take()
        .map(|value| maybe_scrub_secret_text(value, secret_scrubber_enabled));
    let messages = request
        .messages
        .into_iter()
        .map(|mut message| {
            message.content = maybe_scrub_secret_text(message.content, secret_scrubber_enabled);
            message
        })
        .collect::<Vec<_>>();
    request.transcript_text = transcript_text;
    request.summary_text = summary_text;
    request.messages = messages;
    let mut metadata = request.metadata.as_object().cloned().unwrap_or_default();
    let mut subsystem = metadata
        .remove("_docdex_personal_preferences")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    subsystem.insert(
        "secret_scrubber_enabled".to_string(),
        Value::Bool(secret_scrubber_enabled),
    );
    if let Some(cipher) = cipher {
        subsystem.insert("content_encrypted".to_string(), Value::Bool(true));
        subsystem.insert(
            "content_encryption_key_env".to_string(),
            Value::String(cipher.env_name.clone()),
        );
        subsystem.insert(
            "content_encryption_key_id".to_string(),
            Value::String(cipher.key_id.clone()),
        );
    }
    if let Some(external_ref) = external_ref_for_capture_request(&request) {
        subsystem.insert("external_ref".to_string(), Value::String(external_ref));
    }
    metadata.insert(
        "_docdex_personal_preferences".to_string(),
        Value::Object(subsystem),
    );
    request.metadata = Value::Object(metadata);
    request
}

fn maybe_scrub_secret_text(input: String, enabled: bool) -> String {
    if !enabled {
        return input;
    }
    scrub_secret_text(&input)
}

fn scrub_secret_text(input: &str) -> String {
    let mut output = input.to_string();
    for pattern in TRANSCRIPT_SECRET_PATTERNS.iter() {
        output = pattern
            .replace_all(&output, "[redacted_secret]")
            .into_owned();
    }
    output
}

fn protect_text_for_storage(text: &str, cipher: Option<&ContentCipher>) -> String {
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }
    let Some(cipher) = cipher else {
        return text.to_string();
    };
    encrypt_text(cipher, text).unwrap_or_else(|_| text.to_string())
}

fn unprotect_text_for_reading(text: &str, cipher: Option<&ContentCipher>) -> String {
    if !text.starts_with(ENCRYPTED_PREFIX) {
        return text.to_string();
    }
    let Some(cipher) = cipher else {
        return ENCRYPTED_UNAVAILABLE_TEXT.to_string();
    };
    decrypt_text(cipher, text).unwrap_or_else(|_| ENCRYPTED_UNREADABLE_TEXT.to_string())
}

fn encrypt_text(cipher: &ContentCipher, text: &str) -> Result<String> {
    let aes = Aes256Gcm::new_from_slice(&cipher.key_bytes)
        .context("initialize personal preferences content cipher")?;
    let nonce_seed = Uuid::new_v4().into_bytes();
    let nonce = Nonce::from_slice(&nonce_seed[..12]);
    let ciphertext = aes
        .encrypt(nonce, text.as_bytes())
        .map_err(|err| anyhow!("encrypt personal preferences content: {err}"))?;
    Ok(format!(
        "{ENCRYPTED_PREFIX}{}:{}:{}",
        cipher.key_id,
        Base64Engine.encode(&nonce_seed[..12]),
        Base64Engine.encode(ciphertext)
    ))
}

fn decrypt_text(cipher: &ContentCipher, text: &str) -> Result<String> {
    let payload = text
        .strip_prefix(ENCRYPTED_PREFIX)
        .ok_or_else(|| anyhow!("missing encrypted prefix"))?;
    let mut parts = payload.splitn(3, ':');
    let key_id = parts.next().unwrap_or_default();
    let nonce_b64 = parts.next().unwrap_or_default();
    let ciphertext_b64 = parts.next().unwrap_or_default();
    if key_id != cipher.key_id {
        return Err(anyhow!("content encryption key mismatch"));
    }
    let nonce_bytes = Base64Engine
        .decode(nonce_b64)
        .context("decode content nonce")?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!("invalid content nonce length"));
    }
    let ciphertext = Base64Engine
        .decode(ciphertext_b64)
        .context("decode encrypted content")?;
    let aes = Aes256Gcm::new_from_slice(&cipher.key_bytes)
        .context("initialize personal preferences decrypt cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = aes
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|err| anyhow!("decrypt personal preferences content: {err}"))?;
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

fn resolve_cipher_from_metadata(metadata: &Value) -> Option<ContentCipher> {
    metadata
        .get("_docdex_personal_preferences")
        .and_then(Value::as_object)
        .and_then(|value| value.get("content_encryption_key_env"))
        .and_then(Value::as_str)
        .and_then(|value| resolve_content_cipher(Some(value)))
}

fn protect_capture_request_payload(
    request: &PersonalPreferencesCaptureRequest,
    cipher: Option<&ContentCipher>,
) -> PersonalPreferencesCaptureRequest {
    let mut payload = request.clone();
    payload.transcript_text = payload
        .transcript_text
        .map(|value| protect_text_for_storage(&value, cipher));
    payload.summary_text = payload
        .summary_text
        .map(|value| protect_text_for_storage(&value, cipher));
    payload.messages = payload
        .messages
        .into_iter()
        .map(|mut message| {
            message.content = protect_text_for_storage(&message.content, cipher);
            message
        })
        .collect();
    payload
}

fn hydrate_capture_content(capture: &mut PersonalPreferencesCaptureRecord) {
    let cipher = resolve_cipher_from_metadata(&capture.metadata);
    capture.transcript_text = unprotect_text_for_reading(&capture.transcript_text, cipher.as_ref());
}

fn upsert_source_and_session_lineage(
    conn: &Connection,
    capture_id: &str,
    request: &PersonalPreferencesCaptureRequest,
    digest_status: &str,
    now: i64,
) -> Result<()> {
    let normalized_source = slugify_identifier(&request.source);
    let source_id = if normalized_source.is_empty() {
        "manual".to_string()
    } else {
        normalized_source
    };
    let source_type = if is_supported_client_transcript_source(&request.source) {
        "supported_client"
    } else if request
        .capture_kind
        .as_deref()
        .unwrap_or_default()
        .contains("hook")
    {
        "docdex_hook"
    } else if request
        .capture_kind
        .as_deref()
        .unwrap_or_default()
        .contains("import")
    {
        "conversation_import"
    } else {
        "docdex"
    };
    let external_ref = external_ref_for_capture_request(request);
    let external_ref_hash = external_ref.as_deref().map(sha256_hex);
    conn.execute(
        "INSERT INTO pp_sources(
            source_id, source_type, client_kind, agent_kind, enabled, last_seen_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
         ON CONFLICT(source_id) DO UPDATE SET
            source_type = excluded.source_type,
            client_kind = excluded.client_kind,
            agent_kind = excluded.agent_kind,
            enabled = excluded.enabled,
            last_seen_at_ms = excluded.last_seen_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            source_id,
            source_type,
            slugify_identifier(&request.source),
            request.agent_id.clone().unwrap_or_default(),
            now,
            serde_json::to_string(&json!({
                "source": request.source,
                "capture_kind": request.capture_kind,
                "transport": request.transport,
            }))?,
        ],
    )?;
    conn.execute(
        "INSERT INTO pp_sessions(
            capture_id, source_id, source_session_id, external_ref, external_ref_hash,
            capture_kind, title, digest_status, sensitivity_summary, started_at_ms,
            ended_at_ms, created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, ?11, ?12)
         ON CONFLICT(capture_id) DO UPDATE SET
            source_id = excluded.source_id,
            source_session_id = excluded.source_session_id,
            external_ref = excluded.external_ref,
            external_ref_hash = excluded.external_ref_hash,
            capture_kind = excluded.capture_kind,
            title = excluded.title,
            digest_status = excluded.digest_status,
            started_at_ms = excluded.started_at_ms,
            ended_at_ms = excluded.ended_at_ms,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            capture_id,
            source_id,
            request.source_session_id,
            external_ref,
            external_ref_hash,
            request.capture_kind,
            request.title,
            digest_status,
            request.started_at_ms,
            request.ended_at_ms,
            now,
            serde_json::to_string(&request.metadata)?,
        ],
    )?;
    Ok(())
}

fn collect_client_transcript_candidates(
    config: &MemoryPersonalPreferencesConfig,
    limit: usize,
) -> Result<Vec<ClientTranscriptCandidate>> {
    let mut roots = config
        .client_transcript_roots
        .iter()
        .filter_map(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(PathBuf::from(trimmed))
            }
        })
        .collect::<Vec<_>>();
    if roots.is_empty() {
        roots.extend(default_client_transcript_roots());
    }
    let mut candidates = Vec::<(std::time::SystemTime, ClientTranscriptCandidate)>::new();
    for root in roots {
        if !root.exists() {
            continue;
        }
        for entry in WalkDir::new(&root)
            .max_depth(6)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !looks_like_transcript_file(path) {
                continue;
            }
            let source = infer_transcript_source(path).unwrap_or_else(|| "manual".to_string());
            if !is_supported_client_transcript_source(&source) {
                continue;
            }
            let adapter_kind = infer_transcript_adapter_kind(&source, path);
            let metadata = entry.metadata().ok();
            let modified = metadata
                .as_ref()
                .and_then(|item| item.modified().ok())
                .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
            let format = infer_transcript_format(path, &source);
            candidates.push((
                modified,
                ClientTranscriptCandidate {
                    source,
                    adapter_kind,
                    path: path.to_path_buf(),
                    format,
                },
            ));
        }
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0));
    candidates.truncate(limit.max(1));
    Ok(candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect())
}

fn default_client_transcript_roots() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    vec![
        home.join(".codex").join("sessions"),
        home.join(".claude").join("projects"),
        home.join(".gemini"),
        home.join(".gemini-cli"),
        home.join(".mcoda").join("conversations"),
    ]
}

fn looks_like_transcript_file(path: &Path) -> bool {
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    let file_name = file_name.to_ascii_lowercase();
    if matches!(
        file_name.as_str(),
        "logs.json" | "conversation.json" | "session.json" | "transcript.json"
    ) {
        return true;
    }
    path.extension()
        .and_then(|value| value.to_str())
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "json" | "jsonl" | "md" | "txt" | "log"
            )
        })
        .unwrap_or(false)
}

fn infer_transcript_source(path: &Path) -> Option<String> {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    for candidate in ["codex", "claude", "gemini", "mcoda", "chatgpt", "openai"] {
        if lower.contains(candidate) {
            return Some(candidate.to_string());
        }
    }
    None
}

fn infer_transcript_adapter_kind(source: &str, path: &Path) -> String {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    match source {
        "codex" => "codex".to_string(),
        "claude" => "claude".to_string(),
        "gemini" => "gemini".to_string(),
        "mcoda" => "mcoda".to_string(),
        "openai" | "chatgpt" => "openai".to_string(),
        _ if lower.contains("codex") => "codex".to_string(),
        _ if lower.contains("claude") => "claude".to_string(),
        _ if lower.contains("gemini") => "gemini".to_string(),
        _ if lower.contains("mcoda") => "mcoda".to_string(),
        _ if lower.contains("openai") || lower.contains("chatgpt") => "openai".to_string(),
        _ => "generic".to_string(),
    }
}

fn infer_transcript_format(path: &Path, source: &str) -> Option<ConversationImportFormat> {
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    match (source, ext.as_deref()) {
        ("codex", Some("jsonl")) => Some(ConversationImportFormat::CodexJsonl),
        ("claude", Some("jsonl")) => Some(ConversationImportFormat::ClaudeJsonl),
        ("chatgpt", Some("json")) => Some(ConversationImportFormat::ChatgptExport),
        (_, Some("txt" | "md" | "log")) => Some(ConversationImportFormat::PlainText),
        (_, Some("json")) => Some(ConversationImportFormat::GenericJson),
        (_, Some("jsonl")) => Some(ConversationImportFormat::Auto),
        _ => Some(ConversationImportFormat::Auto),
    }
}

fn load_transcript_candidate_imports(
    candidate: &ClientTranscriptCandidate,
) -> Result<Vec<ConversationImport>> {
    let raw = fs::read_to_string(&candidate.path)
        .with_context(|| format!("read transcript {}", candidate.path.display()))?;
    if raw.trim().is_empty() {
        return Ok(Vec::new());
    }
    match candidate.adapter_kind.as_str() {
        "gemini" => {
            if let Ok(imports) = load_gemini_transcript_imports(candidate, &raw) {
                if !imports.is_empty() {
                    return Ok(imports);
                }
            }
        }
        "codex" | "claude" | "mcoda" | "openai" | "generic" => {}
        _ => {}
    }
    let envelope = ConversationImportEnvelope {
        source: Some(candidate.source.clone()),
        source_session_id: None,
        title: candidate
            .path
            .file_stem()
            .and_then(|value| value.to_str())
            .map(ToOwned::to_owned),
        agent_id: None,
        transport: Some("client_transcript_scan".to_string()),
        started_at_ms: None,
        ended_at_ms: None,
        format: candidate.format.map(|value| value.as_str().to_string()),
        messages: None,
        transcript_text: Some(raw),
        metadata: json!({}),
    };
    let import = normalize_import_request(envelope).map_err(|err| anyhow!(err))?;
    Ok(vec![import])
}

fn load_gemini_transcript_imports(
    candidate: &ClientTranscriptCandidate,
    raw: &str,
) -> Result<Vec<ConversationImport>> {
    let value: Value = serde_json::from_str(raw)
        .with_context(|| format!("parse gemini transcript {}", candidate.path.display()))?;
    let sessions = match &value {
        Value::Array(items)
            if items.iter().all(|item| {
                item.get("messages").is_some()
                    || item.get("contents").is_some()
                    || item.get("history").is_some()
            }) =>
        {
            items.clone()
        }
        _ => vec![value],
    };
    let mut imports = Vec::new();
    for session in sessions {
        let Some(messages_value) = session
            .get("messages")
            .or_else(|| session.get("contents"))
            .or_else(|| session.get("history"))
        else {
            continue;
        };
        let messages = gemini_messages_from_value(messages_value);
        if messages.is_empty() {
            continue;
        }
        let source_session_id = first_text_from_value(
            &session,
            &["source_session_id", "session_id", "id", "conversation_id"],
        );
        let title = first_text_from_value(&session, &["title", "name"]);
        imports.push(ConversationImport {
            source: candidate.source.clone(),
            source_session_id,
            title,
            agent_id: None,
            transport: Some("client_transcript_scan".to_string()),
            started_at_ms: None,
            ended_at_ms: None,
            messages,
            metadata: object_or_empty_for_personal_preferences(session),
        });
    }
    Ok(imports)
}

fn gemini_messages_from_value(value: &Value) -> Vec<ConversationMessage> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let role = item
                .get("role")
                .and_then(Value::as_str)
                .or_else(|| item.get("author").and_then(Value::as_str))
                .unwrap_or("other");
            let content = item
                .get("parts")
                .and_then(Value::as_array)
                .map(|parts| {
                    parts
                        .iter()
                        .filter_map(|part| {
                            part.get("text")
                                .and_then(Value::as_str)
                                .map(ToOwned::to_owned)
                        })
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .filter(|text| !text.trim().is_empty())
                .or_else(|| {
                    item.get("content")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .or_else(|| {
                    item.get("text")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })?;
            Some(ConversationMessage {
                role: crate::conversations::ConversationRole::from_str(role),
                content: content.trim().to_string(),
                author: item
                    .get("author")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                created_at_ms: parse_timestamp_json_value(
                    item.get("created_at_ms")
                        .or_else(|| item.get("created_at"))
                        .or_else(|| item.get("timestamp")),
                ),
                metadata: object_or_empty_for_personal_preferences(item.clone()),
            })
        })
        .filter(|message| !message.content.is_empty())
        .collect()
}

fn capture_request_from_import(
    candidate: &ClientTranscriptCandidate,
    import: ConversationImport,
) -> PersonalPreferencesCaptureRequest {
    let messages = import
        .messages
        .into_iter()
        .map(|message| PersonalPreferencesMessage {
            role: message.role.as_str().to_string(),
            content: message.content,
            created_at_ms: message.created_at_ms,
            metadata: message.metadata,
        })
        .collect::<Vec<_>>();
    let transcript_text = if messages.is_empty() {
        None
    } else {
        Some(
            messages
                .iter()
                .map(|message| format!("{}: {}", message.role, message.content.trim()))
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };
    let mut metadata = import.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert(
        "client_transcript_path".to_string(),
        Value::String(candidate.path.display().to_string()),
    );
    metadata.insert(
        "client_transcript_source".to_string(),
        Value::String(candidate.source.clone()),
    );
    metadata.insert(
        "client_transcript_adapter".to_string(),
        Value::String(candidate.adapter_kind.clone()),
    );
    metadata.insert(
        "client_transcript_format".to_string(),
        Value::String(
            candidate
                .format
                .unwrap_or(ConversationImportFormat::Auto)
                .as_str()
                .to_string(),
        ),
    );
    metadata.insert(
        "external_ref".to_string(),
        Value::String(format!(
            "{}:{}",
            candidate.path.display(),
            import
                .source_session_id
                .clone()
                .or_else(|| import.title.clone())
                .unwrap_or_else(|| "session".to_string())
        )),
    );
    PersonalPreferencesCaptureRequest {
        source: candidate.source.clone(),
        source_session_id: import.source_session_id,
        capture_kind: Some("client_transcript_scan".to_string()),
        title: import.title,
        agent_id: import.agent_id,
        transport: Some("client_transcript_scan".to_string()),
        repo_id: None,
        repo_root: None,
        scope_id: Some(format!(
            "client_transcript:{}",
            slugify_identifier(&candidate.source)
        )),
        scope_label: Some(candidate.path.display().to_string()),
        started_at_ms: import.started_at_ms,
        ended_at_ms: import.ended_at_ms,
        messages,
        transcript_text,
        summary_text: None,
        metadata: Value::Object(metadata),
    }
}

fn external_ref_for_capture_request(request: &PersonalPreferencesCaptureRequest) -> Option<String> {
    request
        .metadata
        .get("_docdex_personal_preferences")
        .and_then(Value::as_object)
        .and_then(|value| value.get("external_ref"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            request
                .metadata
                .get("external_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            request
                .metadata
                .get("client_transcript_path")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            request
                .source_session_id
                .as_deref()
                .map(|value| format!("{}:{value}", request.source))
        })
}

fn seed_default_sensitivity_levels(conn: &Connection) -> Result<()> {
    for (level, rank, description) in [
        ("low", 0_i64, "Safe to use for default context assembly."),
        (
            "private",
            1_i64,
            "Private user context; excluded unless explicitly allowed.",
        ),
        (
            "sensitive",
            2_i64,
            "Sensitive personal or business information.",
        ),
        (
            "special",
            3_i64,
            "Highly sensitive or specially protected information.",
        ),
    ] {
        conn.execute(
            "INSERT INTO pp_sensitivity_levels(level, rank, description)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(level) DO UPDATE SET
                rank = excluded.rank,
                description = excluded.description",
            params![level, rank, description],
        )?;
    }
    Ok(())
}

fn seed_default_context_policies(conn: &Connection) -> Result<()> {
    for seed in DEFAULT_CATEGORY_POLICIES {
        conn.execute(
            "INSERT INTO pp_context_policies(
                category, context_section, context_allowed_default, allow_sensitive,
                requires_review_for_sensitive, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(category) DO UPDATE SET
                context_section = excluded.context_section,
                context_allowed_default = excluded.context_allowed_default,
                allow_sensitive = excluded.allow_sensitive,
                requires_review_for_sensitive = excluded.requires_review_for_sensitive,
                updated_at_ms = excluded.updated_at_ms",
            params![
                seed.category,
                seed.context_section,
                if seed.context_allowed_default { 1 } else { 0 },
                if seed.context_allowed_default { 0 } else { 1 },
                if seed.requires_review_for_sensitive {
                    1
                } else {
                    0
                },
                now_ms(),
            ],
        )?;
    }
    Ok(())
}

fn seed_default_retention_policies(conn: &Connection) -> Result<()> {
    let defaults = MemoryPersonalPreferencesConfig::default();
    let now = now_ms();
    for (policy_key, lane, raw_days, derived_days, claim_days, snapshot_days, export_days) in [
        (
            "raw_archive",
            "raw_archive",
            Some(defaults.raw_retention_days),
            None,
            None,
            None,
            Some(defaults.raw_retention_days),
        ),
        (
            "derived_memory",
            "derived_memory",
            None,
            Some(defaults.derived_retention_days),
            Some(defaults.derived_retention_days),
            Some(defaults.derived_retention_days),
            None,
        ),
        (
            "clone_artifacts",
            "clone_artifacts",
            None,
            None,
            Some(defaults.derived_retention_days),
            Some(defaults.derived_retention_days),
            Some(defaults.raw_retention_days),
        ),
    ] {
        conn.execute(
            "INSERT INTO pp_retention_policies(
                id, policy_key, lane, category, raw_retention_days, derived_retention_days,
                claim_retention_days, snapshot_retention_days, export_retention_days,
                updated_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(policy_key) DO UPDATE SET
                lane = excluded.lane,
                raw_retention_days = excluded.raw_retention_days,
                derived_retention_days = excluded.derived_retention_days,
                claim_retention_days = excluded.claim_retention_days,
                snapshot_retention_days = excluded.snapshot_retention_days,
                export_retention_days = excluded.export_retention_days,
                updated_at_ms = excluded.updated_at_ms,
                metadata_json = excluded.metadata_json",
            params![
                format!("retention_policy_{}", policy_key),
                policy_key,
                lane,
                raw_days.map(i64::from),
                derived_days.map(i64::from),
                claim_days.map(i64::from),
                snapshot_days.map(i64::from),
                export_days.map(i64::from),
                now,
                serde_json::to_string(&json!({ "seeded": true }))?,
            ],
        )?;
    }
    Ok(())
}

fn load_retention_policies(conn: &Connection) -> Result<Vec<PersonalPreferenceRetentionPolicy>> {
    let mut stmt = conn.prepare(
        "SELECT policy_key, lane, category, raw_retention_days, derived_retention_days,
                claim_retention_days, snapshot_retention_days, export_retention_days,
                updated_at_ms, metadata_json
         FROM pp_retention_policies
         ORDER BY lane ASC, policy_key ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut items = Vec::new();
    while let Some(row) = rows.next()? {
        items.push(PersonalPreferenceRetentionPolicy {
            policy_key: row.get(0)?,
            lane: row.get(1)?,
            category: row.get(2)?,
            raw_retention_days: optional_i64_to_u32(row.get(3)?),
            derived_retention_days: optional_i64_to_u32(row.get(4)?),
            claim_retention_days: optional_i64_to_u32(row.get(5)?),
            snapshot_retention_days: optional_i64_to_u32(row.get(6)?),
            export_retention_days: optional_i64_to_u32(row.get(7)?),
            updated_at_ms: row.get(8)?,
            metadata: parse_json_value(&row.get::<_, String>(9)?),
        });
    }
    Ok(items)
}

fn optional_i64_to_u32(value: Option<i64>) -> Option<u32> {
    value.and_then(|item| u32::try_from(item).ok())
}

fn upsert_retention_policy(
    conn: &Connection,
    policy_key: &str,
    lane: &str,
    raw_retention_days: Option<u32>,
    derived_retention_days: Option<u32>,
    claim_retention_days: Option<u32>,
    snapshot_retention_days: Option<u32>,
    export_retention_days: Option<u32>,
    metadata: &Value,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_retention_policies(
            id, policy_key, lane, category, raw_retention_days, derived_retention_days,
            claim_retention_days, snapshot_retention_days, export_retention_days,
            updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, NULL, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
         ON CONFLICT(policy_key) DO UPDATE SET
            lane = excluded.lane,
            raw_retention_days = excluded.raw_retention_days,
            derived_retention_days = excluded.derived_retention_days,
            claim_retention_days = excluded.claim_retention_days,
            snapshot_retention_days = excluded.snapshot_retention_days,
            export_retention_days = excluded.export_retention_days,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            format!("retention_policy_{policy_key}"),
            policy_key,
            lane,
            raw_retention_days.map(i64::from),
            derived_retention_days.map(i64::from),
            claim_retention_days.map(i64::from),
            snapshot_retention_days.map(i64::from),
            export_retention_days.map(i64::from),
            now_ms(),
            serde_json::to_string(metadata)?,
        ],
    )?;
    Ok(())
}

fn write_redaction_span(
    conn: &Connection,
    capture_id: &str,
    claim_id: Option<&str>,
    span_kind: &str,
    start_offset: Option<i64>,
    end_offset: Option<i64>,
    replacement_text: &str,
    reason: &str,
    metadata: &Value,
    created_at_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_redaction_spans(
            id, capture_id, claim_id, span_kind, start_offset, end_offset, replacement_text,
            reason, created_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            format!("redaction_span_{}", Uuid::new_v4()),
            capture_id,
            claim_id,
            normalize_text(span_kind),
            start_offset,
            end_offset,
            normalize_text(replacement_text),
            normalize_text(reason),
            created_at_ms,
            serde_json::to_string(metadata)?,
        ],
    )?;
    Ok(())
}

fn file_modified_at_ms(path: &Path) -> Result<i64> {
    let modified = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .modified()
        .with_context(|| format!("read modified time for {}", path.display()))?;
    Ok(modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0))
}

fn count_files_older_than(dir: &Path, cutoff_ms: i64) -> Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut count = 0usize;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if file_modified_at_ms(&entry.path())? < cutoff_ms {
            count += 1;
        }
    }
    Ok(count)
}

fn prune_files_older_than(dir: &Path, cutoff_ms: i64) -> Result<usize> {
    if !dir.exists() {
        return Ok(0);
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let path = entry.path();
        if file_modified_at_ms(&path)? < cutoff_ms {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn backfill_rich_capture_lineage(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, source, source_session_id, capture_kind, title, agent_id, transport,
                started_at_ms, ended_at_ms, created_at_ms, updated_at_ms, digest_status, metadata_json
         FROM captured_conversations",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<i64>>(7)?,
            row.get::<_, Option<i64>>(8)?,
            row.get::<_, i64>(9)?,
            row.get::<_, i64>(10)?,
            row.get::<_, String>(11)?,
            row.get::<_, String>(12)?,
        ))
    })?;
    for row in rows {
        let (
            capture_id,
            source,
            source_session_id,
            capture_kind,
            title,
            agent_id,
            transport,
            started_at_ms,
            ended_at_ms,
            created_at_ms,
            updated_at_ms,
            digest_status,
            metadata_json,
        ) = row?;
        let metadata = parse_json_value(&metadata_json);
        let request = PersonalPreferencesCaptureRequest {
            source,
            source_session_id,
            capture_kind,
            title,
            agent_id,
            transport,
            repo_id: None,
            repo_root: None,
            scope_id: None,
            scope_label: None,
            started_at_ms,
            ended_at_ms,
            messages: Vec::new(),
            transcript_text: None,
            summary_text: None,
            metadata: metadata.clone(),
        };
        upsert_source_and_session_lineage(
            conn,
            &capture_id,
            &request,
            &digest_status,
            updated_at_ms.max(created_at_ms),
        )?;
    }

    let mut stmt = conn.prepare(
        "SELECT id, capture_id, ordinal, role, content, created_at_ms, metadata_json
         FROM captured_messages
         ORDER BY capture_id ASC, ordinal ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<i64>>(5)?,
            row.get::<_, String>(6)?,
        ))
    })?;
    for row in rows {
        let (id, capture_id, ordinal, role, content, created_at_ms, metadata_json) = row?;
        conn.execute(
            "INSERT OR IGNORE INTO pp_messages(
                id, capture_id, message_id, ordinal, role, content, created_at_ms, metadata_json
             ) VALUES (?1, ?2, ?1, ?3, ?4, ?5, ?6, ?7)",
            params![
                id,
                capture_id,
                ordinal,
                role,
                content,
                created_at_ms,
                metadata_json
            ],
        )?;
    }
    Ok(())
}

fn backfill_rich_derived_materialization(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT id, capture_id, record_type, category, subcategory, subject, attribute, value,
                confidence, sensitivity, evidence, created_at_ms, updated_at_ms, metadata_json,
                review_status
         FROM derived_records
         ORDER BY updated_at_ms ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(BackfillRecord {
            id: row.get(0)?,
            capture_id: row.get(1)?,
            record_type: row.get(2)?,
            category: row.get(3)?,
            subcategory: row.get(4)?,
            subject: row.get(5)?,
            attribute: row.get(6)?,
            value: row.get(7)?,
            confidence: row.get(8)?,
            sensitivity: row.get(9)?,
            evidence: row.get(10)?,
            created_at_ms: row.get(11)?,
            updated_at_ms: row.get(12)?,
            metadata: parse_json_value(&row.get::<_, String>(13)?),
            review_status: row.get(14)?,
        })
    })?;
    for row in rows {
        materialize_record_views(conn, &row?)?;
    }
    backfill_snapshot_summaries(conn)?;
    cleanup_orphan_entities(conn)?;
    Ok(())
}

#[derive(Debug, Clone)]
struct BackfillRecord {
    id: String,
    capture_id: String,
    record_type: String,
    category: String,
    subcategory: Option<String>,
    subject: String,
    attribute: Option<String>,
    value: String,
    confidence: f32,
    sensitivity: String,
    evidence: Option<String>,
    created_at_ms: i64,
    updated_at_ms: i64,
    metadata: Value,
    review_status: String,
}

fn materialize_record_views(conn: &Connection, record: &BackfillRecord) -> Result<()> {
    if let Some(subcategory) = record
        .subcategory
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        conn.execute(
            "INSERT INTO pp_subcategories(category, subcategory, description, created_at_ms, updated_at_ms)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(category, subcategory) DO UPDATE SET
                description = COALESCE(excluded.description, pp_subcategories.description),
                updated_at_ms = excluded.updated_at_ms",
            params![
                record.category,
                subcategory,
                format!("Observed subcategory for {}", record.category),
                record.created_at_ms,
                record.updated_at_ms,
            ],
        )?;
    }

    let subject_entity_id = ensure_entity(
        conn,
        entity_kind_for_record(record),
        &record.subject,
        &record.metadata,
        record.created_at_ms,
        record.updated_at_ms,
    )?;
    let object_entity_id = if should_use_object_entity(record) {
        Some(ensure_entity(
            conn,
            object_entity_kind_for_record(record),
            &record.value,
            &record.metadata,
            record.created_at_ms,
            record.updated_at_ms,
        )?)
    } else {
        None
    };

    let observation_id = format!("obs_{}", record.id);
    conn.execute(
        "INSERT INTO pp_observations(
            id, digest_run_id, record_id, capture_id, observation_type, summary,
            confidence, sensitivity, created_at_ms, metadata_json
         ) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET
            observation_type = excluded.observation_type,
            summary = excluded.summary,
            confidence = excluded.confidence,
            sensitivity = excluded.sensitivity,
            metadata_json = excluded.metadata_json",
        params![
            observation_id,
            record.id,
            record.capture_id,
            record.record_type,
            format!(
                "[{}] {} {} {}",
                record.category,
                record.subject,
                record.attribute.as_deref().unwrap_or("notes"),
                record.value
            ),
            record.confidence,
            record.sensitivity,
            record.created_at_ms,
            serde_json::to_string(&json!({
                "record_metadata": record.metadata,
                "evidence": record.evidence,
            }))?,
        ],
    )?;

    let relation_id = format!("rel_{}", record.id);
    conn.execute(
        "INSERT INTO pp_relations(
            id, record_id, capture_id, subject_entity_id, relation_type, object_entity_id,
            literal_object, confidence, sensitivity, status, created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
         ON CONFLICT(id) DO UPDATE SET
            relation_type = excluded.relation_type,
            object_entity_id = excluded.object_entity_id,
            literal_object = excluded.literal_object,
            confidence = excluded.confidence,
            sensitivity = excluded.sensitivity,
            status = excluded.status,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            relation_id,
            record.id,
            record.capture_id,
            subject_entity_id,
            relation_type_for_record(record),
            object_entity_id,
            if should_use_object_entity(record) {
                Option::<String>::None
            } else {
                Some(record.value.clone())
            },
            record.confidence,
            record.sensitivity,
            record.review_status,
            record.created_at_ms,
            record.updated_at_ms,
            serde_json::to_string(&record.metadata)?,
        ],
    )?;

    upsert_materialized_table(conn, record)?;
    Ok(())
}

fn upsert_materialized_table(conn: &Connection, record: &BackfillRecord) -> Result<()> {
    let id = format!("typed_{}", record.id);
    match record.record_type.as_str() {
        "preference" | "like" | "dislike" => {
            conn.execute(
                "INSERT INTO pp_preferences(
                    id, record_id, preference_type, target_name, normalized_target, confidence,
                    sensitivity, status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(record_id) DO UPDATE SET
                    preference_type = excluded.preference_type,
                    target_name = excluded.target_name,
                    normalized_target = excluded.normalized_target,
                    confidence = excluded.confidence,
                    sensitivity = excluded.sensitivity,
                    status = excluded.status,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    id,
                    record.id,
                    record
                        .attribute
                        .clone()
                        .unwrap_or_else(|| record.record_type.clone()),
                    record.value,
                    slugify_identifier(&record.value),
                    record.confidence,
                    record.sensitivity,
                    record.review_status,
                    record.created_at_ms,
                    record.updated_at_ms,
                ],
            )?;
        }
        "capability" | "trait"
            if matches!(record.category.as_str(), "strengths" | "limitations") =>
        {
            conn.execute(
                "INSERT INTO pp_capabilities(
                    id, record_id, capability_name, proficiency_signal, confidence,
                    sensitivity, status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(record_id) DO UPDATE SET
                    capability_name = excluded.capability_name,
                    proficiency_signal = excluded.proficiency_signal,
                    confidence = excluded.confidence,
                    sensitivity = excluded.sensitivity,
                    status = excluded.status,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    id,
                    record.id,
                    record.value,
                    record.attribute,
                    record.confidence,
                    record.sensitivity,
                    record.review_status,
                    record.created_at_ms,
                    record.updated_at_ms,
                ],
            )?;
        }
        "project" | "goal"
            if record.category.contains("project") || record.category.contains("goal") =>
        {
            conn.execute(
                "INSERT INTO pp_projects(
                    id, record_id, project_name, repo_root, goal_summary, confidence,
                    sensitivity, status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT(record_id) DO UPDATE SET
                    project_name = excluded.project_name,
                    repo_root = excluded.repo_root,
                    goal_summary = excluded.goal_summary,
                    confidence = excluded.confidence,
                    sensitivity = excluded.sensitivity,
                    status = excluded.status,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    id,
                    record.id,
                    record.subject,
                    record
                        .metadata
                        .get("repo_root")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned),
                    record.value,
                    record.confidence,
                    record.sensitivity,
                    record.review_status,
                    record.created_at_ms,
                    record.updated_at_ms,
                ],
            )?;
        }
        "method" | "bridge" => {
            conn.execute(
                "INSERT INTO pp_methods(
                    id, record_id, method_name, method_kind, confidence,
                    sensitivity, status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                 ON CONFLICT(record_id) DO UPDATE SET
                    method_name = excluded.method_name,
                    method_kind = excluded.method_kind,
                    confidence = excluded.confidence,
                    sensitivity = excluded.sensitivity,
                    status = excluded.status,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    id,
                    record.id,
                    record.value,
                    record.attribute,
                    record.confidence,
                    record.sensitivity,
                    record.review_status,
                    record.created_at_ms,
                    record.updated_at_ms,
                ],
            )?;
        }
        _ => {
            conn.execute(
                "INSERT INTO pp_personal_facts(
                    id, record_id, category, subcategory, subject, attribute, value,
                    confidence, sensitivity, status, created_at_ms, updated_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                 ON CONFLICT(record_id) DO UPDATE SET
                    category = excluded.category,
                    subcategory = excluded.subcategory,
                    subject = excluded.subject,
                    attribute = excluded.attribute,
                    value = excluded.value,
                    confidence = excluded.confidence,
                    sensitivity = excluded.sensitivity,
                    status = excluded.status,
                    updated_at_ms = excluded.updated_at_ms",
                params![
                    id,
                    record.id,
                    record.category,
                    record.subcategory,
                    record.subject,
                    record.attribute,
                    record.value,
                    record.confidence,
                    record.sensitivity,
                    record.review_status,
                    record.created_at_ms,
                    record.updated_at_ms,
                ],
            )?;
        }
    }
    Ok(())
}

fn backfill_snapshot_summaries(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT capture_id, COUNT(*), GROUP_CONCAT(category || ':' || value, ' | ')
         FROM derived_records
         GROUP BY capture_id",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for row in rows {
        let (capture_id, record_count, summary_blob) = row?;
        let summary = truncate_chars(&summary_blob, 640);
        conn.execute(
            "INSERT OR IGNORE INTO pp_snapshot_summaries(
                id, capture_id, digest_run_id, summary, record_count, created_at_ms, metadata_json
             ) VALUES (?1, ?2, NULL, ?3, ?4, ?5, ?6)",
            params![
                format!("snapshot_{capture_id}"),
                capture_id,
                summary,
                record_count,
                now_ms(),
                serde_json::to_string(&json!({ "backfilled": true }))?,
            ],
        )?;
    }
    Ok(())
}

fn ensure_entity(
    conn: &Connection,
    entity_kind: &str,
    canonical_name: &str,
    metadata: &Value,
    created_at_ms: i64,
    updated_at_ms: i64,
) -> Result<String> {
    let normalized_name = slugify_identifier(canonical_name);
    if normalized_name.is_empty() {
        return Ok("entity_user".to_string());
    }
    if let Some(id) = conn
        .query_row(
            "SELECT id FROM pp_entities WHERE normalized_name = ?1",
            params![normalized_name],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    {
        conn.execute(
            "UPDATE pp_entities
             SET canonical_name = ?2, entity_kind = ?3, updated_at_ms = ?4, metadata_json = ?5
             WHERE id = ?1",
            params![
                id,
                canonical_name,
                entity_kind,
                updated_at_ms,
                serde_json::to_string(metadata)?,
            ],
        )?;
        return Ok(id);
    }
    let id = format!("entity_{}", Uuid::new_v4());
    conn.execute(
        "INSERT INTO pp_entities(
            id, entity_kind, canonical_name, normalized_name, created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id,
            entity_kind,
            canonical_name,
            normalized_name,
            created_at_ms,
            updated_at_ms,
            serde_json::to_string(metadata)?,
        ],
    )?;
    conn.execute(
        "INSERT OR IGNORE INTO pp_entity_aliases(
            id, entity_id, alias, normalized_alias, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            format!("alias_{}", Uuid::new_v4()),
            id,
            canonical_name,
            normalized_name,
            created_at_ms,
        ],
    )?;
    Ok(id)
}

fn cleanup_orphan_entities(conn: &Connection) -> Result<()> {
    conn.execute(
        "DELETE FROM pp_entity_aliases
         WHERE entity_id NOT IN (SELECT id FROM pp_entities)",
        [],
    )?;
    conn.execute(
        "DELETE FROM pp_entities
         WHERE id NOT IN (SELECT subject_entity_id FROM pp_relations)
           AND id NOT IN (SELECT object_entity_id FROM pp_relations WHERE object_entity_id IS NOT NULL)",
        [],
    )?;
    conn.execute(
        "DELETE FROM pp_sources
         WHERE source_id NOT IN (SELECT DISTINCT source_id FROM pp_sessions)",
        [],
    )?;
    Ok(())
}

fn sync_materialized_record_status(
    conn: &Connection,
    record_id: &str,
    status: &str,
    updated_at_ms: i64,
) -> Result<()> {
    for table in [
        "pp_personal_facts",
        "pp_preferences",
        "pp_capabilities",
        "pp_projects",
        "pp_methods",
    ] {
        let sql =
            format!("UPDATE {table} SET status = ?2, updated_at_ms = ?3 WHERE record_id = ?1");
        conn.execute(&sql, params![record_id, status, updated_at_ms])?;
    }
    conn.execute(
        "UPDATE pp_relations SET status = ?2, updated_at_ms = ?3 WHERE record_id = ?1",
        params![record_id, status, updated_at_ms],
    )?;
    Ok(())
}

fn relation_type_for_record(record: &BackfillRecord) -> String {
    record
        .attribute
        .clone()
        .unwrap_or_else(|| record.record_type.clone())
}

fn entity_kind_for_record(record: &BackfillRecord) -> &str {
    match record.record_type.as_str() {
        "project" | "goal" => "project",
        "capability" | "trait" => "person",
        _ => "subject",
    }
}

fn object_entity_kind_for_record(record: &BackfillRecord) -> &str {
    match record.record_type.as_str() {
        "project" | "goal" => "project",
        "method" | "bridge" => "method",
        "preference" | "like" | "dislike" => "preference_target",
        _ => "fact",
    }
}

fn should_use_object_entity(record: &BackfillRecord) -> bool {
    matches!(
        record.record_type.as_str(),
        "project" | "goal" | "method" | "bridge"
    ) || matches!(
        record.category.as_str(),
        "current_projects" | "product_goals" | "cross_project_bridge"
    )
}

fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn parse_timestamp_json_value(value: Option<&Value>) -> Option<i64> {
    let value = value?;
    if let Some(number) = value.as_i64() {
        return Some(number);
    }
    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    if let Ok(number) = text.parse::<i64>() {
        return Some(number);
    }
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|value| value.timestamp_millis())
}

fn first_text_from_value(value: &Value, keys: &[&str]) -> Option<String> {
    let object = value.as_object()?;
    for key in keys {
        if let Some(value) = object.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn object_or_empty_for_personal_preferences(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        _ => json!({}),
    }
}

pub async fn process_pending_with_local_agents(
    store: &PersonalPreferencesStore,
    global_state_dir: Option<&Path>,
    llm_config: &LlmConfig,
    config: &MemoryPersonalPreferencesConfig,
    limit: Option<usize>,
) -> Result<PersonalPreferencesProcessingSummary> {
    if !config.digest_enabled {
        return Ok(PersonalPreferencesProcessingSummary::default());
    }
    let batch_limit = limit
        .filter(|value| *value > 0)
        .unwrap_or(config.max_parallel_digest_jobs)
        .max(1)
        .min(config.max_parallel_digest_jobs.max(1));
    let mut effective_llm_config = llm_config.clone();
    effective_llm_config.delegation.cloud.enabled = false;
    effective_llm_config.delegation.cloud_agent_id.clear();
    effective_llm_config.delegation.code.cloud_agent_id.clear();
    effective_llm_config
        .delegation
        .general
        .cloud_agent_id
        .clear();
    let library = match refresh_local_library_if_stale(
        global_state_dir,
        &effective_llm_config,
        false,
    )
    .await
    {
        Ok(library) => library,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "personal preferences local library refresh failed; falling back to cached library"
            );
            load_local_library(global_state_dir)?
        }
    };
    let mut library = library;
    let mut local_targets = build_local_target_candidates_with_config(
        global_state_dir,
        &effective_llm_config,
        TaskType::GeneralQuestion,
        &mut library,
    );
    if config.digest_with_local_mcoda_only {
        local_targets.retain(|target| match target {
            LocalTarget::McodaAgent(agent_id) => library
                .agents
                .iter()
                .find(|entry| entry.agent_id == *agent_id)
                .map(|entry| !local_agent_is_cloud(entry))
                .unwrap_or(false),
            LocalTarget::OllamaModel(_) => false,
        });
    }
    let local_targets = std::sync::Arc::new(local_targets);
    let effective_config = config.clone();
    let state_dir = global_state_dir.map(PathBuf::from);
    store
        .process_pending_with_runner(batch_limit, move |input| {
            let local_targets = local_targets.clone();
            let llm_config = effective_llm_config.clone();
            let state_dir = state_dir.clone();
            let effective_config = effective_config.clone();
            async move {
                if local_targets.is_empty() {
                    return Ok(None);
                }
                let completion = run_delegation_flow_with_failure_history(
                    &llm_config,
                    None,
                    local_targets.as_ref(),
                    &[],
                    TaskType::GeneralQuestion,
                    &build_digest_instruction(&input.capture),
                    &build_digest_context(&input.capture, &effective_config),
                    llm_config.delegation.max_context_chars.min(64_000),
                    None,
                    Some(
                        llm_config
                            .delegation
                            .timeout_ms
                            .min(PERSONAL_PREFERENCES_DIGEST_TIMEOUT_CAP_MS),
                    ),
                    DelegationMode::DraftOnly,
                    Some(DelegationFailureHistoryContext {
                        global_state_dir: state_dir.clone(),
                        repo_id: input.capture.repo_id.clone(),
                        repo_root: input.capture.repo_root.clone(),
                        source: Some("personal_preferences".to_string()),
                    }),
                )
                .await?;
                match parse_digest_output(&completion.completion.output) {
                    Ok(output) => Ok(Some(output)),
                    Err(parse_err) => {
                        let parse_err_text = parse_err.to_string();
                        warn!(
                            target: "docdexd",
                            capture_id = %input.capture.id,
                            error = %parse_err_text,
                            "personal preferences digest output failed JSON parse; attempting local repair"
                        );
                        let repair_instruction = build_digest_repair_instruction(&input.capture);
                        let repair_context =
                            build_digest_repair_context(&completion.completion.output);
                        let repair_completion = run_delegation_flow_with_failure_history(
                            &llm_config,
                            None,
                            local_targets.as_ref(),
                            &[],
                            TaskType::GeneralQuestion,
                            &repair_instruction,
                            &repair_context,
                            llm_config.delegation.max_context_chars.min(64_000),
                            None,
                            Some(
                                llm_config
                                    .delegation
                                    .timeout_ms
                                    .min(PERSONAL_PREFERENCES_DIGEST_TIMEOUT_CAP_MS),
                            ),
                            DelegationMode::DraftOnly,
                            Some(DelegationFailureHistoryContext {
                                global_state_dir: state_dir,
                                repo_id: input.capture.repo_id.clone(),
                                repo_root: input.capture.repo_root.clone(),
                                source: Some("personal_preferences_repair".to_string()),
                            }),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "digest output was not valid JSON and repair delegation failed: {parse_err_text}"
                            )
                        })?;
                        let repaired =
                            parse_digest_output(&repair_completion.completion.output)
                                .with_context(|| {
                                    format!(
                                        "digest output was not valid JSON and repair output was also invalid: {parse_err_text}"
                                    )
                                })?;
                        Ok(Some(repaired))
                    }
                }
            }
        })
        .await
}

pub async fn project_safe_preferences_to_profile(
    store: &PersonalPreferencesStore,
    manager: &ProfileManager,
    embedder: Option<&ProfileEmbedder>,
    config: &MemoryPersonalPreferencesConfig,
    default_agent_id: Option<&str>,
) -> Result<usize> {
    if !config.auto_project_safe_preferences_to_profile {
        return Ok(0);
    }
    let Some(embedder) = embedder else {
        return Ok(0);
    };
    let mut projected = 0usize;
    let mut projected_record_ids = Vec::new();
    let mut ensured_agents = HashSet::new();
    let records = store.list_projectable_records(MAX_PROJECTABLE_RECORDS)?;
    for record in records {
        let Some(category) = map_record_to_profile_category(&record) else {
            continue;
        };
        let content = format!("[personal_preferences] {}", render_record(&record));
        let agent_id = record_agent_id(&record)
            .or_else(|| default_agent_id.map(ToOwned::to_owned))
            .unwrap_or_else(|| "default".to_string());
        if ensured_agents.insert(agent_id.clone()) && manager.get_agent(&agent_id)?.is_none() {
            manager.create_agent(&agent_id, "personal_preferences", now_ms())?;
        }
        let embedding = embedder.embed(&content).await?;
        manager.add_preference(&agent_id, &content, &embedding, category, now_ms())?;
        projected_record_ids.push(record.id);
        projected += 1;
    }
    store.mark_records_projected(&projected_record_ids)?;
    Ok(projected)
}

pub fn extract_digest_output(text: &str) -> Result<PersonalPreferenceDigestOutput> {
    parse_digest_output(text)
}

pub fn is_supported_client_transcript_source(source: &str) -> bool {
    let normalized = slugify_identifier(source);
    if normalized.is_empty() {
        return false;
    }
    [
        "codex",
        "codex_cli",
        "claude",
        "claude_cli",
        "claude_code",
        "gemini",
        "gemini_cli",
        "openai",
        "openai_cli",
        "cursor",
        "zed",
        "copilot",
        "mcoda",
    ]
    .iter()
    .any(|item| normalized == *item || normalized.starts_with(&format!("{item}_")))
}

pub fn should_capture_external_source(
    config: &MemoryPersonalPreferencesConfig,
    source: &str,
    explicit_capture_enabled: bool,
) -> bool {
    config.capture_enabled
        && config.allows_source(source)
        && (explicit_capture_enabled
            || (config.capture_supported_client_transcripts
                && is_supported_client_transcript_source(source)))
}

fn build_digest_instruction(capture: &PersonalPreferencesCaptureRecord) -> String {
    let categories = DEFAULT_CATEGORY_POLICIES
        .iter()
        .map(|policy| format!("- {}: {}", policy.category, policy.description))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "You are extracting durable personal-profile knowledge about a local user from a conversation transcript.\n\
Extract only durable user-specific signals that would help future agents work in the user's preferred style.\n\
Focus on the user's preferences, methods, goals, communication style, projects, personality, business context, personal context, likes/dislikes, strengths, constraints, and cross-project bridges.\n\
Do not include secrets, credentials, API keys, one-time codes, or transient single-turn details.\n\
Use these suggested categories when possible:\n{categories}\n\
Return JSON only with this exact shape:\n\
{{\"records\":[{{\"record_type\":\"preference\",\"category\":\"coding_preference\",\"subcategory\":\"rust\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Rust\",\"confidence\":0.92,\"sensitivity\":\"low\",\"evidence\":\"short quote or paraphrase\",\"metadata\":{{}}}}]}}\n\
Rules:\n\
- At most {MAX_DIGEST_RECORDS_PER_CAPTURE} records.\n\
- `record_type` should be one of preference, method, goal, project, trait, capability, context, like, dislike, bridge, or other.\n\
- `confidence` must be 0.0-1.0.\n\
- `sensitivity` must be low, private, sensitive, or special.\n\
- `subject` should usually be `user` unless the user explicitly frames another enduring subject.\n\
- Skip anything speculative, contradictory, or too weak.\n\
- The conversation capture id is {}.",
        capture.id
    )
}

fn build_digest_context(
    capture: &PersonalPreferencesCaptureRecord,
    config: &MemoryPersonalPreferencesConfig,
) -> String {
    let mut parts = Vec::new();
    parts.push(format!("source: {}", capture.source));
    if let Some(value) = capture.capture_kind.as_deref() {
        parts.push(format!("capture_kind: {value}"));
    }
    if let Some(value) = capture.repo_root.as_deref() {
        parts.push(format!("repo_root: {value}"));
    }
    if let Some(value) = capture.scope_label.as_deref() {
        parts.push(format!("scope_label: {value}"));
    }
    if let Some(value) = capture.title.as_deref() {
        parts.push(format!("title: {value}"));
    }
    if let Some(value) = capture.agent_id.as_deref() {
        parts.push(format!("agent_id: {value}"));
    }
    parts.push(format!(
        "archive_raw_conversations: {}",
        config.archive_raw_conversations
    ));
    if !capture.transcript_text.trim().is_empty() {
        parts.push("transcript:".to_string());
        parts.push(capture.transcript_text.trim().to_string());
    }
    if !capture.messages.is_empty() {
        parts.push("messages:".to_string());
        for message in &capture.messages {
            parts.push(format!(
                "- {}: {}",
                normalize_text(&message.role),
                message.content.trim()
            ));
        }
    }
    parts.join("\n")
}

fn build_digest_repair_instruction(capture: &PersonalPreferencesCaptureRecord) -> String {
    format!(
        "Repair a malformed personal-preferences digest for capture {}.\n\
Return JSON only with this exact shape: {{\"records\":[...]}}.\n\
Use only durable records already present in the malformed output. Do not add new facts from memory, do not infer missing facts, and do not include markdown, reasoning, comments, or prose.\n\
If the malformed output contains no usable durable records, return {{\"records\":[]}}.\n\
Each record must preserve the personal-preferences schema fields when available: record_type, category, subcategory, subject, attribute, value, confidence, sensitivity, evidence, metadata.",
        capture.id
    )
}

fn build_digest_repair_context(malformed_output: &str) -> String {
    format!(
        "malformed_digest_output:\n{}",
        truncate_chars(malformed_output, 60_000)
    )
}

fn parse_digest_output(text: &str) -> Result<PersonalPreferenceDigestOutput> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(PersonalPreferenceDigestOutput::default());
    }
    let mut candidates = Vec::new();
    candidates.push(trimmed);
    candidates.push(
        trimmed
            .strip_prefix("```json")
            .and_then(|value| value.strip_suffix("```"))
            .map(str::trim)
            .unwrap_or(trimmed),
    );
    candidates.push(
        trimmed
            .strip_prefix("```")
            .and_then(|value| value.strip_suffix("```"))
            .map(str::trim)
            .unwrap_or(trimmed),
    );
    candidates.extend(extract_balanced_json_candidates(trimmed).into_iter().rev());

    let mut shape_error = None;
    for candidate in candidates {
        if candidate.trim().is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(candidate) {
            match parse_digest_value(&value) {
                Ok(output) => return Ok(output),
                Err(err) => shape_error = Some(err.to_string()),
            }
        }
    }
    if let Some(err) = shape_error {
        return Err(anyhow!(err));
    }
    Err(anyhow!("digest output was not valid JSON"))
}

fn parse_digest_value(value: &Value) -> Result<PersonalPreferenceDigestOutput> {
    if let Some(records) = value.get("records").and_then(Value::as_array) {
        let mut out = Vec::new();
        for record in records {
            if let Ok(parsed) =
                serde_json::from_value::<PersonalPreferenceDigestRecord>(record.clone())
            {
                out.push(parsed);
            }
        }
        return Ok(PersonalPreferenceDigestOutput { records: out });
    }
    if let Some(records) = value.as_array() {
        let mut out = Vec::new();
        for record in records {
            if let Ok(parsed) =
                serde_json::from_value::<PersonalPreferenceDigestRecord>(record.clone())
            {
                out.push(parsed);
            }
        }
        return Ok(PersonalPreferenceDigestOutput { records: out });
    }
    Err(anyhow!("digest JSON did not contain a records array"))
}

fn init_db(path: &Path) -> Result<()> {
    let conn = open_db(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS personal_preferences_meta(
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS captured_conversations(
             id TEXT PRIMARY KEY,
             source TEXT NOT NULL,
             source_session_id TEXT,
             capture_kind TEXT,
             title TEXT,
             agent_id TEXT,
             transport TEXT,
             repo_id TEXT,
             repo_root TEXT,
             scope_id TEXT,
             scope_label TEXT,
             started_at_ms INTEGER,
             ended_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             digest_status TEXT NOT NULL,
             transcript_text TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             archive_path TEXT,
             raw_message_count INTEGER NOT NULL DEFAULT 0,
             archive_redacted_at_ms INTEGER,
             last_digest_error TEXT
         );
         CREATE TABLE IF NOT EXISTS captured_messages(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             ordinal INTEGER NOT NULL,
             role TEXT NOT NULL,
             content TEXT NOT NULL,
             created_at_ms INTEGER,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_sources(
             source_id TEXT PRIMARY KEY,
             source_type TEXT NOT NULL,
             client_kind TEXT,
             agent_kind TEXT,
             enabled INTEGER NOT NULL DEFAULT 1,
             last_seen_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_sessions(
             capture_id TEXT PRIMARY KEY,
             source_id TEXT NOT NULL,
             source_session_id TEXT,
             external_ref TEXT,
             external_ref_hash TEXT,
             capture_kind TEXT,
             title TEXT,
             digest_status TEXT NOT NULL,
             sensitivity_summary TEXT,
             started_at_ms INTEGER,
             ended_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(source_id) REFERENCES pp_sources(source_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_messages(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             message_id TEXT,
             ordinal INTEGER NOT NULL,
             role TEXT NOT NULL,
             content TEXT NOT NULL,
             created_at_ms INTEGER,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_attachments(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             attachment_kind TEXT NOT NULL,
             attachment_ref TEXT,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS derived_records(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             record_type TEXT NOT NULL,
             category TEXT NOT NULL,
             subcategory TEXT,
             subject TEXT NOT NULL,
             attribute TEXT,
             value TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             evidence TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             projected_to_profile_at_ms INTEGER,
             review_status TEXT NOT NULL DEFAULT 'approved',
             review_updated_at_ms INTEGER,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_categories(
             category TEXT PRIMARY KEY,
             description TEXT NOT NULL,
             context_section TEXT,
             context_allowed_default INTEGER NOT NULL DEFAULT 0,
             requires_review_for_sensitive INTEGER NOT NULL DEFAULT 0,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_subcategories(
             category TEXT NOT NULL,
             subcategory TEXT NOT NULL,
             description TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             PRIMARY KEY(category, subcategory)
         );
         CREATE TABLE IF NOT EXISTS pp_sensitivity_levels(
             level TEXT PRIMARY KEY,
             rank INTEGER NOT NULL,
             description TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_context_policies(
             category TEXT PRIMARY KEY,
             context_section TEXT,
             context_allowed_default INTEGER NOT NULL DEFAULT 0,
             allow_sensitive INTEGER NOT NULL DEFAULT 0,
             requires_review_for_sensitive INTEGER NOT NULL DEFAULT 0,
             updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_tombstones(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             action TEXT NOT NULL,
             details_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_reviews(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             verdict TEXT NOT NULL,
             notes TEXT,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_digest_jobs(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             status TEXT NOT NULL,
             error_text TEXT,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_digest_runs(
             id TEXT PRIMARY KEY,
             job_id TEXT,
             capture_id TEXT NOT NULL,
             agent_id TEXT,
             model_hint TEXT,
             prompt_version TEXT,
             outcome_status TEXT NOT NULL,
             input_records INTEGER NOT NULL DEFAULT 0,
             output_records INTEGER NOT NULL DEFAULT 0,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER,
             error_text TEXT,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(job_id) REFERENCES pp_digest_jobs(id) ON DELETE SET NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_entities(
             id TEXT PRIMARY KEY,
             entity_kind TEXT NOT NULL,
             canonical_name TEXT NOT NULL,
             normalized_name TEXT NOT NULL UNIQUE,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_entity_aliases(
             id TEXT PRIMARY KEY,
             entity_id TEXT NOT NULL,
             alias TEXT NOT NULL,
             normalized_alias TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             UNIQUE(entity_id, normalized_alias),
             FOREIGN KEY(entity_id) REFERENCES pp_entities(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_relations(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             capture_id TEXT NOT NULL,
             subject_entity_id TEXT NOT NULL,
             relation_type TEXT NOT NULL,
             object_entity_id TEXT,
             literal_object TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(subject_entity_id) REFERENCES pp_entities(id) ON DELETE CASCADE,
             FOREIGN KEY(object_entity_id) REFERENCES pp_entities(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_observations(
             id TEXT PRIMARY KEY,
             digest_run_id TEXT,
             record_id TEXT NOT NULL,
             capture_id TEXT NOT NULL,
             observation_type TEXT NOT NULL,
             summary TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(digest_run_id) REFERENCES pp_digest_runs(id) ON DELETE SET NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_personal_facts(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             category TEXT NOT NULL,
             subcategory TEXT,
             subject TEXT NOT NULL,
             attribute TEXT,
             value TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_preferences(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             preference_type TEXT NOT NULL,
             target_name TEXT NOT NULL,
             normalized_target TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_capabilities(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             capability_name TEXT NOT NULL,
             proficiency_signal TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_projects(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             project_name TEXT NOT NULL,
             repo_root TEXT,
             goal_summary TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_methods(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             method_name TEXT NOT NULL,
             method_kind TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_evidence(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             capture_id TEXT NOT NULL,
             evidence_text TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_cross_project_bridges(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             source_repo_root TEXT NOT NULL,
             target_repo_root TEXT,
             bridge_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_snapshot_summaries(
             id TEXT PRIMARY KEY,
             capture_id TEXT,
             digest_run_id TEXT,
             summary TEXT NOT NULL,
             record_count INTEGER NOT NULL,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(digest_run_id) REFERENCES pp_digest_runs(id) ON DELETE SET NULL
         );
         CREATE INDEX IF NOT EXISTS idx_pp_captured_status_created
             ON captured_conversations(digest_status, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_sources_kind
             ON pp_sources(source_type, client_kind);
         CREATE INDEX IF NOT EXISTS idx_pp_sessions_source_created
             ON pp_sessions(source_id, created_at_ms);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_pp_sessions_external_ref_hash
             ON pp_sessions(external_ref_hash);
         CREATE INDEX IF NOT EXISTS idx_pp_messages_capture_ordinal
             ON pp_messages(capture_id, ordinal);
         CREATE INDEX IF NOT EXISTS idx_pp_categories_context
             ON pp_categories(context_section, context_allowed_default);
         CREATE INDEX IF NOT EXISTS idx_pp_context_policies_section
             ON pp_context_policies(context_section, context_allowed_default);
         CREATE INDEX IF NOT EXISTS idx_pp_records_category_updated
             ON derived_records(category, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_records_capture
             ON derived_records(capture_id);
         CREATE INDEX IF NOT EXISTS idx_pp_records_projected
             ON derived_records(projected_to_profile_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_records_review_status
             ON derived_records(review_status, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_reviews_record_created
             ON pp_reviews(record_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_digest_jobs_capture_created
             ON pp_digest_jobs(capture_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_digest_runs_capture_started
             ON pp_digest_runs(capture_id, started_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_entities_kind_name
             ON pp_entities(entity_kind, normalized_name);
         CREATE INDEX IF NOT EXISTS idx_pp_relations_subject_relation
             ON pp_relations(subject_entity_id, relation_type);
         CREATE INDEX IF NOT EXISTS idx_pp_observations_capture_created
             ON pp_observations(capture_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_personal_facts_category
             ON pp_personal_facts(category, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_preferences_target
             ON pp_preferences(normalized_target, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_projects_name
             ON pp_projects(project_name, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_methods_name
             ON pp_methods(method_name, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_evidence_record
             ON pp_evidence(record_id);
         CREATE INDEX IF NOT EXISTS idx_pp_bridges_source
             ON pp_cross_project_bridges(source_repo_root, bridge_key);",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pp_claims(
             id TEXT PRIMARY KEY,
             record_id TEXT UNIQUE,
             capture_id TEXT,
             category TEXT NOT NULL,
             subcategory TEXT,
             subject TEXT NOT NULL,
             attribute TEXT,
             value TEXT NOT NULL,
             claim_origin TEXT NOT NULL,
             truth_status TEXT NOT NULL,
             stability_class TEXT NOT NULL,
             sensitivity TEXT NOT NULL,
             confidence REAL NOT NULL,
             review_status TEXT NOT NULL,
             evidence_summary TEXT,
             valid_from_ms INTEGER,
             valid_to_ms INTEGER,
             supersedes_claim_id TEXT,
             contradicted_by_claim_id TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_claim_versions(
             id TEXT PRIMARY KEY,
             claim_id TEXT NOT NULL,
             change_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_claim_evidence(
             id TEXT PRIMARY KEY,
             claim_id TEXT NOT NULL,
             capture_id TEXT,
             evidence_text TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_claim_links(
             id TEXT PRIMARY KEY,
             claim_id TEXT NOT NULL,
             linked_claim_id TEXT,
             link_type TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(linked_claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_feedback_events(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             capture_id TEXT,
             event_type TEXT NOT NULL,
             notes TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE SET NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_identity_snapshots(
             id TEXT PRIMARY KEY,
             snapshot_kind TEXT NOT NULL,
             summary TEXT NOT NULL,
             stable_summary TEXT,
             changed_summary TEXT,
             active_projects_summary TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_decision_patterns(
             id TEXT PRIMARY KEY,
             snapshot_id TEXT,
             pattern_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             confidence REAL NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_style_signals(
             id TEXT PRIMARY KEY,
             snapshot_id TEXT,
             signal_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             confidence REAL NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_clone_profiles(
             id TEXT PRIMARY KEY,
             mode TEXT NOT NULL UNIQUE,
             summary TEXT NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_clone_context_packs(
             id TEXT PRIMARY KEY,
             mode TEXT NOT NULL,
             query TEXT NOT NULL,
             query_hash TEXT NOT NULL,
             current_repo_root TEXT,
             summary TEXT NOT NULL,
             explanation_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_clone_evaluations(
             id TEXT PRIMARY KEY,
             mode TEXT NOT NULL,
             score REAL NOT NULL,
             query TEXT NOT NULL,
             notes TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_project_timelines(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             snapshot_id TEXT,
             project_name TEXT NOT NULL,
             repo_root TEXT,
             lifecycle_state TEXT NOT NULL,
             valid_from_ms INTEGER,
             valid_to_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_goal_graph(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             snapshot_id TEXT,
             goal_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             status TEXT NOT NULL,
             project_name TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_override_rules(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             category TEXT NOT NULL,
             attribute TEXT,
             subject TEXT,
             override_value TEXT NOT NULL,
             reason TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_redaction_spans(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             claim_id TEXT,
             span_kind TEXT NOT NULL,
             start_offset INTEGER,
             end_offset INTEGER,
             replacement_text TEXT NOT NULL,
             reason TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_retention_policies(
             id TEXT PRIMARY KEY,
             policy_key TEXT NOT NULL UNIQUE,
             lane TEXT NOT NULL,
             category TEXT,
             raw_retention_days INTEGER,
             derived_retention_days INTEGER,
             claim_retention_days INTEGER,
             snapshot_retention_days INTEGER,
             export_retention_days INTEGER,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_pp_claims_truth_updated
             ON pp_claims(truth_status, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claims_origin_updated
             ON pp_claims(claim_origin, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claims_category_updated
             ON pp_claims(category, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claims_review_status
             ON pp_claims(review_status, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claim_versions_claim_created
             ON pp_claim_versions(claim_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claim_evidence_claim
             ON pp_claim_evidence(claim_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claim_links_claim
             ON pp_claim_links(claim_id, link_type, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_feedback_events_created
             ON pp_feedback_events(created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_snapshots_created
             ON pp_identity_snapshots(created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_decision_patterns_snapshot
             ON pp_decision_patterns(snapshot_id, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_style_signals_snapshot
             ON pp_style_signals(snapshot_id, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_clone_context_query
             ON pp_clone_context_packs(query_hash, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_clone_evaluations_mode_created
             ON pp_clone_evaluations(mode, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_project_timelines_project
             ON pp_project_timelines(project_name, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_goal_graph_key
             ON pp_goal_graph(goal_key, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_override_rules_lookup
             ON pp_override_rules(category, attribute, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_redaction_spans_capture
             ON pp_redaction_spans(capture_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_retention_policies_lane
             ON pp_retention_policies(lane, updated_at_ms);",
    )?;
    ensure_column(&conn, "captured_conversations", "archive_path", "TEXT")?;
    ensure_column(
        &conn,
        "captured_conversations",
        "raw_message_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "captured_conversations",
        "archive_redacted_at_ms",
        "INTEGER",
    )?;
    ensure_column(
        &conn,
        "derived_records",
        "projected_to_profile_at_ms",
        "INTEGER",
    )?;
    ensure_column(
        &conn,
        "derived_records",
        "review_status",
        "TEXT NOT NULL DEFAULT 'approved'",
    )?;
    ensure_column(&conn, "derived_records", "review_updated_at_ms", "INTEGER")?;
    seed_default_category_policies(&conn)?;
    seed_default_sensitivity_levels(&conn)?;
    seed_default_context_policies(&conn)?;
    seed_default_retention_policies(&conn)?;
    backfill_rich_capture_lineage(&conn)?;
    backfill_rich_derived_materialization(&conn)?;
    backfill_claims_from_records(&conn, None)?;
    conn.execute(
        "INSERT OR REPLACE INTO personal_preferences_meta(key, value) VALUES (?1, ?2)",
        params!["schema_version", SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

fn ensure_column(conn: &Connection, table: &str, column: &str, spec: &str) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let existing = row.get::<_, String>(1)?;
        if existing == column {
            return Ok(());
        }
    }
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {spec}");
    conn.execute(&sql, [])?;
    Ok(())
}

fn open_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .with_context(|| format!("open {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn count_query(conn: &Connection, sql: &str) -> Result<usize> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, i64>(0))? as usize)
}

fn count_query_with_param<P>(conn: &Connection, sql: &str, params: P) -> Result<usize>
where
    P: rusqlite::Params,
{
    Ok(conn.query_row(sql, params, |row| row.get::<_, i64>(0))? as usize)
}

fn load_all_records(conn: &Connection) -> Result<Vec<PersonalPreferenceRecord>> {
    let mut stmt = conn.prepare(
        "SELECT id, capture_id, record_type, category, subcategory, subject, attribute, value,
                confidence, sensitivity, evidence, created_at_ms, updated_at_ms, metadata_json,
                projected_to_profile_at_ms, review_status, review_updated_at_ms
         FROM derived_records",
    )?;
    let mut rows = stmt.query([])?;
    let mut records = Vec::new();
    while let Some(row) = rows.next()? {
        records.push(row_to_record(row)?);
    }
    Ok(records)
}

fn load_all_claims(conn: &Connection) -> Result<Vec<PersonalPreferenceClaim>> {
    let mut stmt = conn.prepare(
        "SELECT id, record_id, capture_id, category, subcategory, subject, attribute, value,
                claim_origin, truth_status, stability_class, sensitivity, confidence,
                review_status, evidence_summary, valid_from_ms, valid_to_ms,
                supersedes_claim_id, contradicted_by_claim_id, created_at_ms, updated_at_ms,
                metadata_json
         FROM pp_claims
         ORDER BY updated_at_ms DESC, confidence DESC",
    )?;
    let mut rows = stmt.query([])?;
    let mut claims = Vec::new();
    while let Some(row) = rows.next()? {
        claims.push(row_to_claim(row)?);
    }
    Ok(claims)
}

fn load_claim_by_id(conn: &Connection, claim_id: &str) -> Result<Option<PersonalPreferenceClaim>> {
    Ok(conn
        .query_row(
            "SELECT id, record_id, capture_id, category, subcategory, subject, attribute, value,
                    claim_origin, truth_status, stability_class, sensitivity, confidence,
                    review_status, evidence_summary, valid_from_ms, valid_to_ms,
                    supersedes_claim_id, contradicted_by_claim_id, created_at_ms, updated_at_ms,
                    metadata_json
             FROM pp_claims
             WHERE id = ?1",
            params![claim_id],
            row_to_claim,
        )
        .optional()?)
}

fn load_records_for_capture_ids(
    conn: &Connection,
    capture_ids: &[String],
) -> Result<Vec<PersonalPreferenceRecord>> {
    let mut records = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT id, capture_id, record_type, category, subcategory, subject, attribute, value,
                confidence, sensitivity, evidence, created_at_ms, updated_at_ms, metadata_json,
                projected_to_profile_at_ms, review_status, review_updated_at_ms
         FROM derived_records
         WHERE capture_id = ?1
         ORDER BY updated_at_ms DESC",
    )?;
    for capture_id in capture_ids {
        let mut rows = stmt.query(params![capture_id])?;
        while let Some(row) = rows.next()? {
            records.push(row_to_record(row)?);
        }
    }
    Ok(records)
}

fn row_to_capture(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalPreferencesCaptureRecord> {
    Ok(PersonalPreferencesCaptureRecord {
        id: row.get(0)?,
        source: row.get(1)?,
        source_session_id: row.get(2)?,
        capture_kind: row.get(3)?,
        title: row.get(4)?,
        agent_id: row.get(5)?,
        transport: row.get(6)?,
        repo_id: row.get(7)?,
        repo_root: row.get(8)?,
        scope_id: row.get(9)?,
        scope_label: row.get(10)?,
        started_at_ms: row.get(11)?,
        ended_at_ms: row.get(12)?,
        created_at_ms: row.get(13)?,
        updated_at_ms: row.get(14)?,
        digest_status: row.get(15)?,
        transcript_text: row.get(16)?,
        metadata: parse_json_value(&row.get::<_, String>(17)?),
        archive_path: row.get(18)?,
        raw_message_count: row.get::<_, i64>(19)? as usize,
        archive_redacted_at_ms: row.get(20)?,
        last_digest_error: row.get(21)?,
        messages: Vec::new(),
    })
}

fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalPreferenceRecord> {
    Ok(PersonalPreferenceRecord {
        id: row.get(0)?,
        capture_id: row.get(1)?,
        record_type: row.get(2)?,
        category: row.get(3)?,
        subcategory: row.get(4)?,
        subject: row.get(5)?,
        attribute: row.get(6)?,
        value: row.get(7)?,
        confidence: row.get(8)?,
        sensitivity: row.get(9)?,
        evidence: row.get(10)?,
        created_at_ms: row.get(11)?,
        updated_at_ms: row.get(12)?,
        metadata: parse_json_value(&row.get::<_, String>(13)?),
        projected_to_profile_at_ms: row.get(14)?,
        review_status: row.get(15)?,
        review_updated_at_ms: row.get(16)?,
    })
}

fn row_to_claim(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalPreferenceClaim> {
    Ok(PersonalPreferenceClaim {
        id: row.get(0)?,
        record_id: row.get(1)?,
        capture_id: row.get(2)?,
        category: row.get(3)?,
        subcategory: row.get(4)?,
        subject: row.get(5)?,
        attribute: row.get(6)?,
        value: row.get(7)?,
        claim_origin: row.get(8)?,
        truth_status: row.get(9)?,
        stability_class: row.get(10)?,
        sensitivity: row.get(11)?,
        confidence: row.get(12)?,
        review_status: row.get(13)?,
        evidence_summary: row.get(14)?,
        valid_from_ms: row.get(15)?,
        valid_to_ms: row.get(16)?,
        supersedes_claim_id: row.get(17)?,
        contradicted_by_claim_id: row.get(18)?,
        created_at_ms: row.get(19)?,
        updated_at_ms: row.get(20)?,
        metadata: parse_json_value(&row.get::<_, String>(21)?),
    })
}

fn row_to_feedback_event(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersonalPreferenceFeedbackEvent> {
    Ok(PersonalPreferenceFeedbackEvent {
        id: row.get(0)?,
        event_type: row.get(1)?,
        claim_id: row.get(2)?,
        capture_id: row.get(3)?,
        notes: row.get(4)?,
        created_at_ms: row.get(5)?,
        metadata: parse_json_value(&row.get::<_, String>(6)?),
    })
}

fn row_to_snapshot(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalPreferenceSnapshot> {
    Ok(PersonalPreferenceSnapshot {
        id: row.get(0)?,
        snapshot_kind: row.get(1)?,
        summary: row.get(2)?,
        stable_summary: row.get(3)?,
        changed_summary: row.get(4)?,
        active_projects_summary: row.get(5)?,
        created_at_ms: row.get(6)?,
        metadata: parse_json_value(&row.get::<_, String>(7)?),
    })
}

fn normalize_capture_text(request: &PersonalPreferencesCaptureRequest) -> String {
    if let Some(transcript) = request
        .transcript_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return transcript.to_string();
    }
    let mut lines = Vec::new();
    for message in &request.messages {
        let content = message.content.trim();
        if content.is_empty() {
            continue;
        }
        lines.push(format!("{}: {}", normalize_text(&message.role), content));
    }
    if lines.is_empty() {
        request
            .summary_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
            .to_string()
    } else {
        lines.join("\n")
    }
}

fn normalize_digest_record(
    record: &PersonalPreferenceDigestRecord,
    capture: &PersonalPreferencesCaptureRecord,
) -> PersonalPreferenceDigestRecord {
    let category = normalize_category(&record.category);
    let confidence = record.confidence.unwrap_or(0.5).clamp(0.0, 1.0);
    let sensitivity = normalize_sensitivity(record.sensitivity.as_deref().unwrap_or("private"));
    let evidence = record
        .evidence
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| truncate_chars(value, MAX_DIGEST_EVIDENCE_CHARS));
    let mut metadata = record.metadata.clone();
    let mut obj = metadata.as_object().cloned().unwrap_or_default();
    obj.insert("source".to_string(), json!(capture.source.clone()));
    obj.insert(
        "capture_kind".to_string(),
        json!(capture.capture_kind.clone()),
    );
    obj.insert("repo_root".to_string(), json!(capture.repo_root.clone()));
    obj.insert("repo_id".to_string(), json!(capture.repo_id.clone()));
    obj.insert(
        "scope_label".to_string(),
        json!(capture.scope_label.clone()),
    );
    obj.insert("agent_id".to_string(), json!(capture.agent_id.clone()));
    metadata = Value::Object(obj);
    PersonalPreferenceDigestRecord {
        record_type: normalize_record_type(&record.record_type),
        category,
        subcategory: normalize_optional_text(record.subcategory.as_deref()),
        subject: normalize_non_empty_text(&record.subject).unwrap_or_else(|| "user".to_string()),
        attribute: normalize_optional_text(record.attribute.as_deref()),
        value: normalize_text(&record.value),
        confidence: Some(confidence),
        sensitivity: Some(sensitivity),
        evidence,
        metadata,
    }
}

fn rank_records(query: &str, records: &mut Vec<PersonalPreferenceRecord>) {
    let terms = query
        .split_whitespace()
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| !term.is_empty())
        .take(8)
        .collect::<Vec<_>>();
    records.sort_by(|left, right| {
        let left_score = record_match_score(left, &terms);
        let right_score = record_match_score(right, &terms);
        right_score
            .cmp(&left_score)
            .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
            .then_with(|| {
                right
                    .confidence
                    .partial_cmp(&left.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
}

fn rank_claims(query: &str, claims: &mut Vec<PersonalPreferenceClaim>) {
    let terms = query
        .split_whitespace()
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| !term.is_empty())
        .take(8)
        .collect::<Vec<_>>();
    claims.sort_by(|left, right| {
        let left_score = claim_match_score(left, &terms);
        let right_score = claim_match_score(right, &terms);
        right_score
            .cmp(&left_score)
            .then_with(|| {
                truth_status_rank(&right.truth_status).cmp(&truth_status_rank(&left.truth_status))
            })
            .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
            .then_with(|| {
                right
                    .confidence
                    .partial_cmp(&left.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
}

fn record_match_score(record: &PersonalPreferenceRecord, terms: &[String]) -> i32 {
    if terms.is_empty() {
        return 0;
    }
    let haystack = format!(
        "{} {} {} {} {} {} {}",
        record.record_type,
        record.category,
        record.subcategory.clone().unwrap_or_default(),
        record.subject,
        record.attribute.clone().unwrap_or_default(),
        record.value,
        record.evidence.clone().unwrap_or_default()
    )
    .to_ascii_lowercase();
    let mut score = 0i32;
    for term in terms {
        if haystack.contains(term) {
            score += 3;
        }
        if record.category.eq_ignore_ascii_case(term) {
            score += 3;
        }
        if record.subject.eq_ignore_ascii_case(term) {
            score += 2;
        }
    }
    score
}

fn claim_match_score(claim: &PersonalPreferenceClaim, terms: &[String]) -> i32 {
    let haystack = format!(
        "{} {} {} {} {} {} {} {}",
        claim.category,
        claim.subcategory.clone().unwrap_or_default(),
        claim.subject,
        claim.attribute.clone().unwrap_or_default(),
        claim.value,
        claim.claim_origin,
        claim.truth_status,
        claim.evidence_summary.clone().unwrap_or_default()
    )
    .to_ascii_lowercase();
    let mut score =
        truth_status_rank(&claim.truth_status) * 4 + stability_rank(&claim.stability_class);
    for term in terms {
        if haystack.contains(term) {
            score += 4;
        }
        if claim.category.eq_ignore_ascii_case(term) {
            score += 3;
        }
        if claim.subject.eq_ignore_ascii_case(term) {
            score += 2;
        }
    }
    score
}

fn render_record(record: &PersonalPreferenceRecord) -> String {
    let mut head = format!("[{}]", record.category);
    if let Some(subcategory) = record
        .subcategory
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        head.push('/');
        head.push_str(subcategory);
    }
    let attribute = record
        .attribute
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("notes");
    format!("{head} {} {} {}", record.subject, attribute, record.value)
}

fn render_digest_record(record: &PersonalPreferenceDigestRecord) -> String {
    let mut head = format!("[{}]", record.category);
    if let Some(subcategory) = record
        .subcategory
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        head.push('/');
        head.push_str(subcategory);
    }
    let attribute = record
        .attribute
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("notes");
    format!("{head} {} {} {}", record.subject, attribute, record.value)
}

fn load_feedback_events(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<PersonalPreferenceFeedbackEvent>> {
    let mut stmt = conn.prepare(
        "SELECT id, event_type, claim_id, capture_id, notes, created_at_ms, metadata_json
         FROM pp_feedback_events
         ORDER BY created_at_ms DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let mut rows = stmt.query(params![limit.max(1) as i64, offset as i64])?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(row_to_feedback_event(row)?);
    }
    Ok(events)
}

fn load_snapshots(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<PersonalPreferenceSnapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, snapshot_kind, summary, stable_summary, changed_summary,
                active_projects_summary, created_at_ms, metadata_json
         FROM pp_identity_snapshots
         ORDER BY created_at_ms DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let mut rows = stmt.query(params![limit.max(1) as i64, offset as i64])?;
    let mut snapshots = Vec::new();
    while let Some(row) = rows.next()? {
        snapshots.push(row_to_snapshot(row)?);
    }
    Ok(snapshots)
}

fn load_snapshot_by_id(
    conn: &Connection,
    snapshot_id: &str,
) -> Result<Option<PersonalPreferenceSnapshot>> {
    Ok(conn
        .query_row(
            "SELECT id, snapshot_kind, summary, stable_summary, changed_summary,
                    active_projects_summary, created_at_ms, metadata_json
             FROM pp_identity_snapshots
             WHERE id = ?1",
            params![snapshot_id],
            row_to_snapshot,
        )
        .optional()?)
}

fn load_category_rows(conn: &Connection) -> Result<Vec<PersonalPreferenceCategory>> {
    let mut stmt = conn.prepare(
        "SELECT category, description, context_section, context_allowed_default,
                requires_review_for_sensitive, created_at_ms, updated_at_ms
         FROM pp_categories
         ORDER BY category ASC",
    )?;
    let mut rows = stmt.query([])?;
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        out.push(PersonalPreferenceCategory {
            category: row.get(0)?,
            description: row.get(1)?,
            context_section: row.get(2)?,
            context_allowed_default: row.get::<_, i64>(3)? != 0,
            requires_review_for_sensitive: row.get::<_, i64>(4)? != 0,
            created_at_ms: row.get(5)?,
            updated_at_ms: row.get(6)?,
        });
    }
    Ok(out)
}

fn load_category_policy_map(conn: &Connection) -> Result<BTreeMap<String, CategoryPolicy>> {
    let mut out = BTreeMap::new();
    for row in load_category_rows(conn)? {
        out.insert(
            row.category.clone(),
            CategoryPolicy {
                category: row.category,
                description: row.description,
                context_section: row.context_section,
                context_allowed_default: row.context_allowed_default,
                requires_review_for_sensitive: row.requires_review_for_sensitive,
            },
        );
    }
    Ok(out)
}

fn seed_default_category_policies(conn: &Connection) -> Result<()> {
    for seed in DEFAULT_CATEGORY_POLICIES {
        let policy = CategoryPolicy {
            category: seed.category.to_string(),
            description: seed.description.to_string(),
            context_section: seed.context_section.map(ToOwned::to_owned),
            context_allowed_default: seed.context_allowed_default,
            requires_review_for_sensitive: seed.requires_review_for_sensitive,
        };
        upsert_category_policy(conn, &policy)?;
    }
    Ok(())
}

fn upsert_category_policy(conn: &Connection, policy: &CategoryPolicy) -> Result<()> {
    let now = now_ms();
    conn.execute(
        "INSERT INTO pp_categories(
            category, description, context_section, context_allowed_default,
            requires_review_for_sensitive, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
         ON CONFLICT(category) DO UPDATE SET
            description = excluded.description,
            context_section = excluded.context_section,
            context_allowed_default = excluded.context_allowed_default,
            requires_review_for_sensitive = excluded.requires_review_for_sensitive,
            updated_at_ms = excluded.updated_at_ms",
        params![
            policy.category,
            policy.description,
            policy.context_section,
            if policy.context_allowed_default { 1 } else { 0 },
            if policy.requires_review_for_sensitive {
                1
            } else {
                0
            },
            now,
        ],
    )?;
    Ok(())
}

fn ensure_category_policy_for_record(
    conn: &Connection,
    record: &PersonalPreferenceDigestRecord,
) -> Result<CategoryPolicy> {
    let category = record.category.trim();
    let existing = conn
        .query_row(
            "SELECT description, context_section, context_allowed_default, requires_review_for_sensitive
             FROM pp_categories
             WHERE category = ?1",
            params![category],
            |row| {
                Ok(CategoryPolicy {
                    category: category.to_string(),
                    description: row.get(0)?,
                    context_section: row.get(1)?,
                    context_allowed_default: row.get::<_, i64>(2)? != 0,
                    requires_review_for_sensitive: row.get::<_, i64>(3)? != 0,
                })
            },
        )
        .optional()?;
    if let Some(existing) = existing {
        return Ok(existing);
    }
    let policy = default_category_policy(
        &record.category,
        &record.record_type,
        record.sensitivity.as_deref(),
    );
    upsert_category_policy(conn, &policy)?;
    Ok(policy)
}

fn default_category_policy(
    category: &str,
    record_type: &str,
    sensitivity: Option<&str>,
) -> CategoryPolicy {
    if let Some(seed) = DEFAULT_CATEGORY_POLICIES
        .iter()
        .find(|seed| seed.category == category)
    {
        return CategoryPolicy {
            category: seed.category.to_string(),
            description: seed.description.to_string(),
            context_section: seed.context_section.map(ToOwned::to_owned),
            context_allowed_default: seed.context_allowed_default,
            requires_review_for_sensitive: seed.requires_review_for_sensitive,
        };
    }
    let context_section = default_context_section_for(category, record_type);
    let sensitive =
        sensitivity.map(is_sensitive_level).unwrap_or(false) || category_is_sensitive(category);
    CategoryPolicy {
        category: category.to_string(),
        description: format!(
            "User-derived '{}' category captured from local conversation digests.",
            category.replace('_', " ")
        ),
        context_allowed_default: context_section.is_some() && !sensitive && category != "other",
        requires_review_for_sensitive: sensitive || record_type == "context",
        context_section,
    }
}

fn default_context_section_for(category: &str, record_type: &str) -> Option<String> {
    let category = category.trim();
    if category.is_empty() || category == "other" {
        return None;
    }
    if matches!(category, "cross_project_bridge")
        || category.contains("bridge")
        || record_type == "bridge"
    {
        return Some("cross_project_bridges".to_string());
    }
    if category.contains("project")
        || category.contains("goal")
        || category.contains("business")
        || matches!(record_type, "goal" | "project")
    {
        return Some("current_projects_and_goals".to_string());
    }
    if category.contains("communication")
        || category.contains("collaboration")
        || category.contains("learning")
        || category.contains("decision")
        || category.contains("personality")
        || record_type == "trait"
    {
        return Some("communication_and_collaboration_style".to_string());
    }
    if category.contains("strength")
        || category.contains("limitation")
        || record_type == "capability"
    {
        return Some("known_capabilities_and_history".to_string());
    }
    if category.contains("dislike") || category.contains("avoid") {
        return Some("avoidances_and_dislikes".to_string());
    }
    if category.contains("workflow")
        || category.contains("coding")
        || category.contains("tool")
        || category.contains("architecture")
        || category.contains("delivery")
        || category.contains("quality")
        || category.contains("like")
        || matches!(record_type, "preference" | "method" | "like" | "dislike")
    {
        return Some("stable_preferences".to_string());
    }
    None
}

fn category_is_sensitive(category: &str) -> bool {
    matches!(
        category,
        "business_context" | "personal_context" | "identity_context" | "health_context"
    ) || category.contains("private")
        || category.contains("health")
        || category.contains("identity")
        || category.contains("personal")
}

fn policy_for_category_fields(
    policies: &BTreeMap<String, CategoryPolicy>,
    category: &str,
    record_type: &str,
    sensitivity: &str,
) -> CategoryPolicy {
    policies
        .get(category)
        .cloned()
        .unwrap_or_else(|| default_category_policy(category, record_type, Some(sensitivity)))
}

fn should_materialize_bridge(record: &PersonalPreferenceDigestRecord) -> bool {
    matches!(
        record.category.as_str(),
        "tooling_preference"
            | "architecture_preference"
            | "workflow_method"
            | "current_projects"
            | "product_goals"
            | "cross_project_bridge"
    ) || matches!(
        record.record_type.as_str(),
        "bridge" | "project" | "goal" | "method"
    )
}

fn bridge_key_for_record(record: &PersonalPreferenceDigestRecord) -> String {
    slugify_identifier(&format!(
        "{}-{}-{}-{}",
        record.category,
        record.record_type,
        record.subject,
        record.attribute.as_deref().unwrap_or("notes")
    ))
}

fn default_review_status_for_record(
    record: &PersonalPreferenceDigestRecord,
    policy: &CategoryPolicy,
) -> &'static str {
    if policy.requires_review_for_sensitive
        && record
            .sensitivity
            .as_deref()
            .map(is_sensitive_level)
            .unwrap_or(false)
    {
        REVIEW_STATUS_PENDING
    } else {
        REVIEW_STATUS_APPROVED
    }
}

fn normalize_review_status(value: &str) -> Option<&'static str> {
    match normalize_text(value).to_ascii_lowercase().as_str() {
        "approved" | "approve" => Some(REVIEW_STATUS_APPROVED),
        "pending" | "pending_review" | "needs_review" => Some(REVIEW_STATUS_PENDING),
        "rejected" | "reject" => Some(REVIEW_STATUS_REJECTED),
        _ => None,
    }
}

fn normalize_feedback_event_type(value: &str) -> Option<&'static str> {
    match normalize_text(value).as_str() {
        "accept_output" | "accept" => Some(FEEDBACK_EVENT_ACCEPT_OUTPUT),
        "reject_output" | "reject" => Some(FEEDBACK_EVENT_REJECT_OUTPUT),
        "correct_output" | "correct" => Some(FEEDBACK_EVENT_CORRECT_OUTPUT),
        "rewrite_output" | "rewrite" => Some(FEEDBACK_EVENT_REWRITE_OUTPUT),
        "override_preference" | "override" => Some(FEEDBACK_EVENT_OVERRIDE_PREFERENCE),
        "downgrade_inference" | "downgrade" => Some(FEEDBACK_EVENT_DOWNGRADE_INFERENCE),
        "confirm_inference" | "confirm" => Some(FEEDBACK_EVENT_CONFIRM_INFERENCE),
        _ => None,
    }
}

fn normalize_clone_mode(value: &str) -> String {
    match normalize_text(value).as_str() {
        CLONE_MODE_PROJECT_BUILD => CLONE_MODE_PROJECT_BUILD.to_string(),
        CLONE_MODE_REVIEW => CLONE_MODE_REVIEW.to_string(),
        CLONE_MODE_RELEASE => CLONE_MODE_RELEASE.to_string(),
        CLONE_MODE_SIMULATE_USER_PREFERENCE => CLONE_MODE_SIMULATE_USER_PREFERENCE.to_string(),
        _ => CLONE_MODE_ADAPTIVE.to_string(),
    }
}

fn retention_cutoff_ms(days: u32) -> Option<i64> {
    if days == 0 {
        return None;
    }
    Some(now_ms().saturating_sub(days as i64 * 24 * 60 * 60 * 1000))
}

fn record_agent_id(record: &PersonalPreferenceRecord) -> Option<String> {
    record
        .metadata
        .get("agent_id")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn map_record_to_profile_category(record: &PersonalPreferenceRecord) -> Option<PreferenceCategory> {
    match record.category.as_str() {
        "tooling_preference" => Some(PreferenceCategory::Tooling),
        "workflow_method" | "decision_style" | "collaboration_style" | "learning_style" => {
            Some(PreferenceCategory::Workflow)
        }
        "communication_style"
        | "coding_preference"
        | "architecture_preference"
        | "delivery_preference"
        | "quality_bar"
        | "personality" => Some(PreferenceCategory::Style),
        "dislikes" | "limitations" => Some(PreferenceCategory::Constraint),
        _ => None,
    }
}

fn truth_status_rank(value: &str) -> i32 {
    match value {
        TRUTH_STATUS_CONFIRMED => 6,
        TRUTH_STATUS_INFERRED => 5,
        TRUTH_STATUS_CANDIDATE => 4,
        TRUTH_STATUS_SUPERSEDED => 3,
        TRUTH_STATUS_EXPIRED => 2,
        TRUTH_STATUS_REJECTED => 1,
        _ => 0,
    }
}

fn stability_rank(value: &str) -> i32 {
    match value {
        STABILITY_CLASS_FOUNDATIONAL => 5,
        STABILITY_CLASS_STABLE => 4,
        STABILITY_CLASS_CURRENT => 3,
        STABILITY_CLASS_SESSIONAL => 2,
        STABILITY_CLASS_EPHEMERAL => 1,
        _ => 0,
    }
}

fn truth_status_for_claim(review_status: &str, claim_origin: &str) -> &'static str {
    match review_status {
        REVIEW_STATUS_REJECTED => TRUTH_STATUS_REJECTED,
        REVIEW_STATUS_PENDING => TRUTH_STATUS_CANDIDATE,
        _ => {
            if matches!(
                claim_origin,
                CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT
                    | CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION
                    | CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY
            ) {
                TRUTH_STATUS_CONFIRMED
            } else {
                TRUTH_STATUS_INFERRED
            }
        }
    }
}

fn infer_claim_origin_from_backfill_record(record: &BackfillRecord) -> &'static str {
    if record
        .metadata
        .get("manual_review")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY;
    }
    if matches!(
        record.category.as_str(),
        "cross_project_bridge" | "business_context" | "current_projects"
    ) || matches!(record.record_type.as_str(), "bridge" | "project")
    {
        return CLAIM_ORIGIN_CROSS_SESSION_INFERENCE;
    }
    if matches!(
        record.record_type.as_str(),
        "preference" | "like" | "dislike" | "goal" | "method"
    ) {
        return CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT;
    }
    if matches!(record.record_type.as_str(), "trait" | "capability") {
        return CLAIM_ORIGIN_OBSERVED_BEHAVIOR;
    }
    CLAIM_ORIGIN_ENVIRONMENTAL_INFERENCE
}

fn infer_stability_class_from_backfill_record(record: &BackfillRecord) -> &'static str {
    if matches!(
        record.category.as_str(),
        "personality" | "decision_style" | "collaboration_style"
    ) {
        return STABILITY_CLASS_FOUNDATIONAL;
    }
    if matches!(
        record.category.as_str(),
        "current_projects" | "product_goals" | "business_context"
    ) || matches!(record.record_type.as_str(), "project" | "goal")
    {
        return STABILITY_CLASS_CURRENT;
    }
    if matches!(
        record.category.as_str(),
        "health_context" | "personal_context" | "identity_context"
    ) {
        return STABILITY_CLASS_SESSIONAL;
    }
    STABILITY_CLASS_STABLE
}

fn personal_record_to_backfill(record: &PersonalPreferenceRecord) -> BackfillRecord {
    BackfillRecord {
        id: record.id.clone(),
        capture_id: record.capture_id.clone(),
        record_type: record.record_type.clone(),
        category: record.category.clone(),
        subcategory: record.subcategory.clone(),
        subject: record.subject.clone(),
        attribute: record.attribute.clone(),
        value: record.value.clone(),
        confidence: record.confidence,
        sensitivity: record.sensitivity.clone(),
        evidence: record.evidence.clone(),
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
        metadata: record.metadata.clone(),
        review_status: record.review_status.clone(),
    }
}

fn upsert_claim_from_backfill_record(
    conn: &Connection,
    record: &BackfillRecord,
    write_path: &str,
) -> Result<()> {
    let claim_origin = infer_claim_origin_from_backfill_record(record);
    let truth_status = truth_status_for_claim(&record.review_status, claim_origin);
    let stability_class = infer_stability_class_from_backfill_record(record);
    let valid_from_ms = parse_timestamp_json_value(record.metadata.get("valid_from_ms"))
        .or(Some(record.created_at_ms));
    let valid_to_ms = parse_timestamp_json_value(record.metadata.get("valid_to_ms"));
    let mut metadata = record.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert("record_type".to_string(), json!(record.record_type.clone()));
    metadata.insert("capture_id".to_string(), json!(record.capture_id.clone()));
    metadata.insert("claim_materialized_from_record".to_string(), json!(true));
    metadata.insert("claim_write_path".to_string(), json!(write_path));
    let claim_id = conn
        .query_row(
            "SELECT id FROM pp_claims WHERE record_id = ?1",
            params![record.id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| format!("claim_{}", Uuid::new_v4()));
    conn.execute(
        "INSERT INTO pp_claims(
            id, record_id, capture_id, category, subcategory, subject, attribute, value,
            claim_origin, truth_status, stability_class, sensitivity, confidence,
            review_status, evidence_summary, valid_from_ms, valid_to_ms,
            supersedes_claim_id, contradicted_by_claim_id, created_at_ms, updated_at_ms,
            metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16,
                   ?17, NULL, NULL, ?18, ?19, ?20)
         ON CONFLICT(record_id) DO UPDATE SET
            capture_id = excluded.capture_id,
            category = excluded.category,
            subcategory = excluded.subcategory,
            subject = excluded.subject,
            attribute = excluded.attribute,
            value = excluded.value,
            claim_origin = excluded.claim_origin,
            truth_status = excluded.truth_status,
            stability_class = excluded.stability_class,
            sensitivity = excluded.sensitivity,
            confidence = excluded.confidence,
            review_status = excluded.review_status,
            evidence_summary = excluded.evidence_summary,
            valid_from_ms = excluded.valid_from_ms,
            valid_to_ms = excluded.valid_to_ms,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            claim_id,
            record.id,
            record.capture_id,
            record.category,
            record.subcategory,
            record.subject,
            record.attribute,
            record.value,
            claim_origin,
            truth_status,
            stability_class,
            record.sensitivity,
            record.confidence,
            record.review_status,
            record.evidence,
            valid_from_ms,
            valid_to_ms,
            record.created_at_ms,
            record.updated_at_ms,
            serde_json::to_string(&Value::Object(metadata.clone()))?,
        ],
    )?;
    replace_claim_evidence(
        conn,
        &claim_id,
        Some(&record.capture_id),
        record.evidence.as_deref(),
        &Value::Object(metadata.clone()),
        record.updated_at_ms,
    )?;
    write_claim_link(
        conn,
        &claim_id,
        None,
        "derived_from_record",
        &json!({ "record_id": record.id }),
        record.updated_at_ms,
    )?;
    Ok(())
}

fn backfill_claims_from_records(conn: &Connection, capture_id: Option<&str>) -> Result<usize> {
    let mut records = load_all_records(conn)?;
    if let Some(capture_id) = capture_id {
        records.retain(|record| record.capture_id == capture_id);
    }
    let mut changed = 0usize;
    for record in records {
        if record_is_forgotten(&record) {
            if let Some(existing_claim) = conn
                .query_row(
                    "SELECT id, record_id, capture_id, category, subcategory, subject, attribute, value,
                            claim_origin, truth_status, stability_class, sensitivity, confidence,
                            review_status, evidence_summary, valid_from_ms, valid_to_ms,
                            supersedes_claim_id, contradicted_by_claim_id, created_at_ms, updated_at_ms,
                            metadata_json
                     FROM pp_claims
                     WHERE record_id = ?1",
                    params![record.id],
                    row_to_claim,
                )
                .optional()?
            {
                let now = now_ms();
                let mut metadata = existing_claim
                    .metadata
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                metadata.insert("forgotten".to_string(), json!(true));
                metadata.insert("forgotten_at_ms".to_string(), json!(now));
                conn.execute(
                    "UPDATE pp_claims
                     SET truth_status = ?2,
                         review_status = ?3,
                         value = ?4,
                         evidence_summary = ?4,
                         valid_to_ms = ?5,
                         updated_at_ms = ?5,
                         metadata_json = ?6
                     WHERE id = ?1",
                    params![
                        existing_claim.id,
                        TRUTH_STATUS_EXPIRED,
                        REVIEW_STATUS_REJECTED,
                        REDACTED_TEXT,
                        now,
                        serde_json::to_string(&Value::Object(metadata))?,
                    ],
                )?;
            }
            continue;
        }
        let materialized = personal_record_to_backfill(&record);
        upsert_claim_from_backfill_record(conn, &materialized, "compat_backfill")?;
        changed += 1;
    }
    Ok(changed)
}

fn write_claim_version(
    conn: &Connection,
    claim_id: &str,
    change: &Value,
    created_at_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_claim_versions(id, claim_id, change_json, created_at_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            format!("claim_version_{}", Uuid::new_v4()),
            claim_id,
            serde_json::to_string(change)?,
            created_at_ms
        ],
    )?;
    Ok(())
}

fn replace_claim_evidence(
    conn: &Connection,
    claim_id: &str,
    capture_id: Option<&str>,
    evidence_text: Option<&str>,
    metadata: &Value,
    created_at_ms: i64,
) -> Result<()> {
    conn.execute(
        "DELETE FROM pp_claim_evidence WHERE claim_id = ?1",
        params![claim_id],
    )?;
    let Some(evidence_text) = evidence_text
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != REDACTED_TEXT)
    else {
        return Ok(());
    };
    let evidence_id = format!(
        "claim_evidence_{}",
        sha256_hex(&format!("{claim_id}:{evidence_text}"))
    );
    conn.execute(
        "INSERT OR REPLACE INTO pp_claim_evidence(
            id, claim_id, capture_id, evidence_text, metadata_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            evidence_id,
            claim_id,
            capture_id,
            evidence_text,
            serde_json::to_string(metadata)?,
            created_at_ms,
        ],
    )?;
    Ok(())
}

fn write_claim_link(
    conn: &Connection,
    claim_id: &str,
    linked_claim_id: Option<&str>,
    link_type: &str,
    metadata: &Value,
    created_at_ms: i64,
) -> Result<()> {
    let link_id = format!(
        "claim_link_{}",
        sha256_hex(&format!(
            "{}:{}:{}:{}",
            claim_id,
            linked_claim_id.unwrap_or_default(),
            link_type,
            metadata
        ))
    );
    conn.execute(
        "INSERT OR REPLACE INTO pp_claim_links(
            id, claim_id, linked_claim_id, link_type, metadata_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            link_id,
            claim_id,
            linked_claim_id,
            link_type,
            serde_json::to_string(metadata)?,
            created_at_ms,
        ],
    )?;
    Ok(())
}

fn claim_is_forgotten(claim: &PersonalPreferenceClaim) -> bool {
    claim
        .metadata
        .get("forgotten")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || claim
            .metadata
            .get("forgotten_at_ms")
            .and_then(Value::as_i64)
            .is_some()
}

fn record_is_forgotten(record: &PersonalPreferenceRecord) -> bool {
    record
        .metadata
        .get("forgotten")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || record
            .metadata
            .get("forgotten_at_ms")
            .and_then(Value::as_i64)
            .is_some()
}

fn apply_feedback_to_claim(
    claim: &PersonalPreferenceClaim,
    event_type: &str,
    _value: Option<&str>,
) -> (f32, &'static str) {
    match event_type {
        FEEDBACK_EVENT_ACCEPT_OUTPUT | FEEDBACK_EVENT_CONFIRM_INFERENCE => (
            (claim.confidence + 0.08).clamp(0.0, 1.0),
            if event_type == FEEDBACK_EVENT_CONFIRM_INFERENCE {
                TRUTH_STATUS_CONFIRMED
            } else if claim.truth_status == TRUTH_STATUS_REJECTED {
                TRUTH_STATUS_CANDIDATE
            } else if claim.truth_status == TRUTH_STATUS_CANDIDATE {
                TRUTH_STATUS_INFERRED
            } else {
                TRUTH_STATUS_CONFIRMED
            },
        ),
        FEEDBACK_EVENT_REJECT_OUTPUT => (
            (claim.confidence - 0.25).clamp(0.0, 1.0),
            TRUTH_STATUS_REJECTED,
        ),
        FEEDBACK_EVENT_DOWNGRADE_INFERENCE => (
            (claim.confidence - 0.18).clamp(0.0, 1.0),
            TRUTH_STATUS_CANDIDATE,
        ),
        FEEDBACK_EVENT_CORRECT_OUTPUT
        | FEEDBACK_EVENT_REWRITE_OUTPUT
        | FEEDBACK_EVENT_OVERRIDE_PREFERENCE => (
            (claim.confidence - 0.2).clamp(0.0, 1.0),
            TRUTH_STATUS_SUPERSEDED,
        ),
        _ => (claim.confidence, TRUTH_STATUS_CANDIDATE),
    }
}

fn create_override_claim_from_claim(
    conn: &Connection,
    claim: &PersonalPreferenceClaim,
    category: Option<&str>,
    attribute: Option<&str>,
    override_value: &str,
    notes: Option<&str>,
    now: i64,
) -> Result<PersonalPreferenceClaim> {
    let id = format!("claim_{}", Uuid::new_v4());
    let category = category
        .map(normalize_category)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| claim.category.clone());
    let attribute = attribute
        .map(|value| normalize_optional_text(Some(value)))
        .flatten()
        .or_else(|| claim.attribute.clone());
    let mut metadata = claim.metadata.as_object().cloned().unwrap_or_default();
    metadata.insert("manual_override".to_string(), json!(true));
    metadata.insert("notes".to_string(), json!(notes));
    conn.execute(
        "INSERT INTO pp_claims(
            id, record_id, capture_id, category, subcategory, subject, attribute, value,
            claim_origin, truth_status, stability_class, sensitivity, confidence, review_status,
            evidence_summary, valid_from_ms, valid_to_ms, supersedes_claim_id,
            contradicted_by_claim_id, created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                   NULL, ?16, NULL, ?17, ?17, ?18)",
        params![
            id,
            claim.capture_id,
            category,
            claim.subcategory,
            claim.subject,
            attribute,
            normalize_text(override_value),
            CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY,
            TRUTH_STATUS_CONFIRMED,
            claim.stability_class,
            claim.sensitivity,
            0.98_f32,
            REVIEW_STATUS_APPROVED,
            notes.or(claim.evidence_summary.as_deref()),
            Some(now),
            claim.id,
            now,
            serde_json::to_string(&Value::Object(metadata.clone()))?,
        ],
    )?;
    write_claim_version(
        conn,
        &id,
        &json!({
            "action": "override_create",
            "supersedes_claim_id": claim.id,
            "value": override_value,
            "notes": notes,
        }),
        now,
    )?;
    replace_claim_evidence(
        conn,
        &id,
        claim.capture_id.as_deref(),
        notes.or(claim.evidence_summary.as_deref()),
        &Value::Object(metadata.clone()),
        now,
    )?;
    write_claim_link(
        conn,
        &id,
        Some(&claim.id),
        "supersedes_claim",
        &json!({ "source": "override_feedback" }),
        now,
    )?;
    let created =
        load_claim_by_id(conn, &id)?.ok_or_else(|| anyhow!("override claim was not created"))?;
    upsert_override_rule_from_claim(conn, &created, now)?;
    Ok(created)
}

fn create_manual_feedback_claim(
    conn: &Connection,
    event_type: &str,
    capture_id: Option<&str>,
    category: Option<&str>,
    attribute: Option<&str>,
    new_value: &str,
    notes: Option<&str>,
    now: i64,
) -> Result<PersonalPreferenceClaim> {
    let id = format!("claim_{}", Uuid::new_v4());
    let category = category
        .map(normalize_category)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "other".to_string());
    let attribute = attribute
        .map(|value| normalize_optional_text(Some(value)))
        .flatten();
    let stability_class = if category == "other" {
        STABILITY_CLASS_CURRENT
    } else {
        STABILITY_CLASS_STABLE
    };
    conn.execute(
        "INSERT INTO pp_claims(
            id, record_id, capture_id, category, subcategory, subject, attribute, value,
            claim_origin, truth_status, stability_class, sensitivity, confidence, review_status,
            evidence_summary, valid_from_ms, valid_to_ms, supersedes_claim_id,
            contradicted_by_claim_id, created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, NULL, ?2, ?3, NULL, 'user', ?4, ?5, ?6, ?7, ?8, 'low', ?9, ?10, ?11,
                   ?12, NULL, NULL, NULL, ?12, ?12, ?13)",
        params![
            id,
            capture_id,
            category,
            attribute,
            normalize_text(new_value),
            CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY,
            TRUTH_STATUS_CONFIRMED,
            stability_class,
            0.96_f32,
            REVIEW_STATUS_APPROVED,
            notes,
            now,
            serde_json::to_string(&json!({
                "manual_feedback": true,
                "event_type": event_type,
            }))?,
        ],
    )?;
    write_claim_version(
        conn,
        &id,
        &json!({
            "action": "manual_feedback_claim",
            "event_type": event_type,
            "value": new_value,
            "notes": notes,
        }),
        now,
    )?;
    let metadata = json!({
        "manual_feedback": true,
        "event_type": event_type,
    });
    replace_claim_evidence(conn, &id, capture_id, notes, &metadata, now)?;
    let created = load_claim_by_id(conn, &id)?
        .ok_or_else(|| anyhow!("manual feedback claim was not created"))?;
    if event_type == FEEDBACK_EVENT_OVERRIDE_PREFERENCE {
        upsert_override_rule_from_claim(conn, &created, now)?;
    }
    Ok(created)
}

fn section_for_claim(claim: &PersonalPreferenceClaim, record_type: &str, mode: &str) -> String {
    if claim.category == "cross_project_bridge" || record_type == "bridge" {
        return "relevant_cross_project_bridges".to_string();
    }
    if matches!(
        claim.category.as_str(),
        "communication_style" | "collaboration_style" | "learning_style" | "personality"
    ) {
        return "relevant_communication_style_expectations".to_string();
    }
    if matches!(
        claim.category.as_str(),
        "current_projects" | "product_goals" | "business_context"
    ) || matches!(record_type, "project" | "goal")
    {
        return "active_project_and_strategic_context".to_string();
    }
    if matches!(
        claim.category.as_str(),
        "workflow_method" | "quality_bar" | "delivery_preference" | "decision_style"
    ) || (mode == CLONE_MODE_REVIEW
        && matches!(
            claim.category.as_str(),
            "coding_preference" | "architecture_preference"
        ))
    {
        return "current_workflow_and_quality_expectations".to_string();
    }
    if matches!(claim.category.as_str(), "strengths" | "limitations") || record_type == "capability"
    {
        return "known_capabilities_and_history".to_string();
    }
    "stable_preferences".to_string()
}

fn render_claim_content(claim: &PersonalPreferenceClaim) -> String {
    let mut head = format!("[{}]", claim.category);
    if let Some(subcategory) = claim
        .subcategory
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        head.push('/');
        head.push_str(subcategory);
    }
    let attribute = claim
        .attribute
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("notes");
    format!("{head} {} {} {}", claim.subject, attribute, claim.value)
}

fn clone_mode_section_boost(section: &str, mode: &str) -> f32 {
    match (mode, section) {
        (CLONE_MODE_PROJECT_BUILD, "active_project_and_strategic_context")
        | (CLONE_MODE_PROJECT_BUILD, "current_workflow_and_quality_expectations")
        | (CLONE_MODE_REVIEW, "current_workflow_and_quality_expectations")
        | (CLONE_MODE_REVIEW, "relevant_communication_style_expectations")
        | (CLONE_MODE_RELEASE, "active_project_and_strategic_context")
        | (CLONE_MODE_RELEASE, "current_workflow_and_quality_expectations")
        | (CLONE_MODE_SIMULATE_USER_PREFERENCE, "relevant_communication_style_expectations")
        | (CLONE_MODE_SIMULATE_USER_PREFERENCE, "stable_preferences") => 1.25,
        _ => 1.0,
    }
}

fn clone_term_match_score(text: &str, query: &str) -> f32 {
    let haystack = text.to_ascii_lowercase();
    query
        .split_whitespace()
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| !term.is_empty())
        .map(|term| if haystack.contains(&term) { 0.5 } else { 0.0 })
        .sum()
}

fn load_clone_context_candidates(
    conn: &Connection,
    query: &str,
    mode: &str,
    allow_sensitive: bool,
) -> Result<Vec<CloneContextCandidate>> {
    let policies = load_category_policy_map(conn)?;
    let mut claims = load_all_claims(conn)?;
    claims.retain(|claim| {
        !claim_is_forgotten(claim)
            && !matches!(
                claim.truth_status.as_str(),
                TRUTH_STATUS_REJECTED | TRUTH_STATUS_EXPIRED
            )
    });
    let mut candidates = Vec::new();
    for claim in claims {
        let record_type = claim
            .metadata
            .get("record_type")
            .and_then(Value::as_str)
            .unwrap_or("preference")
            .to_string();
        let policy = policy_for_category_fields(
            &policies,
            &claim.category,
            &record_type,
            &claim.sensitivity,
        );
        let allowed = allow_sensitive
            || (policy.context_allowed_default && !is_sensitive_level(&claim.sensitivity));
        let section = section_for_claim(&claim, &record_type, mode);
        let content = render_claim_content(&claim);
        let mut score = claim.confidence * 10.0
            + truth_status_rank(&claim.truth_status) as f32 * 2.0
            + stability_rank(&claim.stability_class) as f32
            + clone_term_match_score(&content, query);
        score *= clone_mode_section_boost(&section, mode);
        if claim.claim_origin == CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION {
            score += 4.0;
        }
        candidates.push(CloneContextCandidate {
            claim,
            section,
            content,
            record_type,
            source_repo_root: None,
            allowed,
            reason: format!("{mode} candidate"),
            score,
        });
    }
    Ok(candidates)
}

fn load_claim_bridge_candidates(
    conn: &Connection,
    current_repo_root: &str,
    allow_sensitive: bool,
    policies: &BTreeMap<String, CategoryPolicy>,
) -> Result<Vec<CloneContextCandidate>> {
    let mut stmt = conn.prepare(
        "SELECT id, record_id, capture_id, category, subcategory, subject, attribute, value,
                claim_origin, truth_status, stability_class, sensitivity, confidence,
                review_status, evidence_summary, valid_from_ms, valid_to_ms,
                supersedes_claim_id, contradicted_by_claim_id, created_at_ms, updated_at_ms,
                metadata_json
         FROM pp_claims
         WHERE category = 'cross_project_bridge'
            OR EXISTS (
                SELECT 1
                FROM pp_cross_project_bridges b
                WHERE b.record_id = pp_claims.record_id
                  AND b.source_repo_root != ?1
            )
         ORDER BY updated_at_ms DESC, confidence DESC",
    )?;
    let mut rows = stmt.query(params![current_repo_root])?;
    let mut items = Vec::new();
    let mut seen = HashSet::new();
    while let Some(row) = rows.next()? {
        let claim = row_to_claim(row)?;
        if claim_is_forgotten(&claim)
            || claim.review_status == REVIEW_STATUS_REJECTED
            || matches!(
                claim.truth_status.as_str(),
                TRUTH_STATUS_REJECTED | TRUTH_STATUS_EXPIRED
            )
        {
            continue;
        }
        let record_type = claim
            .metadata
            .get("record_type")
            .and_then(Value::as_str)
            .unwrap_or("bridge")
            .to_string();
        let policy =
            policy_for_category_fields(policies, &claim.category, &record_type, &claim.sensitivity);
        let allowed = allow_sensitive
            || (policy.context_allowed_default && !is_sensitive_level(&claim.sensitivity));
        let source_repo_root = claim
            .metadata
            .get("repo_root")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if source_repo_root.as_deref() == Some(current_repo_root) {
            continue;
        }
        let repo_label = source_repo_root
            .as_deref()
            .and_then(|value| Path::new(value).file_name().and_then(|part| part.to_str()))
            .unwrap_or("other project");
        let content = format!("From {repo_label}: {}", render_claim_content(&claim));
        if !seen.insert(content.clone()) {
            continue;
        }
        items.push(CloneContextCandidate {
            claim,
            section: "relevant_cross_project_bridges".to_string(),
            content,
            record_type,
            source_repo_root,
            allowed,
            reason: "cross_project_bridge".to_string(),
            score: 8.0,
        });
    }
    Ok(items)
}

fn render_clone_context_summary(items: &[PersonalPreferencesContextItem]) -> String {
    if items.is_empty() {
        return "No relevant personal-preferences clone context was selected.".to_string();
    }
    let mut by_section: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for item in items {
        by_section
            .entry(item.section.as_str())
            .or_default()
            .push(item.content.as_str());
    }
    by_section
        .into_iter()
        .map(|(section, values)| {
            let preview = values.into_iter().take(2).collect::<Vec<_>>().join(" | ");
            format!("{section}: {preview}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn upsert_clone_profile(
    conn: &Connection,
    mode: &str,
    summary: &str,
    updated_at_ms: i64,
) -> Result<()> {
    let id = conn
        .query_row(
            "SELECT id FROM pp_clone_profiles WHERE mode = ?1",
            params![mode],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_else(|| format!("clone_profile_{}", Uuid::new_v4()));
    conn.execute(
        "INSERT INTO pp_clone_profiles(id, mode, summary, updated_at_ms, metadata_json)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(mode) DO UPDATE SET
            summary = excluded.summary,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            id,
            mode,
            summary,
            updated_at_ms,
            serde_json::to_string(&json!({ "summary_length": summary.len() }))?
        ],
    )?;
    Ok(())
}

fn rebuild_identity_snapshots_tx(
    conn: &Connection,
    capture_id: Option<&str>,
    reason: &str,
) -> Result<Option<String>> {
    backfill_claims_from_records(conn, capture_id)?;
    let mut claims = load_all_claims(conn)?;
    claims.retain(|claim| {
        !claim_is_forgotten(claim)
            && claim.review_status == REVIEW_STATUS_APPROVED
            && !matches!(
                claim.truth_status.as_str(),
                TRUTH_STATUS_REJECTED | TRUTH_STATUS_SUPERSEDED | TRUTH_STATUS_EXPIRED
            )
    });
    if claims.is_empty() {
        return Ok(None);
    }
    claims.sort_by(|left, right| {
        right
            .confidence
            .partial_cmp(&left.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| right.updated_at_ms.cmp(&left.updated_at_ms))
    });
    let stable_summary = claims
        .iter()
        .filter(|claim| {
            matches!(
                claim.stability_class.as_str(),
                STABILITY_CLASS_FOUNDATIONAL | STABILITY_CLASS_STABLE
            )
        })
        .take(4)
        .map(render_claim_snapshot_line)
        .collect::<Vec<_>>()
        .join(" | ");
    let changed_summary = claims
        .iter()
        .filter(|claim| capture_id.is_none() || claim.capture_id.as_deref() == capture_id)
        .take(4)
        .map(render_claim_snapshot_line)
        .collect::<Vec<_>>()
        .join(" | ");
    let active_projects_summary = claims
        .iter()
        .filter(|claim| {
            matches!(
                claim.category.as_str(),
                "current_projects" | "product_goals" | "business_context"
            )
        })
        .take(4)
        .map(render_claim_snapshot_line)
        .collect::<Vec<_>>()
        .join(" | ");
    let summary = [
        stable_summary.as_str(),
        changed_summary.as_str(),
        active_projects_summary.as_str(),
    ]
    .into_iter()
    .filter(|value| !value.trim().is_empty())
    .take(3)
    .collect::<Vec<_>>()
    .join("\n");
    let snapshot_id = format!("snapshot_{}", Uuid::new_v4());
    let created_at_ms = now_ms();
    conn.execute(
        "INSERT INTO pp_identity_snapshots(
            id, snapshot_kind, summary, stable_summary, changed_summary,
            active_projects_summary, created_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            snapshot_id,
            "identity",
            summary,
            empty_to_null(&stable_summary),
            empty_to_null(&changed_summary),
            empty_to_null(&active_projects_summary),
            created_at_ms,
            serde_json::to_string(&json!({
                "reason": reason,
                "capture_id": capture_id,
                "claim_count": claims.len(),
            }))?,
        ],
    )?;
    rebuild_snapshot_signal_tables(conn, &snapshot_id, &claims, created_at_ms)?;
    Ok(Some(snapshot_id))
}

fn rebuild_snapshot_signal_tables(
    conn: &Connection,
    snapshot_id: &str,
    claims: &[PersonalPreferenceClaim],
    created_at_ms: i64,
) -> Result<()> {
    for claim in claims {
        if matches!(
            claim.category.as_str(),
            "workflow_method" | "decision_style" | "quality_bar" | "delivery_preference"
        ) {
            conn.execute(
                "INSERT INTO pp_decision_patterns(
                    id, snapshot_id, pattern_key, summary, confidence, created_at_ms, updated_at_ms,
                    metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
                params![
                    format!("decision_pattern_{}", Uuid::new_v4()),
                    snapshot_id,
                    slugify_identifier(&format!(
                        "{}-{}",
                        claim.category,
                        claim.attribute.as_deref().unwrap_or("notes")
                    )),
                    render_claim_snapshot_line(claim),
                    claim.confidence,
                    created_at_ms,
                    serde_json::to_string(&json!({ "claim_id": claim.id }))?,
                ],
            )?;
        }
        if matches!(
            claim.category.as_str(),
            "communication_style" | "collaboration_style" | "learning_style" | "personality"
        ) {
            conn.execute(
                "INSERT INTO pp_style_signals(
                    id, snapshot_id, signal_key, summary, confidence, created_at_ms, updated_at_ms,
                    metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7)",
                params![
                    format!("style_signal_{}", Uuid::new_v4()),
                    snapshot_id,
                    slugify_identifier(&format!(
                        "{}-{}",
                        claim.category,
                        claim.attribute.as_deref().unwrap_or("notes")
                    )),
                    render_claim_snapshot_line(claim),
                    claim.confidence,
                    created_at_ms,
                    serde_json::to_string(&json!({ "claim_id": claim.id }))?,
                ],
            )?;
        }
        if let Some(project_name) = project_name_for_claim(claim) {
            conn.execute(
                "INSERT INTO pp_project_timelines(
                    id, claim_id, snapshot_id, project_name, repo_root, lifecycle_state,
                    valid_from_ms, valid_to_ms, created_at_ms, updated_at_ms, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?9, ?10)",
                params![
                    format!(
                        "project_timeline_{}_{}",
                        snapshot_id,
                        slugify_identifier(&claim.id)
                    ),
                    claim.id,
                    snapshot_id,
                    project_name,
                    claim_repo_root(claim),
                    project_lifecycle_state_for_claim(claim),
                    claim.valid_from_ms,
                    claim.valid_to_ms,
                    created_at_ms,
                    serde_json::to_string(&json!({
                        "claim_id": claim.id,
                        "category": claim.category,
                    }))?,
                ],
            )?;
        }
        if goal_graph_relevant(claim) {
            conn.execute(
                "INSERT INTO pp_goal_graph(
                    id, claim_id, snapshot_id, goal_key, summary, status, project_name,
                    created_at_ms, updated_at_ms, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)",
                params![
                    format!(
                        "goal_graph_{}_{}",
                        snapshot_id,
                        slugify_identifier(&claim.id)
                    ),
                    claim.id,
                    snapshot_id,
                    goal_key_for_claim(claim),
                    render_claim_snapshot_line(claim),
                    goal_status_for_claim(claim),
                    project_name_for_claim(claim),
                    created_at_ms,
                    serde_json::to_string(&json!({
                        "claim_id": claim.id,
                        "category": claim.category,
                    }))?,
                ],
            )?;
        }
        if is_override_rule_claim(claim) {
            upsert_override_rule_from_claim(conn, claim, created_at_ms)?;
        }
    }
    Ok(())
}

fn claim_repo_root(claim: &PersonalPreferenceClaim) -> Option<String> {
    claim
        .metadata
        .get("repo_root")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn project_name_for_claim(claim: &PersonalPreferenceClaim) -> Option<String> {
    claim
        .metadata
        .get("project_name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| {
            claim_repo_root(claim)
                .as_deref()
                .and_then(|value| Path::new(value).file_name().and_then(|part| part.to_str()))
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            if matches!(
                claim.category.as_str(),
                "current_projects" | "project_history" | "business_context"
            ) || claim.metadata.get("record_type").and_then(Value::as_str) == Some("project")
            {
                Some(truncate_chars(&claim.value, 96))
            } else {
                None
            }
        })
}

fn project_lifecycle_state_for_claim(claim: &PersonalPreferenceClaim) -> String {
    claim
        .metadata
        .get("lifecycle_state")
        .and_then(Value::as_str)
        .map(normalize_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| match claim.category.as_str() {
            "current_projects" | "business_context" => "active".to_string(),
            "project_history" => "historical".to_string(),
            "cross_project_bridge" => "related".to_string(),
            _ => "observed".to_string(),
        })
}

fn goal_graph_relevant(claim: &PersonalPreferenceClaim) -> bool {
    matches!(
        claim.category.as_str(),
        "product_goals" | "business_context" | "current_projects"
    ) || claim.metadata.get("record_type").and_then(Value::as_str) == Some("goal")
}

fn goal_key_for_claim(claim: &PersonalPreferenceClaim) -> String {
    claim
        .metadata
        .get("goal_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            slugify_identifier(&format!(
                "{}-{}",
                claim.category,
                truncate_chars(&claim.value, 48)
            ))
        })
}

fn goal_status_for_claim(claim: &PersonalPreferenceClaim) -> String {
    claim
        .metadata
        .get("goal_status")
        .and_then(Value::as_str)
        .map(normalize_text)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| match claim.category.as_str() {
            "product_goals" | "current_projects" => "active".to_string(),
            "business_context" => "context".to_string(),
            _ => "observed".to_string(),
        })
}

fn is_override_rule_claim(claim: &PersonalPreferenceClaim) -> bool {
    claim
        .metadata
        .get("manual_override")
        .and_then(Value::as_bool)
        .unwrap_or(false)
        || claim
            .metadata
            .get("manual_feedback")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

fn upsert_override_rule_from_claim(
    conn: &Connection,
    claim: &PersonalPreferenceClaim,
    updated_at_ms: i64,
) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO pp_override_rules(
            id, claim_id, category, attribute, subject, override_value, reason,
            created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, ?9)",
        params![
            format!("override_rule_{}", claim.id),
            claim.id,
            claim.category,
            claim.attribute,
            claim.subject,
            claim.value,
            claim
                .metadata
                .get("notes")
                .and_then(Value::as_str)
                .or(claim.evidence_summary.as_deref()),
            updated_at_ms,
            serde_json::to_string(&json!({
                "claim_id": claim.id,
                "claim_origin": claim.claim_origin,
            }))?,
        ],
    )?;
    Ok(())
}

fn render_claim_snapshot_line(claim: &PersonalPreferenceClaim) -> String {
    let attribute = claim
        .attribute
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("notes");
    format!(
        "[{}] {} {} {}",
        claim.category, claim.subject, attribute, claim.value
    )
}

fn empty_to_null(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn estimate_tokens(text: &str) -> usize {
    text.split_whitespace()
        .filter(|part| !part.is_empty())
        .count()
}

fn truncate_to_tokens(text: &str, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    let mut truncated = false;
    for (index, token) in text.split_whitespace().enumerate() {
        if index >= max_tokens {
            truncated = true;
            break;
        }
        out.push(token);
    }
    if out.is_empty() {
        String::new()
    } else {
        let mut text = out.join(" ");
        if truncated {
            text.push('…');
        }
        text
    }
}

fn normalize_category(value: &str) -> String {
    let normalized = slugify_identifier(value);
    if normalized.is_empty() {
        return "other".to_string();
    }
    normalized
}

fn normalize_record_type(value: &str) -> String {
    match normalize_text(value).as_str() {
        "preference" | "method" | "goal" | "project" | "trait" | "capability" | "context"
        | "like" | "dislike" | "bridge" | "other" => normalize_text(value),
        _ => "other".to_string(),
    }
}

fn normalize_sensitivity(value: &str) -> String {
    match normalize_text(value).as_str() {
        "low" => "low".to_string(),
        "medium" | "private" => "private".to_string(),
        "high" | "sensitive" => "sensitive".to_string(),
        "special" => "special".to_string(),
        _ => "private".to_string(),
    }
}

fn is_sensitive_level(value: &str) -> bool {
    matches!(value, "private" | "sensitive" | "special")
}

fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    let value = value?;
    let normalized = normalize_text(value);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_non_empty_text(value: &str) -> Option<String> {
    let normalized = normalize_text(value);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn normalize_text(value: &str) -> String {
    value.trim().replace('\n', " ")
}

fn slugify_identifier(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in value.trim().chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            out.push(normalized);
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

fn parse_json_value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::Object(Default::default()))
}

fn extract_balanced_json_candidates(text: &str) -> Vec<&str> {
    let mut candidates = Vec::new();
    let mut stack: Vec<(char, usize)> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            continue;
        }

        match ch {
            '{' | '[' => stack.push((ch, idx)),
            '}' | ']' => {
                let Some((open, start)) = stack.pop() else {
                    continue;
                };
                let matched = matches!((open, ch), ('{', '}') | ('[', ']'));
                if !matched {
                    stack.clear();
                    continue;
                }
                if stack.is_empty() {
                    candidates.push(&text[start..idx + ch.len_utf8()]);
                }
            }
            _ => {}
        }
    }

    candidates
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out = String::new();
    for ch in text.chars().take(max_chars) {
        out.push(ch);
    }
    out.push('…');
    out
}

fn count_files(dir: &Path) -> Result<usize> {
    let mut count = 0usize;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

fn remove_dir_contents(dir: &Path) -> Result<usize> {
    let mut removed = 0usize;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

fn delete_if_exists(path: &Path) -> Result<bool> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}
