use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    pub operator_routines_total: usize,
    #[serde(default)]
    pub operator_events_total: usize,
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
    #[serde(default)]
    pub digest_failure_breakdown: Vec<PersonalPreferenceDigestFailureGroup>,
    #[serde(default)]
    pub clone_readiness: PersonalPreferenceCloneReadiness,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReadiness {
    pub level: u8,
    pub stage: String,
    pub score: f32,
    pub collection_ready: bool,
    pub profile_projection_ready: bool,
    pub routine_ready: bool,
    #[serde(default)]
    pub action_telemetry_ready: bool,
    pub replay_ready: bool,
    pub feedback_ready: bool,
    pub autonomy_ready: bool,
    pub queue_healthy: bool,
    pub source_diversity_ready: bool,
    pub evidence_ready: bool,
    pub noise_control_ready: bool,
    #[serde(default)]
    pub metrics: Vec<PersonalPreferenceCloneReadinessMetric>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub next_actions: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReadinessMetric {
    pub id: String,
    pub label: String,
    pub ready: bool,
    pub observed: usize,
    pub target: usize,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceDigestFailureGroup {
    pub source: String,
    pub capture_kind: String,
    pub failure_class: String,
    pub count: usize,
    #[serde(default)]
    pub latest_error: Option<String>,
    #[serde(default)]
    pub latest_at_ms: Option<i64>,
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
pub struct PersonalPreferenceOperatorRoutineStep {
    pub id: String,
    pub routine_id: String,
    pub step_order: usize,
    pub step_key: String,
    pub title: String,
    pub instruction: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub tool_hints: Vec<String>,
    #[serde(default)]
    pub expected_artifacts: Vec<String>,
    #[serde(default)]
    pub evidence_query: String,
    #[serde(default)]
    pub success_check: String,
    #[serde(default)]
    pub failure_recovery: String,
    #[serde(default)]
    pub approval_required: bool,
    #[serde(default)]
    pub evidence_claim_ids: Vec<String>,
    #[serde(default)]
    pub event_evidence_ids: Vec<String>,
    pub confidence: f32,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorEventRequest {
    #[serde(default, alias = "kind", alias = "event_type")]
    pub event_kind: Option<String>,
    pub action: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub command_text: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub capture_id: Option<String>,
    #[serde(default)]
    pub artifact_path: Option<String>,
    #[serde(default)]
    pub occurred_at_ms: Option<i64>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorEvent {
    pub id: String,
    pub source: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    pub event_kind: String,
    pub action: String,
    pub summary: String,
    #[serde(default)]
    pub command_text: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub repo_root: Option<String>,
    #[serde(default)]
    pub capture_id: Option<String>,
    #[serde(default)]
    pub artifact_path: Option<String>,
    pub occurred_at_ms: i64,
    pub created_at_ms: i64,
    pub content_hash: String,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorEventList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceOperatorEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorEventScanSummary {
    pub scanned_files: usize,
    pub created_events: usize,
    pub skipped_existing: usize,
    #[serde(default)]
    pub items: Vec<PersonalPreferenceOperatorEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorRoutine {
    pub id: String,
    pub routine_key: String,
    pub title: String,
    pub summary: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub trigger_terms: Vec<String>,
    #[serde(default)]
    pub applies_when: Vec<String>,
    pub confidence: f32,
    pub support_count: usize,
    #[serde(default)]
    pub cross_project_support_count: usize,
    #[serde(default)]
    pub event_support_count: usize,
    #[serde(default)]
    pub risk_level: String,
    #[serde(default)]
    pub autonomy_level: String,
    #[serde(default = "default_operator_routine_version")]
    pub version: u32,
    #[serde(default)]
    pub valid_from_ms: Option<i64>,
    #[serde(default)]
    pub valid_to_ms: Option<i64>,
    #[serde(default)]
    pub drift_status: String,
    #[serde(default)]
    pub drift_score: f32,
    pub status: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub steps: Vec<PersonalPreferenceOperatorRoutineStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorRoutineList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceOperatorRoutine>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorRoutineRebuildSummary {
    pub rebuilt: usize,
    pub total: usize,
    #[serde(default)]
    pub executable_total: usize,
    #[serde(default)]
    pub event_supported_steps: usize,
    #[serde(default)]
    pub drifted_total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorRoutineStepEvidence {
    pub step_key: String,
    #[serde(default)]
    pub claim_ids: Vec<String>,
    #[serde(default)]
    pub claims: Vec<PersonalPreferenceClaim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceOperatorRoutineExplanation {
    pub routine: PersonalPreferenceOperatorRoutine,
    #[serde(default)]
    pub step_evidence: Vec<PersonalPreferenceOperatorRoutineStepEvidence>,
    pub evidence_claims_total: usize,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceMindMapNode {
    pub id: String,
    pub node_type: String,
    pub label: String,
    pub summary: String,
    pub weight: f32,
    #[serde(default)]
    pub claim_ids: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceMindMapEdge {
    pub id: String,
    pub source_id: String,
    pub target_id: String,
    pub relation: String,
    pub summary: String,
    pub weight: f32,
    #[serde(default)]
    pub claim_ids: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceMindMap {
    #[serde(default)]
    pub query: Option<String>,
    pub generated_at_ms: i64,
    pub nodes: Vec<PersonalPreferenceMindMapNode>,
    pub edges: Vec<PersonalPreferenceMindMapEdge>,
    #[serde(default)]
    pub routines: Vec<PersonalPreferenceOperatorRoutine>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceSkillPlaybookStep {
    pub step_order: usize,
    pub step_key: String,
    pub title: String,
    pub instruction: String,
    #[serde(default = "default_true")]
    pub required: bool,
    #[serde(default)]
    pub tool_hints: Vec<String>,
    #[serde(default)]
    pub expected_artifacts: Vec<String>,
    #[serde(default)]
    pub success_check: String,
    #[serde(default)]
    pub failure_recovery: String,
    #[serde(default)]
    pub approval_required: bool,
    #[serde(default)]
    pub evidence_claim_ids: Vec<String>,
    #[serde(default)]
    pub event_evidence_ids: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceSkillPlaybook {
    pub id: String,
    pub routine_id: String,
    pub routine_key: String,
    pub title: String,
    pub description: String,
    pub version: String,
    pub format: String,
    pub confidence: f32,
    pub support_count: usize,
    pub review_required: bool,
    #[serde(default)]
    pub review_reasons: Vec<String>,
    #[serde(default)]
    pub trigger_terms: Vec<String>,
    #[serde(default)]
    pub steps: Vec<PersonalPreferenceSkillPlaybookStep>,
    pub skill_markdown: String,
    #[serde(default)]
    pub evidence_claim_ids: Vec<String>,
    pub generated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceSkillPlaybookBundle {
    pub generated_at_ms: i64,
    pub min_confidence: f32,
    pub min_support_count: usize,
    pub items: Vec<PersonalPreferenceSkillPlaybook>,
    pub skipped: usize,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceAiTerminalIntegration {
    pub integration_id: String,
    pub terminal: String,
    pub enabled: bool,
    pub capture_enabled: bool,
    pub skill_sync_enabled: bool,
    pub activation_enabled: bool,
    pub capture_mode: String,
    #[serde(default)]
    pub skill_roots: Vec<String>,
    pub mcp_registration_status: String,
    #[serde(default)]
    pub last_capture_at_ms: Option<i64>,
    #[serde(default)]
    pub last_digest_at_ms: Option<i64>,
    #[serde(default)]
    pub last_skill_sync_at_ms: Option<i64>,
    #[serde(default)]
    pub last_activation_check_at_ms: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceAiTerminalIntegrationSummary {
    pub generated_at_ms: i64,
    pub integrations: Vec<PersonalPreferenceAiTerminalIntegration>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceAiTerminalCaptureRequest {
    pub terminal: String,
    #[serde(default)]
    pub integration_id: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub event_kind: Option<String>,
    #[serde(default)]
    pub repo_scope: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub transcript_text: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceAiTerminalCaptureEvent {
    pub event_id: String,
    pub integration_id: String,
    pub terminal: String,
    #[serde(default)]
    pub source_session_id: Option<String>,
    pub event_kind: String,
    #[serde(default)]
    pub repo_scope: Option<String>,
    pub summary: String,
    #[serde(default)]
    pub capture_id: Option<String>,
    pub redaction_status: String,
    pub digest_status: String,
    pub created_at_ms: i64,
    #[serde(default)]
    pub processed_at_ms: Option<i64>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceAiTerminalCaptureEventList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceAiTerminalCaptureEvent>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillValidation {
    pub validation_id: String,
    pub skill_id: String,
    pub version_id: String,
    pub validator: String,
    pub status: String,
    #[serde(default)]
    pub details: Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillInstallation {
    pub installation_id: String,
    pub skill_id: String,
    pub version_id: String,
    pub integration_id: String,
    pub agent_target: String,
    pub install_root: String,
    pub installed_path: String,
    pub status: String,
    pub installed_at_ms: i64,
    #[serde(default)]
    pub last_seen_at_ms: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillActivationEvent {
    pub activation_id: String,
    pub skill_id: String,
    pub version_id: String,
    pub integration_id: String,
    pub terminal: String,
    pub activation_kind: String,
    #[serde(default)]
    pub trigger_query: Option<String>,
    pub used: bool,
    pub accepted: bool,
    #[serde(default)]
    pub rejected_reason: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillEvent {
    pub event_id: String,
    pub skill_id: String,
    #[serde(default)]
    pub version_id: Option<String>,
    pub event_kind: String,
    pub summary: String,
    #[serde(default)]
    pub metadata: Value,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillEventList {
    pub total: usize,
    pub items: Vec<PersonalPreferenceGeneratedSkillEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillVersion {
    pub version_id: String,
    pub skill_id: String,
    pub version: String,
    pub evidence_hash: String,
    pub skill_markdown: String,
    #[serde(default)]
    pub sidecar: Value,
    pub rendered_at_ms: i64,
    pub rendered_by: String,
    pub validation_status: String,
    pub validation_summary: String,
    pub install_policy: String,
    #[serde(default)]
    pub rollback_from_version_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkill {
    pub skill_id: String,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub scope: String,
    #[serde(default)]
    pub scope_key: Option<String>,
    pub source_compiler: String,
    pub status: String,
    pub risk_level: String,
    pub autonomy_level: String,
    pub confidence: f32,
    pub support_count: usize,
    #[serde(default)]
    pub current_version_id: Option<String>,
    #[serde(default)]
    pub current_version: Option<PersonalPreferenceGeneratedSkillVersion>,
    #[serde(default)]
    pub validations: Vec<PersonalPreferenceGeneratedSkillValidation>,
    #[serde(default)]
    pub installations: Vec<PersonalPreferenceGeneratedSkillInstallation>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    #[serde(default)]
    pub metadata: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersonalPreferenceGeneratedSkillQualitySummary {
    pub total: usize,
    pub promote: usize,
    pub keep: usize,
    pub review: usize,
    pub demote: usize,
    pub quarantine: usize,
    pub stale: usize,
    pub replay_passed: usize,
    pub replay_warning: usize,
    pub replay_failed: usize,
    #[serde(default)]
    pub items: Vec<PersonalPreferenceGeneratedSkillQualityItem>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillQualityItem {
    pub skill_id: String,
    pub slug: String,
    pub name: String,
    pub status: String,
    pub risk_level: String,
    pub install_policy: String,
    #[serde(default)]
    pub version_id: Option<String>,
    pub confidence: f32,
    pub support_count: usize,
    #[serde(default)]
    pub replay_validation_status: Option<String>,
    #[serde(default)]
    pub latest_replay_score: Option<f32>,
    #[serde(default)]
    pub routine_key: Option<String>,
    #[serde(default)]
    pub routine_drift_status: Option<String>,
    #[serde(default)]
    pub stale: bool,
    pub accepted_activation_events: usize,
    pub rejected_activation_events: usize,
    #[serde(default)]
    pub last_activation_at_ms: Option<i64>,
    pub recommendation: String,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillList {
    pub generated_at_ms: i64,
    pub items: Vec<PersonalPreferenceGeneratedSkill>,
    #[serde(default)]
    pub quality: PersonalPreferenceGeneratedSkillQualitySummary,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillsSyncOptions {
    #[serde(default)]
    pub min_confidence: Option<f32>,
    #[serde(default)]
    pub min_support_count: Option<usize>,
    #[serde(default)]
    pub include_sensitive: Option<bool>,
    #[serde(default)]
    pub install: Option<bool>,
    #[serde(default)]
    pub terminals: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillsSyncSummary {
    pub generated_at_ms: i64,
    pub candidates: usize,
    pub rendered: usize,
    pub installed: usize,
    pub skipped: usize,
    pub validation_failures: usize,
    pub auto_installed: usize,
    pub review_required: usize,
    pub quarantined: usize,
    pub items: Vec<PersonalPreferenceGeneratedSkill>,
    #[serde(default)]
    pub integrations: Vec<PersonalPreferenceAiTerminalIntegration>,
    #[serde(default)]
    pub quality: PersonalPreferenceGeneratedSkillQualitySummary,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceAiTerminalStatus {
    pub generated_at_ms: i64,
    pub integrations: Vec<PersonalPreferenceAiTerminalIntegration>,
    pub capture_events_total: usize,
    #[serde(default)]
    pub pending_capture_events_total: usize,
    #[serde(default)]
    pub failed_capture_events_total: usize,
    pub generated_skills_total: usize,
    pub installed_skills_total: usize,
    pub review_required_total: usize,
    pub quarantined_total: usize,
    pub activation_events_total: usize,
    #[serde(default)]
    pub accepted_activation_events_total: usize,
    #[serde(default)]
    pub rejected_activation_events_total: usize,
    #[serde(default)]
    pub stale_generated_skills_total: usize,
    #[serde(default)]
    pub generated_skill_replay_validations_total: usize,
    #[serde(default)]
    pub clone_replay_evaluations_total: usize,
    #[serde(default)]
    pub drifted_operator_routines_total: usize,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillActionRequest {
    #[serde(default)]
    pub skill_id: Option<String>,
    #[serde(default)]
    pub terminals: Vec<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceGeneratedSkillActionSummary {
    pub generated_at_ms: i64,
    pub action: String,
    #[serde(default)]
    pub skill: Option<PersonalPreferenceGeneratedSkill>,
    #[serde(default)]
    pub validation: Option<PersonalPreferenceGeneratedSkillValidation>,
    #[serde(default)]
    pub installed: usize,
    #[serde(default)]
    pub rolled_back: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

fn default_true() -> bool {
    true
}

fn default_operator_routine_version() -> u32 {
    1
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
pub struct PersonalPreferenceCloneReplayExpectation {
    pub category: String,
    pub matched: bool,
    pub score: f32,
    #[serde(default)]
    pub matched_claim_ids: Vec<String>,
    #[serde(default)]
    pub matched_routine_keys: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReplayEvaluation {
    pub mode: String,
    pub query: String,
    pub overall_score: f32,
    #[serde(default)]
    pub expected_categories: Vec<String>,
    #[serde(default)]
    pub matched_categories: Vec<String>,
    #[serde(default)]
    pub missing_categories: Vec<String>,
    pub exact_routine_step_matches: usize,
    pub semantic_matches: usize,
    pub pack: PersonalPreferenceCloneContextPack,
    pub created_at_ms: i64,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub expectations: Vec<PersonalPreferenceCloneReplayExpectation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReplayDatasetCase {
    pub case_id: String,
    pub query: String,
    pub mode: String,
    #[serde(default)]
    pub current_repo_root: Option<String>,
    #[serde(default)]
    pub expected_categories: Vec<String>,
    #[serde(default)]
    pub expected_routine_keys: Vec<String>,
    #[serde(default)]
    pub expected_step_keys: Vec<String>,
    pub source: String,
    #[serde(default)]
    pub source_ids: Vec<String>,
    pub ci_subset: bool,
    pub created_at_ms: i64,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReplayDataset {
    pub generated_at_ms: i64,
    pub total: usize,
    pub ci_subset_total: usize,
    #[serde(default)]
    pub cases: Vec<PersonalPreferenceCloneReplayDatasetCase>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneDirectivePrediction {
    pub case_id: String,
    pub query: String,
    pub mode: String,
    #[serde(default)]
    pub predicted_categories: Vec<String>,
    #[serde(default)]
    pub predicted_routine_keys: Vec<String>,
    #[serde(default)]
    pub predicted_step_keys: Vec<String>,
    #[serde(default)]
    pub predicted_required_steps: Vec<String>,
    #[serde(default)]
    pub predicted_approval_gates: Vec<String>,
    pub confidence: f32,
    pub directive: PersonalPreferenceCloneDirective,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReplayCaseResult {
    pub case: PersonalPreferenceCloneReplayDatasetCase,
    pub prediction: PersonalPreferenceCloneDirectivePrediction,
    pub evaluation: PersonalPreferenceCloneReplayEvaluation,
    pub category_recall: f32,
    pub routine_recall: f32,
    pub step_recall: f32,
    pub approval_gate_expected: bool,
    pub approval_gate_predicted: bool,
    pub approval_gate_accuracy: f32,
    pub score: f32,
    pub passed: bool,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReplayMetrics {
    pub case_count: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub average_score: f32,
    pub category_recall: f32,
    pub routine_recall: f32,
    pub step_recall: f32,
    pub approval_gate_accuracy: f32,
    pub min_score: f32,
    pub max_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneReplaySuite {
    pub generated_at_ms: i64,
    pub ci_subset: bool,
    pub threshold: f32,
    pub metrics: PersonalPreferenceCloneReplayMetrics,
    #[serde(default)]
    pub results: Vec<PersonalPreferenceCloneReplayCaseResult>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneDirectiveRoutine {
    pub routine_id: String,
    pub routine_key: String,
    pub title: String,
    pub summary: String,
    pub purpose: String,
    pub confidence: f32,
    pub support_count: usize,
    pub cross_project_support_count: usize,
    pub event_support_count: usize,
    pub risk_level: String,
    pub autonomy_level: String,
    pub status: String,
    pub version: u32,
    pub drift_status: String,
    #[serde(default)]
    pub applies_when: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneDirectiveStep {
    pub step_order: usize,
    pub routine_id: String,
    pub routine_key: String,
    pub step_key: String,
    pub title: String,
    pub instruction: String,
    pub required: bool,
    pub approval_required: bool,
    #[serde(default)]
    pub tool_hints: Vec<String>,
    #[serde(default)]
    pub expected_artifacts: Vec<String>,
    pub success_check: String,
    pub failure_recovery: String,
    #[serde(default)]
    pub evidence_claim_ids: Vec<String>,
    #[serde(default)]
    pub event_evidence_ids: Vec<String>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneApprovalGate {
    pub gate_key: String,
    pub routine_key: String,
    pub step_key: String,
    pub title: String,
    pub reason: String,
    pub risk_level: String,
    pub required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonalPreferenceCloneDirective {
    #[serde(default)]
    pub agent_id: Option<String>,
    pub mode: String,
    pub enforcement_level: String,
    pub query: String,
    #[serde(default)]
    pub task_type: Option<String>,
    pub risk_level: String,
    pub inferred_task_phase: String,
    #[serde(default)]
    pub current_repo_root: Option<String>,
    #[serde(default)]
    pub current_files: Vec<String>,
    #[serde(default)]
    pub current_plan_path: Option<String>,
    pub selected_routines: Vec<PersonalPreferenceCloneDirectiveRoutine>,
    pub required_steps: Vec<PersonalPreferenceCloneDirectiveStep>,
    pub optional_steps: Vec<PersonalPreferenceCloneDirectiveStep>,
    pub required_artifacts: Vec<String>,
    pub approval_gates: Vec<PersonalPreferenceCloneApprovalGate>,
    pub validation_plan: Vec<String>,
    pub memory_to_load: Vec<String>,
    pub stop_conditions: Vec<String>,
    pub avoidances: Vec<String>,
    pub confidence: f32,
    pub evidence_summary: String,
    pub pack: PersonalPreferenceCloneContextPack,
    pub generated_at_ms: i64,
    #[serde(default)]
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
    #[serde(default)]
    pub claims: usize,
    #[serde(default)]
    pub claim_versions: usize,
    #[serde(default)]
    pub claim_evidence: usize,
    #[serde(default)]
    pub claim_links: usize,
    #[serde(default)]
    pub feedback_events: usize,
    #[serde(default)]
    pub identity_snapshots: usize,
    #[serde(default)]
    pub decision_patterns: usize,
    #[serde(default)]
    pub style_signals: usize,
    #[serde(default)]
    pub clone_profiles: usize,
    #[serde(default)]
    pub clone_context_packs: usize,
    #[serde(default)]
    pub clone_evaluations: usize,
    #[serde(default)]
    pub project_timelines: usize,
    #[serde(default)]
    pub goal_graph: usize,
    #[serde(default)]
    pub operator_routines: usize,
    #[serde(default)]
    pub operator_routine_steps: usize,
    #[serde(default)]
    pub override_rules: usize,
    #[serde(default)]
    pub redaction_spans: usize,
    #[serde(default)]
    pub retention_policies: usize,
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

pub(super) const DB_FILE: &str = "personal_preferences.db";
pub(super) const SCHEMA_VERSION: u32 = 9;
pub(super) const DIGEST_STATUS_PENDING: &str = "pending";
pub(super) const DIGEST_STATUS_PROCESSING: &str = "processing";
pub(super) const DIGEST_STATUS_COMPLETED: &str = "completed";
pub(super) const DIGEST_STATUS_FAILED: &str = "failed";
pub(super) const DIGEST_STATUS_CAPTURED: &str = "captured";
pub(super) const REDACTED_TEXT: &str = "[redacted]";
pub(super) const ENCRYPTED_UNAVAILABLE_TEXT: &str = "[encrypted: unavailable]";
pub(super) const ENCRYPTED_UNREADABLE_TEXT: &str = "[encrypted: unreadable]";
pub(super) const ENCRYPTED_PREFIX: &str = "enc:v1:";
pub(super) const MAX_DIGEST_RECORDS_PER_CAPTURE: usize = 16;
pub(super) const MAX_DIGEST_EVIDENCE_CHARS: usize = 240;
pub(super) const MAX_DIGEST_CONTEXT_CHARS: usize = 40_000;
pub(super) const MAX_DIGEST_USER_MESSAGE_CHARS: usize = 6_000;
pub(super) const MAX_DIGEST_USER_MESSAGES: usize = 24;
pub(super) const MAX_PROJECTABLE_RECORDS: usize = 24;
pub(super) const DEFAULT_TRANSCRIPT_SCAN_LIMIT: usize = 12;
pub(super) const DEFAULT_OPERATOR_ARTIFACT_SCAN_LIMIT: usize = 200;
pub(super) const SNAPSHOT_SUMMARY_LIMIT: usize = 8;
pub(super) const LAST_TRANSCRIPT_SCAN_META_KEY: &str = "last_client_transcript_scan_at_ms";
pub(super) const LAST_OPERATOR_ARTIFACT_SCAN_META_KEY: &str = "last_operator_artifact_scan_at_ms";
pub(super) const OPERATOR_ROUTINE_CLAIM_ID_PREFIX: &str = "claim_operator_routine_";
pub(super) const OPERATOR_EVENT_KIND_OPERATOR_EVENT: &str = "operator_event";
pub(super) const OPERATOR_EVENT_KIND_SHELL_COMMAND: &str = "shell_command";
pub(super) const OPERATOR_EVENT_KIND_GIT_ACTION: &str = "git_action";
pub(super) const OPERATOR_EVENT_KIND_TEST_ACTION: &str = "test_action";
pub(super) const OPERATOR_EVENT_KIND_DEPLOY_ACTION: &str = "deploy_action";
pub(super) const OPERATOR_EVENT_KIND_BACKUP_ACTION: &str = "backup_action";
pub(super) const OPERATOR_EVENT_KIND_ARTIFACT_UPDATE: &str = "artifact_update";
pub(super) const OPERATOR_EVENT_KIND_APPROVAL_GATE: &str = "approval_gate";
pub(super) const OPERATOR_EVENT_KIND_CORRECTION: &str = "correction";

pub(super) const REVIEW_STATUS_APPROVED: &str = "approved";
pub(super) const REVIEW_STATUS_PENDING: &str = "pending_review";
pub(super) const REVIEW_STATUS_REJECTED: &str = "rejected";

pub(super) const CLAIM_ORIGIN_EXPLICIT_USER_STATEMENT: &str = "explicit_user_statement";
pub(super) const CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION: &str = "explicit_user_correction";
pub(super) const CLAIM_ORIGIN_OBSERVED_BEHAVIOR: &str = "observed_behavior";
pub(super) const CLAIM_ORIGIN_ENVIRONMENTAL_INFERENCE: &str = "environmental_inference";
pub(super) const CLAIM_ORIGIN_CROSS_SESSION_INFERENCE: &str = "cross_session_inference";
pub(super) const CLAIM_ORIGIN_MANUAL_REVIEW_ENTRY: &str = "manual_review_entry";

pub(super) const TRUTH_STATUS_CANDIDATE: &str = "candidate";
pub(super) const TRUTH_STATUS_INFERRED: &str = "inferred";
pub(super) const TRUTH_STATUS_CONFIRMED: &str = "confirmed";
pub(super) const TRUTH_STATUS_REJECTED: &str = "rejected";
pub(super) const TRUTH_STATUS_SUPERSEDED: &str = "superseded";
pub(super) const TRUTH_STATUS_EXPIRED: &str = "expired";

pub(super) const STABILITY_CLASS_EPHEMERAL: &str = "ephemeral";
pub(super) const STABILITY_CLASS_SESSIONAL: &str = "sessional";
pub(super) const STABILITY_CLASS_CURRENT: &str = "current";
pub(super) const STABILITY_CLASS_STABLE: &str = "stable";
pub(super) const STABILITY_CLASS_FOUNDATIONAL: &str = "foundational";

pub const CLONE_MODE_ADAPTIVE: &str = "adaptive";
pub const CLONE_MODE_PROJECT_BUILD: &str = "project_build";
pub const CLONE_MODE_REVIEW: &str = "review";
pub const CLONE_MODE_RELEASE: &str = "release";
pub const CLONE_MODE_SIMULATE_USER_PREFERENCE: &str = "simulate_user_preference";

pub(super) const FEEDBACK_EVENT_ACCEPT_OUTPUT: &str = "accept_output";
pub(super) const FEEDBACK_EVENT_REJECT_OUTPUT: &str = "reject_output";
pub(super) const FEEDBACK_EVENT_CORRECT_OUTPUT: &str = "correct_output";
pub(super) const FEEDBACK_EVENT_REWRITE_OUTPUT: &str = "rewrite_output";
pub(super) const FEEDBACK_EVENT_OVERRIDE_PREFERENCE: &str = "override_preference";

pub(super) const GENERATED_SKILL_STATUS_DRAFT: &str = "draft";
pub(super) const GENERATED_SKILL_STATUS_VALIDATED: &str = "validated";
pub(super) const GENERATED_SKILL_STATUS_INSTALLED: &str = "installed";
pub(super) const GENERATED_SKILL_STATUS_QUARANTINED: &str = "quarantined";
pub(super) const GENERATED_SKILL_STATUS_DISABLED: &str = "disabled";
pub(super) const GENERATED_SKILL_STATUS_ROLLED_BACK: &str = "rolled_back";

pub(super) const GENERATED_SKILL_RISK_LOW: &str = "low";
pub(super) const GENERATED_SKILL_RISK_MEDIUM: &str = "medium";
pub(super) const GENERATED_SKILL_RISK_HIGH: &str = "high";
pub(super) const GENERATED_SKILL_RISK_CRITICAL: &str = "critical";

pub(super) const GENERATED_SKILL_INSTALL_POLICY_AUTO: &str = "auto";
pub(super) const GENERATED_SKILL_INSTALL_POLICY_REVIEW: &str = "review";
pub(super) const GENERATED_SKILL_INSTALL_POLICY_MANUAL_ONLY: &str = "manual_only";
pub(super) const GENERATED_SKILL_INSTALL_POLICY_QUARANTINE: &str = "quarantine";

pub(super) const GENERATED_SKILL_VALIDATION_PASSED: &str = "passed";
pub(super) const GENERATED_SKILL_VALIDATION_FAILED: &str = "failed";
pub(super) const GENERATED_SKILL_VALIDATION_WARNING: &str = "warning";

pub(super) const AI_TERMINAL_CODEX: &str = "codex";
pub(super) const AI_TERMINAL_CLAUDE: &str = "claude";
pub(super) const AI_TERMINAL_GENERIC_MCP: &str = "generic_mcp";
pub(super) const FEEDBACK_EVENT_DOWNGRADE_INFERENCE: &str = "downgrade_inference";
pub(super) const FEEDBACK_EVENT_CONFIRM_INFERENCE: &str = "confirm_inference";
pub(super) const PERSONAL_PREFERENCES_DIGEST_TIMEOUT_CAP_MS: u64 = 600_000;

pub(super) static TRANSCRIPT_SECRET_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
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
pub(super) struct CategoryPolicySeed {
    pub(super) category: &'static str,
    pub(super) description: &'static str,
    pub(super) context_section: Option<&'static str>,
    pub(super) context_allowed_default: bool,
    pub(super) requires_review_for_sensitive: bool,
}

pub(super) const DEFAULT_CATEGORY_POLICIES: &[CategoryPolicySeed] = &[
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
        category: "operator_routine",
        description: "Evidence-backed multi-step routines that describe how the user operates agents and production work.",
        context_section: Some("operator_routines"),
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
