use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[derive(Debug, Clone)]
pub(super) struct OperatorRoutineTemplate {
    pub(super) key: &'static str,
    pub(super) title: &'static str,
    pub(super) summary: &'static str,
    pub(super) trigger_terms: &'static [&'static str],
    pub(super) min_supported_steps: usize,
    pub(super) min_support_count: usize,
    pub(super) steps: Vec<OperatorRoutineStepTemplate>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct OperatorRoutineStepTemplate {
    pub(super) key: &'static str,
    pub(super) title: &'static str,
    pub(super) instruction: &'static str,
    pub(super) keywords: &'static [&'static str],
    pub(super) category_hints: &'static [&'static str],
    pub(super) record_type_hints: &'static [&'static str],
}

#[derive(Debug, Clone)]
pub(super) struct SupportedOperatorRoutineStep {
    pub(super) template: OperatorRoutineStepTemplate,
    pub(super) claim_ids: Vec<String>,
    pub(super) confidence: f32,
}

#[derive(Debug, Clone, Default)]
struct OperatorRoutineEventEvidence {
    event_ids: Vec<String>,
    repo_roots: BTreeSet<String>,
    first_seen_ms: Option<i64>,
    last_seen_ms: Option<i64>,
}

#[derive(Debug, Clone, Default)]
struct ExistingOperatorRoutineState {
    version: u32,
    valid_from_ms: Option<i64>,
    signature: Option<String>,
}

pub(super) fn load_operator_routines(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<PersonalPreferenceOperatorRoutine>> {
    let mut stmt = conn.prepare(
        "SELECT id, routine_key, title, summary, trigger_terms_json, confidence,
                support_count, status, created_at_ms, updated_at_ms, metadata_json,
                purpose, applies_when_json, cross_project_support_count, risk_level,
                autonomy_level, version, valid_from_ms, valid_to_ms, drift_status,
                drift_score, event_support_count
         FROM pp_operator_routines
         ORDER BY confidence DESC, support_count DESC, updated_at_ms DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let mut rows = stmt.query(params![limit.max(1) as i64, offset as i64])?;
    let mut routines = Vec::new();
    while let Some(row) = rows.next()? {
        let mut routine = row_to_operator_routine(row)?;
        routine.steps = load_operator_routine_steps(conn, &routine.id)?;
        routines.push(routine);
    }
    Ok(routines)
}

pub(super) fn load_operator_routine_by_id_or_key(
    conn: &Connection,
    routine_id_or_key: &str,
) -> Result<Option<PersonalPreferenceOperatorRoutine>> {
    let routine_id_or_key = routine_id_or_key.trim();
    if routine_id_or_key.is_empty() {
        return Ok(None);
    }
    let mut routine = conn
        .query_row(
            "SELECT id, routine_key, title, summary, trigger_terms_json, confidence,
                    support_count, status, created_at_ms, updated_at_ms, metadata_json,
                    purpose, applies_when_json, cross_project_support_count, risk_level,
                    autonomy_level, version, valid_from_ms, valid_to_ms, drift_status,
                    drift_score, event_support_count
             FROM pp_operator_routines
             WHERE id = ?1 OR routine_key = ?1",
            params![routine_id_or_key],
            row_to_operator_routine,
        )
        .optional()?;
    if let Some(routine) = routine.as_mut() {
        routine.steps = load_operator_routine_steps(conn, &routine.id)?;
    }
    Ok(routine)
}

pub(super) fn load_operator_routine_steps(
    conn: &Connection,
    routine_id: &str,
) -> Result<Vec<PersonalPreferenceOperatorRoutineStep>> {
    let mut stmt = conn.prepare(
        "SELECT id, routine_id, step_order, step_key, title, instruction,
                required, tool_hints_json, expected_artifacts_json, evidence_query,
                success_check, failure_recovery, approval_required,
                evidence_claim_ids_json, event_evidence_ids_json, confidence,
                created_at_ms, updated_at_ms, metadata_json
         FROM pp_operator_routine_steps
         WHERE routine_id = ?1
         ORDER BY step_order ASC, created_at_ms ASC",
    )?;
    let mut rows = stmt.query(params![routine_id])?;
    let mut steps = Vec::new();
    while let Some(row) = rows.next()? {
        steps.push(row_to_operator_routine_step(row)?);
    }
    Ok(steps)
}

pub(super) fn routine_is_relevant_to_query(
    routine: &PersonalPreferenceOperatorRoutine,
    query: &str,
) -> bool {
    if query.trim().is_empty() || query_is_operator_style(query) {
        return true;
    }
    let haystack = format!(
        "{} {} {} {} {}",
        routine.title,
        routine.summary,
        routine.purpose,
        routine.trigger_terms.join(" "),
        routine.applies_when.join(" ")
    )
    .to_ascii_lowercase();
    query
        .split_whitespace()
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| term.len() > 2)
        .any(|term| haystack.contains(&term))
}

pub(super) fn playbook_review_reasons(routine: &PersonalPreferenceOperatorRoutine) -> Vec<String> {
    let text = format!(
        "{} {} {}",
        routine.title,
        routine.summary,
        routine
            .steps
            .iter()
            .map(|step| format!("{} {}", step.title, step.instruction))
            .collect::<Vec<_>>()
            .join(" ")
    )
    .to_ascii_lowercase();
    let mut reasons = Vec::new();
    if routine.risk_level == "high" {
        reasons.push("high-risk routine".to_string());
    }
    if routine.autonomy_level == "approval_gated" {
        reasons.push("approval-gated autonomy".to_string());
    }
    if routine.steps.iter().any(|step| step.approval_required) {
        reasons.push("approval-required step".to_string());
    }
    for (term, reason) in [
        ("production", "production action"),
        ("deploy", "deployment action"),
        ("ssh", "remote access or security action"),
        ("security", "security-sensitive action"),
        ("credential", "credential-sensitive action"),
        ("billing", "billing/payment-sensitive action"),
        ("payment", "billing/payment-sensitive action"),
        ("delete", "destructive action"),
        ("reset --hard", "destructive git action"),
    ] {
        if text.contains(term) && !reasons.iter().any(|value| value == reason) {
            reasons.push(reason.to_string());
        }
    }
    reasons
}

pub(super) fn render_skill_playbook_markdown(
    routine: &PersonalPreferenceOperatorRoutine,
    version: &str,
    review_reasons: &[String],
    steps: &[PersonalPreferenceSkillPlaybookStep],
) -> String {
    let slug = slugify_identifier(&routine.routine_key);
    let triggers = if routine.trigger_terms.is_empty() {
        "general operator-clone workflow".to_string()
    } else {
        routine.trigger_terms.join(", ")
    };
    let mut markdown = format!(
        "---\nname: {slug}\ndescription: Use when the agent needs to follow the user's {title} routine; triggers include {triggers}.\nversion: {version}\n---\n\n# {title}\n\n{summary}\n\n## When To Use\n\nUse this skill when the task matches: {triggers}.\n",
        title = routine.title,
        summary = routine.summary
    );
    if !review_reasons.is_empty() {
        markdown.push_str("\n## Review Gate\n\n");
        markdown.push_str("Require human review before executing high-risk steps involving ");
        markdown.push_str(&review_reasons.join(", "));
        markdown.push_str(".\n");
    }
    markdown.push_str("\n## Steps\n\n");
    for step in steps {
        markdown.push_str(&format!(
            "{}. {}: {}\n",
            step.step_order, step.title, step.instruction
        ));
        if !step.tool_hints.is_empty() {
            markdown.push_str(&format!("   - Tools: {}\n", step.tool_hints.join(", ")));
        }
        if !step.expected_artifacts.is_empty() {
            markdown.push_str(&format!(
                "   - Artifacts: {}\n",
                step.expected_artifacts.join(", ")
            ));
        }
        if !step.success_check.is_empty() {
            markdown.push_str(&format!("   - Success: {}\n", step.success_check));
        }
        if !step.failure_recovery.is_empty() {
            markdown.push_str(&format!("   - Recovery: {}\n", step.failure_recovery));
        }
        if step.approval_required {
            markdown.push_str("   - Approval: require explicit human approval before execution.\n");
        }
    }
    markdown.push_str("\n## Validation\n\nConfirm the selected steps are supported by current repo truth, run relevant validation, and record blockers or evidence before reporting completion.\n");
    markdown.push_str("\n## Evidence\n\nCompiled from approved personal-preference claims and synthesized operator-routine evidence ids; do not inject raw transcripts.\n");
    markdown
}

pub(super) fn rebuild_operator_routines_tx(
    conn: &Connection,
    snapshot_id: Option<&str>,
    claims: &[PersonalPreferenceClaim],
    updated_at_ms: i64,
) -> Result<usize> {
    let suppressed_routine_keys = load_suppressed_operator_routine_keys(conn)?;
    let existing_routines = load_existing_operator_routine_states(conn)?;
    conn.execute("DELETE FROM pp_operator_routine_steps", [])?;
    conn.execute("DELETE FROM pp_operator_routines", [])?;
    conn.execute(
        "DELETE FROM pp_claims WHERE id LIKE ?1",
        params![format!("{OPERATOR_ROUTINE_CLAIM_ID_PREFIX}%")],
    )?;

    let source_claims = claims
        .iter()
        .filter(|claim| {
            claim.category != "operator_routine"
                && !claim_is_forgotten(claim)
                && claim.review_status != REVIEW_STATUS_REJECTED
                && !matches!(
                    claim.truth_status.as_str(),
                    TRUTH_STATUS_REJECTED | TRUTH_STATUS_EXPIRED
                )
                && !is_sensitive_level(&claim.sensitivity)
        })
        .collect::<Vec<_>>();

    let mut created = 0usize;
    for template in operator_routine_templates() {
        if suppressed_routine_keys.contains(template.key) {
            continue;
        }
        let supported_steps = supported_operator_routine_steps(&template, &source_claims);
        let mut source_claim_ids = HashSet::new();
        for step in &supported_steps {
            for claim_id in &step.claim_ids {
                source_claim_ids.insert(claim_id.clone());
            }
        }
        let support_count = source_claim_ids.len();
        if supported_steps.len() < template.min_supported_steps
            || support_count < template.min_support_count
        {
            continue;
        }

        let routine_id = format!("operator_routine_{}", template.key);
        let event_evidence_by_step = load_operator_routine_event_evidence(conn, &template)?;
        let confidence = operator_routine_confidence(&template, &supported_steps, support_count);
        let supported_step_keys = supported_steps
            .iter()
            .map(|step| step.template.key)
            .collect::<Vec<_>>();
        let mut evidence_claim_ids = source_claim_ids.into_iter().collect::<Vec<_>>();
        evidence_claim_ids.sort();
        let mut event_evidence_ids = supported_steps
            .iter()
            .filter_map(|step| event_evidence_by_step.get(step.template.key))
            .flat_map(|evidence| evidence.event_ids.iter().cloned())
            .collect::<Vec<_>>();
        event_evidence_ids.sort();
        event_evidence_ids.dedup();
        let event_support_count = event_evidence_ids.len();
        let cross_project_support_count = operator_routine_cross_project_support_count(
            &source_claims,
            &evidence_claim_ids,
            &event_evidence_by_step,
        );
        let purpose = operator_routine_purpose(&template);
        let applies_when = operator_routine_applies_when(&template);
        let risk_level = operator_routine_risk_level(&template);
        let autonomy_level = operator_routine_autonomy_level(&template, risk_level);
        let status = operator_routine_status(
            &template,
            supported_steps.len(),
            support_count,
            event_support_count,
        );
        let routine_signature = operator_routine_signature(
            &template,
            &supported_step_keys,
            &evidence_claim_ids,
            &event_evidence_ids,
            risk_level,
            autonomy_level,
        );
        let previous = existing_routines.get(template.key);
        let version = operator_routine_version(previous, &routine_signature);
        let valid_from_ms = if previous.and_then(|state| state.signature.as_deref())
            == Some(routine_signature.as_str())
        {
            previous
                .and_then(|state| state.valid_from_ms)
                .unwrap_or(updated_at_ms)
        } else {
            updated_at_ms
        };
        let drift_score = operator_routine_drift_score(previous, &routine_signature);
        let drift_status = operator_routine_drift_status(previous, &routine_signature, drift_score);
        let metadata = json!({
            "snapshot_id": snapshot_id,
            "supported_step_keys": supported_step_keys,
            "evidence_claim_ids": evidence_claim_ids,
            "event_evidence_ids": event_evidence_ids,
            "routine_signature": routine_signature,
            "template_version": 1,
        });
        conn.execute(
            "INSERT INTO pp_operator_routines(
                id, routine_key, title, summary, purpose, trigger_terms_json,
                applies_when_json, confidence, support_count, cross_project_support_count,
                event_support_count, risk_level, autonomy_level, version, valid_from_ms,
                valid_to_ms, drift_status, drift_score, status, created_at_ms,
                updated_at_ms, metadata_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                       ?14, ?15, NULL, ?16, ?17, ?18, ?19, ?19, ?20)
             ON CONFLICT(routine_key) DO UPDATE SET
                title = excluded.title,
                summary = excluded.summary,
                purpose = excluded.purpose,
                trigger_terms_json = excluded.trigger_terms_json,
                applies_when_json = excluded.applies_when_json,
                confidence = excluded.confidence,
                support_count = excluded.support_count,
                cross_project_support_count = excluded.cross_project_support_count,
                event_support_count = excluded.event_support_count,
                risk_level = excluded.risk_level,
                autonomy_level = excluded.autonomy_level,
                version = excluded.version,
                valid_from_ms = excluded.valid_from_ms,
                valid_to_ms = excluded.valid_to_ms,
                drift_status = excluded.drift_status,
                drift_score = excluded.drift_score,
                status = excluded.status,
                updated_at_ms = excluded.updated_at_ms,
                metadata_json = excluded.metadata_json",
            params![
                routine_id,
                template.key,
                template.title,
                template.summary,
                purpose,
                serde_json::to_string(&template.trigger_terms)?,
                serde_json::to_string(&applies_when)?,
                confidence,
                support_count as i64,
                cross_project_support_count as i64,
                event_support_count as i64,
                risk_level,
                autonomy_level,
                version as i64,
                valid_from_ms,
                drift_status,
                drift_score,
                status,
                updated_at_ms,
                serde_json::to_string(&metadata)?,
            ],
        )?;

        for (index, step) in supported_steps.iter().enumerate() {
            let event_evidence = event_evidence_by_step
                .get(step.template.key)
                .cloned()
                .unwrap_or_default();
            let tool_hints = operator_routine_step_tool_hints(&step.template);
            let expected_artifacts = operator_routine_step_expected_artifacts(&step.template);
            let evidence_query = operator_routine_step_evidence_query(&step.template);
            let success_check = operator_routine_step_success_check(&step.template);
            let failure_recovery = operator_routine_step_failure_recovery(&step.template);
            let approval_required =
                operator_routine_step_approval_required(&step.template, risk_level);
            conn.execute(
                "INSERT INTO pp_operator_routine_steps(
                    id, routine_id, step_order, step_key, title, instruction,
                    required, tool_hints_json, expected_artifacts_json, evidence_query,
                    success_check, failure_recovery, approval_required,
                    evidence_claim_ids_json, event_evidence_ids_json, confidence,
                    created_at_ms, updated_at_ms, metadata_json
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12,
                           ?13, ?14, ?15, ?16, ?17, ?17, ?18)",
                params![
                    format!(
                        "operator_routine_step_{}_{}",
                        template.key, step.template.key
                    ),
                    routine_id,
                    index as i64 + 1,
                    step.template.key,
                    step.template.title,
                    step.template.instruction,
                    1_i64,
                    serde_json::to_string(&tool_hints)?,
                    serde_json::to_string(&expected_artifacts)?,
                    evidence_query,
                    success_check,
                    failure_recovery,
                    i64::from(approval_required),
                    serde_json::to_string(&step.claim_ids)?,
                    serde_json::to_string(&event_evidence.event_ids)?,
                    step.confidence,
                    updated_at_ms,
                    serde_json::to_string(&json!({
                        "keyword_family": step.template.key,
                        "event_support_count": event_evidence.event_ids.len(),
                        "event_first_seen_ms": event_evidence.first_seen_ms,
                        "event_last_seen_ms": event_evidence.last_seen_ms,
                        "event_repo_roots": event_evidence.repo_roots.iter().cloned().collect::<Vec<_>>(),
                        "template_version": 1,
                    }))?,
                ],
            )?;
        }

        upsert_operator_routine_claim(
            conn,
            &template,
            &routine_id,
            confidence,
            support_count,
            &supported_steps,
            &event_evidence_ids,
            version,
            risk_level,
            autonomy_level,
            updated_at_ms,
        )?;
        created += 1;
    }
    Ok(created)
}

fn load_existing_operator_routine_states(
    conn: &Connection,
) -> Result<BTreeMap<String, ExistingOperatorRoutineState>> {
    let mut stmt = conn.prepare(
        "SELECT routine_key, version, valid_from_ms, metadata_json
         FROM pp_operator_routines",
    )?;
    let mut rows = stmt.query([])?;
    let mut states = BTreeMap::new();
    while let Some(row) = rows.next()? {
        let routine_key: String = row.get(0)?;
        let metadata = parse_json_value(&row.get::<_, String>(3)?);
        states.insert(
            routine_key,
            ExistingOperatorRoutineState {
                version: row.get::<_, i64>(1).unwrap_or(1).max(1) as u32,
                valid_from_ms: row.get(2)?,
                signature: metadata
                    .get("routine_signature")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            },
        );
    }
    Ok(states)
}

fn load_operator_routine_event_evidence(
    conn: &Connection,
    template: &OperatorRoutineTemplate,
) -> Result<BTreeMap<&'static str, OperatorRoutineEventEvidence>> {
    let mut stmt = conn.prepare(
        "SELECT id, event_kind, action, summary, command_text, repo_root, artifact_path, occurred_at_ms
         FROM pp_operator_events
         ORDER BY occurred_at_ms ASC, created_at_ms ASC
         LIMIT 2000",
    )?;
    let mut rows = stmt.query([])?;
    let mut evidence_by_step: BTreeMap<&'static str, OperatorRoutineEventEvidence> =
        BTreeMap::new();
    while let Some(row) = rows.next()? {
        let event_id: String = row.get(0)?;
        let event_kind: String = row.get(1)?;
        let action: String = row.get(2)?;
        let summary: String = row.get(3)?;
        let command_text: Option<String> = row.get(4)?;
        let repo_root: Option<String> = row.get(5)?;
        let artifact_path: Option<String> = row.get(6)?;
        let occurred_at_ms: i64 = row.get(7)?;
        let blob = operator_event_search_blob(
            &event_kind,
            &action,
            &summary,
            command_text.as_deref(),
            artifact_path.as_deref(),
        );
        for step in &template.steps {
            if !operator_event_matches_step(&blob, &event_kind, step) {
                continue;
            }
            let evidence = evidence_by_step.entry(step.key).or_default();
            if !evidence.event_ids.contains(&event_id) {
                evidence.event_ids.push(event_id.clone());
            }
            if let Some(repo_root) = repo_root.as_ref().filter(|value| !value.trim().is_empty()) {
                evidence.repo_roots.insert(repo_root.clone());
            }
            evidence.first_seen_ms = Some(
                evidence
                    .first_seen_ms
                    .map(|value| value.min(occurred_at_ms))
                    .unwrap_or(occurred_at_ms),
            );
            evidence.last_seen_ms = Some(
                evidence
                    .last_seen_ms
                    .map(|value| value.max(occurred_at_ms))
                    .unwrap_or(occurred_at_ms),
            );
        }
    }
    Ok(evidence_by_step)
}

fn operator_event_search_blob(
    event_kind: &str,
    action: &str,
    summary: &str,
    command_text: Option<&str>,
    artifact_path: Option<&str>,
) -> String {
    [
        event_kind,
        action,
        summary,
        command_text.unwrap_or_default(),
        artifact_path.unwrap_or_default(),
    ]
    .join(" ")
    .to_ascii_lowercase()
}

fn operator_event_matches_step(
    blob: &str,
    event_kind: &str,
    step: &OperatorRoutineStepTemplate,
) -> bool {
    if step
        .keywords
        .iter()
        .any(|keyword| blob.contains(&keyword.to_ascii_lowercase()))
    {
        return true;
    }
    match step.key {
        "repo_inspection_and_dag" => {
            blob.contains("impact")
                || blob.contains("dag")
                || blob.contains("docdex")
                || blob.contains("symbols")
        }
        "validate_with_tests" | "record_validation" => {
            event_kind == OPERATOR_EVENT_KIND_TEST_ACTION || blob.contains("run-tests")
        }
        "release_deploy_backup" | "controlled_deploy" => {
            matches!(
                event_kind,
                OPERATOR_EVENT_KIND_GIT_ACTION
                    | OPERATOR_EVENT_KIND_DEPLOY_ACTION
                    | OPERATOR_EVENT_KIND_BACKUP_ACTION
            )
        }
        "plan_and_progress_docs" | "write_plan" | "track_progress" => {
            event_kind == OPERATOR_EVENT_KIND_ARTIFACT_UPDATE
                && (blob.contains("plan") || blob.contains("progress") || blob.contains("sds"))
        }
        "version_and_git" => event_kind == OPERATOR_EVENT_KIND_GIT_ACTION,
        "backup_or_rollback" => event_kind == OPERATOR_EVENT_KIND_BACKUP_ACTION,
        _ => false,
    }
}

fn operator_routine_cross_project_support_count(
    claims: &[&PersonalPreferenceClaim],
    evidence_claim_ids: &[String],
    event_evidence_by_step: &BTreeMap<&'static str, OperatorRoutineEventEvidence>,
) -> usize {
    let claim_ids = evidence_claim_ids.iter().collect::<BTreeSet<_>>();
    let mut projects = BTreeSet::new();
    for claim in claims {
        if !claim_ids.contains(&claim.id) {
            continue;
        }
        if let Some(repo_root) = claim_repo_root(claim) {
            projects.insert(repo_root);
        }
    }
    for evidence in event_evidence_by_step.values() {
        for repo_root in &evidence.repo_roots {
            projects.insert(repo_root.clone());
        }
    }
    projects.len()
}

fn claim_repo_root(claim: &PersonalPreferenceClaim) -> Option<String> {
    for key in [
        "repo_root",
        "current_repo_root",
        "project_root",
        "repo_path",
    ] {
        if let Some(value) = claim
            .metadata
            .get(key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            return Some(value.to_string());
        }
    }
    None
}

fn operator_routine_purpose(template: &OperatorRoutineTemplate) -> &'static str {
    match template.key {
        "product_development_loop" => {
            "Drive product work from intent through planning, implementation, validation, and release decisions."
        }
        "planning_progress_loop" => {
            "Keep non-trivial work planned, tracked, and auditable while implementation evolves."
        }
        "local_first_release_loop" => {
            "Prefer local validation before git, release, deployment, backup, or rollback operations."
        }
        _ => template.summary,
    }
}

fn operator_routine_applies_when(template: &OperatorRoutineTemplate) -> Vec<&'static str> {
    match template.key {
        "product_development_loop" => vec![
            "User provides an SDS, PRD, product goal, implementation plan, or broad build request.",
            "The task spans planning, repo inspection, code changes, validation, and release choices.",
        ],
        "planning_progress_loop" => vec![
            "The task is non-trivial enough to need a plan or progress trail.",
            "The user asks to keep progress in another markdown file or compare plan to implementation.",
        ],
        "local_first_release_loop" => vec![
            "The user requests commit, tag, push, deploy, backup, or production sync work.",
            "A change needs local validation before release or production action.",
        ],
        _ => template.trigger_terms.to_vec(),
    }
}

fn operator_routine_risk_level(template: &OperatorRoutineTemplate) -> &'static str {
    match template.key {
        "local_first_release_loop" => "high",
        "product_development_loop" => "medium",
        "planning_progress_loop" => "low",
        _ => "medium",
    }
}

fn operator_routine_autonomy_level(
    template: &OperatorRoutineTemplate,
    risk_level: &str,
) -> &'static str {
    match (template.key, risk_level) {
        ("planning_progress_loop", "low") => "autonomous_low_risk",
        ("local_first_release_loop", _) => "approval_gated",
        _ => "assisted",
    }
}

fn operator_routine_status(
    template: &OperatorRoutineTemplate,
    supported_steps: usize,
    support_count: usize,
    event_support_count: usize,
) -> &'static str {
    let full_step_coverage = supported_steps >= template.steps.len().saturating_sub(1).max(1);
    let enough_claims = support_count >= template.min_support_count.saturating_mul(2);
    let enough_events = event_support_count >= supported_steps.max(1);
    if full_step_coverage && (enough_claims || enough_events) {
        "stable"
    } else {
        "tentative"
    }
}

fn operator_routine_signature(
    template: &OperatorRoutineTemplate,
    supported_step_keys: &[&'static str],
    evidence_claim_ids: &[String],
    event_evidence_ids: &[String],
    risk_level: &str,
    autonomy_level: &str,
) -> String {
    sha256_hex(&format!(
        "{}|{}|{}|{}|{}|{}",
        template.key,
        supported_step_keys.join(","),
        evidence_claim_ids.join(","),
        event_evidence_ids.join(","),
        risk_level,
        autonomy_level
    ))
}

fn operator_routine_version(
    previous: Option<&ExistingOperatorRoutineState>,
    routine_signature: &str,
) -> u32 {
    let Some(previous) = previous else {
        return 1;
    };
    if previous.signature.as_deref() == Some(routine_signature) {
        previous.version.max(1)
    } else {
        previous.version.saturating_add(1).max(1)
    }
}

fn operator_routine_drift_score(
    previous: Option<&ExistingOperatorRoutineState>,
    routine_signature: &str,
) -> f32 {
    match previous {
        None => 0.0,
        Some(previous) if previous.signature.as_deref() == Some(routine_signature) => 0.0,
        Some(previous) if previous.signature.is_some() => 0.5,
        Some(_) => 0.25,
    }
}

fn operator_routine_drift_status(
    previous: Option<&ExistingOperatorRoutineState>,
    routine_signature: &str,
    drift_score: f32,
) -> &'static str {
    match previous {
        None => "new",
        Some(previous) if previous.signature.as_deref() == Some(routine_signature) => "stable",
        Some(_) if drift_score >= 0.5 => "changed",
        Some(_) => "needs_review",
    }
}

fn operator_routine_step_tool_hints(step: &OperatorRoutineStepTemplate) -> Vec<&'static str> {
    match step.key {
        "repo_inspection_and_dag" => vec![
            "docdex_search",
            "docdex_symbols",
            "docdex_ast",
            "docdex_impact_graph",
        ],
        "validate_with_tests" | "record_validation" => vec!["docdexd run-tests", "cargo test"],
        "plan_and_progress_docs" | "write_plan" | "track_progress" => {
            vec!["docs/planning", "apply_patch"]
        }
        "release_deploy_backup" | "version_and_git" | "controlled_deploy" => {
            vec!["git status", "git diff", "deployment health checks"]
        }
        "backup_or_rollback" => vec!["backup command", "rollback plan", "git tag"],
        _ => Vec::new(),
    }
}

fn operator_routine_step_expected_artifacts(
    step: &OperatorRoutineStepTemplate,
) -> Vec<&'static str> {
    match step.key {
        "intake_sds_or_goal" => vec!["SDS, PRD, goal statement, or acceptance criteria"],
        "plan_and_progress_docs" | "write_plan" => vec!["implementation plan markdown"],
        "track_progress" => vec!["progress markdown"],
        "repo_inspection_and_dag" => vec!["search, symbol, AST, or impact evidence"],
        "implement_and_close_gaps" => vec!["code changes and gap notes"],
        "validate_with_tests" | "record_validation" => vec!["test/build command output"],
        "release_deploy_backup" | "version_and_git" => vec!["git commit/tag/push evidence"],
        "controlled_deploy" => vec!["deployment command and health check evidence"],
        "backup_or_rollback" => vec!["backup, rollback, or fallback-state note"],
        _ => Vec::new(),
    }
}

fn operator_routine_step_evidence_query(step: &OperatorRoutineStepTemplate) -> String {
    step.keywords.join(" OR ")
}

fn operator_routine_step_success_check(step: &OperatorRoutineStepTemplate) -> &'static str {
    match step.key {
        "intake_sds_or_goal" => "The goal, SDS, or acceptance criteria are reflected in the plan.",
        "plan_and_progress_docs" | "write_plan" => {
            "The plan exists and names concrete implementation and validation work."
        }
        "track_progress" => "The progress document records current status, evidence, and blockers.",
        "repo_inspection_and_dag" => {
            "The agent has consulted repo truth and impact before code changes."
        }
        "implement_and_close_gaps" => {
            "The codebase has been compared against the plan and known gaps are closed or recorded."
        }
        "validate_with_tests" | "record_validation" => {
            "Targeted validation has run and results are recorded."
        }
        "release_deploy_backup" | "version_and_git" => {
            "Release/git actions are requested, validated, and recorded."
        }
        "controlled_deploy" => {
            "Deployment is requested or appropriate and live health is checked afterward."
        }
        "backup_or_rollback" => {
            "Backup or rollback expectations are documented before risky action."
        }
        _ => "Step outcome is recorded with evidence.",
    }
}

fn operator_routine_step_failure_recovery(step: &OperatorRoutineStepTemplate) -> &'static str {
    match step.key {
        "repo_inspection_and_dag" => {
            "If graph or AST evidence is unavailable, state the gap and proceed with narrower local search."
        }
        "validate_with_tests" | "record_validation" => {
            "If validation fails, diagnose, patch, rerun the focused check, and record the blocker if unresolved."
        }
        "release_deploy_backup" | "controlled_deploy" | "backup_or_rollback" => {
            "If release risk is unclear, stop before production action and require explicit human approval."
        }
        _ => "If evidence is incomplete, update the progress trail and continue only within the proven scope.",
    }
}

fn operator_routine_step_approval_required(
    step: &OperatorRoutineStepTemplate,
    risk_level: &str,
) -> bool {
    risk_level == "high"
        || matches!(
            step.key,
            "release_deploy_backup" | "controlled_deploy" | "backup_or_rollback"
        )
}

pub(super) fn operator_routine_templates() -> Vec<OperatorRoutineTemplate> {
    vec![
        OperatorRoutineTemplate {
            key: "product_development_loop",
            title: "Product Development Operator Loop",
            summary: "When driving AI agents on product work, start from the user's product/SDS intent, create or update plan and progress documents, inspect the repo, implement gaps, validate with tests/builds, then handle git/release/deploy steps when appropriate.",
            trigger_terms: &[
                "sds",
                "implementation plan",
                "progress doc",
                "codebase",
                "tests",
                "commit",
                "deploy",
            ],
            min_supported_steps: 3,
            min_support_count: 3,
            steps: vec![
                OperatorRoutineStepTemplate {
                    key: "intake_sds_or_goal",
                    title: "Start From SDS Or Product Goal",
                    instruction: "Clarify the product goal, SDS, requirements, or acceptance criteria before deciding implementation shape.",
                    keywords: &[
                        "sds",
                        "specification",
                        "requirements",
                        "product goal",
                        "objective",
                        "acceptance criteria",
                    ],
                    category_hints: &["product_goals", "current_projects"],
                    record_type_hints: &["goal", "project"],
                },
                OperatorRoutineStepTemplate {
                    key: "plan_and_progress_docs",
                    title: "Create Plan And Progress Docs",
                    instruction: "Create or update a detailed plan document and keep a separate progress markdown file synchronized with real work.",
                    keywords: &[
                        "plan",
                        "planning",
                        "task list",
                        "docs/planning",
                        "implementation plan",
                        "progress md",
                        "progress document",
                        "progress file",
                        "markdown",
                    ],
                    category_hints: &["workflow_method", "delivery_preference"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "repo_inspection_and_dag",
                    title: "Inspect Repo And Dependency Impact",
                    instruction: "Use Docdex/search/symbols/AST/impact/DAG or equivalent repo evidence before changing code.",
                    keywords: &[
                        "codebase",
                        "repo",
                        "docdex",
                        "search",
                        "impact",
                        "dag",
                        "index",
                        "symbols",
                        "ast",
                        "compare",
                    ],
                    category_hints: &[
                        "workflow_method",
                        "tooling_preference",
                        "architecture_preference",
                    ],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "implement_and_close_gaps",
                    title: "Implement And Close Gaps",
                    instruction: "Implement directly, revisit the plan against the codebase, identify missing items, and iterate until gaps are closed.",
                    keywords: &[
                        "implement",
                        "fix",
                        "complete",
                        "fill gaps",
                        "missing",
                        "revisit",
                        "alignment",
                        "iterate",
                    ],
                    category_hints: &["workflow_method", "quality_bar"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "validate_with_tests",
                    title: "Validate With Tests",
                    instruction: "Run targeted tests first, then broader build/test validation when risk or scope requires it.",
                    keywords: &[
                        "test",
                        "tests",
                        "run-tests",
                        "build",
                        "validation",
                        "validate",
                        "verify",
                        "green",
                    ],
                    category_hints: &["quality_bar", "workflow_method", "delivery_preference"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "release_deploy_backup",
                    title: "Release, Deploy, And Backup Deliberately",
                    instruction: "When requested and validated, use the user's git/release/deploy/backup routine rather than leaving work only in the local tree.",
                    keywords: &[
                        "git",
                        "commit",
                        "tag",
                        "push",
                        "deploy",
                        "production",
                        "ci",
                        "cd",
                        "backup",
                        "docker",
                    ],
                    category_hints: &["delivery_preference", "workflow_method"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
            ],
        },
        OperatorRoutineTemplate {
            key: "planning_progress_loop",
            title: "Planning And Progress Documentation Loop",
            summary: "For non-trivial work, keep a detailed plan and a separate progress document, then update progress as implementation and validation evidence changes.",
            trigger_terms: &[
                "plan",
                "progress",
                "docs/planning",
                "tasks",
                "validation evidence",
            ],
            min_supported_steps: 2,
            min_support_count: 2,
            steps: vec![
                OperatorRoutineStepTemplate {
                    key: "write_plan",
                    title: "Write The Plan",
                    instruction: "Create a detailed plan or task breakdown before broad implementation work.",
                    keywords: &["plan", "planning", "task breakdown", "implementation plan"],
                    category_hints: &["workflow_method"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "track_progress",
                    title: "Track Progress Separately",
                    instruction: "Keep a separate progress markdown file and update it during work.",
                    keywords: &["progress", "progress md", "progress file", "another md file"],
                    category_hints: &["workflow_method", "delivery_preference"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "record_validation",
                    title: "Record Validation Evidence",
                    instruction: "Record completed checks, tests, blockers, and validation commands in the progress trail.",
                    keywords: &[
                        "test evidence",
                        "validation evidence",
                        "blocker",
                        "run-tests",
                        "tests",
                    ],
                    category_hints: &["quality_bar", "workflow_method"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
            ],
        },
        OperatorRoutineTemplate {
            key: "local_first_release_loop",
            title: "Local-First Release Loop",
            summary: "Prefer local implementation and validation first; after approval or instruction, commit/tag/push and deploy or sync production in a controlled way.",
            trigger_terms: &[
                "local first",
                "commit",
                "tag",
                "push",
                "deploy",
                "production",
                "backup",
            ],
            min_supported_steps: 2,
            min_support_count: 2,
            steps: vec![
                OperatorRoutineStepTemplate {
                    key: "local_first",
                    title: "Work Locally First",
                    instruction: "Make and validate changes locally before production operations.",
                    keywords: &["local first", "work locally", "local repo", "before production"],
                    category_hints: &["workflow_method", "delivery_preference"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "version_and_git",
                    title: "Version And Git",
                    instruction: "Use the requested git flow: commit, tag, push, and keep repos synchronized.",
                    keywords: &["version", "bump version", "commit", "tag", "push", "git"],
                    category_hints: &["delivery_preference", "workflow_method"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "controlled_deploy",
                    title: "Controlled Deploy",
                    instruction: "Deploy only when requested or appropriate, and verify live service health after deployment.",
                    keywords: &[
                        "deploy",
                        "production",
                        "prod",
                        "healthz",
                        "readyz",
                        "docker compose",
                        "pull on prod",
                    ],
                    category_hints: &["delivery_preference", "workflow_method"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
                OperatorRoutineStepTemplate {
                    key: "backup_or_rollback",
                    title: "Backup Or Rollback Awareness",
                    instruction: "Respect backup, rollback, and fallback-state preferences for high-risk release work.",
                    keywords: &["backup", "rollback", "fallback", "restore", "git tag"],
                    category_hints: &["delivery_preference", "quality_bar"],
                    record_type_hints: &["method", "workflow", "preference"],
                },
            ],
        },
    ]
}

pub(super) fn supported_operator_routine_steps(
    template: &OperatorRoutineTemplate,
    claims: &[&PersonalPreferenceClaim],
) -> Vec<SupportedOperatorRoutineStep> {
    let mut supported = Vec::new();
    for step in &template.steps {
        let mut claim_ids = Vec::new();
        let mut confidence_total = 0.0f32;
        for claim in claims {
            if operator_claim_matches_step(claim, step) && !claim_ids.contains(&claim.id) {
                claim_ids.push(claim.id.clone());
                confidence_total += claim.confidence;
            }
        }
        if !claim_ids.is_empty() {
            let confidence = (confidence_total / claim_ids.len() as f32).clamp(0.0, 1.0);
            supported.push(SupportedOperatorRoutineStep {
                template: *step,
                claim_ids,
                confidence,
            });
        }
    }
    supported
}

pub(super) fn operator_claim_matches_step(
    claim: &PersonalPreferenceClaim,
    step: &OperatorRoutineStepTemplate,
) -> bool {
    let blob = operator_claim_search_blob(claim);
    if step
        .keywords
        .iter()
        .any(|keyword| blob.contains(&keyword.to_ascii_lowercase()))
    {
        return true;
    }
    let record_type = claim
        .metadata
        .get("record_type")
        .and_then(Value::as_str)
        .unwrap_or("preference");
    let attribute = claim
        .attribute
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    step.category_hints.contains(&claim.category.as_str())
        && step.record_type_hints.contains(&record_type)
        && step
            .keywords
            .iter()
            .any(|keyword| attribute.contains(&keyword.to_ascii_lowercase()))
}

pub(super) fn operator_claim_search_blob(claim: &PersonalPreferenceClaim) -> String {
    [
        claim.category.as_str(),
        claim.subcategory.as_deref().unwrap_or_default(),
        claim.attribute.as_deref().unwrap_or_default(),
        claim.value.as_str(),
        claim.evidence_summary.as_deref().unwrap_or_default(),
        claim
            .metadata
            .get("record_type")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    ]
    .join(" ")
    .to_ascii_lowercase()
}

pub(super) fn operator_routine_confidence(
    template: &OperatorRoutineTemplate,
    supported_steps: &[SupportedOperatorRoutineStep],
    support_count: usize,
) -> f32 {
    let avg_step_confidence = supported_steps
        .iter()
        .map(|step| step.confidence)
        .sum::<f32>()
        / supported_steps.len().max(1) as f32;
    let step_coverage = supported_steps.len() as f32 / template.steps.len().max(1) as f32;
    let support_strength = (support_count.min(8) as f32) / 8.0;
    (0.45 + avg_step_confidence * 0.3 + step_coverage * 0.2 + support_strength * 0.05)
        .clamp(0.0, 0.99)
}

pub(super) fn upsert_operator_routine_claim(
    conn: &Connection,
    template: &OperatorRoutineTemplate,
    routine_id: &str,
    confidence: f32,
    support_count: usize,
    supported_steps: &[SupportedOperatorRoutineStep],
    event_evidence_ids: &[String],
    version: u32,
    risk_level: &str,
    autonomy_level: &str,
    updated_at_ms: i64,
) -> Result<()> {
    let claim_id = format!("{OPERATOR_ROUTINE_CLAIM_ID_PREFIX}{}", template.key);
    let supported_step_keys = supported_steps
        .iter()
        .map(|step| step.template.key)
        .collect::<Vec<_>>();
    let step_titles = supported_steps
        .iter()
        .map(|step| step.template.title)
        .collect::<Vec<_>>();
    let mut evidence_claim_ids = supported_steps
        .iter()
        .flat_map(|step| step.claim_ids.iter().cloned())
        .collect::<Vec<_>>();
    evidence_claim_ids.sort();
    evidence_claim_ids.dedup();
    let evidence_summary = format!(
        "Synthesized from {support_count} claims and {} operator events across {} supported steps: {}.",
        event_evidence_ids.len(),
        supported_steps.len(),
        step_titles.join(", ")
    );
    let metadata = json!({
        "record_type": "operator_routine",
        "routine_id": routine_id,
        "routine_key": template.key,
        "supported_step_keys": supported_step_keys,
        "evidence_claim_ids": evidence_claim_ids.clone(),
        "event_evidence_ids": event_evidence_ids,
        "version": version,
        "risk_level": risk_level,
        "autonomy_level": autonomy_level,
        "claim_write_path": "operator_routine_synthesis",
        "template_version": 1,
    });
    conn.execute(
        "INSERT INTO pp_claims(
            id, record_id, capture_id, category, subcategory, subject, attribute, value,
            claim_origin, truth_status, stability_class, sensitivity, confidence,
            review_status, evidence_summary, valid_from_ms, valid_to_ms,
            supersedes_claim_id, contradicted_by_claim_id, created_at_ms, updated_at_ms,
            metadata_json
         ) VALUES (?1, NULL, NULL, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                   NULL, NULL, NULL, NULL, ?14, ?14, ?15)
         ON CONFLICT(id) DO UPDATE SET
            subcategory = excluded.subcategory,
            value = excluded.value,
            truth_status = excluded.truth_status,
            stability_class = excluded.stability_class,
            confidence = excluded.confidence,
            review_status = excluded.review_status,
            evidence_summary = excluded.evidence_summary,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            claim_id,
            "operator_routine",
            template.key,
            "user",
            "uses",
            template.summary,
            CLAIM_ORIGIN_CROSS_SESSION_INFERENCE,
            TRUTH_STATUS_INFERRED,
            STABILITY_CLASS_STABLE,
            "low",
            confidence,
            REVIEW_STATUS_APPROVED,
            evidence_summary,
            updated_at_ms,
            serde_json::to_string(&metadata)?,
        ],
    )?;
    replace_claim_evidence(
        conn,
        &claim_id,
        None,
        Some(&evidence_summary),
        &metadata,
        updated_at_ms,
    )?;
    for linked_claim_id in evidence_claim_ids.iter().take(20) {
        write_claim_link(
            conn,
            &claim_id,
            Some(linked_claim_id),
            "synthesized_from_claim",
            &json!({ "routine_key": template.key }),
            updated_at_ms,
        )?;
    }
    Ok(())
}
