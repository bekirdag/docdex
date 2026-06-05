use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CloneContextCandidate {
    pub(super) claim: PersonalPreferenceClaim,
    pub(super) section: String,
    pub(super) content: String,
    pub(super) record_type: String,
    pub(super) source_repo_root: Option<String>,
    pub(super) allowed: bool,
    pub(super) reason: String,
    pub(super) score: f32,
}

pub(super) fn normalize_clone_mode(value: &str) -> String {
    match normalize_text(value).as_str() {
        CLONE_MODE_PROJECT_BUILD => CLONE_MODE_PROJECT_BUILD.to_string(),
        CLONE_MODE_REVIEW => CLONE_MODE_REVIEW.to_string(),
        CLONE_MODE_RELEASE => CLONE_MODE_RELEASE.to_string(),
        CLONE_MODE_SIMULATE_USER_PREFERENCE => CLONE_MODE_SIMULATE_USER_PREFERENCE.to_string(),
        _ => CLONE_MODE_ADAPTIVE.to_string(),
    }
}

pub(super) fn section_for_claim(
    claim: &PersonalPreferenceClaim,
    record_type: &str,
    mode: &str,
) -> String {
    if claim.category == "operator_routine" || record_type == "operator_routine" {
        return "operator_routines".to_string();
    }
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

pub(super) fn render_claim_content(claim: &PersonalPreferenceClaim) -> String {
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

pub(super) fn clone_mode_section_boost(section: &str, mode: &str) -> f32 {
    match (mode, section) {
        (CLONE_MODE_PROJECT_BUILD, "active_project_and_strategic_context")
        | (CLONE_MODE_PROJECT_BUILD, "current_workflow_and_quality_expectations")
        | (CLONE_MODE_REVIEW, "current_workflow_and_quality_expectations")
        | (CLONE_MODE_REVIEW, "relevant_communication_style_expectations")
        | (CLONE_MODE_RELEASE, "active_project_and_strategic_context")
        | (CLONE_MODE_RELEASE, "current_workflow_and_quality_expectations")
        | (CLONE_MODE_PROJECT_BUILD, "operator_routines")
        | (CLONE_MODE_RELEASE, "operator_routines")
        | (CLONE_MODE_SIMULATE_USER_PREFERENCE, "operator_routines")
        | (CLONE_MODE_SIMULATE_USER_PREFERENCE, "relevant_communication_style_expectations")
        | (CLONE_MODE_SIMULATE_USER_PREFERENCE, "stable_preferences") => 1.25,
        _ => 1.0,
    }
}

pub(super) fn clone_term_match_score(text: &str, query: &str) -> f32 {
    let haystack = text.to_ascii_lowercase();
    query
        .split_whitespace()
        .map(|term| term.trim().to_ascii_lowercase())
        .filter(|term| !term.is_empty())
        .map(|term| if haystack.contains(&term) { 0.5 } else { 0.0 })
        .sum()
}

pub(super) fn normalize_replay_categories(categories: Vec<String>, query: &str) -> Vec<String> {
    let mut normalized = categories
        .into_iter()
        .filter_map(|value| normalize_non_empty_text(&value))
        .map(|value| slugify_identifier(&value))
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        normalized = derive_replay_categories_from_query(query);
    }
    normalized.sort();
    normalized.dedup();
    normalized
}

pub(super) fn derive_replay_categories_from_query(query: &str) -> Vec<String> {
    let lower = query.to_ascii_lowercase();
    let mut categories = Vec::new();
    for (needle, category) in [
        ("plan", "plan"),
        ("progress", "progress_update"),
        ("repo", "repo_inspection"),
        ("codebase", "repo_inspection"),
        ("implement", "implementation"),
        ("fix", "implementation"),
        ("gap", "gap_review"),
        ("test", "tests"),
        ("validate", "tests"),
        ("commit", "commit"),
        ("git", "commit"),
        ("deploy", "deploy"),
        ("production", "deploy"),
        ("backup", "backup"),
        ("rollback", "backup"),
    ] {
        if lower.contains(needle) && !categories.iter().any(|value| value == category) {
            categories.push(category.to_string());
        }
    }
    if categories.is_empty() && query_is_operator_style(query) {
        categories.extend(
            [
                "plan",
                "progress_update",
                "repo_inspection",
                "implementation",
                "tests",
            ]
            .into_iter()
            .map(ToOwned::to_owned),
        );
    }
    if categories.is_empty() {
        categories.push("preference_alignment".to_string());
    }
    categories
}

pub(super) fn replay_category_terms(category: &str) -> Vec<String> {
    match category {
        "plan" => vec!["plan", "planning", "implementation plan"],
        "progress_update" => vec!["progress", "progress markdown", "progress file"],
        "repo_inspection" => vec![
            "repo", "codebase", "docdex", "impact", "dag", "symbols", "ast",
        ],
        "implementation" => vec!["implement", "fix", "complete", "code"],
        "gap_review" => vec!["gap", "missing", "revisit", "alignment"],
        "tests" => vec!["test", "run-tests", "validation", "validate", "build"],
        "commit" => vec!["commit", "tag", "push", "git"],
        "deploy" => vec!["deploy", "production", "docker", "ci", "cd"],
        "backup" => vec!["backup", "rollback", "fallback", "restore"],
        "preference_alignment" => vec!["prefer", "preference", "expects", "workflow"],
        other => vec![other],
    }
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

pub(super) fn claim_support_count(claim: &PersonalPreferenceClaim) -> usize {
    claim
        .metadata
        .get("evidence_claim_ids")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .or_else(|| {
            claim
                .metadata
                .get("support_count")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
        })
        .unwrap_or(1)
}

pub(super) fn noisy_environment_claim(claim: &PersonalPreferenceClaim, query: &str) -> bool {
    let lower_query = query.to_ascii_lowercase();
    if ["environment", "path", "daemon", "port", "url", "machine"]
        .iter()
        .any(|term| lower_query.contains(term))
    {
        return false;
    }
    if claim.claim_origin == CLAIM_ORIGIN_ENVIRONMENTAL_INFERENCE {
        return true;
    }
    let content = render_claim_content(claim).to_ascii_lowercase();
    [
        "/users/",
        "127.0.0.1",
        "localhost",
        "http://",
        "https://",
        "port ",
        "shell",
    ]
    .iter()
    .any(|needle| content.contains(needle))
}

pub(super) fn clone_candidate_reason(
    mode: &str,
    operator_query: bool,
    record_type: &str,
    category: &str,
) -> String {
    if record_type == "operator_routine" || category == "operator_routine" {
        if operator_query {
            format!("{mode} operator-routine candidate with broad workflow boost")
        } else {
            format!("{mode} operator-routine candidate")
        }
    } else if operator_query
        && matches!(
            category,
            "workflow_method" | "quality_bar" | "delivery_preference" | "decision_style"
        )
    {
        format!("{mode} workflow candidate with operator-query boost")
    } else {
        format!("{mode} candidate")
    }
}

pub(super) fn load_clone_context_candidates(
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
        let operator_query = query_is_operator_style(query);
        let mut score = claim.confidence * 10.0
            + truth_status_rank(&claim.truth_status) as f32 * 2.0
            + stability_rank(&claim.stability_class) as f32
            + clone_term_match_score(&content, query);
        score *= clone_mode_section_boost(&section, mode);
        if claim.claim_origin == CLAIM_ORIGIN_EXPLICIT_USER_CORRECTION {
            score += 4.0;
        }
        if record_type == "operator_routine" || claim.category == "operator_routine" {
            score += 6.0 + claim_support_count(&claim).min(12) as f32 * 0.4;
            if operator_query {
                score += 5.0;
            }
        } else if operator_query
            && matches!(
                claim.category.as_str(),
                "workflow_method" | "quality_bar" | "delivery_preference" | "decision_style"
            )
        {
            score += 3.0;
        }
        if operator_query
            && matches!(
                claim.category.as_str(),
                "current_projects" | "business_context" | "health_context"
            )
            && claim.claim_origin != CLAIM_ORIGIN_CROSS_SESSION_INFERENCE
        {
            score -= 2.0;
        }
        if noisy_environment_claim(&claim, query) {
            score -= 6.0;
        }
        let reason = clone_candidate_reason(mode, operator_query, &record_type, &claim.category);
        candidates.push(CloneContextCandidate {
            claim,
            section,
            content,
            record_type,
            source_repo_root: None,
            allowed,
            reason,
            score,
        });
    }
    Ok(candidates)
}

pub(super) fn load_claim_bridge_candidates(
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

pub(super) fn render_clone_context_summary(items: &[PersonalPreferencesContextItem]) -> String {
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

pub(super) fn upsert_clone_profile(
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
