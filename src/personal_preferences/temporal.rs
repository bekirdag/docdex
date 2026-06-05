use super::*;

pub(super) fn load_snapshots(
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

pub(super) fn load_snapshot_by_id(
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

pub(super) fn rebuild_identity_snapshots_tx(
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

pub(super) fn rebuild_snapshot_signal_tables(
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
    rebuild_operator_routines_tx(conn, Some(snapshot_id), claims, created_at_ms)?;
    Ok(())
}

pub(super) fn claim_repo_root(claim: &PersonalPreferenceClaim) -> Option<String> {
    claim
        .metadata
        .get("repo_root")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn project_name_for_claim(claim: &PersonalPreferenceClaim) -> Option<String> {
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

pub(super) fn project_lifecycle_state_for_claim(claim: &PersonalPreferenceClaim) -> String {
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

pub(super) fn goal_graph_relevant(claim: &PersonalPreferenceClaim) -> bool {
    matches!(
        claim.category.as_str(),
        "product_goals" | "business_context" | "current_projects"
    ) || claim.metadata.get("record_type").and_then(Value::as_str) == Some("goal")
}

pub(super) fn goal_key_for_claim(claim: &PersonalPreferenceClaim) -> String {
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

pub(super) fn goal_status_for_claim(claim: &PersonalPreferenceClaim) -> String {
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

pub(super) fn is_override_rule_claim(claim: &PersonalPreferenceClaim) -> bool {
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

pub(super) fn upsert_override_rule_from_claim(
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

pub(super) fn render_claim_snapshot_line(claim: &PersonalPreferenceClaim) -> String {
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
