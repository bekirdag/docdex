use super::*;

pub(super) fn load_feedback_events(
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

pub(super) fn normalize_feedback_event_type(value: &str) -> Option<&'static str> {
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

pub(super) fn apply_feedback_to_claim(
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

pub(super) fn create_override_claim_from_claim(
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

pub(super) fn create_manual_feedback_claim(
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
