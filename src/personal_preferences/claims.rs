use super::*;

pub(super) fn backfill_rich_capture_lineage(conn: &Connection) -> Result<()> {
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

pub(super) fn backfill_rich_derived_materialization(conn: &Connection) -> Result<()> {
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
pub(super) struct BackfillRecord {
    pub(super) id: String,
    pub(super) capture_id: String,
    pub(super) record_type: String,
    pub(super) category: String,
    pub(super) subcategory: Option<String>,
    pub(super) subject: String,
    pub(super) attribute: Option<String>,
    pub(super) value: String,
    pub(super) confidence: f32,
    pub(super) sensitivity: String,
    pub(super) evidence: Option<String>,
    pub(super) created_at_ms: i64,
    pub(super) updated_at_ms: i64,
    pub(super) metadata: Value,
    pub(super) review_status: String,
}

pub(super) fn materialize_record_views(conn: &Connection, record: &BackfillRecord) -> Result<()> {
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

pub(super) fn upsert_materialized_table(conn: &Connection, record: &BackfillRecord) -> Result<()> {
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

pub(super) fn backfill_snapshot_summaries(conn: &Connection) -> Result<()> {
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

pub(super) fn ensure_entity(
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

pub(super) fn cleanup_orphan_entities(conn: &Connection) -> Result<()> {
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

pub(super) fn sync_materialized_record_status(
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

pub(super) fn relation_type_for_record(record: &BackfillRecord) -> String {
    record
        .attribute
        .clone()
        .unwrap_or_else(|| record.record_type.clone())
}

pub(super) fn entity_kind_for_record(record: &BackfillRecord) -> &str {
    match record.record_type.as_str() {
        "project" | "goal" => "project",
        "capability" | "trait" => "person",
        _ => "subject",
    }
}

pub(super) fn object_entity_kind_for_record(record: &BackfillRecord) -> &str {
    match record.record_type.as_str() {
        "project" | "goal" => "project",
        "method" | "bridge" => "method",
        "preference" | "like" | "dislike" => "preference_target",
        _ => "fact",
    }
}

pub(super) fn should_use_object_entity(record: &BackfillRecord) -> bool {
    matches!(
        record.record_type.as_str(),
        "project" | "goal" | "method" | "bridge"
    ) || matches!(
        record.category.as_str(),
        "current_projects" | "product_goals" | "cross_project_bridge"
    )
}

pub(super) fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub(super) fn parse_timestamp_json_value(value: Option<&Value>) -> Option<i64> {
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

pub(super) fn first_text_from_value(value: &Value, keys: &[&str]) -> Option<String> {
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

pub(super) fn object_or_empty_for_personal_preferences(value: Value) -> Value {
    match value {
        Value::Object(_) => value,
        _ => json!({}),
    }
}

pub(super) fn load_all_records(conn: &Connection) -> Result<Vec<PersonalPreferenceRecord>> {
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

pub(super) fn load_all_claims(conn: &Connection) -> Result<Vec<PersonalPreferenceClaim>> {
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

pub(super) fn load_claim_by_id(
    conn: &Connection,
    claim_id: &str,
) -> Result<Option<PersonalPreferenceClaim>> {
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

pub(super) fn load_records_for_capture_ids(
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

pub(super) fn row_to_capture(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersonalPreferencesCaptureRecord> {
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

pub(super) fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalPreferenceRecord> {
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

pub(super) fn row_to_claim(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersonalPreferenceClaim> {
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

pub(super) fn row_to_feedback_event(
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

pub(super) fn row_to_snapshot(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersonalPreferenceSnapshot> {
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

pub(super) fn row_to_operator_routine(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersonalPreferenceOperatorRoutine> {
    let trigger_terms_json: String = row.get(4)?;
    let applies_when_json: String = row.get(12)?;
    Ok(PersonalPreferenceOperatorRoutine {
        id: row.get(0)?,
        routine_key: row.get(1)?,
        title: row.get(2)?,
        summary: row.get(3)?,
        purpose: row.get(11)?,
        trigger_terms: parse_json_string_array(&trigger_terms_json),
        applies_when: parse_json_string_array(&applies_when_json),
        confidence: row.get(5)?,
        support_count: row.get::<_, i64>(6)? as usize,
        cross_project_support_count: row.get::<_, i64>(13)? as usize,
        event_support_count: row.get::<_, i64>(21)? as usize,
        risk_level: row.get(14)?,
        autonomy_level: row.get(15)?,
        version: row.get::<_, i64>(16)? as u32,
        valid_from_ms: row.get(17)?,
        valid_to_ms: row.get(18)?,
        drift_status: row.get(19)?,
        drift_score: row.get(20)?,
        status: row.get(7)?,
        created_at_ms: row.get(8)?,
        updated_at_ms: row.get(9)?,
        metadata: parse_json_value(&row.get::<_, String>(10)?),
        steps: Vec::new(),
    })
}

pub(super) fn row_to_operator_routine_step(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersonalPreferenceOperatorRoutineStep> {
    let evidence_claim_ids_json: String = row.get(13)?;
    let tool_hints_json: String = row.get(7)?;
    let expected_artifacts_json: String = row.get(8)?;
    let event_evidence_ids_json: String = row.get(14)?;
    Ok(PersonalPreferenceOperatorRoutineStep {
        id: row.get(0)?,
        routine_id: row.get(1)?,
        step_order: row.get::<_, i64>(2)? as usize,
        step_key: row.get(3)?,
        title: row.get(4)?,
        instruction: row.get(5)?,
        required: row.get::<_, i64>(6)? != 0,
        tool_hints: parse_json_string_array(&tool_hints_json),
        expected_artifacts: parse_json_string_array(&expected_artifacts_json),
        evidence_query: row.get(9)?,
        success_check: row.get(10)?,
        failure_recovery: row.get(11)?,
        approval_required: row.get::<_, i64>(12)? != 0,
        evidence_claim_ids: parse_json_string_array(&evidence_claim_ids_json),
        event_evidence_ids: parse_json_string_array(&event_evidence_ids_json),
        confidence: row.get(15)?,
        created_at_ms: row.get(16)?,
        updated_at_ms: row.get(17)?,
        metadata: parse_json_value(&row.get::<_, String>(18)?),
    })
}

pub(super) fn normalize_capture_text(request: &PersonalPreferencesCaptureRequest) -> String {
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

pub(super) fn normalize_digest_record(
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

pub(super) fn rank_records(query: &str, records: &mut Vec<PersonalPreferenceRecord>) {
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

pub(super) fn rank_claims(query: &str, claims: &mut Vec<PersonalPreferenceClaim>) {
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

pub(super) fn record_match_score(record: &PersonalPreferenceRecord, terms: &[String]) -> i32 {
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

pub(super) fn claim_match_score(claim: &PersonalPreferenceClaim, terms: &[String]) -> i32 {
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

pub(super) fn render_record(record: &PersonalPreferenceRecord) -> String {
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

pub(super) fn render_digest_record(record: &PersonalPreferenceDigestRecord) -> String {
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

pub(super) fn record_agent_id(record: &PersonalPreferenceRecord) -> Option<String> {
    record
        .metadata
        .get("agent_id")
        .and_then(Value::as_str)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(super) fn map_record_to_profile_category(
    record: &PersonalPreferenceRecord,
) -> Option<PreferenceCategory> {
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

pub(super) fn truth_status_rank(value: &str) -> i32 {
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

pub(super) fn stability_rank(value: &str) -> i32 {
    match value {
        STABILITY_CLASS_FOUNDATIONAL => 5,
        STABILITY_CLASS_STABLE => 4,
        STABILITY_CLASS_CURRENT => 3,
        STABILITY_CLASS_SESSIONAL => 2,
        STABILITY_CLASS_EPHEMERAL => 1,
        _ => 0,
    }
}

pub(super) fn truth_status_for_claim(review_status: &str, claim_origin: &str) -> &'static str {
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

pub(super) fn infer_claim_origin_from_backfill_record(record: &BackfillRecord) -> &'static str {
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

pub(super) fn infer_stability_class_from_backfill_record(record: &BackfillRecord) -> &'static str {
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

pub(super) fn personal_record_to_backfill(record: &PersonalPreferenceRecord) -> BackfillRecord {
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

pub(super) fn upsert_claim_from_backfill_record(
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

pub(super) fn backfill_claims_from_records(
    conn: &Connection,
    capture_id: Option<&str>,
) -> Result<usize> {
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

pub(super) fn write_claim_version(
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

pub(super) fn replace_claim_evidence(
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

pub(super) fn write_claim_link(
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

pub(super) fn claim_is_forgotten(claim: &PersonalPreferenceClaim) -> bool {
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

pub(super) fn operator_routine_key_for_claim(claim: &PersonalPreferenceClaim) -> Option<String> {
    if claim.category != "operator_routine"
        && claim.metadata.get("record_type").and_then(Value::as_str) != Some("operator_routine")
    {
        return None;
    }
    claim
        .metadata
        .get("routine_key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(super) fn load_suppressed_operator_routine_keys(conn: &Connection) -> Result<HashSet<String>> {
    let mut stmt = conn.prepare(
        "SELECT details_json
         FROM pp_tombstones
         WHERE action = 'forget_operator_routine'",
    )?;
    let mut rows = stmt.query([])?;
    let mut keys = HashSet::new();
    while let Some(row) = rows.next()? {
        let details = parse_json_value(&row.get::<_, String>(0)?);
        if let Some(key) = details
            .get("routine_key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            keys.insert(key.to_string());
        }
    }
    Ok(keys)
}

pub(super) fn record_is_forgotten(record: &PersonalPreferenceRecord) -> bool {
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
