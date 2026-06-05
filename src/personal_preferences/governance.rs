use super::*;

#[derive(Debug, Clone)]
pub(super) struct CategoryPolicy {
    pub(super) category: String,
    pub(super) description: String,
    pub(super) context_section: Option<String>,
    pub(super) context_allowed_default: bool,
    pub(super) requires_review_for_sensitive: bool,
}

pub(super) fn write_redaction_span(
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

pub(super) fn load_category_rows(conn: &Connection) -> Result<Vec<PersonalPreferenceCategory>> {
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

pub(super) fn load_category_policy_map(
    conn: &Connection,
) -> Result<BTreeMap<String, CategoryPolicy>> {
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

pub(super) fn seed_default_category_policies(conn: &Connection) -> Result<()> {
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

pub(super) fn upsert_category_policy(conn: &Connection, policy: &CategoryPolicy) -> Result<()> {
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

pub(super) fn ensure_category_policy_for_record(
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

pub(super) fn default_category_policy(
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

pub(super) fn default_context_section_for(category: &str, record_type: &str) -> Option<String> {
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

pub(super) fn category_is_sensitive(category: &str) -> bool {
    matches!(
        category,
        "business_context" | "personal_context" | "identity_context" | "health_context"
    ) || category.contains("private")
        || category.contains("health")
        || category.contains("identity")
        || category.contains("personal")
}

pub(super) fn policy_for_category_fields(
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

pub(super) fn should_materialize_bridge(record: &PersonalPreferenceDigestRecord) -> bool {
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

pub(super) fn bridge_key_for_record(record: &PersonalPreferenceDigestRecord) -> String {
    slugify_identifier(&format!(
        "{}-{}-{}-{}",
        record.category,
        record.record_type,
        record.subject,
        record.attribute.as_deref().unwrap_or("notes")
    ))
}

pub(super) fn default_review_status_for_record(
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

pub(super) fn normalize_review_status(value: &str) -> Option<&'static str> {
    match normalize_text(value).to_ascii_lowercase().as_str() {
        "approved" | "approve" => Some(REVIEW_STATUS_APPROVED),
        "pending" | "pending_review" | "needs_review" => Some(REVIEW_STATUS_PENDING),
        "rejected" | "reject" => Some(REVIEW_STATUS_REJECTED),
        _ => None,
    }
}
