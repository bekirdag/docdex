use super::*;

pub(super) fn seed_default_sensitivity_levels(conn: &Connection) -> Result<()> {
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

pub(super) fn seed_default_context_policies(conn: &Connection) -> Result<()> {
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

pub(super) fn seed_default_retention_policies(conn: &Connection) -> Result<()> {
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

pub(super) fn load_retention_policies(
    conn: &Connection,
) -> Result<Vec<PersonalPreferenceRetentionPolicy>> {
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

pub(super) fn optional_i64_to_u32(value: Option<i64>) -> Option<u32> {
    value.and_then(|item| u32::try_from(item).ok())
}

pub(super) fn upsert_retention_policy(
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

pub(super) fn file_modified_at_ms(path: &Path) -> Result<i64> {
    let modified = fs::metadata(path)
        .with_context(|| format!("stat {}", path.display()))?
        .modified()
        .with_context(|| format!("read modified time for {}", path.display()))?;
    Ok(modified
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0))
}

pub(super) fn count_files_older_than(dir: &Path, cutoff_ms: i64) -> Result<usize> {
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

pub(super) fn prune_files_older_than(dir: &Path, cutoff_ms: i64) -> Result<usize> {
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

pub(super) fn retention_cutoff_ms(days: u32) -> Option<i64> {
    if days == 0 {
        return None;
    }
    Some(now_ms().saturating_sub(days as i64 * 24 * 60 * 60 * 1000))
}
