use super::*;

const MAX_OPERATOR_EVENT_SUMMARY_CHARS: usize = 360;
const MAX_OPERATOR_EVENT_COMMAND_CHARS: usize = 1_000;
const MAX_OPERATOR_ARTIFACT_SCAN_LIMIT: usize = 2_000;

impl PersonalPreferencesStore {
    pub fn record_operator_event(
        &self,
        request: PersonalPreferenceOperatorEventRequest,
        source: &str,
    ) -> Result<PersonalPreferenceOperatorEvent> {
        let conn = open_db(&self.db_path)?;
        let (event, _) = record_operator_event_tx(&conn, request, source)?;
        Ok(event)
    }

    pub fn list_operator_events(
        &self,
        event_kind: Option<&str>,
        action: Option<&str>,
        repo_root: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferenceOperatorEventList> {
        let conn = open_db(&self.db_path)?;
        let event_kind = event_kind
            .and_then(normalize_operator_event_kind_filter)
            .filter(|value| !value.is_empty());
        let action = action.and_then(normalize_non_empty_text);
        let repo_root = repo_root.and_then(normalize_non_empty_text);
        let total = conn.query_row(
            "SELECT COUNT(*) FROM pp_operator_events
             WHERE (?1 IS NULL OR event_kind = ?1)
               AND (?2 IS NULL OR action = ?2)
               AND (?3 IS NULL OR repo_root = ?3)",
            params![
                event_kind.as_deref(),
                action.as_deref(),
                repo_root.as_deref()
            ],
            |row| row.get::<_, i64>(0),
        )? as usize;
        let mut stmt = conn.prepare(
            "SELECT id, source, source_session_id, event_kind, action, summary, command_text,
                    repo_id, repo_root, capture_id, artifact_path, occurred_at_ms, created_at_ms,
                    content_hash, metadata_json
             FROM pp_operator_events
             WHERE (?1 IS NULL OR event_kind = ?1)
               AND (?2 IS NULL OR action = ?2)
               AND (?3 IS NULL OR repo_root = ?3)
             ORDER BY occurred_at_ms DESC, created_at_ms DESC
             LIMIT ?4 OFFSET ?5",
        )?;
        let mut rows = stmt.query(params![
            event_kind.as_deref(),
            action.as_deref(),
            repo_root.as_deref(),
            limit.clamp(1, 200) as i64,
            offset as i64
        ])?;
        let mut items = Vec::new();
        while let Some(row) = rows.next()? {
            items.push(row_to_operator_event(row)?);
        }
        Ok(PersonalPreferenceOperatorEventList { total, items })
    }

    pub fn scan_operator_artifacts(
        &self,
        repo_root: &Path,
        limit: Option<usize>,
    ) -> Result<PersonalPreferenceOperatorEventScanSummary> {
        let repo_root = repo_root
            .canonicalize()
            .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
        if !repo_root.is_dir() {
            return Err(anyhow!(
                "repo root is not a directory: {}",
                repo_root.display()
            ));
        }
        let limit = limit
            .unwrap_or(DEFAULT_OPERATOR_ARTIFACT_SCAN_LIMIT)
            .clamp(1, MAX_OPERATOR_ARTIFACT_SCAN_LIMIT);
        let conn = open_db(&self.db_path)?;
        let repo_root_text = repo_root.display().to_string();
        let repo_id = crate::repo_manager::repo_fingerprint_sha256(&repo_root).ok();
        let mut summary = PersonalPreferenceOperatorEventScanSummary {
            scanned_files: 0,
            created_events: 0,
            skipped_existing: 0,
            items: Vec::new(),
        };

        for path in collect_operator_artifact_candidates(&repo_root)? {
            if summary.items.len() >= limit {
                break;
            }
            let rel_path = path
                .strip_prefix(&repo_root)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            let Some(artifact_kind) = infer_operator_artifact_kind(&rel_path) else {
                continue;
            };
            let metadata = fs::metadata(&path)
                .with_context(|| format!("read metadata for {}", path.display()))?;
            let modified_at_ms = metadata
                .modified()
                .ok()
                .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|value| value.as_millis() as i64)
                .unwrap_or_else(now_ms);
            let file_size_bytes = metadata.len();
            summary.scanned_files += 1;
            let request = PersonalPreferenceOperatorEventRequest {
                event_kind: Some(OPERATOR_EVENT_KIND_ARTIFACT_UPDATE.to_string()),
                action: format!("artifact_{artifact_kind}"),
                summary: Some(format!(
                    "Operator artifact observed: {} at {rel_path}",
                    operator_artifact_label(artifact_kind)
                )),
                command_text: None,
                source_session_id: None,
                repo_id: repo_id.clone(),
                repo_root: Some(repo_root_text.clone()),
                capture_id: None,
                artifact_path: Some(rel_path.clone()),
                occurred_at_ms: Some(modified_at_ms),
                metadata: json!({
                    "artifact_kind": artifact_kind,
                    "file_size_bytes": file_size_bytes,
                    "modified_at_ms": modified_at_ms,
                    "scan_root": repo_root_text,
                }),
            };
            let (event, created) = record_operator_event_tx(&conn, request, "artifact_scan")?;
            if created {
                summary.created_events += 1;
            } else {
                summary.skipped_existing += 1;
            }
            summary.items.push(event);
        }
        conn.execute(
            "INSERT OR REPLACE INTO personal_preferences_meta(key, value) VALUES (?1, ?2)",
            params![LAST_OPERATOR_ARTIFACT_SCAN_META_KEY, now_ms().to_string()],
        )?;
        Ok(summary)
    }
}

fn record_operator_event_tx(
    conn: &Connection,
    request: PersonalPreferenceOperatorEventRequest,
    source: &str,
) -> Result<(PersonalPreferenceOperatorEvent, bool)> {
    let source = normalize_operator_event_source(source);
    let action = normalize_non_empty_text(&request.action)
        .ok_or_else(|| anyhow!("operator event action must not be empty"))?;
    let command_text = request.command_text.as_deref().and_then(|value| {
        normalize_non_empty_text(&sanitize_operator_event_text(
            value,
            MAX_OPERATOR_EVENT_COMMAND_CHARS,
        ))
    });
    let event_kind = infer_operator_event_kind(
        request.event_kind.as_deref(),
        &action,
        command_text.as_deref(),
        request.artifact_path.as_deref(),
    );
    let artifact_path = request
        .artifact_path
        .and_then(|value| normalize_non_empty_text(&value).map(|value| value.replace('\\', "/")));
    let summary = request
        .summary
        .as_deref()
        .and_then(|value| {
            normalize_non_empty_text(&sanitize_operator_event_text(
                value,
                MAX_OPERATOR_EVENT_SUMMARY_CHARS,
            ))
        })
        .unwrap_or_else(|| {
            default_operator_event_summary(&event_kind, &action, artifact_path.as_deref())
        });
    let source_session_id = request
        .source_session_id
        .and_then(|value| normalize_non_empty_text(&value));
    let repo_id = request
        .repo_id
        .and_then(|value| normalize_non_empty_text(&value));
    let repo_root = request
        .repo_root
        .and_then(|value| normalize_non_empty_text(&value));
    let capture_id = request
        .capture_id
        .and_then(|value| normalize_non_empty_text(&value));
    let occurred_at_ms = request.occurred_at_ms.unwrap_or_else(now_ms);
    let created_at_ms = now_ms();
    let metadata = if request.metadata.is_null() {
        json!({})
    } else {
        request.metadata
    };
    let metadata_json = serde_json::to_string(&metadata)?;
    let content_hash = operator_event_hash(&[
        &source,
        source_session_id.as_deref().unwrap_or_default(),
        &event_kind,
        &action,
        &summary,
        command_text.as_deref().unwrap_or_default(),
        repo_id.as_deref().unwrap_or_default(),
        repo_root.as_deref().unwrap_or_default(),
        capture_id.as_deref().unwrap_or_default(),
        artifact_path.as_deref().unwrap_or_default(),
        &occurred_at_ms.to_string(),
    ]);
    let id = format!("operator_event_{}", Uuid::new_v4());
    let inserted = conn.execute(
        "INSERT OR IGNORE INTO pp_operator_events(
             id, source, source_session_id, event_kind, action, summary, command_text,
             repo_id, repo_root, capture_id, artifact_path, occurred_at_ms, created_at_ms,
             content_hash, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
        params![
            &id,
            &source,
            source_session_id.as_deref(),
            &event_kind,
            &action,
            &summary,
            command_text.as_deref(),
            repo_id.as_deref(),
            repo_root.as_deref(),
            capture_id.as_deref(),
            artifact_path.as_deref(),
            occurred_at_ms,
            created_at_ms,
            &content_hash,
            &metadata_json
        ],
    )? > 0;
    let event = load_operator_event_by_hash(conn, &content_hash)?
        .ok_or_else(|| anyhow!("operator event insert failed"))?;
    Ok((event, inserted))
}

fn load_operator_event_by_hash(
    conn: &Connection,
    content_hash: &str,
) -> Result<Option<PersonalPreferenceOperatorEvent>> {
    conn.query_row(
        "SELECT id, source, source_session_id, event_kind, action, summary, command_text,
                repo_id, repo_root, capture_id, artifact_path, occurred_at_ms, created_at_ms,
                content_hash, metadata_json
         FROM pp_operator_events
         WHERE content_hash = ?1",
        params![content_hash],
        row_to_operator_event,
    )
    .optional()
    .map_err(Into::into)
}

fn row_to_operator_event(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<PersonalPreferenceOperatorEvent> {
    let metadata_json: String = row.get(14)?;
    Ok(PersonalPreferenceOperatorEvent {
        id: row.get(0)?,
        source: row.get(1)?,
        source_session_id: row.get(2)?,
        event_kind: row.get(3)?,
        action: row.get(4)?,
        summary: row.get(5)?,
        command_text: row.get(6)?,
        repo_id: row.get(7)?,
        repo_root: row.get(8)?,
        capture_id: row.get(9)?,
        artifact_path: row.get(10)?,
        occurred_at_ms: row.get(11)?,
        created_at_ms: row.get(12)?,
        content_hash: row.get(13)?,
        metadata: parse_json_value(&metadata_json),
    })
}

fn normalize_operator_event_source(source: &str) -> String {
    let source = slugify_identifier(source);
    if source.is_empty() {
        "manual".to_string()
    } else {
        source
    }
}

fn normalize_operator_event_kind_filter(value: &str) -> Option<String> {
    let normalized = slugify_identifier(value);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn infer_operator_event_kind(
    provided: Option<&str>,
    action: &str,
    command_text: Option<&str>,
    artifact_path: Option<&str>,
) -> String {
    if let Some(kind) = provided.and_then(normalize_operator_event_kind_filter) {
        return kind;
    }
    if artifact_path.is_some() {
        return OPERATOR_EVENT_KIND_ARTIFACT_UPDATE.to_string();
    }
    let haystack = format!(
        "{} {}",
        action.to_ascii_lowercase(),
        command_text.unwrap_or_default().to_ascii_lowercase()
    );
    let trimmed_command = command_text.unwrap_or_default().trim_start();
    if trimmed_command.starts_with("git ") || haystack.contains(" git ") {
        return OPERATOR_EVENT_KIND_GIT_ACTION.to_string();
    }
    if contains_any(
        &haystack,
        &[
            "cargo test",
            "cargo nextest",
            "docdexd run-tests",
            "npm test",
            "pnpm test",
            "yarn test",
            "pytest",
            "go test",
            "rspec",
        ],
    ) {
        return OPERATOR_EVENT_KIND_TEST_ACTION.to_string();
    }
    if contains_any(
        &haystack,
        &[
            "deploy",
            "systemctl",
            "kubectl",
            "docker compose",
            "docker-compose",
            "rsync",
            "scp ",
            "ssh ",
            "release",
        ],
    ) {
        return OPERATOR_EVENT_KIND_DEPLOY_ACTION.to_string();
    }
    if contains_any(
        &haystack,
        &[
            "backup",
            "snapshot",
            "pg_dump",
            "mongodump",
            "mysqldump",
            "tar ",
            "zip ",
            "restore",
            "rollback",
        ],
    ) {
        return OPERATOR_EVENT_KIND_BACKUP_ACTION.to_string();
    }
    if contains_any(&haystack, &["approve", "approval", "confirm", "permission"]) {
        return OPERATOR_EVENT_KIND_APPROVAL_GATE.to_string();
    }
    if contains_any(&haystack, &["correct", "fix", "revise", "reject"]) {
        return OPERATOR_EVENT_KIND_CORRECTION.to_string();
    }
    if command_text.is_some() {
        OPERATOR_EVENT_KIND_SHELL_COMMAND.to_string()
    } else {
        OPERATOR_EVENT_KIND_OPERATOR_EVENT.to_string()
    }
}

fn default_operator_event_summary(
    event_kind: &str,
    action: &str,
    artifact_path: Option<&str>,
) -> String {
    if let Some(path) = artifact_path {
        return format!("Operator artifact event: {action} at {path}");
    }
    format!("Operator event: {event_kind} / {action}")
}

fn sanitize_operator_event_text(text: &str, max_chars: usize) -> String {
    let mut sanitized = normalize_text(text);
    for pattern in TRANSCRIPT_SECRET_PATTERNS.iter() {
        sanitized = pattern.replace_all(&sanitized, "[redacted]").into_owned();
    }
    sanitized = redact_secret_assignment_tokens(&sanitized);
    truncate_chars(&sanitized, max_chars)
}

fn redact_secret_assignment_tokens(text: &str) -> String {
    text.split_whitespace()
        .map(redact_secret_assignment_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_secret_assignment_token(token: &str) -> String {
    let Some((idx, delimiter)) = token.char_indices().find(|(_, ch)| matches!(ch, '=' | ':'))
    else {
        return token.to_string();
    };
    let key = &token[..idx];
    let value = &token[idx + delimiter.len_utf8()..];
    if value.chars().count() < 4 {
        return token.to_string();
    }
    let key_lower = key
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`'))
        .to_ascii_lowercase();
    let secretish = [
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "passwd",
        "private_key",
    ]
    .iter()
    .any(|needle| key_lower.contains(needle));
    if secretish {
        format!("{key}{delimiter}[redacted]")
    } else {
        token.to_string()
    }
}

fn operator_event_hash(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{:x}", hasher.finalize())
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn collect_operator_artifact_candidates(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let mut search_roots = Vec::new();
    for rel in ["docs/planning", "docs/sds", "docs/specs", "docs"] {
        let path = repo_root.join(rel);
        if path.exists() && path.is_dir() {
            search_roots.push(path);
        }
    }
    search_roots.push(repo_root.to_path_buf());
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for search_root in search_roots {
        let max_depth = if search_root == repo_root { 1 } else { 8 };
        for entry in WalkDir::new(&search_root)
            .follow_links(false)
            .max_depth(max_depth)
            .into_iter()
            .filter_entry(|entry| !is_ignored_operator_artifact_entry(entry))
        {
            let entry = entry?;
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path().to_path_buf();
            let rel = path
                .strip_prefix(repo_root)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            if !is_operator_artifact_candidate(&rel) {
                continue;
            }
            if seen.insert(path.clone()) {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    Ok(candidates)
}

fn is_ignored_operator_artifact_entry(entry: &walkdir::DirEntry) -> bool {
    if !entry.file_type().is_dir() {
        return false;
    }
    let name = entry.file_name().to_string_lossy();
    matches!(
        name.as_ref(),
        ".git" | ".docdex" | "target" | "node_modules" | ".next" | "dist" | "build"
    )
}

fn is_operator_artifact_candidate(rel_path: &str) -> bool {
    let lower = rel_path.to_ascii_lowercase();
    let has_supported_ext = lower.ends_with(".md") || lower.ends_with(".markdown");
    has_supported_ext
        && contains_any(
            &lower,
            &[
                "sds", "prd", "spec", "plan", "progress", "roadmap", "todo", "release", "deploy",
                "rollback", "backup",
            ],
        )
}

fn infer_operator_artifact_kind(rel_path: &str) -> Option<&'static str> {
    let lower = rel_path.to_ascii_lowercase();
    if lower.contains("sds") {
        Some("sds")
    } else if lower.contains("prd") {
        Some("prd")
    } else if lower.contains("progress") {
        Some("progress")
    } else if lower.contains("roadmap") {
        Some("roadmap")
    } else if lower.contains("todo") {
        Some("todo")
    } else if lower.contains("plan") {
        Some("plan")
    } else if lower.contains("release") {
        Some("release")
    } else if lower.contains("deploy") {
        Some("deploy")
    } else if lower.contains("rollback") {
        Some("rollback")
    } else if lower.contains("backup") {
        Some("backup")
    } else if lower.contains("spec") {
        Some("spec")
    } else {
        None
    }
}

fn operator_artifact_label(kind: &str) -> &'static str {
    match kind {
        "sds" => "SDS",
        "prd" => "PRD",
        "progress" => "progress",
        "roadmap" => "roadmap",
        "todo" => "todo",
        "plan" => "plan",
        "release" => "release",
        "deploy" => "deployment",
        "rollback" => "rollback",
        "backup" => "backup",
        "spec" => "spec",
        _ => "planning",
    }
}
