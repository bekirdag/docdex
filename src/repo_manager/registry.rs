use crate::error::{
    repo_resolution_details, AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_REPO_PATH,
};
use crate::repo_manager::fingerprint::{
    git_dir_for_repo, legacy_repo_id_for_root, normalize_path, repo_fingerprint_sha256,
};
use crate::state_paths;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tracing::warn;

#[derive(Debug, thiserror::Error)]
pub enum RepoIdentityError {
    #[error("repo state metadata fingerprint mismatch (state_key={state_key}): expected {expected_fingerprint}, found {found_fingerprint}")]
    StateMetaFingerprintMismatch {
        state_key: String,
        expected_fingerprint: String,
        found_fingerprint: String,
    },
    #[error("canonical path `{canonical_path}` is already associated with a different repo fingerprint `{other_fingerprint}`")]
    CanonicalPathCollision {
        canonical_path: String,
        other_fingerprint: String,
    },
    #[error("repo fingerprint `{fingerprint}` is already mapped to state_key `{existing_state_key}`; refusing to remap to `{requested_state_key}`")]
    StateKeyConflict {
        fingerprint: String,
        existing_state_key: String,
        requested_state_key: String,
    },
    #[error(
        "repo fingerprint `{fingerprint}` is registered for `{registered_canonical_path}`; refusing to use it for `{requested_canonical_path}` without explicit re-association"
    )]
    ReassociationRequired {
        fingerprint: String,
        state_key: String,
        registered_canonical_path: String,
        requested_canonical_path: String,
    },
    #[error(
        "cannot re-associate `{old_path}`: multiple fingerprints match; re-run with --fingerprint to select one"
    )]
    AmbiguousOldPath {
        old_path: String,
        candidate_fingerprints: Vec<String>,
    },
    #[error(
        "cannot re-associate: fingerprint `{fingerprint}` not found in registry at {registry_path}"
    )]
    UnknownFingerprint {
        fingerprint: String,
        registry_path: PathBuf,
    },
    #[error("failed to persist repo registry at {path}: {source}")]
    PersistFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct RepoStateKeyResolution {
    pub state_key: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoReassociateResult {
    pub fingerprint: String,
    pub state_key: String,
    pub canonical_path: String,
    pub prior_canonical_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInspectReport {
    pub repo_root: String,
    pub normalized_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub computed_fingerprint: Option<String>,
    pub resolved_index_state_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_paths: Option<crate::state_layout::StatePathsDebug>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_state_base_dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mapping: Option<RepoInspectMapping>,
    pub status: RepoInspectStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<RepoInspectDiagnostics>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInspectMapping {
    pub fingerprint: String,
    pub state_key: String,
    pub canonical_path: String,
    pub aliases: Vec<String>,
    pub last_seen_at_epoch_ms: i64,
    #[serde(rename = "lastSeen")]
    pub last_seen: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoInspectStatus {
    LocalStateDir,
    Unmapped,
    Ok,
    ReassociationRequired,
    CanonicalPathCollision,
    RepoStateMismatch,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoInspectDiagnostics {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RepoRegistryFile {
    version: u32,
    repos: BTreeMap<String, RepoRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoRegistryEntry {
    state_key: String,
    canonical_path: String,
    #[serde(default)]
    prior_paths: Vec<String>,
    #[serde(default)]
    last_seen_at_epoch_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoStateMetaV1 {
    version: u32,
    fingerprint_sha256: String,
    canonical_path: String,
    #[serde(default)]
    created_at_epoch_ms: i64,
    #[serde(default)]
    last_seen_at_epoch_ms: i64,
}

const REPO_REGISTRY_VERSION: u32 = 1;
const REPO_META_VERSION: u32 = 1;
const REPO_REGISTRY_FILENAME: &str = "repo_registry.json";
const REPO_META_FILENAME: &str = "repo_meta.json";
const WORKSPACE_META_DIR: &str = ".docdex";

pub fn inspect_repo(
    repo_root: &Path,
    state_dir_override: Option<&Path>,
) -> Result<RepoInspectReport> {
    if !repo_root.exists() {
        return Err(AppError::new(ERR_MISSING_REPO_PATH, "repo path not found")
            .with_details(repo_resolution_details(
                repo_root.to_string_lossy().replace('\\', "/"),
                None,
                None,
                vec![
                    "Repo may have moved or been renamed.".to_string(),
                    "Re-run with the repo's current path.".to_string(),
                ],
            ))
            .into());
    }
    if !repo_root.is_dir() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("repo root is not a directory: {}", repo_root.display()),
        )
        .into());
    }

    let repo_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_root_str = repo_root.display().to_string();
    let normalized_path = normalize_path(&repo_root);
    let computed_fingerprint = repo_fingerprint_sha256(&repo_root).ok();

    let resolved = resolve_state_dir_for_inspect(&repo_root, state_dir_override);
    let state_paths = Some(derive_state_paths_debug(
        &resolved.resolved_index_dir,
        resolved.shared_base_dir.as_deref(),
        resolved.state_key.as_deref(),
        computed_fingerprint.as_deref(),
    ));
    let mut report = RepoInspectReport {
        repo_root: repo_root_str,
        normalized_path,
        computed_fingerprint: computed_fingerprint.clone(),
        resolved_index_state_dir: resolved.resolved_index_dir.display().to_string(),
        state_paths,
        shared_state_base_dir: resolved
            .shared_base_dir
            .as_ref()
            .map(|p| p.display().to_string()),
        state_key: resolved.state_key.clone(),
        mapping: None,
        status: RepoInspectStatus::LocalStateDir,
        diagnostics: None,
    };

    let Some(shared_base_dir) = resolved.shared_base_dir.as_ref() else {
        return Ok(report);
    };

    let Some(fingerprint) = computed_fingerprint else {
        report.status = RepoInspectStatus::Unmapped;
        report.diagnostics = Some(RepoInspectDiagnostics {
            code: "fingerprint_unavailable",
            message: "failed to compute repo fingerprint".to_string(),
            details: None,
        });
        return Ok(report);
    };

    let registry_path = repo_registry_path(shared_base_dir);
    let registry = load_registry(&registry_path)?;
    if let Some(entry) = registry.repos.get(&fingerprint) {
        report.mapping = Some(RepoInspectMapping {
            fingerprint: fingerprint.clone(),
            state_key: entry.state_key.clone(),
            canonical_path: entry.canonical_path.clone(),
            aliases: entry.prior_paths.clone(),
            last_seen_at_epoch_ms: entry.last_seen_at_epoch_ms,
            last_seen: entry.last_seen_at_epoch_ms,
        });
    }

    let canonical_new = normalize_path(&repo_root);
    if let Some((other_fp, _)) = registry.repos.iter().find(|(fp, entry)| {
        fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_new
    }) {
        report.status = RepoInspectStatus::CanonicalPathCollision;
        report.diagnostics = Some(RepoInspectDiagnostics {
            code: "canonical_path_collision",
            message: "canonical path is already associated with a different fingerprint"
                .to_string(),
            details: Some(serde_json::json!({
                "canonicalPath": canonical_new,
                "otherFingerprint": other_fp,
            })),
        });
        return Ok(report);
    }

    if let Some(mapping) = report.mapping.as_ref() {
        if mapping.canonical_path != canonical_new {
            report.status = RepoInspectStatus::ReassociationRequired;
            report.diagnostics = Some(RepoInspectDiagnostics {
                code: "reassociation_required",
                message: "repo fingerprint is registered for a different canonical path"
                    .to_string(),
                details: Some(serde_json::json!({
                    "fingerprint": fingerprint,
                    "registeredCanonicalPath": mapping.canonical_path,
                    "requestedCanonicalPath": canonical_new,
                })),
            });
            return Ok(report);
        }
    }

    if let Some(meta) = read_repo_meta(
        &repo_root,
        Some(shared_base_dir.as_path()),
        resolved.state_key.as_deref(),
    ) {
        if meta.fingerprint_sha256 != fingerprint {
            report.status = RepoInspectStatus::RepoStateMismatch;
            report.diagnostics = Some(RepoInspectDiagnostics {
                code: "repo_meta_fingerprint_mismatch",
                message: "repo metadata fingerprint mismatch".to_string(),
                details: Some(serde_json::json!({
                    "expectedFingerprint": fingerprint,
                    "foundFingerprint": meta.fingerprint_sha256,
                    "metaCanonicalPath": meta.canonical_path,
                })),
            });
            return Ok(report);
        }
    }

    report.status = if report.mapping.is_some() {
        RepoInspectStatus::Ok
    } else {
        RepoInspectStatus::Unmapped
    };
    Ok(report)
}

pub fn resolve_shared_state_key(
    repo_root: &Path,
    shared_base_dir: &Path,
) -> Result<RepoStateKeyResolution> {
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    let meta_base_dir = resolve_repo_meta_base_dir(repo_root, shared_base_dir);
    let registry_path = repo_registry_path(shared_base_dir);
    let registry = load_registry(&registry_path)?;

    let mut state_key = if let Some(entry) = registry.repos.get(&fingerprint) {
        entry.state_key.clone()
    } else {
        fingerprint.clone()
    };

    // Back-compat: if registry doesn't know this repo yet, prefer existing on-disk state dirs.
    if !registry.repos.contains_key(&fingerprint) {
        let preferred = shared_repo_root_dir(shared_base_dir, &fingerprint);
        let legacy = legacy_repo_id_for_root(repo_root);
        let legacy_dir = shared_repo_root_dir(shared_base_dir, &legacy);
        if preferred.join("index").exists() {
            state_key = fingerprint.clone();
        } else if legacy_dir.join("index").exists() {
            state_key = legacy;
        } else {
            state_key = fingerprint.clone();
        }
    }

    // Fast-fail on explicit mismatches when metadata exists.
    validate_repo_meta(
        repo_root,
        &fingerprint,
        Some(&meta_base_dir),
        Some(&state_key),
    )?;

    Ok(RepoStateKeyResolution { state_key })
}

pub fn resolve_shared_index_state_dir(
    repo_root: &Path,
    custom_state_dir: &Path,
) -> Result<PathBuf> {
    let (base_dir, maybe_scoped_key, scoped_has_index) = split_scoped_state_dir(custom_state_dir)
        .unwrap_or_else(|| (custom_state_dir.to_path_buf(), None, false));

    let resolution = resolve_shared_state_key(repo_root, &base_dir)?;
    let expected = resolution.state_key.clone();

    if let Some(scoped_key) = maybe_scoped_key {
        if scoped_key == expected {
            if scoped_has_index {
                return Ok(custom_state_dir.to_path_buf());
            }
            return Ok(custom_state_dir.join("index"));
        }
    }

    Ok(shared_repo_root_dir(&base_dir, &expected).join("index"))
}

pub fn record_repo_opened(repo_root: &Path, index_state_dir: &Path) -> Result<()> {
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    let canonical_path = normalize_path(repo_root);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let maybe_state = base_dir_and_state_key_from_index_dir(index_state_dir);
    let (meta_base_dir, meta_state_key) = if let Some((base_dir, state_key)) = maybe_state.as_ref()
    {
        (
            resolve_repo_meta_base_dir(repo_root, base_dir),
            state_key.clone(),
        )
    } else {
        let fallback_base = state_paths::default_state_base_dir()
            .context("resolve default state base dir for repo meta")?;
        (
            resolve_repo_meta_base_dir(repo_root, &fallback_base),
            fingerprint.clone(),
        )
    };
    validate_repo_meta(
        repo_root,
        &fingerprint,
        Some(&meta_base_dir),
        Some(meta_state_key.as_str()),
    )?;

    let Some((base_dir, state_key)) = maybe_state else {
        write_repo_meta(
            repo_root,
            &meta_base_dir,
            meta_state_key.as_str(),
            &fingerprint,
            &canonical_path,
            now_ms,
        )?;
        return Ok(());
    };

    let registry_path = repo_registry_path(&base_dir);
    fs::create_dir_all(registry_path.parent().expect("registry parent"))
        .with_context(|| format!("create {}", registry_path.parent().unwrap().display()))?;

    let mut registry = load_registry(&registry_path)?;

    let collision_fp = registry
        .repos
        .iter()
        .find(|(fp, entry)| {
            fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_path
        })
        .map(|(fp, _)| fp.to_string());
    if let Some(other_fp) = collision_fp {
        let healed = try_auto_heal_canonical_path_collision(
            &mut registry,
            &canonical_path,
            &fingerprint,
            &meta_base_dir,
        )?;
        if healed {
            warn!(
                canonical_path,
                other_fingerprint = other_fp.as_str(),
                "auto-healed canonical path collision in repo registry"
            );
        } else if is_daemon_root(repo_root, Some(index_state_dir)) {
            registry.repos.remove(&other_fp);
        } else {
            return Err(RepoIdentityError::CanonicalPathCollision {
                canonical_path,
                other_fingerprint: other_fp,
            }
            .into());
        }
    }

    let existing_entry = registry.repos.get(&fingerprint).cloned();
    let entry = registry
        .repos
        .entry(fingerprint.clone())
        .or_insert_with(|| RepoRegistryEntry {
            state_key: state_key.clone(),
            canonical_path: canonical_path.clone(),
            prior_paths: Vec::new(),
            last_seen_at_epoch_ms: now_ms,
        });

    if entry.state_key != state_key {
        return Err(RepoIdentityError::StateKeyConflict {
            fingerprint,
            existing_state_key: entry.state_key.clone(),
            requested_state_key: state_key,
        }
        .into());
    }

    if let Some(existing) = existing_entry {
        if existing.canonical_path != canonical_path {
            if !entry
                .prior_paths
                .iter()
                .any(|path| path == &existing.canonical_path)
            {
                entry.prior_paths.push(existing.canonical_path.clone());
            }
            entry.canonical_path = canonical_path.clone();
        }
    }
    entry.last_seen_at_epoch_ms = now_ms;

    write_repo_meta(
        repo_root,
        &meta_base_dir,
        meta_state_key.as_str(),
        &fingerprint,
        &canonical_path,
        now_ms,
    )?;
    save_registry_atomic(&registry_path, &registry)?;

    Ok(())
}

pub fn validate_repo_state_dir(repo_root: &Path, index_state_dir: &Path) -> Result<()> {
    let Some((base_dir, state_key)) = base_dir_and_state_key_from_index_dir(index_state_dir) else {
        let fingerprint = repo_fingerprint_sha256(repo_root)?;
        if let Ok(default_base) = state_paths::default_state_base_dir() {
            let meta_base_dir = resolve_repo_meta_base_dir(repo_root, &default_base);
            return validate_repo_meta(
                repo_root,
                &fingerprint,
                Some(&meta_base_dir),
                Some(&fingerprint),
            );
        }
        return validate_repo_meta(repo_root, &fingerprint, None, None);
    };
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    let meta_base_dir = resolve_repo_meta_base_dir(repo_root, &base_dir);
    validate_repo_meta(
        repo_root,
        &fingerprint,
        Some(&meta_base_dir),
        Some(&state_key),
    )?;

    let canonical_path = normalize_path(repo_root);
    let registry_path = repo_registry_path(&base_dir);
    let mut registry = load_registry(&registry_path)?;
    let mut registry_updated = false;
    if let Some(entry) = registry.repos.get(&fingerprint) {
        if entry.state_key != state_key {
            return Err(RepoIdentityError::StateKeyConflict {
                fingerprint: fingerprint.clone(),
                existing_state_key: entry.state_key.clone(),
                requested_state_key: state_key,
            }
            .into());
        }
    }

    let collision_fp = registry
        .repos
        .iter()
        .find(|(fp, entry)| {
            fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_path
        })
        .map(|(fp, _)| fp.to_string());
    if let Some(other_fp) = collision_fp {
        let healed = try_auto_heal_canonical_path_collision(
            &mut registry,
            &canonical_path,
            &fingerprint,
            &meta_base_dir,
        )?;
        if healed {
            warn!(
                canonical_path,
                other_fingerprint = other_fp.as_str(),
                "auto-healed canonical path collision in repo registry"
            );
            registry_updated = true;
        } else if is_daemon_root(repo_root, Some(index_state_dir)) {
            registry.repos.remove(&other_fp);
            registry_updated = true;
        } else {
            return Err(RepoIdentityError::CanonicalPathCollision {
                canonical_path,
                other_fingerprint: other_fp,
            }
            .into());
        }
    }

    if registry_updated {
        save_registry_atomic(&registry_path, &registry)?;
    }

    Ok(())
}

pub fn reassociate_repo_path(
    repo_root: &Path,
    custom_state_dir: &Path,
    fingerprint_override: Option<&str>,
    old_path_hint: Option<&Path>,
) -> Result<RepoReassociateResult> {
    if !repo_root.exists() {
        anyhow::bail!("repo path not found: {}", repo_root.display());
    }
    if !repo_root.is_dir() {
        anyhow::bail!("repo root is not a directory: {}", repo_root.display());
    }

    let (base_dir, _, _) = split_scoped_state_dir(custom_state_dir)
        .unwrap_or_else(|| (custom_state_dir.to_path_buf(), None, false));
    let registry_path = repo_registry_path(&base_dir);
    let mut registry = load_registry(&registry_path)?;

    let canonical_new = normalize_path(repo_root);
    let computed_fingerprint = repo_fingerprint_sha256(repo_root)?;

    let target_fingerprint = if let Some(fp) = fingerprint_override {
        fp.trim().to_string()
    } else if let Some(old_path) = old_path_hint {
        let normalized_old = normalize_path(old_path);
        let matches: Vec<String> = registry
            .repos
            .iter()
            .filter_map(|(fp, entry)| {
                if entry.canonical_path == normalized_old
                    || entry.prior_paths.iter().any(|p| p == &normalized_old)
                {
                    Some(fp.clone())
                } else {
                    None
                }
            })
            .collect();
        match matches.len() {
            0 => anyhow::bail!("no registry entry matches old path `{}`", normalized_old),
            1 => matches[0].clone(),
            _ => {
                return Err(RepoIdentityError::AmbiguousOldPath {
                    old_path: normalized_old,
                    candidate_fingerprints: matches,
                }
                .into());
            }
        }
    } else {
        anyhow::bail!("missing association selector: provide --fingerprint or --old-path");
    };

    if computed_fingerprint != target_fingerprint {
        return Err(RepoIdentityError::StateMetaFingerprintMismatch {
            state_key: "<reassociate>".to_string(),
            expected_fingerprint: target_fingerprint,
            found_fingerprint: computed_fingerprint,
        }
        .into());
    }

    if let Some((other_fp, _)) = registry.repos.iter().find(|(fp, other)| {
        fp.as_str() != target_fingerprint.as_str() && other.canonical_path == canonical_new
    }) {
        return Err(RepoIdentityError::CanonicalPathCollision {
            canonical_path: canonical_new,
            other_fingerprint: other_fp.to_string(),
        }
        .into());
    }

    let entry = registry.repos.get_mut(&target_fingerprint).ok_or_else(|| {
        RepoIdentityError::UnknownFingerprint {
            fingerprint: target_fingerprint.clone(),
            registry_path: registry_path.clone(),
        }
    })?;

    let prior = if entry.canonical_path != canonical_new {
        let prior = entry.canonical_path.clone();
        if !entry.prior_paths.contains(&prior) {
            entry.prior_paths.push(prior.clone());
        }
        entry.canonical_path = canonical_new.clone();
        Some(prior)
    } else {
        None
    };
    let now_ms = chrono::Utc::now().timestamp_millis();
    entry.last_seen_at_epoch_ms = now_ms;

    let state_key = entry.state_key.clone();
    let canonical_path = entry.canonical_path.clone();

    let meta_base_dir = resolve_repo_meta_base_dir(repo_root, &base_dir);
    validate_repo_meta(
        repo_root,
        &target_fingerprint,
        Some(&meta_base_dir),
        Some(&state_key),
    )?;
    write_repo_meta(
        repo_root,
        &meta_base_dir,
        &state_key,
        &target_fingerprint,
        &canonical_path,
        now_ms,
    )?;
    save_registry_atomic(&registry_path, &registry)?;

    Ok(RepoReassociateResult {
        fingerprint: target_fingerprint,
        state_key,
        canonical_path,
        prior_canonical_path: prior,
    })
}

struct InspectStateDirResolution {
    resolved_index_dir: PathBuf,
    shared_base_dir: Option<PathBuf>,
    state_key: Option<String>,
}

fn derive_state_paths_debug(
    resolved_index_dir: &Path,
    shared_base_dir: Option<&Path>,
    state_key: Option<&str>,
    fingerprint: Option<&str>,
) -> crate::state_layout::StatePathsDebug {
    let repo_state_root = match resolved_index_dir.file_name() {
        Some(name) if name == "index" => resolved_index_dir
            .parent()
            .unwrap_or(resolved_index_dir)
            .to_path_buf(),
        _ => resolved_index_dir.to_path_buf(),
    };
    let base_dir = shared_base_dir.unwrap_or(&repo_state_root);
    let fingerprint_value = fingerprint.unwrap_or_default().to_string();
    let state_key_value = state_key
        .map(str::to_string)
        .or_else(|| {
            if fingerprint_value.is_empty() {
                None
            } else {
                Some(fingerprint_value.clone())
            }
        })
        .unwrap_or_default();
    let cache_dir = base_dir.join("cache");
    let profiles_dir = base_dir.join("profiles");
    let browser_profiles_dir = base_dir.join("browser_profiles");
    let mswarm_dir = base_dir.join("mswarm");
    crate::state_layout::StatePathsDebug {
        fingerprint: fingerprint_value,
        state_key: state_key_value,
        base_dir: base_dir.display().to_string(),
        repo_state_root: repo_state_root.display().to_string(),
        index_dir: resolved_index_dir.display().to_string(),
        libs_index_dir: repo_state_root.join("libs_index").display().to_string(),
        memory_path: repo_state_root.join("memory.db").display().to_string(),
        conversation_path: repo_state_root
            .join("conversation.db")
            .display()
            .to_string(),
        knowledge_path: repo_state_root.join("knowledge.db").display().to_string(),
        symbols_dir: repo_state_root.join("symbols.db").display().to_string(),
        dag_path: repo_state_root.join("dag.db").display().to_string(),
        cache_web_dir: cache_dir.join("web").display().to_string(),
        cache_libs_dir: cache_dir.join("libs").display().to_string(),
        profiles_dir: profiles_dir.display().to_string(),
        profiles_sync_dir: profiles_dir.join("sync").display().to_string(),
        browser_profiles_dir: browser_profiles_dir.display().to_string(),
        locks_dir: base_dir.join("locks").display().to_string(),
        logs_dir: base_dir.join("logs").display().to_string(),
        mswarm_dir: mswarm_dir.display().to_string(),
        mswarm_events_dir: mswarm_dir.join("events").display().to_string(),
        mswarm_packages_dir: mswarm_dir.join("packages").display().to_string(),
    }
}

fn resolve_state_dir_for_inspect(
    repo_root: &Path,
    state_dir_override: Option<&Path>,
) -> InspectStateDirResolution {
    match state_dir_override {
        Some(custom) if custom.is_absolute() => {
            let repo_root_canon = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            let custom_canon = custom
                .canonicalize()
                .unwrap_or_else(|_| custom.to_path_buf());
            if custom.starts_with(&repo_root_canon) || custom_canon.starts_with(&repo_root_canon) {
                return InspectStateDirResolution {
                    resolved_index_dir: custom_canon,
                    shared_base_dir: None,
                    state_key: None,
                };
            }

            let (base_dir, maybe_scoped_key, scoped_has_index) = split_scoped_state_dir(custom)
                .unwrap_or_else(|| (custom.to_path_buf(), None, false));
            let fingerprint = repo_fingerprint_sha256(repo_root).ok();
            let state_key = fingerprint.clone().and_then(|fp| {
                let registry = load_registry(&repo_registry_path(&base_dir)).ok()?;
                if let Some(entry) = registry.repos.get(&fp) {
                    return Some(entry.state_key.clone());
                }

                let preferred = shared_repo_root_dir(&base_dir, &fp).join("index");
                let legacy = legacy_repo_id_for_root(repo_root);
                let legacy_dir = shared_repo_root_dir(&base_dir, &legacy).join("index");
                if preferred.exists() {
                    Some(fp)
                } else if legacy_dir.exists() {
                    Some(legacy)
                } else {
                    Some(fp)
                }
            });

            let expected_key = state_key.clone().unwrap_or_else(|| "<unknown>".to_string());
            if let Some(scoped_key) = maybe_scoped_key {
                if scoped_key == expected_key {
                    let resolved_index_dir = if scoped_has_index {
                        custom.to_path_buf()
                    } else {
                        custom.join("index")
                    };
                    return InspectStateDirResolution {
                        resolved_index_dir,
                        shared_base_dir: Some(base_dir),
                        state_key,
                    };
                }
            }

            let resolved_index_dir = shared_repo_root_dir(&base_dir, &expected_key).join("index");
            InspectStateDirResolution {
                resolved_index_dir,
                shared_base_dir: Some(base_dir),
                state_key,
            }
        }
        Some(custom) => InspectStateDirResolution {
            resolved_index_dir: repo_root.join(custom),
            shared_base_dir: None,
            state_key: None,
        },
        None => {
            let default_dir = repo_root.join(".docdex").join("index");
            let legacy_dir = repo_root.join(".gpt-creator").join("docdex").join("index");
            if !default_dir.exists() && legacy_dir.exists() {
                InspectStateDirResolution {
                    resolved_index_dir: legacy_dir,
                    shared_base_dir: None,
                    state_key: None,
                }
            } else {
                InspectStateDirResolution {
                    resolved_index_dir: default_dir,
                    shared_base_dir: None,
                    state_key: None,
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RepoMetaOrigin {
    Scoped,
    Local,
    LegacyRoot,
}

struct RepoMetaSnapshot {
    meta: RepoStateMetaV1,
    path: PathBuf,
    origin: RepoMetaOrigin,
}

fn resolve_repo_meta_base_dir(repo_root: &Path, base_dir: &Path) -> PathBuf {
    let repo_root_canon = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let base_dir_canon = base_dir
        .canonicalize()
        .unwrap_or_else(|_| base_dir.to_path_buf());
    if base_dir_canon.starts_with(&repo_root_canon) {
        if let Ok(default_base) = state_paths::default_state_base_dir() {
            return default_base;
        }
    }
    base_dir.to_path_buf()
}

fn read_repo_meta_at(path: &Path) -> Option<RepoStateMetaV1> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn read_repo_meta_with_origin(
    repo_root: &Path,
    base_dir: Option<&Path>,
    state_key: Option<&str>,
) -> Option<RepoMetaSnapshot> {
    if let (Some(base_dir), Some(state_key)) = (base_dir, state_key) {
        let meta_base = resolve_repo_meta_base_dir(repo_root, base_dir);
        let path = repo_meta_path_for_state(&meta_base, state_key);
        if let Some(meta) = read_repo_meta_at(&path) {
            return Some(RepoMetaSnapshot {
                meta,
                path,
                origin: RepoMetaOrigin::Scoped,
            });
        }
    }

    let local_path = workspace_repo_meta_path(repo_root);
    if let Some(meta) = read_repo_meta_at(&local_path) {
        return Some(RepoMetaSnapshot {
            meta,
            path: local_path,
            origin: RepoMetaOrigin::Local,
        });
    }

    let legacy_root = legacy_root_repo_meta_path(repo_root);
    read_repo_meta_at(&legacy_root).map(|meta| RepoMetaSnapshot {
        meta,
        path: legacy_root,
        origin: RepoMetaOrigin::LegacyRoot,
    })
}

fn read_repo_meta(
    repo_root: &Path,
    base_dir: Option<&Path>,
    state_key: Option<&str>,
) -> Option<RepoStateMetaV1> {
    read_repo_meta_with_origin(repo_root, base_dir, state_key).map(|snapshot| snapshot.meta)
}

fn repo_registry_path(shared_base_dir: &Path) -> PathBuf {
    shared_base_dir.join("repos").join(REPO_REGISTRY_FILENAME)
}

fn shared_repo_root_dir(shared_base_dir: &Path, state_key: &str) -> PathBuf {
    shared_base_dir.join("repos").join(state_key)
}

fn repo_meta_path_for_state(base_dir: &Path, state_key: &str) -> PathBuf {
    base_dir
        .join("repos")
        .join(state_key)
        .join(REPO_META_FILENAME)
}

fn workspace_repo_meta_path(repo_root: &Path) -> PathBuf {
    repo_root.join(WORKSPACE_META_DIR).join(REPO_META_FILENAME)
}

fn legacy_root_repo_meta_path(repo_root: &Path) -> PathBuf {
    repo_root.join(REPO_META_FILENAME)
}

fn load_registry(path: &Path) -> Result<RepoRegistryFile> {
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RepoRegistryFile {
                version: REPO_REGISTRY_VERSION,
                repos: BTreeMap::new(),
            })
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display()))?,
    };
    let mut parsed: RepoRegistryFile =
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    if parsed.version == 0 {
        parsed.version = REPO_REGISTRY_VERSION;
    }
    Ok(parsed)
}

fn save_registry_atomic(path: &Path, registry: &RepoRegistryFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(registry).context("serialize repo registry")?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).map_err(|err| RepoIdentityError::PersistFailed {
        path: path.to_path_buf(),
        source: err,
    })?;
    Ok(())
}

fn validate_repo_meta(
    repo_root: &Path,
    expected_fingerprint: &str,
    base_dir: Option<&Path>,
    state_key: Option<&str>,
) -> Result<()> {
    let Some(snapshot) = read_repo_meta_with_origin(repo_root, base_dir, state_key) else {
        return Ok(());
    };
    if snapshot.meta.fingerprint_sha256 != expected_fingerprint {
        if snapshot.origin == RepoMetaOrigin::Local {
            let _ = fs::remove_file(&snapshot.path);
            return Ok(());
        }
        if try_auto_heal_repo_meta_mismatch(
            repo_root,
            expected_fingerprint,
            base_dir,
            state_key,
            &snapshot,
        )? {
            warn!(
                expected_fingerprint,
                found_fingerprint = snapshot.meta.fingerprint_sha256.as_str(),
                "auto-healed repo metadata fingerprint mismatch"
            );
            return Ok(());
        }
        return Err(RepoIdentityError::StateMetaFingerprintMismatch {
            state_key: state_key.unwrap_or("<repo_meta>").to_string(),
            expected_fingerprint: expected_fingerprint.to_string(),
            found_fingerprint: snapshot.meta.fingerprint_sha256,
        }
        .into());
    }
    Ok(())
}

fn try_auto_heal_repo_meta_mismatch(
    repo_root: &Path,
    expected_fingerprint: &str,
    base_dir: Option<&Path>,
    state_key: Option<&str>,
    snapshot: &RepoMetaSnapshot,
) -> Result<bool> {
    let (Some(base_dir), Some(state_key)) = (base_dir, state_key) else {
        return Ok(false);
    };

    let canonical_path = normalize_path(repo_root);
    if snapshot.meta.canonical_path != canonical_path {
        return Ok(false);
    }

    let registry_path = repo_registry_path(base_dir);
    let mut registry = load_registry(&registry_path)?;

    if let Some(existing) = registry.repos.get(expected_fingerprint) {
        if existing.state_key != state_key {
            return Err(RepoIdentityError::StateKeyConflict {
                fingerprint: expected_fingerprint.to_string(),
                existing_state_key: existing.state_key.clone(),
                requested_state_key: state_key.to_string(),
            }
            .into());
        }
    }

    if let Some((other_fp, _)) = registry.repos.iter().find(|(fp, entry)| {
        fp.as_str() != expected_fingerprint && entry.canonical_path == canonical_path
    }) {
        if other_fp.as_str() != snapshot.meta.fingerprint_sha256.as_str() {
            return Err(RepoIdentityError::CanonicalPathCollision {
                canonical_path,
                other_fingerprint: other_fp.to_string(),
            }
            .into());
        }
    }

    if snapshot.meta.fingerprint_sha256 != expected_fingerprint {
        if let Some(old_entry) = registry.repos.get(&snapshot.meta.fingerprint_sha256) {
            if old_entry.canonical_path == canonical_path || old_entry.state_key == state_key {
                registry.repos.remove(&snapshot.meta.fingerprint_sha256);
            }
        }
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    let entry = registry
        .repos
        .entry(expected_fingerprint.to_string())
        .or_insert_with(|| RepoRegistryEntry {
            state_key: state_key.to_string(),
            canonical_path: canonical_path.clone(),
            prior_paths: Vec::new(),
            last_seen_at_epoch_ms: now_ms,
        });
    if entry.state_key != state_key {
        return Err(RepoIdentityError::StateKeyConflict {
            fingerprint: expected_fingerprint.to_string(),
            existing_state_key: entry.state_key.clone(),
            requested_state_key: state_key.to_string(),
        }
        .into());
    }
    if entry.canonical_path != canonical_path {
        if !entry.prior_paths.contains(&entry.canonical_path) {
            entry.prior_paths.push(entry.canonical_path.clone());
        }
        entry.canonical_path = canonical_path.clone();
    }
    entry.last_seen_at_epoch_ms = now_ms;

    save_registry_atomic(&registry_path, &registry)?;
    write_repo_meta(
        repo_root,
        base_dir,
        state_key,
        expected_fingerprint,
        &canonical_path,
        now_ms,
    )?;
    Ok(true)
}

fn canonical_path_in_use(
    registry: &RepoRegistryFile,
    canonical_path: &str,
    exclude_fingerprint: &str,
) -> bool {
    registry.repos.iter().any(|(fp, entry)| {
        fp.as_str() != exclude_fingerprint && entry.canonical_path == canonical_path
    })
}

fn repo_meta_canonical_path(meta_base_dir: &Path, state_key: &str) -> Option<String> {
    let path = repo_meta_path_for_state(meta_base_dir, state_key);
    read_repo_meta_at(&path).map(|meta| meta.canonical_path)
}

fn try_auto_heal_canonical_path_collision(
    registry: &mut RepoRegistryFile,
    canonical_path: &str,
    expected_fingerprint: &str,
    meta_base_dir: &Path,
) -> Result<bool> {
    let Some((other_fp, other_entry)) = registry
        .repos
        .iter()
        .find(|(fp, entry)| {
            fp.as_str() != expected_fingerprint && entry.canonical_path == canonical_path
        })
        .map(|(fp, entry)| (fp.clone(), entry.clone()))
    else {
        return Ok(false);
    };

    let mut replacement = repo_meta_canonical_path(meta_base_dir, &other_entry.state_key)
        .filter(|candidate| candidate != canonical_path)
        .filter(|candidate| !canonical_path_in_use(registry, candidate, &other_fp));

    if replacement.is_none() {
        replacement = other_entry
            .prior_paths
            .iter()
            .rev()
            .find(|candidate| {
                *candidate != canonical_path
                    && !canonical_path_in_use(registry, candidate, &other_fp)
            })
            .cloned();
    }

    if let Some(replacement_path) = replacement {
        if let Some(entry) = registry.repos.get_mut(&other_fp) {
            if !entry.prior_paths.contains(&entry.canonical_path) {
                entry.prior_paths.push(entry.canonical_path.clone());
            }
            entry.canonical_path = replacement_path;
        }
        return Ok(true);
    }

    registry.repos.remove(&other_fp);
    Ok(true)
}

fn write_repo_meta(
    repo_root: &Path,
    base_dir: &Path,
    state_key: &str,
    fingerprint: &str,
    canonical_path: &str,
    now_ms: i64,
) -> Result<()> {
    let meta_base = resolve_repo_meta_base_dir(repo_root, base_dir);
    let path = repo_meta_path_for_state(&meta_base, state_key);
    let existing = read_repo_meta_with_origin(repo_root, Some(&meta_base), Some(state_key));
    let mut created_at = now_ms;
    if let Some(existing) = existing.as_ref() {
        if existing.meta.version == REPO_META_VERSION
            && existing.meta.fingerprint_sha256 == fingerprint
        {
            created_at = existing.meta.created_at_epoch_ms.max(1);
        }
    }

    let payload = RepoStateMetaV1 {
        version: REPO_META_VERSION,
        fingerprint_sha256: fingerprint.to_string(),
        canonical_path: canonical_path.to_string(),
        created_at_epoch_ms: created_at,
        last_seen_at_epoch_ms: now_ms,
    };
    let bytes = serde_json::to_vec_pretty(&payload).context("serialize repo meta")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    if let Some(existing) = existing {
        if existing.origin == RepoMetaOrigin::LegacyRoot {
            let _ = fs::remove_file(&existing.path);
        }
    }
    if let Err(err) = ensure_workspace_repo_meta(repo_root, fingerprint, canonical_path, now_ms) {
        warn!(error = ?err, "failed to persist workspace repo metadata");
    }
    Ok(())
}

fn ensure_workspace_repo_meta(
    repo_root: &Path,
    fingerprint: &str,
    canonical_path: &str,
    now_ms: i64,
) -> Result<()> {
    let path = workspace_repo_meta_path(repo_root);
    let existing = read_repo_meta_at(&path);
    let mut created_at = now_ms;
    if let Some(existing) = existing.as_ref() {
        if existing.version == REPO_META_VERSION && existing.fingerprint_sha256 == fingerprint {
            created_at = existing.created_at_epoch_ms.max(1);
        }
    }

    let payload = RepoStateMetaV1 {
        version: REPO_META_VERSION,
        fingerprint_sha256: fingerprint.to_string(),
        canonical_path: canonical_path.to_string(),
        created_at_epoch_ms: created_at,
        last_seen_at_epoch_ms: now_ms,
    };
    let bytes = serde_json::to_vec_pretty(&payload).context("serialize workspace repo meta")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;

    ensure_git_exclude(repo_root)?;
    Ok(())
}

fn ensure_git_exclude(repo_root: &Path) -> Result<()> {
    ensure_gitignore(repo_root)?;
    let Some(git_dir) = git_dir_for_repo(repo_root) else {
        return Ok(());
    };
    if !git_dir.is_dir() || !git_dir.join("HEAD").exists() {
        return Ok(());
    }
    let exclude_path = git_dir.join("info").join("exclude");
    let existing = fs::read_to_string(&exclude_path).unwrap_or_default();
    let has_docdex = existing.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == ".docdex"
            || trimmed == ".docdex/"
            || trimmed == "/.docdex/"
            || trimmed == "/.docdex"
    });
    let has_docdex_state = existing.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == ".docdex-state"
            || trimmed == ".docdex-state/"
            || trimmed == "/.docdex-state/"
            || trimmed == "/.docdex-state"
    });
    if has_docdex && has_docdex_state {
        return Ok(());
    }
    if let Some(parent) = exclude_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&exclude_path)
        .with_context(|| format!("open {}", exclude_path.display()))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        file.write_all(b"\n")
            .with_context(|| format!("write {}", exclude_path.display()))?;
    }
    if !has_docdex {
        writeln!(file, "/.docdex/").with_context(|| format!("write {}", exclude_path.display()))?;
    }
    if !has_docdex_state {
        writeln!(file, "/.docdex-state/")
            .with_context(|| format!("write {}", exclude_path.display()))?;
    }
    Ok(())
}

fn ensure_gitignore(repo_root: &Path) -> Result<()> {
    let ignore_path = repo_root.join(".gitignore");
    let existing = fs::read_to_string(&ignore_path).unwrap_or_default();
    let has_docdex = existing.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == ".docdex"
            || trimmed == ".docdex/"
            || trimmed == "/.docdex/"
            || trimmed == "/.docdex"
    });
    let has_docdex_state = existing.lines().any(|line| {
        let trimmed = line.trim();
        trimmed == ".docdex-state"
            || trimmed == ".docdex-state/"
            || trimmed == "/.docdex-state/"
            || trimmed == "/.docdex-state"
    });
    if has_docdex && has_docdex_state {
        return Ok(());
    }
    if let Some(parent) = ignore_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&ignore_path)
        .with_context(|| format!("open {}", ignore_path.display()))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        file.write_all(b"\n")
            .with_context(|| format!("write {}", ignore_path.display()))?;
    }
    if !has_docdex {
        writeln!(file, "/.docdex/").with_context(|| format!("write {}", ignore_path.display()))?;
    }
    if !has_docdex_state {
        writeln!(file, "/.docdex-state/")
            .with_context(|| format!("write {}", ignore_path.display()))?;
    }
    Ok(())
}

fn is_daemon_root(repo_root: &Path, index_state_dir: Option<&Path>) -> bool {
    let normalized_root = normalize_path(repo_root);
    let mut candidates = Vec::new();
    if let Some(index_state_dir) = index_state_dir {
        if let Some((base_dir, _)) = base_dir_and_state_key_from_index_dir(index_state_dir) {
            if let Ok(daemon_root) = state_paths::daemon_root_dir_from_state_base(&base_dir) {
                candidates.push(daemon_root);
            }
        }
    }
    if candidates.is_empty() {
        if let Ok(base_dir) = state_paths::default_state_base_dir() {
            if let Ok(daemon_root) = state_paths::daemon_root_dir_from_state_base(&base_dir) {
                candidates.push(daemon_root);
            }
        }
    }
    candidates
        .into_iter()
        .any(|candidate| normalize_path(&candidate) == normalized_root)
}

fn base_dir_and_state_key_from_index_dir(index_state_dir: &Path) -> Option<(PathBuf, String)> {
    if index_state_dir.file_name().and_then(|s| s.to_str())? != "index" {
        return None;
    }
    let state_key_dir = index_state_dir.parent()?;
    let state_key = state_key_dir.file_name()?.to_string_lossy().to_string();
    let repos_dir = state_key_dir.parent()?;
    if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
        return None;
    }
    let base_dir = repos_dir.parent()?.to_path_buf();
    Some((base_dir, state_key))
}

pub fn resolve_shared_state_key_lenient(
    repo_root: &Path,
    shared_base_dir: &Path,
) -> Result<RepoStateKeyResolution> {
    resolve_shared_state_key(repo_root, shared_base_dir)
}

pub fn split_scoped_state_dir(custom_state_dir: &Path) -> Option<(PathBuf, Option<String>, bool)> {
    let name = custom_state_dir.file_name()?.to_string_lossy();
    if name == "index" {
        let state_key_dir = custom_state_dir.parent()?;
        let state_key = state_key_dir.file_name()?.to_string_lossy().to_string();
        let repos_dir = state_key_dir.parent()?;
        if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
            return None;
        }
        let base_dir = repos_dir.parent()?.to_path_buf();
        return Some((base_dir, Some(state_key), true));
    }

    let state_key = name.to_string();
    let repos_dir = custom_state_dir.parent()?;
    if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
        return None;
    }
    let base_dir = repos_dir.parent()?.to_path_buf();
    Some((base_dir, Some(state_key), false))
}

// --- LRU Logic ---

#[derive(Debug)]
pub struct RepoHandle {
    pub repo_id: String,
    pub generation: u64,
}

impl RepoHandle {
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

pub struct RepoHandleManager {
    repos: HashMap<String, RepoEntry>,
    tick: u64,
    next_generation: u64,
    max_open: usize,
}

struct RepoEntry {
    in_flight: usize,
    last_access: u64,
    generation: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RepoOpenError {
    #[error("repo capacity exceeded (max: {max_open}, in_flight: {in_flight:?})")]
    CapExceeded {
        max_open: usize,
        in_flight: Vec<String>,
    },
}

impl RepoHandleManager {
    pub fn new(max_open: usize) -> Self {
        Self {
            repos: HashMap::new(),
            tick: 0,
            next_generation: 1,
            max_open: max_open.max(1),
        }
    }

    pub fn open_count(&self) -> usize {
        self.repos.len()
    }

    pub fn is_open(&self, repo_id: &str) -> bool {
        self.repos.contains_key(repo_id)
    }

    pub fn acquire(&mut self, repo_id: &str) -> Result<RepoHandle, RepoOpenError> {
        self.tick = self.tick.wrapping_add(1);

        if let Some(entry) = self.repos.get_mut(repo_id) {
            entry.in_flight += 1;
            entry.last_access = self.tick;
            return Ok(RepoHandle {
                repo_id: repo_id.to_string(),
                generation: entry.generation,
            });
        }

        if self.repos.len() >= self.max_open {
            if !self.evict_one() {
                return Err(RepoOpenError::CapExceeded {
                    max_open: self.max_open,
                    in_flight: self.in_flight_repos(),
                });
            }
        }

        self.next_generation = self.next_generation.wrapping_add(1);
        self.repos.insert(
            repo_id.to_string(),
            RepoEntry {
                in_flight: 1,
                last_access: self.tick,
                generation: self.next_generation,
            },
        );

        Ok(RepoHandle {
            repo_id: repo_id.to_string(),
            generation: self.next_generation,
        })
    }

    pub fn release(&mut self, repo_id: &str) {
        if let Some(entry) = self.repos.get_mut(repo_id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
        }
    }

    fn in_flight_repos(&self) -> Vec<String> {
        let mut repos: Vec<String> = self
            .repos
            .iter()
            .filter_map(|(repo_id, entry)| {
                if entry.in_flight > 0 {
                    Some(repo_id.clone())
                } else {
                    None
                }
            })
            .collect();
        repos.sort();
        repos
    }

    fn evict_one(&mut self) -> bool {
        let candidate = self
            .repos
            .iter()
            .filter(|(_, entry)| entry.in_flight == 0)
            .min_by(
                |(id_a, a), (id_b, b)| match a.last_access.cmp(&b.last_access) {
                    Ordering::Equal => id_a.cmp(id_b),
                    other => other,
                },
            )
            .map(|(repo_id, _)| repo_id.clone());

        if let Some(repo_id) = candidate {
            self.repos.remove(&repo_id);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_and_release(manager: &mut RepoHandleManager, repo_id: &str) -> RepoHandle {
        let handle = manager.acquire(repo_id).expect("acquire repo");
        manager.release(repo_id);
        handle
    }

    #[test]
    fn lru_eviction_respects_access_order() {
        let mut manager = RepoHandleManager::new(2);

        open_and_release(&mut manager, "repo-a");
        open_and_release(&mut manager, "repo-b");
        open_and_release(&mut manager, "repo-a");

        assert_eq!(manager.open_count(), 2);
        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-b"));

        manager
            .acquire("repo-c")
            .expect("acquire repo-c after eviction");
        manager.release("repo-c");

        assert_eq!(manager.open_count(), 2);
        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-c"));
        assert!(!manager.is_open("repo-b"));
    }

    #[test]
    fn eviction_skips_inflight_repos() {
        let mut manager = RepoHandleManager::new(2);

        manager.acquire("repo-a").expect("acquire repo-a");
        manager.acquire("repo-b").expect("acquire repo-b");
        manager.release("repo-b");

        manager
            .acquire("repo-c")
            .expect("acquire repo-c with inflight repo-a");
        manager.release("repo-c");

        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-c"));
        assert!(!manager.is_open("repo-b"));
        assert_eq!(
            manager.repos.get("repo-a").map(|entry| entry.in_flight),
            Some(1)
        );
        manager.release("repo-a");
    }

    #[test]
    fn cap_blocked_when_all_repos_inflight() {
        let mut manager = RepoHandleManager::new(2);

        manager.acquire("repo-a").expect("acquire repo-a");
        manager.acquire("repo-b").expect("acquire repo-b");

        let err = manager.acquire("repo-c").expect_err("cap should block");
        match err {
            RepoOpenError::CapExceeded {
                max_open,
                in_flight,
            } => {
                assert_eq!(max_open, 2);
                assert_eq!(in_flight, vec!["repo-a".to_string(), "repo-b".to_string()]);
            }
        }

        assert_eq!(manager.open_count(), 2);
        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-b"));
    }

    #[test]
    fn reopen_after_eviction_refreshes_generation() {
        let mut manager = RepoHandleManager::new(1);

        let first = open_and_release(&mut manager, "repo-a");
        open_and_release(&mut manager, "repo-b");

        let reopened = manager.acquire("repo-a").expect("reopen repo-a");
        assert_ne!(first.generation(), reopened.generation());
        manager.release("repo-a");

        assert_eq!(manager.open_count(), 1);
        assert!(manager.is_open("repo-a"));
    }
}
