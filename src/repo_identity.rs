use anyhow::{Context, Result};
use crate::error::{repo_resolution_details, AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_REPO_PATH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use crate::state_paths::{default_state_base_dir, StatePaths};

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
    #[error("cannot re-associate: fingerprint `{fingerprint}` not found in registry at {registry_path}")]
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
    #[serde(default = "default_fingerprint_version")]
    fingerprint_version: u32,
    canonical_path: String,
    #[serde(default)]
    created_at_epoch_ms: i64,
    #[serde(default)]
    last_seen_at_epoch_ms: i64,
}

const REPO_REGISTRY_VERSION: u32 = 1;
const REPO_META_VERSION: u32 = 1;
<<<<<<< HEAD
=======
const FINGERPRINT_VERSION: u32 = 1;
const REPO_REGISTRY_FILENAME: &str = "repo_registry.json";
const REPO_META_FILENAME: &str = "repo_meta.json";
>>>>>>> mcoda/task/ops-01-us-03-t03

fn default_fingerprint_version() -> u32 {
    FINGERPRINT_VERSION
}

pub fn legacy_repo_id_for_root(repo_root: &Path) -> String {
    let normalized = normalize_path(repo_root);
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn repo_fingerprint_sha256(repo_root: &Path) -> Result<String> {
    let target = git_identity_target(repo_root);
    let payload = file_identity_payload(&target).with_context(|| {
        format!(
            "read filesystem identity for {}",
            target.to_string_lossy()
        )
    })?;
    Ok(hex::encode(Sha256::digest(payload.as_bytes())))
}

pub fn inspect_repo(repo_root: &Path, state_dir_override: Option<&Path>) -> Result<RepoInspectReport> {
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
    let mut report = RepoInspectReport {
        repo_root: repo_root_str,
        normalized_path,
        computed_fingerprint: computed_fingerprint.clone(),
        resolved_index_state_dir: resolved.resolved_index_dir.display().to_string(),
        shared_state_base_dir: resolved.shared_base_dir.as_ref().map(|p| p.display().to_string()),
        state_key: resolved.state_key.clone(),
        mapping: None,
        status: RepoInspectStatus::LocalStateDir,
        diagnostics: None,
    };

    let Some(shared_base_dir) = resolved.shared_base_dir else {
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

    let registry_path = repo_registry_path(&shared_base_dir);
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
            message: "canonical path is already associated with a different fingerprint".to_string(),
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
                message: "repo fingerprint is registered for a different canonical path".to_string(),
                details: Some(serde_json::json!({
                    "fingerprint": fingerprint,
                    "registeredCanonicalPath": mapping.canonical_path,
                    "requestedCanonicalPath": canonical_new,
                })),
            });
            return Ok(report);
        }
    }

    if let Some(state_key) = report.state_key.as_deref() {
        if let Some(meta) = read_repo_meta(&shared_base_dir, state_key) {
            if meta.fingerprint_sha256 != fingerprint {
                report.status = RepoInspectStatus::RepoStateMismatch;
                report.diagnostics = Some(RepoInspectDiagnostics {
                    code: "state_meta_fingerprint_mismatch",
                    message: "repo state metadata fingerprint mismatch".to_string(),
                    details: Some(serde_json::json!({
                        "stateKey": state_key,
                        "expectedFingerprint": fingerprint,
                        "foundFingerprint": meta.fingerprint_sha256,
                        "metaCanonicalPath": meta.canonical_path,
                    })),
                });
                return Ok(report);
            }
        }
    }

    report.status = if report.mapping.is_some() {
        RepoInspectStatus::Ok
    } else {
        RepoInspectStatus::Unmapped
    };
    Ok(report)
}

pub fn resolve_shared_state_key(repo_root: &Path, shared_base_dir: &Path) -> Result<RepoStateKeyResolution> {
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
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
    validate_state_meta(shared_base_dir, &state_key, &fingerprint)?;

    Ok(RepoStateKeyResolution {
        state_key,
    })
}

pub fn resolve_shared_index_state_dir(repo_root: &Path, custom_state_dir: &Path) -> Result<PathBuf> {
    let (base_dir, maybe_scoped_key, scoped_has_index) =
        split_scoped_state_dir(custom_state_dir).unwrap_or_else(|| (custom_state_dir.to_path_buf(), None, false));

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
    let Some((base_dir, state_key)) = base_dir_and_state_key_from_index_dir(index_state_dir) else {
        return Ok(());
    };

    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    validate_state_meta(&base_dir, &state_key, &fingerprint)?;

    let canonical_path = normalize_path(repo_root);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let registry_path = repo_registry_path(&base_dir);
    fs::create_dir_all(registry_path.parent().expect("registry parent"))
        .with_context(|| format!("create {}", registry_path.parent().unwrap().display()))?;

    let mut registry = load_registry(&registry_path)?;

    if let Some((other_fp, _)) = registry
        .repos
        .iter()
        .find(|(fp, entry)| fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_path)
    {
        return Err(RepoIdentityError::CanonicalPathCollision {
            canonical_path,
            other_fingerprint: other_fp.to_string(),
        }
        .into());
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
            return Err(RepoIdentityError::ReassociationRequired {
                fingerprint,
                state_key: existing.state_key,
                registered_canonical_path: existing.canonical_path,
                requested_canonical_path: canonical_path,
            }
            .into());
        }
    }
    entry.last_seen_at_epoch_ms = now_ms;

    write_repo_meta(&base_dir, &entry.state_key, &fingerprint, &canonical_path, now_ms)?;
    save_registry_atomic(&registry_path, &registry)?;

    Ok(())
}

pub fn validate_repo_state_dir(repo_root: &Path, index_state_dir: &Path) -> Result<()> {
    let Some((base_dir, state_key)) = base_dir_and_state_key_from_index_dir(index_state_dir) else {
        return Ok(());
    };
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    validate_state_meta(&base_dir, &state_key, &fingerprint)?;

    let canonical_path = normalize_path(repo_root);
    let registry_path = repo_registry_path(&base_dir);
    let registry = load_registry(&registry_path)?;
    if let Some(entry) = registry.repos.get(&fingerprint) {
        if entry.state_key != state_key {
            return Err(RepoIdentityError::StateKeyConflict {
                fingerprint: fingerprint.clone(),
                existing_state_key: entry.state_key.clone(),
                requested_state_key: state_key,
            }
            .into());
        }
        if entry.canonical_path != canonical_path {
            return Err(RepoIdentityError::ReassociationRequired {
                fingerprint: fingerprint.clone(),
                state_key: entry.state_key.clone(),
                registered_canonical_path: entry.canonical_path.clone(),
                requested_canonical_path: canonical_path.clone(),
            }
            .into());
        }
    }

    if let Some((other_fp, _)) = registry
        .repos
        .iter()
        .find(|(fp, entry)| fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_path)
    {
        return Err(RepoIdentityError::CanonicalPathCollision {
            canonical_path,
            other_fingerprint: other_fp.to_string(),
        }
        .into());
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

    let (base_dir, _, _) =
        split_scoped_state_dir(custom_state_dir).unwrap_or_else(|| (custom_state_dir.to_path_buf(), None, false));
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
                if entry.canonical_path == normalized_old || entry.prior_paths.iter().any(|p| p == &normalized_old) {
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

    if let Some((other_fp, _)) = registry
        .repos
        .iter()
        .find(|(fp, other)| fp.as_str() != target_fingerprint.as_str() && other.canonical_path == canonical_new)
    {
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

    validate_state_meta(&base_dir, &state_key, &target_fingerprint)?;
    write_repo_meta(
        &base_dir,
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

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

struct InspectStateDirResolution {
    resolved_index_dir: PathBuf,
    shared_base_dir: Option<PathBuf>,
    state_key: Option<String>,
}

fn resolve_state_dir_for_inspect(repo_root: &Path, state_dir_override: Option<&Path>) -> InspectStateDirResolution {
    match state_dir_override {
        Some(custom) if custom.is_absolute() => {
            let repo_root_canon = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            if custom.starts_with(&repo_root_canon) {
                return InspectStateDirResolution {
                    resolved_index_dir: custom.to_path_buf(),
                    shared_base_dir: None,
                    state_key: None,
                };
            }

            let (base_dir, maybe_scoped_key, scoped_has_index) =
                split_scoped_state_dir(custom).unwrap_or_else(|| (custom.to_path_buf(), None, false));
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
            let Ok(base_dir) = default_state_base_dir() else {
                return InspectStateDirResolution {
                    resolved_index_dir: repo_root.join(".docdex").join("index"),
                    shared_base_dir: None,
                    state_key: None,
                };
            };
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
            let resolved_index_dir = StatePaths::new(base_dir.clone()).repo_index_dir(&expected_key);
            InspectStateDirResolution {
                resolved_index_dir,
                shared_base_dir: Some(base_dir),
                state_key,
            }
        }
    }
}

fn read_repo_meta(shared_base_dir: &Path, state_key: &str) -> Option<RepoStateMetaV1> {
    let path = repo_meta_path(shared_base_dir, state_key);
    let raw = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn repo_registry_path(shared_base_dir: &Path) -> PathBuf {
    StatePaths::new(shared_base_dir.to_path_buf()).repo_registry_path()
}

fn shared_repo_root_dir(shared_base_dir: &Path, state_key: &str) -> PathBuf {
    StatePaths::new(shared_base_dir.to_path_buf()).repo_root(state_key)
}

fn repo_meta_path(shared_base_dir: &Path, state_key: &str) -> PathBuf {
    StatePaths::new(shared_base_dir.to_path_buf()).repo_meta_path(state_key)
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
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let mut parsed: RepoRegistryFile = serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
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

fn validate_state_meta(shared_base_dir: &Path, state_key: &str, expected_fingerprint: &str) -> Result<()> {
    let path = repo_meta_path(shared_base_dir, state_key);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let parsed: RepoStateMetaV1 = serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    if parsed.fingerprint_sha256 != expected_fingerprint {
        return Err(RepoIdentityError::StateMetaFingerprintMismatch {
            state_key: state_key.to_string(),
            expected_fingerprint: expected_fingerprint.to_string(),
            found_fingerprint: parsed.fingerprint_sha256,
        }
        .into());
    }
    Ok(())
}

fn write_repo_meta(
    shared_base_dir: &Path,
    state_key: &str,
    fingerprint: &str,
    canonical_path: &str,
    now_ms: i64,
) -> Result<()> {
    let path = repo_meta_path(shared_base_dir, state_key);
    fs::create_dir_all(
        path.parent()
            .expect("repo meta parent"),
    )
    .with_context(|| format!("create {}", path.parent().unwrap().display()))?;

    let mut created_at = now_ms;
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(existing) = serde_json::from_str::<RepoStateMetaV1>(&raw) {
            if existing.version == REPO_META_VERSION && existing.fingerprint_sha256 == fingerprint {
                created_at = existing.created_at_epoch_ms.max(1);
            }
        }
    }

    let payload = RepoStateMetaV1 {
        version: REPO_META_VERSION,
        fingerprint_sha256: fingerprint.to_string(),
        fingerprint_version: FINGERPRINT_VERSION,
        canonical_path: canonical_path.to_string(),
        created_at_epoch_ms: created_at,
        last_seen_at_epoch_ms: now_ms,
    };
    let bytes = serde_json::to_vec_pretty(&payload).context("serialize repo meta")?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(&tmp, &path).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
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

pub(crate) fn split_scoped_state_dir(custom_state_dir: &Path) -> Option<(PathBuf, Option<String>, bool)> {
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

fn git_identity_target(repo_root: &Path) -> PathBuf {
    let dot_git = repo_root.join(".git");
    let Ok(meta) = fs::metadata(&dot_git) else {
        return repo_root.to_path_buf();
    };
    if meta.is_dir() {
        return dot_git;
    }
    if !meta.is_file() {
        return repo_root.to_path_buf();
    }
    let Ok(contents) = fs::read_to_string(&dot_git) else {
        return repo_root.to_path_buf();
    };
    let line = contents.lines().next().unwrap_or_default().trim();
    let Some(rest) = line.strip_prefix("gitdir:") else {
        return repo_root.to_path_buf();
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return repo_root.to_path_buf();
    }
    let candidate = PathBuf::from(rest);
    if candidate.is_absolute() {
        return candidate;
    }
    repo_root.join(candidate)
}

fn file_identity_payload(path: &Path) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(format!(
            "v{}|unix|dev={}|ino={}|is_dir={}",
            FINGERPRINT_VERSION,
            meta.dev(),
            meta.ino(),
            meta.is_dir()
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let vsn = meta.volume_serial_number().unwrap_or(0);
        let file_index = meta.file_index().unwrap_or(0);
        return Ok(format!(
            "v{}|windows|volume_serial_number={vsn}|file_index={file_index}|is_dir={}",
            FINGERPRINT_VERSION,
            meta.is_dir()
        ));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let normalized = normalize_path(path);
        Ok(format!("v{}|path|{}", FINGERPRINT_VERSION, normalized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_git_repo(dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        fs::create_dir_all(dir.join(".git"))?;
        fs::write(dir.join("readme.md"), "# Repo\n")?;
        Ok(())
    }

    #[test]
    fn fingerprint_deterministic_for_same_repo() -> Result<()> {
        let base = TempDir::new()?;
        let repo = base.path().join("repo");
        create_git_repo(&repo)?;

        let first = repo_fingerprint_sha256(&repo)?;
        let second = repo_fingerprint_sha256(&repo)?;
        assert_eq!(first, second);
        Ok(())
    }

    #[test]
    fn fingerprint_differs_for_distinct_repos() -> Result<()> {
        let base = TempDir::new()?;
        let repo_a = base.path().join("repo-a");
        let repo_b = base.path().join("repo-b");
        create_git_repo(&repo_a)?;
        create_git_repo(&repo_b)?;

        let fp_a = repo_fingerprint_sha256(&repo_a)?;
        let fp_b = repo_fingerprint_sha256(&repo_b)?;
        assert_ne!(fp_a, fp_b);
        Ok(())
    }

    #[test]
    fn fingerprint_stable_across_rename_when_git_dir_preserved() -> Result<()> {
        let base = TempDir::new()?;
        let repo_a = base.path().join("repo-a");
        let repo_b = base.path().join("repo-b");
        create_git_repo(&repo_a)?;

        let fp1 = repo_fingerprint_sha256(&repo_a)?;
        fs::rename(&repo_a, &repo_b)?;
        let fp2 = repo_fingerprint_sha256(&repo_b)?;
        assert_eq!(fp1, fp2);
        Ok(())
    }

    #[test]
    fn registry_updates_canonical_path_and_keeps_state_key() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(StatePaths::new(shared.clone()).repos_dir())?;

        let repo_root = base.path().join("repo-a");
        create_git_repo(&repo_root)?;
        let fingerprint = repo_fingerprint_sha256(&repo_root)?;

        let resolution = resolve_shared_state_key(&repo_root, &shared)?;
        let state_key = resolution.state_key.clone();
        fs::create_dir_all(shared_repo_root_dir(&shared, &state_key).join("index"))?;

        record_repo_opened(&repo_root, &shared_repo_root_dir(&shared, &state_key).join("index"))?;
        let registry = load_registry(&repo_registry_path(&shared))?;
        assert!(registry.repos.contains_key(&fingerprint));
        assert_eq!(
            registry.repos.get(&fingerprint).unwrap().state_key,
            state_key
        );

        let moved = base.path().join("repo-moved");
        fs::rename(&repo_root, &moved)?;
        let err = record_repo_opened(&moved, &shared_repo_root_dir(&shared, &state_key).join("index"))
            .unwrap_err();
        assert!(
            matches!(
                err.downcast_ref::<RepoIdentityError>(),
                Some(RepoIdentityError::ReassociationRequired { .. })
            ),
            "expected ReassociationRequired; got: {err}"
        );

        let reassociated =
            reassociate_repo_path(&moved, &shared, Some(fingerprint.as_str()), None)?;
        assert_eq!(reassociated.fingerprint, fingerprint);
        assert_eq!(reassociated.state_key, state_key);
        assert_eq!(reassociated.canonical_path, normalize_path(&moved));

        record_repo_opened(&moved, &shared_repo_root_dir(&shared, &state_key).join("index"))?;
        let registry2 = load_registry(&repo_registry_path(&shared))?;
        let entry = registry2.repos.get(&fingerprint).unwrap();
        assert_eq!(entry.state_key, state_key);
        assert_eq!(entry.canonical_path, normalize_path(&moved));
        assert!(!entry.prior_paths.is_empty());
        Ok(())
    }

    #[test]
    fn canonical_path_collision_is_rejected() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(StatePaths::new(shared.clone()).repos_dir())?;

        let repo_a = base.path().join("repo-a");
        let repo_b = base.path().join("repo-b");
        create_git_repo(&repo_a)?;
        create_git_repo(&repo_b)?;
        let fp_a = repo_fingerprint_sha256(&repo_a)?;

        let res_a = resolve_shared_state_key(&repo_a, &shared)?;
        let res_b = resolve_shared_state_key(&repo_b, &shared)?;

        let state_a = shared_repo_root_dir(&shared, &res_a.state_key).join("index");
        let state_b = shared_repo_root_dir(&shared, &res_b.state_key).join("index");
        fs::create_dir_all(&state_a)?;
        fs::create_dir_all(&state_b)?;

        record_repo_opened(&repo_a, &state_a)?;

        // Force collision by corrupting repo A's registry entry to claim repo B's canonical path.
        let mut registry = load_registry(&repo_registry_path(&shared))?;
        let entry_a = registry
            .repos
            .get_mut(&fp_a)
            .expect("repo A entry");
        entry_a.canonical_path = normalize_path(&repo_b);
        save_registry_atomic(&repo_registry_path(&shared), &registry)?;

        let err = record_repo_opened(&repo_b, &state_b).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("canonical path") && msg.contains("already associated"),
            "unexpected error: {msg}"
        );
        Ok(())
    }

    #[test]
    fn inspect_reports_reassociation_required_after_repo_move() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(StatePaths::new(shared.clone()).repos_dir())?;

        let repo_root = base.path().join("repo-a");
        create_git_repo(&repo_root)?;
        let fingerprint = repo_fingerprint_sha256(&repo_root)?;
        let resolution = resolve_shared_state_key(&repo_root, &shared)?;
        let state_key = resolution.state_key.clone();
        fs::create_dir_all(shared_repo_root_dir(&shared, &state_key).join("index"))?;
        record_repo_opened(&repo_root, &shared_repo_root_dir(&shared, &state_key).join("index"))?;

        let moved = base.path().join("repo-moved");
        fs::rename(&repo_root, &moved)?;

        let report = inspect_repo(&moved, Some(shared.as_path()))?;
        assert_eq!(report.computed_fingerprint.as_deref(), Some(fingerprint.as_str()));
        assert!(matches!(report.status, RepoInspectStatus::ReassociationRequired));
        let mapping = report.mapping.expect("mapping");
        assert_ne!(mapping.canonical_path, report.normalized_path);
        Ok(())
    }

    #[test]
    fn inspect_missing_path_returns_app_error() {
        let base = tempfile::TempDir::new().expect("tempdir");
        let missing = base.path().join("missing-repo");
        let err = inspect_repo(&missing, None).unwrap_err();
        let app = err
            .downcast_ref::<AppError>()
            .expect("expected AppError");
        assert_eq!(app.code, ERR_MISSING_REPO_PATH);
    }

    #[test]
    fn inspect_serializes_expected_top_level_fields() -> Result<()> {
        let base = TempDir::new()?;
        let repo_root = base.path().join("repo");
        create_git_repo(&repo_root)?;

        let report = inspect_repo(&repo_root, None)?;
        let value = serde_json::to_value(&report)?;
        let obj = value.as_object().expect("object");
        for key in [
            "repoRoot",
            "normalizedPath",
            "computedFingerprint",
            "resolvedIndexStateDir",
            "status",
        ] {
            assert!(obj.contains_key(key), "missing key: {key}");
        }
        Ok(())
    }

    #[test]
    fn inspect_includes_shared_mapping_and_last_seen() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(StatePaths::new(shared.clone()).repos_dir())?;

        let repo_root = base.path().join("repo-a");
        create_git_repo(&repo_root)?;
        let fingerprint = repo_fingerprint_sha256(&repo_root)?;
        let resolution = resolve_shared_state_key(&repo_root, &shared)?;
        let state_key = resolution.state_key.clone();
        let state_index = shared_repo_root_dir(&shared, &state_key).join("index");
        fs::create_dir_all(&state_index)?;

        record_repo_opened(&repo_root, &state_index)?;

        let report = inspect_repo(&repo_root, Some(shared.as_path()))?;
        assert!(matches!(report.status, RepoInspectStatus::Ok));
        assert_eq!(report.computed_fingerprint.as_deref(), Some(fingerprint.as_str()));
        let mapping = report.mapping.as_ref().expect("mapping");
        assert_eq!(mapping.fingerprint, fingerprint);
        assert_eq!(mapping.state_key, state_key);
        assert_eq!(mapping.canonical_path, report.normalized_path);
        assert!(mapping.last_seen_at_epoch_ms > 0);

        let value = serde_json::to_value(&report)?;
        let obj = value.as_object().expect("object");
        let mapping_obj = obj
            .get("mapping")
            .and_then(|v| v.as_object())
            .expect("mapping object");
        for key in ["fingerprint", "stateKey", "canonicalPath", "aliases", "lastSeen"] {
            assert!(mapping_obj.contains_key(key), "missing mapping key: {key}");
        }
        assert!(mapping_obj.contains_key("lastSeenAtEpochMs"));
        Ok(())
    }

    #[test]
    fn repo_meta_includes_fingerprint_version() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(shared.join("repos"))?;

        let repo_root = base.path().join("repo-a");
        create_git_repo(&repo_root)?;
        let resolution = resolve_shared_state_key(&repo_root, &shared)?;
        let state_key = resolution.state_key.clone();
        let state_index = shared_repo_root_dir(&shared, &state_key).join("index");
        fs::create_dir_all(&state_index)?;

        record_repo_opened(&repo_root, &state_index)?;
        let meta = read_repo_meta(&shared, &state_key).expect("repo meta");
        assert_eq!(meta.fingerprint_version, FINGERPRINT_VERSION);
        Ok(())
    }
}
