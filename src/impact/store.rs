use super::{
    default_impact_schema, impact_graph_path, normalize_edge_kind, ImpactGraphEdge,
    IMPACT_GRAPH_SCHEMA_NAME, IMPACT_GRAPH_SCHEMA_VERSION,
};
use crate::error::{AppError, ERR_MISSING_INDEX};
use crate::symbols::SchemaInfo;
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tracing::warn;

pub struct ImpactGraphStore {
    path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactDiagnostics {
    pub unresolved_imports_total: usize,
    #[serde(default)]
    pub unresolved_imports_sample: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ImpactGraphStoreEntryRaw {
    #[serde(default)]
    schema: Option<SchemaInfo>,
    #[serde(default)]
    repo_id: String,
    source: String,
    #[serde(default)]
    inbound: Vec<String>,
    #[serde(default)]
    outbound: Vec<String>,
    #[serde(default)]
    edges: Vec<ImpactGraphEdge>,
    #[serde(default)]
    diagnostics: Option<ImpactDiagnostics>,
}

#[derive(Debug, Clone, Deserialize)]
struct ImpactGraphStoreFileRaw {
    #[serde(default)]
    schema: Option<SchemaInfo>,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    graphs: Vec<ImpactGraphStoreEntryRaw>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImpactGraphStoreFile {
    schema: SchemaInfo,
    repo_id: String,
    graphs: Vec<ImpactGraphStoreEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImpactGraphStoreEntry {
    schema: SchemaInfo,
    repo_id: String,
    source: String,
    inbound: Vec<String>,
    outbound: Vec<String>,
    edges: Vec<ImpactGraphEdge>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostics: Option<ImpactDiagnostics>,
}

enum ImpactGraphStorePayload {
    Entries {
        entries: Vec<ImpactGraphStoreEntry>,
        migrated: bool,
        newer_compatible: bool,
    },
    Edges(Vec<ImpactGraphEdge>),
}

struct ImpactSchemaValidation {
    schema: SchemaInfo,
    migrated: bool,
    from_version: u32,
    newer_compatible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ImpactGraphFingerprint {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Debug, Clone)]
struct ParsedImpactGraph {
    edges: Vec<ImpactGraphEdge>,
    diagnostics_map: HashMap<String, ImpactDiagnostics>,
}

#[derive(Debug, Clone)]
struct ImpactGraphCacheEntry {
    fingerprint: ImpactGraphFingerprint,
    graph: ParsedImpactGraph,
}

static IMPACT_GRAPH_CACHE: Lazy<Mutex<HashMap<PathBuf, ImpactGraphCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn normalize_impact_schema(
    schema: Option<SchemaInfo>,
    fallback: Option<&SchemaInfo>,
) -> Result<ImpactSchemaValidation> {
    let mut migrated = false;
    let mut from_version = 0;
    let mut schema = match schema {
        Some(value) => {
            from_version = value.version;
            value
        }
        None => {
            migrated = true;
            if let Some(fallback) = fallback {
                from_version = fallback.version;
                fallback.clone()
            } else {
                default_impact_schema()
            }
        }
    };

    if schema.name != IMPACT_GRAPH_SCHEMA_NAME {
        return Err(anyhow!(
            "unsupported impact graph schema name {}",
            schema.name
        ));
    }
    if schema.compatible.min > schema.compatible.max {
        return Err(anyhow!(
            "impact graph schema compatible range is invalid (min > max)"
        ));
    }
    if schema.compatible.min > schema.version || schema.compatible.max < schema.version {
        return Err(anyhow!(
            "impact graph schema version {} outside compatible range {}..{}",
            schema.version,
            schema.compatible.min,
            schema.compatible.max
        ));
    }
    let current = IMPACT_GRAPH_SCHEMA_VERSION;
    if schema.version >= current
        && (schema.compatible.min > current || schema.compatible.max < current)
    {
        return Err(anyhow!(
            "impact graph schema version {} is not compatible with current {}",
            schema.version,
            current
        ));
    }

    let newer_compatible = schema.version > current;
    if schema.version < current {
        migrated = true;
        schema = default_impact_schema();
    }

    Ok(ImpactSchemaValidation {
        schema,
        migrated,
        from_version,
        newer_compatible,
    })
}

fn normalize_impact_entry(
    raw: ImpactGraphStoreEntryRaw,
    fallback_schema: Option<&SchemaInfo>,
    fallback_repo_id: Option<&str>,
    enforce_schema_match: bool,
) -> Result<(ImpactGraphStoreEntry, ImpactSchemaValidation)> {
    if enforce_schema_match {
        if let (Some(expected), Some(entry_schema)) = (fallback_schema, raw.schema.as_ref()) {
            if entry_schema.name != expected.name || entry_schema.version != expected.version {
                return Err(anyhow!(
                    "impact graph entry schema does not match file schema ({} v{})",
                    entry_schema.name,
                    entry_schema.version
                ));
            }
        }
    }
    let ImpactSchemaValidation {
        schema,
        migrated: schema_migrated,
        from_version,
        newer_compatible,
    } = normalize_impact_schema(raw.schema, fallback_schema)?;
    let mut migrated = schema_migrated;
    let repo_id = if raw.repo_id.is_empty() {
        if let Some(fallback) = fallback_repo_id {
            migrated = true;
            fallback.to_string()
        } else {
            raw.repo_id
        }
    } else {
        raw.repo_id
    };

    let schema_for_validation = schema.clone();
    Ok((
        ImpactGraphStoreEntry {
            schema,
            repo_id,
            source: raw.source,
            inbound: raw.inbound,
            outbound: raw.outbound,
            edges: raw.edges,
            diagnostics: raw.diagnostics,
        },
        ImpactSchemaValidation {
            schema: schema_for_validation,
            migrated,
            from_version,
            newer_compatible,
        },
    ))
}

fn parse_store_payload(value: serde_json::Value) -> Result<ImpactGraphStorePayload> {
    if let Some(edges_value) = value.get("edges") {
        let edges: Vec<ImpactGraphEdge> =
            serde_json::from_value(edges_value.clone()).context("parse impact_graph.json edges")?;
        return Ok(ImpactGraphStorePayload::Edges(edges));
    }

    if value.get("graphs").is_some() {
        let file: ImpactGraphStoreFileRaw =
            serde_json::from_value(value).context("parse impact_graph.json graphs")?;
        let file_schema_present = file.schema.is_some();
        let file_validation = normalize_impact_schema(file.schema.clone(), None)?;
        let enforce_schema_match = file_schema_present && !file_validation.migrated;
        let fallback_schema = Some(&file_validation.schema);
        let fallback_repo_id = file.repo_id.as_deref();
        let mut migrated = file_validation.migrated || file.repo_id.is_none();
        let mut newer_compatible = file_validation.newer_compatible;
        let mut min_from_version = file_validation.from_version;
        let mut entries = Vec::with_capacity(file.graphs.len());
        for raw in file.graphs {
            let (entry, entry_validation) = normalize_impact_entry(
                raw,
                fallback_schema,
                fallback_repo_id,
                enforce_schema_match,
            )?;
            migrated |= entry_validation.migrated;
            newer_compatible |= entry_validation.newer_compatible;
            if entry_validation.from_version > 0 {
                min_from_version = min_from_version.min(entry_validation.from_version);
            }
            entries.push(entry);
        }
        if min_from_version < IMPACT_GRAPH_SCHEMA_VERSION {
            run_impact_graph_migrations(min_from_version, &mut entries)?;
            migrated = true;
        }
        return Ok(ImpactGraphStorePayload::Entries {
            entries,
            migrated,
            newer_compatible,
        });
    }

    if let Some(list) = value.as_array() {
        if list.first().and_then(|item| item.get("target")).is_some()
            && list.first().and_then(|item| item.get("edges")).is_none()
        {
            let edges: Vec<ImpactGraphEdge> =
                serde_json::from_value(value).context("parse impact_graph.json edges")?;
            return Ok(ImpactGraphStorePayload::Edges(edges));
        }
        let raws: Vec<ImpactGraphStoreEntryRaw> =
            serde_json::from_value(value).context("parse impact_graph.json entries")?;
        let mut entries = Vec::with_capacity(raws.len());
        let mut migrated = false;
        let mut newer_compatible = false;
        let mut min_from_version: Option<u32> = None;
        for raw in raws {
            let (entry, entry_validation) = normalize_impact_entry(raw, None, None, false)?;
            migrated |= entry_validation.migrated;
            newer_compatible |= entry_validation.newer_compatible;
            if entry_validation.from_version > 0 {
                min_from_version = Some(
                    min_from_version
                        .unwrap_or(entry_validation.from_version)
                        .min(entry_validation.from_version),
                );
            }
            entries.push(entry);
        }
        if let Some(from_version) = min_from_version {
            if from_version < IMPACT_GRAPH_SCHEMA_VERSION {
                run_impact_graph_migrations(from_version, &mut entries)?;
                migrated = true;
            }
        } else if migrated {
            run_impact_graph_migrations(0, &mut entries)?;
            migrated = true;
        }
        return Ok(ImpactGraphStorePayload::Entries {
            entries,
            migrated,
            newer_compatible,
        });
    }

    Err(anyhow!("impact_graph.json missing edges"))
}

fn build_store_entries(
    repo_id: &str,
    edges: &[ImpactGraphEdge],
    diagnostics: Option<&HashMap<String, ImpactDiagnostics>>,
) -> Vec<ImpactGraphStoreEntry> {
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut inbound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut outbound: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut edges_by_node: BTreeMap<String, BTreeSet<ImpactGraphEdge>> = BTreeMap::new();

    for edge in edges {
        nodes.insert(edge.source.clone());
        nodes.insert(edge.target.clone());
        outbound
            .entry(edge.source.clone())
            .or_default()
            .insert(edge.target.clone());
        inbound
            .entry(edge.target.clone())
            .or_default()
            .insert(edge.source.clone());
        edges_by_node
            .entry(edge.source.clone())
            .or_default()
            .insert(edge.clone());
        edges_by_node
            .entry(edge.target.clone())
            .or_default()
            .insert(edge.clone());
    }

    let mut entries = Vec::new();
    for source in nodes {
        let inbound_list = inbound
            .get(&source)
            .map(|values| values.iter().cloned().collect())
            .unwrap_or_default();
        let outbound_list = outbound
            .get(&source)
            .map(|values| values.iter().cloned().collect())
            .unwrap_or_default();
        let edges_list = edges_by_node
            .get(&source)
            .map(|values| values.iter().cloned().collect())
            .unwrap_or_default();
        let entry_diagnostics = diagnostics.and_then(|map| map.get(&source).cloned());
        entries.push(ImpactGraphStoreEntry {
            schema: default_impact_schema(),
            repo_id: repo_id.to_string(),
            source,
            inbound: inbound_list,
            outbound: outbound_list,
            edges: edges_list,
            diagnostics: entry_diagnostics,
        });
    }
    entries
}

fn flatten_store_edges(entries: Vec<ImpactGraphStoreEntry>) -> Vec<ImpactGraphEdge> {
    let mut merged: BTreeSet<ImpactGraphEdge> = BTreeSet::new();
    for entry in entries {
        for edge in entry.edges {
            merged.insert(edge);
        }
    }
    merged.into_iter().collect()
}

fn impact_graph_fingerprint(path: &Path) -> Result<ImpactGraphFingerprint> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(AppError::new(
                ERR_MISSING_INDEX,
                format!(
                    "impact graph not found at {}; run `docdexd index` for this repo and ensure the state dir is writable",
                    path.display()
                ),
            )
            .into())
        }
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    };
    Ok(ImpactGraphFingerprint {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn lock_impact_graph_cache(
) -> std::sync::MutexGuard<'static, HashMap<PathBuf, ImpactGraphCacheEntry>> {
    IMPACT_GRAPH_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn invalidate_impact_graph_cache(path: &Path) {
    lock_impact_graph_cache().remove(path);
}

fn read_impact_graph_with_stable_fingerprint(
    path: &Path,
) -> Result<(String, ImpactGraphFingerprint)> {
    for _ in 0..2 {
        let before = impact_graph_fingerprint(path)?;
        let raw = match std::fs::read_to_string(path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                invalidate_impact_graph_cache(path);
                return Err(AppError::new(
                    ERR_MISSING_INDEX,
                    format!(
                        "impact graph not found at {}; run `docdexd index` for this repo and ensure the state dir is writable",
                        path.display()
                    ),
                )
                .into());
            }
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        };
        let after = impact_graph_fingerprint(path)?;
        if before == after {
            return Ok((raw, after));
        }
    }

    let fingerprint = impact_graph_fingerprint(path)?;
    let raw = match std::fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            invalidate_impact_graph_cache(path);
            return Err(AppError::new(
                ERR_MISSING_INDEX,
                format!(
                    "impact graph not found at {}; run `docdexd index` for this repo and ensure the state dir is writable",
                    path.display()
                ),
            )
            .into());
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    Ok((raw, fingerprint))
}

fn parse_impact_graph(path: &Path, value: serde_json::Value) -> Result<ParsedImpactGraph> {
    match parse_store_payload(value)? {
        ImpactGraphStorePayload::Edges(edges) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                "impact graph store uses legacy edge format; reindex to migrate"
            );
            Ok(ParsedImpactGraph {
                edges,
                diagnostics_map: HashMap::new(),
            })
        }
        ImpactGraphStorePayload::Entries {
            entries,
            migrated,
            newer_compatible,
        } => {
            if migrated {
                warn!(
                    target: "docdexd",
                    path = %path.display(),
                    "impact graph store schema migrated in-memory; reindex to persist"
                );
            }
            if newer_compatible {
                warn!(
                    target: "docdexd",
                    path = %path.display(),
                    "impact graph store schema is newer but compatible with this version"
                );
            }
            let diagnostics_map = entries
                .iter()
                .filter_map(|entry| {
                    entry
                        .diagnostics
                        .clone()
                        .map(|diag| (entry.source.clone(), diag))
                })
                .collect::<HashMap<_, _>>();
            Ok(ParsedImpactGraph {
                edges: flatten_store_edges(entries),
                diagnostics_map,
            })
        }
    }
}

impl ImpactGraphStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: impact_graph_path(state_dir),
        }
    }

    fn missing_index_error(&self) -> AppError {
        AppError::new(
            ERR_MISSING_INDEX,
            format!(
                "impact graph not found at {}; run `docdexd index` for this repo and ensure the state dir is writable",
                self.path.display()
            ),
        )
    }

    pub fn ensure_exists(&self) -> Result<()> {
        if self.path.exists() {
            return Ok(());
        }
        invalidate_impact_graph_cache(&self.path);
        Err(self.missing_index_error().into())
    }

    fn read_parsed_graph(&self) -> Result<ParsedImpactGraph> {
        self.ensure_exists()?;
        let fingerprint = impact_graph_fingerprint(&self.path)?;
        if let Some(entry) = lock_impact_graph_cache().get(&self.path).cloned() {
            if entry.fingerprint == fingerprint {
                return Ok(entry.graph);
            }
        }

        let (raw, stable_fingerprint) = read_impact_graph_with_stable_fingerprint(&self.path)?;
        let value: serde_json::Value =
            serde_json::from_str(&raw).context("parse impact_graph.json")?;
        let parsed = parse_impact_graph(&self.path, value)?;
        lock_impact_graph_cache().insert(
            self.path.clone(),
            ImpactGraphCacheEntry {
                fingerprint: stable_fingerprint,
                graph: parsed.clone(),
            },
        );
        Ok(parsed)
    }

    pub fn read_edges(&self) -> Result<Vec<ImpactGraphEdge>> {
        Ok(self.read_parsed_graph()?.edges)
    }

    pub fn read_diagnostics_map(&self) -> Result<HashMap<String, ImpactDiagnostics>> {
        Ok(self.read_parsed_graph()?.diagnostics_map)
    }

    pub fn read_diagnostics(&self, source: &str) -> Result<Option<ImpactDiagnostics>> {
        Ok(self
            .read_parsed_graph()?
            .diagnostics_map
            .get(source)
            .cloned())
    }

    /// Read the current graph for a write operation. A missing graph is the
    /// valid initial state for the first incremental ingest into a new index;
    /// query-facing reads intentionally continue to report `missing_index`.
    pub(crate) fn read_snapshot_for_update(
        &self,
    ) -> Result<(Vec<ImpactGraphEdge>, HashMap<String, ImpactDiagnostics>)> {
        match self.read_parsed_graph() {
            Ok(graph) => Ok((graph.edges, graph.diagnostics_map)),
            Err(err)
                if err
                    .downcast_ref::<AppError>()
                    .is_some_and(|app| app.code == ERR_MISSING_INDEX) =>
            {
                invalidate_impact_graph_cache(&self.path);
                Ok((Vec::new(), HashMap::new()))
            }
            Err(err) => Err(err),
        }
    }

    pub fn write_graph(
        &self,
        repo_id: &str,
        edges: &[ImpactGraphEdge],
        diagnostics: Option<&HashMap<String, ImpactDiagnostics>>,
    ) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        let entries = build_store_entries(repo_id, edges, diagnostics);
        let diagnostics_map = entries
            .iter()
            .filter_map(|entry| {
                entry
                    .diagnostics
                    .clone()
                    .map(|diag| (entry.source.clone(), diag))
            })
            .collect::<HashMap<_, _>>();
        let cached_graph = ParsedImpactGraph {
            edges: flatten_store_edges(entries.clone()),
            diagnostics_map,
        };
        let payload = ImpactGraphStoreFile {
            schema: default_impact_schema(),
            repo_id: repo_id.to_string(),
            graphs: entries,
        };
        let bytes =
            serde_json::to_vec_pretty(&payload).context("serialize impact graph entries")?;
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;

        if let Ok(fingerprint) = impact_graph_fingerprint(&self.path) {
            lock_impact_graph_cache().insert(
                self.path.clone(),
                ImpactGraphCacheEntry {
                    fingerprint,
                    graph: cached_graph,
                },
            );
        } else {
            invalidate_impact_graph_cache(&self.path);
        }
        Ok(())
    }
}

fn run_impact_graph_migrations(
    from_version: u32,
    entries: &mut Vec<ImpactGraphStoreEntry>,
) -> Result<()> {
    if from_version >= IMPACT_GRAPH_SCHEMA_VERSION {
        return Ok(());
    }
    match from_version {
        0 | 1 => migrate_impact_graph_v1_to_v2(entries),
        _ => Err(anyhow!(
            "missing impact graph migration step for v{from_version}"
        )),
    }
}

fn migrate_impact_graph_v1_to_v2(entries: &mut Vec<ImpactGraphStoreEntry>) -> Result<()> {
    for entry in entries.iter_mut() {
        for edge in entry.edges.iter_mut() {
            let Some(raw) = edge.kind.take() else {
                continue;
            };
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            edge.kind = Some(normalize_edge_kind(trimmed).to_string());
        }
    }
    Ok(())
}
