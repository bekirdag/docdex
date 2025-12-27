use crate::symbols::{language_for_path, SchemaCompatibleRange, SchemaInfo, SourceLanguage};
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tracing::{info, warn};
use tree_sitter::{Node, Parser};
use tree_sitter_go as ts_go;
use tree_sitter_javascript as ts_javascript;
use tree_sitter_python as ts_python;
use tree_sitter_rust as ts_rust;
use tree_sitter_typescript as ts_typescript;
use walkdir::WalkDir;

const HARD_MAX_EDGES: usize = 10_000;
const HARD_MAX_DEPTH: usize = 100;
const DYNAMIC_IMPORT_SCAN_LIMIT: usize = 50_000;
const IMPORT_MAP_FILE: &str = "docdex.import_map.json";
const IMPORT_TRACES_FILE: &str = "docdex.import_traces.jsonl";
const UNRESOLVED_IMPORT_SAMPLE_LIMIT: usize = 5;
const IMPACT_GRAPH_SCHEMA_NAME: &str = "docdex.impact_graph";
const IMPACT_GRAPH_SCHEMA_VERSION: u32 = 1;

fn default_impact_schema() -> SchemaInfo {
    SchemaInfo {
        name: IMPACT_GRAPH_SCHEMA_NAME.to_string(),
        version: IMPACT_GRAPH_SCHEMA_VERSION,
        compatible: SchemaCompatibleRange {
            min: IMPACT_GRAPH_SCHEMA_VERSION,
            max: IMPACT_GRAPH_SCHEMA_VERSION,
        },
    }
}

fn default_impact_diagnostics_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.impact_diagnostics".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImpactGraphEdge {
    pub source: String,
    pub target: String,
    // Backwards/forwards compatibility: some producers may emit edge label under `type`.
    #[serde(skip_serializing_if = "Option::is_none", alias = "type")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactQueryControlsRaw {
    #[serde(default)]
    pub max_edges: Option<i64>,
    #[serde(default)]
    pub max_depth: Option<i64>,
    #[serde(default)]
    pub edge_types: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct ImpactQueryControls {
    pub max_edges: usize,
    pub max_depth: usize,
    pub edge_types: Option<HashSet<String>>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct InvalidFieldIssue {
    pub field: &'static str,
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FieldErrorDetail {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InvalidArgumentDetails {
    pub issues: Vec<InvalidFieldIssue>,
    pub field_errors: BTreeMap<String, Vec<FieldErrorDetail>>,
}

impl InvalidArgumentDetails {
    pub fn new(issues: Vec<InvalidFieldIssue>) -> Self {
        let mut field_errors: BTreeMap<String, Vec<FieldErrorDetail>> = BTreeMap::new();
        for issue in &issues {
            field_errors
                .entry(issue.field.to_string())
                .or_default()
                .push(FieldErrorDetail {
                    code: issue.code,
                    message: issue.message.clone(),
                });
        }
        Self {
            issues,
            field_errors,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvalidArgumentError {
    pub details: InvalidArgumentDetails,
}

impl std::fmt::Display for InvalidArgumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid argument")
    }
}

impl std::error::Error for InvalidArgumentError {}

fn push_issue(
    issues: &mut Vec<InvalidFieldIssue>,
    field: &'static str,
    code: &'static str,
    msg: impl Into<String>,
) {
    issues.push(InvalidFieldIssue {
        field,
        code,
        message: msg.into(),
    });
}

impl ImpactQueryControlsRaw {
    pub fn validate(self) -> std::result::Result<ImpactQueryControls, InvalidArgumentError> {
        let mut issues: Vec<InvalidFieldIssue> = Vec::new();

        let max_edges = match self.max_edges {
            None => HARD_MAX_EDGES.min(1000),
            Some(value) if value < 0 => {
                push_issue(
                    &mut issues,
                    "maxEdges",
                    "must_be_non_negative",
                    "maxEdges must be >= 0",
                );
                0
            }
            Some(value) if value as u128 > (HARD_MAX_EDGES as u128) => {
                push_issue(
                    &mut issues,
                    "maxEdges",
                    "must_be_at_most",
                    format!("maxEdges must be <= {HARD_MAX_EDGES}"),
                );
                HARD_MAX_EDGES
            }
            Some(value) => value as usize,
        };

        let max_depth = match self.max_depth {
            None => HARD_MAX_DEPTH.min(10),
            Some(value) if value < 0 => {
                push_issue(
                    &mut issues,
                    "maxDepth",
                    "must_be_non_negative",
                    "maxDepth must be >= 0",
                );
                0
            }
            Some(value) if value as u128 > (HARD_MAX_DEPTH as u128) => {
                push_issue(
                    &mut issues,
                    "maxDepth",
                    "must_be_at_most",
                    format!("maxDepth must be <= {HARD_MAX_DEPTH}"),
                );
                HARD_MAX_DEPTH
            }
            Some(value) => value as usize,
        };

        let edge_types = match self.edge_types {
            None => None,
            Some(list) => {
                if list.is_empty() {
                    push_issue(
                        &mut issues,
                        "edgeTypes",
                        "must_be_non_empty",
                        "edgeTypes must not be empty when provided",
                    );
                    None
                } else {
                    let mut set = HashSet::new();
                    for item in list {
                        let trimmed = item.trim();
                        if trimmed.is_empty() {
                            push_issue(
                                &mut issues,
                                "edgeTypes",
                                "must_be_non_empty_string",
                                "edgeTypes entries must be non-empty strings",
                            );
                            continue;
                        }
                        set.insert(trimmed.to_string());
                    }
                    Some(set)
                }
            }
        };

        if !issues.is_empty() {
            return Err(InvalidArgumentError {
                details: InvalidArgumentDetails::new(issues),
            });
        }

        Ok(ImpactQueryControls {
            max_edges,
            max_depth,
            edge_types,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactGraphResponseV1 {
    #[serde(default = "default_impact_schema")]
    pub schema: SchemaInfo,
    #[serde(default)]
    pub repo_id: String,
    pub source: String,
    pub inbound: Vec<String>,
    pub outbound: Vec<String>,
    pub edges: Vec<ImpactGraphEdge>,
    pub truncated: bool,
    pub applied: AppliedImpactControls,
    pub applied_limits: AppliedImpactControls,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<ImpactDiagnostics>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactDiagnosticsEntry {
    pub file: String,
    pub diagnostics: ImpactDiagnostics,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactDiagnosticsResponseV1 {
    #[serde(default = "default_impact_diagnostics_schema")]
    pub schema: SchemaInfo,
    #[serde(default)]
    pub repo_id: String,
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub truncated: bool,
    pub diagnostics: Vec<ImpactDiagnosticsEntry>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedImpactControls {
    pub max_edges: usize,
    pub max_depth: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edge_types: Option<Vec<String>>,
}

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
    },
    Edges(Vec<ImpactGraphEdge>),
}

fn normalize_impact_schema(
    schema: Option<SchemaInfo>,
    fallback: Option<&SchemaInfo>,
) -> Result<(SchemaInfo, bool)> {
    let mut migrated = false;
    let schema = match schema {
        Some(value) => value,
        None => {
            migrated = true;
            fallback.cloned().unwrap_or_else(default_impact_schema)
        }
    };

    if schema.name != IMPACT_GRAPH_SCHEMA_NAME {
        return Err(anyhow!(
            "unsupported impact graph schema name {}",
            schema.name
        ));
    }
    if schema.version > IMPACT_GRAPH_SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported impact graph schema version {}",
            schema.version
        ));
    }
    if schema.version < IMPACT_GRAPH_SCHEMA_VERSION {
        return Ok((default_impact_schema(), true));
    }
    if schema.compatible.min > schema.version || schema.compatible.max < schema.version {
        return Err(anyhow!(
            "impact graph schema version {} outside compatible range {}..{}",
            schema.version,
            schema.compatible.min,
            schema.compatible.max
        ));
    }

    Ok((schema, migrated))
}

fn normalize_impact_entry(
    raw: ImpactGraphStoreEntryRaw,
    fallback_schema: Option<&SchemaInfo>,
    fallback_repo_id: Option<&str>,
) -> Result<(ImpactGraphStoreEntry, bool)> {
    let (schema, migrated_schema) = normalize_impact_schema(raw.schema, fallback_schema)?;
    let mut migrated = migrated_schema;
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
        migrated,
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
        let fallback_schema = file.schema.as_ref();
        let fallback_repo_id = file.repo_id.as_deref();
        let mut migrated = file.schema.is_none() || file.repo_id.is_none();
        if let Some(schema) = fallback_schema {
            let (_, schema_migrated) = normalize_impact_schema(Some(schema.clone()), None)?;
            migrated |= schema_migrated;
        }
        let mut entries = Vec::with_capacity(file.graphs.len());
        for raw in file.graphs {
            let (entry, entry_migrated) =
                normalize_impact_entry(raw, fallback_schema, fallback_repo_id)?;
            migrated |= entry_migrated;
            entries.push(entry);
        }
        return Ok(ImpactGraphStorePayload::Entries { entries, migrated });
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
        for raw in raws {
            let (entry, entry_migrated) = normalize_impact_entry(raw, None, None)?;
            migrated |= entry_migrated;
            entries.push(entry);
        }
        return Ok(ImpactGraphStorePayload::Entries { entries, migrated });
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

impl ImpactGraphStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: impact_graph_path(state_dir),
        }
    }

    pub fn read_edges(&self) -> Result<Vec<ImpactGraphEdge>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).with_context(|| format!("read {}", self.path.display())),
        };
        let value: serde_json::Value =
            serde_json::from_str(&raw).context("parse impact_graph.json")?;
        match parse_store_payload(value)? {
            ImpactGraphStorePayload::Edges(edges) => {
                warn!(
                    target: "docdexd",
                    path = %self.path.display(),
                    "impact graph store uses legacy edge format; reindex to migrate"
                );
                Ok(edges)
            }
            ImpactGraphStorePayload::Entries { entries, migrated } => {
                if migrated {
                    warn!(
                        target: "docdexd",
                        path = %self.path.display(),
                        "impact graph store schema migrated in-memory; reindex to persist"
                    );
                }
                Ok(flatten_store_edges(entries))
            }
        }
    }

    pub fn read_diagnostics_map(&self) -> Result<HashMap<String, ImpactDiagnostics>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(err) => return Err(err).with_context(|| format!("read {}", self.path.display())),
        };
        let value: serde_json::Value =
            serde_json::from_str(&raw).context("parse impact_graph.json")?;
        let entries = match parse_store_payload(value)? {
            ImpactGraphStorePayload::Edges(_) => {
                warn!(
                    target: "docdexd",
                    path = %self.path.display(),
                    "impact graph store uses legacy edge format; diagnostics unavailable until reindex"
                );
                return Ok(HashMap::new());
            }
            ImpactGraphStorePayload::Entries { entries, migrated } => {
                if migrated {
                    warn!(
                        target: "docdexd",
                        path = %self.path.display(),
                        "impact graph store schema migrated in-memory; reindex to persist"
                    );
                }
                entries
            }
        };
        let mut map = HashMap::new();
        for entry in entries {
            if let Some(diag) = entry.diagnostics {
                map.insert(entry.source, diag);
            }
        }
        Ok(map)
    }

    pub fn read_diagnostics(&self, source: &str) -> Result<Option<ImpactDiagnostics>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("read {}", self.path.display())),
        };
        let value: serde_json::Value =
            serde_json::from_str(&raw).context("parse impact_graph.json")?;
        let entries = match parse_store_payload(value)? {
            ImpactGraphStorePayload::Edges(_) => {
                warn!(
                    target: "docdexd",
                    path = %self.path.display(),
                    "impact graph store uses legacy edge format; diagnostics unavailable until reindex"
                );
                return Ok(None);
            }
            ImpactGraphStorePayload::Entries { entries, migrated } => {
                if migrated {
                    warn!(
                        target: "docdexd",
                        path = %self.path.display(),
                        "impact graph store schema migrated in-memory; reindex to persist"
                    );
                }
                entries
            }
        };
        for entry in entries {
            if entry.source == source {
                return Ok(entry.diagnostics);
            }
        }
        Ok(None)
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
        let bytes =
            serde_json::to_vec_pretty(&entries).context("serialize impact graph entries")?;
        let tmp = self
            .path
            .with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        std::fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), self.path.display()))?;
        Ok(())
    }
}

fn impact_graph_path(state_dir: &Path) -> PathBuf {
    if state_dir.file_name().and_then(|name| name.to_str()) == Some("index") {
        return state_dir
            .parent()
            .unwrap_or(state_dir)
            .join("impact_graph.json");
    }
    state_dir.join("impact_graph.json")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactTraversalResult {
    pub edges: Vec<ImpactGraphEdge>,
    pub truncated: bool,
}

fn edge_kind_matches(edge: &ImpactGraphEdge, edge_types: &Option<HashSet<String>>) -> bool {
    let Some(edge_types) = edge_types else {
        return true;
    };
    let Some(kind) = edge.kind.as_deref() else {
        return false;
    };
    edge_types.contains(kind)
}

pub fn traverse_impact(
    root: &str,
    all_edges: &[ImpactGraphEdge],
    controls: &ImpactQueryControls,
) -> ImpactTraversalResult {
    fn edge_sort_key(edge: &ImpactGraphEdge) -> (&str, &str, Option<&str>) {
        (
            edge.source.as_str(),
            edge.target.as_str(),
            edge.kind.as_deref(),
        )
    }

    let mut outgoing: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut incoming: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, edge) in all_edges.iter().enumerate() {
        outgoing.entry(edge.source.as_str()).or_default().push(idx);
        incoming.entry(edge.target.as_str()).or_default().push(idx);
    }

    let mut seen_edges: HashSet<(&str, &str, Option<&str>)> = HashSet::new();
    let mut result: Vec<ImpactGraphEdge> = Vec::new();
    let mut hard_truncated = false;
    let mut filter_truncated = false;

    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(root.to_string());
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((root.to_string(), 0));

    let incident_edges = |node: &str,
                          outgoing: &HashMap<&str, Vec<usize>>,
                          incoming: &HashMap<&str, Vec<usize>>|
     -> Vec<usize> {
        let mut incident: Vec<usize> = Vec::new();
        if let Some(list) = outgoing.get(node) {
            incident.extend(list.iter().copied());
        }
        if let Some(list) = incoming.get(node) {
            incident.extend(list.iter().copied());
        }
        incident.sort_unstable();
        incident.dedup();
        incident.sort_unstable_by(|left, right| {
            edge_sort_key(&all_edges[*left]).cmp(&edge_sort_key(&all_edges[*right]))
        });
        incident
    };

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= controls.max_depth {
            if depth == controls.max_depth && !hard_truncated {
                let incident = incident_edges(node.as_str(), &outgoing, &incoming);
                for edge_idx in incident {
                    let edge = &all_edges[edge_idx];
                    if !edge_kind_matches(edge, &controls.edge_types) {
                        filter_truncated = filter_truncated || controls.edge_types.is_some();
                        continue;
                    }
                    let key = edge_sort_key(edge);
                    if !seen_edges.contains(&key) {
                        hard_truncated = true;
                        break;
                    }
                }
                if hard_truncated {
                    break;
                }
            }
            continue;
        }

        let incident = incident_edges(node.as_str(), &outgoing, &incoming);

        for edge_idx in incident {
            let edge = &all_edges[edge_idx];
            if !edge_kind_matches(edge, &controls.edge_types) {
                filter_truncated = filter_truncated || controls.edge_types.is_some();
                continue;
            }
            let key = edge_sort_key(edge);
            if !seen_edges.insert(key) {
                continue;
            }
            if result.len() >= controls.max_edges {
                hard_truncated = true;
                break;
            }
            result.push(edge.clone());

            let neighbor = if edge.source == node {
                &edge.target
            } else {
                &edge.source
            };
            if depth + 1 <= controls.max_depth && visited.insert(neighbor.clone()) {
                queue.push_back((neighbor.clone(), depth + 1));
            }
        }

        if hard_truncated {
            break;
        }
    }

    ImpactTraversalResult {
        edges: result,
        truncated: hard_truncated || filter_truncated,
    }
}

pub(crate) fn extract_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(language) = language_for_path(rel_path) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    match language {
        SourceLanguage::Markdown => ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        },
        SourceLanguage::Rust => extract_rust_import_edges(repo_root, rel_path, content),
        SourceLanguage::Python => extract_python_import_edges(repo_root, rel_path, content),
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            extract_js_ts_import_edges(repo_root, rel_path, content, language)
        }
        SourceLanguage::Go => extract_go_import_edges(repo_root, rel_path, content),
    }
}

#[derive(Debug, Clone)]
enum StringEval {
    Exact(String),
    Pattern(StringPattern),
    Unknown,
}

#[derive(Debug, Clone)]
struct StringPattern {
    parts: Vec<String>,
    anchored_start: bool,
    anchored_end: bool,
}

#[derive(Debug, Clone)]
enum ImportPath {
    Exact(String),
    Pattern(StringPattern),
}

#[derive(Debug, Clone)]
struct ImportRef {
    path: ImportPath,
    kind: &'static str,
    language: SourceLanguage,
}

#[derive(Debug, Clone)]
pub(crate) struct ImpactEdgeBuildResult {
    pub(crate) edges: Vec<ImpactGraphEdge>,
    pub(crate) diagnostics: Option<ImpactDiagnostics>,
}

impl StringPattern {
    fn normalize(mut self) -> Self {
        self.parts.retain(|part| !part.is_empty());
        if self.parts.is_empty() {
            self.anchored_start = false;
            self.anchored_end = false;
        }
        self
    }

    fn is_useful(&self) -> bool {
        self.parts.iter().any(|part| !part.is_empty())
    }

    fn first_part(&self) -> Option<&str> {
        self.parts.first().map(|part| part.as_str())
    }

    fn last_part(&self) -> Option<&str> {
        self.parts.last().map(|part| part.as_str())
    }
}

#[derive(Debug, Default, Clone)]
struct ImportHints {
    edges: Vec<ImportMapEdge>,
    mappings: Vec<ImportMapMapping>,
    traces: Vec<ImportTraceEntry>,
}

#[derive(Debug, Default, Clone)]
struct ImportMapFile {
    edges: Vec<ImportMapEdge>,
    mappings: Vec<ImportMapMapping>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportMapFileRaw {
    #[serde(default)]
    edges: Vec<ImportMapEdgeRaw>,
    #[serde(default)]
    mappings: Vec<ImportMapMappingRaw>,
}

#[derive(Debug, Clone)]
struct ImportMapEdge {
    source: String,
    target: String,
    kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportMapEdgeRaw {
    source: String,
    target: String,
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, Clone)]
struct ImportMapMapping {
    source: Option<String>,
    spec: String,
    target: String,
    kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportMapMappingRaw {
    #[serde(default)]
    source: Option<String>,
    spec: String,
    target: String,
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImportTraceEntry {
    source: String,
    target: String,
    #[serde(default)]
    kind: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct RepoFileIndex {
    js_ts: Vec<String>,
    python: Vec<String>,
}

#[derive(Debug, Default, Clone)]
struct ImportHintCacheEntry {
    map_mtime: Option<SystemTime>,
    trace_mtime: Option<SystemTime>,
    hints: ImportHints,
}

static IMPORT_HINT_CACHE: Lazy<Mutex<HashMap<PathBuf, ImportHintCacheEntry>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static REPO_FILE_CACHE: Lazy<Mutex<HashMap<PathBuf, RepoFileIndex>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn extract_js_ts_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(language, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let mut imports: Vec<ImportRef> = Vec::new();
    let mut bindings: HashMap<String, StringEval> = HashMap::new();
    seed_js_ts_bindings(rel_path, &mut bindings);
    collect_js_ts_imports(content, root, language, &mut imports, &mut bindings);
    build_edges(repo_root, rel_path, imports, resolve_js_ts_import)
}

fn extract_python_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(SourceLanguage::Python, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let mut imports: Vec<ImportRef> = Vec::new();
    let mut bindings: HashMap<String, StringEval> = HashMap::new();
    collect_python_imports(content, root, &mut imports, &mut bindings);
    build_edges(repo_root, rel_path, imports, resolve_python_import)
}

fn extract_rust_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(SourceLanguage::Rust, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let mut edges = Vec::new();
    collect_rust_import_edges(repo_root, rel_path, content, root, &mut edges);
    ImpactEdgeBuildResult {
        edges,
        diagnostics: None,
    }
}

fn extract_go_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
) -> ImpactEdgeBuildResult {
    let Some(tree) = parse_tree(SourceLanguage::Go, rel_path, content) else {
        return ImpactEdgeBuildResult {
            edges: Vec::new(),
            diagnostics: None,
        };
    };
    let root = tree.root_node();
    let module_path = go_module_path(repo_root);
    let mut imports: Vec<ImportRef> = Vec::new();
    collect_go_imports(content, root, &mut imports);
    build_edges_with_context(
        repo_root,
        rel_path,
        imports,
        |root, file, import_path| resolve_go_import(root, file, import_path, module_path.as_deref()),
    )
}

fn seed_js_ts_bindings(rel_path: &str, bindings: &mut HashMap<String, StringEval>) {
    if !bindings.contains_key("__dirname") {
        bindings.insert("__dirname".to_string(), StringEval::Exact(".".to_string()));
    }
    if !bindings.contains_key("__filename") {
        if let Some(file_name) = Path::new(rel_path).file_name().and_then(|name| name.to_str()) {
            bindings.insert("__filename".to_string(), StringEval::Exact(file_name.to_string()));
        }
    }
}

fn parse_tree(
    language: SourceLanguage,
    rel_path: &str,
    content: &str,
) -> Option<tree_sitter::Tree> {
    let ts_language = tree_sitter_language(language, rel_path)?;
    let mut parser = Parser::new();
    parser.set_language(ts_language).ok()?;
    parser.parse(content, None)
}

fn tree_sitter_language(
    language: SourceLanguage,
    rel_path: &str,
) -> Option<tree_sitter::Language> {
    match language {
        SourceLanguage::Rust => Some(ts_rust::language()),
        SourceLanguage::Python => Some(ts_python::language()),
        SourceLanguage::JavaScript => Some(ts_javascript::language()),
        SourceLanguage::TypeScript => {
            if rel_path.to_lowercase().ends_with(".tsx") {
                Some(ts_typescript::language_tsx())
            } else {
                Some(ts_typescript::language_typescript())
            }
        }
        SourceLanguage::Go => Some(ts_go::language()),
        SourceLanguage::Markdown => None,
    }
}

fn collect_js_ts_imports(
    content: &str,
    node: Node,
    language: SourceLanguage,
    imports: &mut Vec<ImportRef>,
    bindings: &mut HashMap<String, StringEval>,
) {
    match node.kind() {
        "import_statement" | "export_statement" => {
            if let Some(source) = node.child_by_field_name("source") {
                if let Some(eval) = string_literal_eval(content, source) {
                    if let Some(path) = eval_to_import_path(eval) {
                        let kind = "import";
                        imports.push(ImportRef {
                            path,
                            kind,
                            language,
                        });
                    }
                }
            }
        }
        "call_expression" => {
            if let Some(name) = call_function_name(content, node) {
                if let Some(kind) = js_dynamic_import_kind(name.as_str()) {
                    if let Some(arg) =
                        first_argument_import_path(content, node, &|id| bindings.get(id).cloned())
                    {
                        imports.push(ImportRef {
                            path: arg,
                            kind,
                            language,
                        });
                    }
                }
            }
        }
        "import_call" => {
            if let Some(arg) =
                first_argument_import_path(content, node, &|id| bindings.get(id).cloned())
            {
                imports.push(ImportRef {
                    path: arg,
                    kind: "import",
                    language,
                });
            }
        }
        "variable_declarator" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                if name_node.kind() == "identifier" {
                    if let Some(value_node) = node.child_by_field_name("value") {
                        let eval = static_string_eval_with_resolver(
                            content,
                            value_node,
                            &|id| bindings.get(id).cloned(),
                        );
                        if is_meaningful_eval(&eval) {
                            if let Some(name) = node_text(content, name_node)
                                .map(|text| text.trim().to_string())
                                .filter(|text| !text.is_empty())
                            {
                                bindings.insert(name, eval);
                            }
                        }
                    }
                }
            }
        }
        "assignment_expression" => {
            if assignment_operator_is_eq(content, node) {
                if let Some(left) = node.child_by_field_name("left") {
                    if left.kind() == "identifier" {
                        if let Some(right) = node.child_by_field_name("right") {
                            let eval = static_string_eval_with_resolver(
                                content,
                                right,
                                &|id| bindings.get(id).cloned(),
                            );
                            if is_meaningful_eval(&eval) {
                                if let Some(name) = node_text(content, left)
                                    .map(|text| text.trim().to_string())
                                    .filter(|text| !text.is_empty())
                                {
                                    bindings.insert(name, eval);
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_js_ts_imports(content, child, language, imports, bindings);
    }
}

fn collect_python_imports(
    content: &str,
    node: Node,
    imports: &mut Vec<ImportRef>,
    bindings: &mut HashMap<String, StringEval>,
) {
    match node.kind() {
        "import_statement" => {
            let text = node_text(content, node).unwrap_or_default();
            let list = text.trim().strip_prefix("import ").unwrap_or(text.trim());
            for raw in list.split(',') {
                let entry = raw.trim();
                if entry.is_empty() {
                    continue;
                }
                let name = entry.split_whitespace().next().unwrap_or(entry);
                imports.push(ImportRef {
                    path: ImportPath::Exact(name.to_string()),
                    kind: "import",
                    language: SourceLanguage::Python,
                });
            }
        }
        "import_from_statement" => {
            let text = node_text(content, node).unwrap_or_default();
            if let Some(from_idx) = text.find("from ") {
                let after_from = &text[from_idx + 5..];
                let module = after_from
                    .splitn(2, "import")
                    .next()
                    .unwrap_or(after_from)
                    .trim();
                if !module.is_empty() {
                    imports.push(ImportRef {
                        path: ImportPath::Exact(module.to_string()),
                        kind: "import",
                        language: SourceLanguage::Python,
                    });
                }
            }
        }
        "call" => {
            if let Some(name) = call_function_name(content, node) {
                if let Some((kind, arg_index)) = python_dynamic_import_spec(name.as_str()) {
                    if let Some(arg) = argument_import_path(
                        content,
                        node,
                        arg_index,
                        &|id| bindings.get(id).cloned(),
                    ) {
                        imports.push(ImportRef {
                            path: arg,
                            kind,
                            language: SourceLanguage::Python,
                        });
                    }
                }
            }
        }
        "assignment" => {
            if let Some((name, value_node)) = python_assignment_parts(content, node) {
                let eval = static_string_eval_with_resolver(
                    content,
                    value_node,
                    &|id| bindings.get(id).cloned(),
                );
                if is_meaningful_eval(&eval) {
                    bindings.insert(name, eval);
                }
            }
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_python_imports(content, child, imports, bindings);
    }
}

fn collect_rust_import_edges(
    repo_root: &Path,
    rel_path: &str,
    content: &str,
    node: Node,
    edges: &mut Vec<ImpactGraphEdge>,
) {
    if node.kind() == "mod_item" {
        let has_body = node.child_by_field_name("body").is_some();
        if !has_body {
            if let Some(name) = node_name(content, node, "name") {
                if let Some(target) = resolve_rust_mod(repo_root, rel_path, &name) {
                    edges.push(ImpactGraphEdge {
                        source: rel_path.to_string(),
                        target,
                        kind: Some("import".to_string()),
                    });
                }
            }
        }
    } else if node.kind() == "use_declaration" {
        let text = node_text(content, node).unwrap_or_default();
        for path in extract_rust_use_paths(text) {
            if let Some(target) = resolve_rust_use(repo_root, rel_path, &path) {
                edges.push(ImpactGraphEdge {
                    source: rel_path.to_string(),
                    target,
                    kind: Some("import".to_string()),
                });
            }
        }
    } else if node.kind() == "macro_invocation" {
        if let Some(name) = rust_macro_name(content, node) {
            if matches!(name.as_str(), "include" | "include_str" | "include_bytes") {
                if let Some(arg) = first_string_literal_in_node(content, node) {
                    if let Some(target) = resolve_rust_include(repo_root, rel_path, &arg) {
                        edges.push(ImpactGraphEdge {
                            source: rel_path.to_string(),
                            target,
                            kind: Some("include".to_string()),
                        });
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_rust_import_edges(repo_root, rel_path, content, child, edges);
    }
}

fn collect_go_imports(content: &str, node: Node, imports: &mut Vec<ImportRef>) {
    if node.kind() == "import_spec" {
        if let Some(path) = node.child_by_field_name("path") {
            if let Some(value) = string_literal_value(content, path) {
                imports.push(ImportRef {
                    path: ImportPath::Exact(value),
                    kind: "import",
                    language: SourceLanguage::Go,
                });
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_go_imports(content, child, imports);
    }
}

fn build_edges<F>(
    repo_root: &Path,
    rel_path: &str,
    imports: Vec<ImportRef>,
    resolver: F,
) -> ImpactEdgeBuildResult
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    build_edges_with_context(repo_root, rel_path, imports, resolver)
}

fn build_edges_with_context<F>(
    repo_root: &Path,
    rel_path: &str,
    imports: Vec<ImportRef>,
    resolver: F,
) -> ImpactEdgeBuildResult
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let mut edges: BTreeSet<ImpactGraphEdge> = BTreeSet::new();
    let hints = import_hints_for_repo(repo_root);
    for edge in hint_edges_for_source(repo_root, rel_path, &hints, &resolver) {
        edges.insert(edge);
    }
    let mut unresolved = Vec::new();
    for import_ref in imports {
        if let Some(target) =
            resolve_import_ref(repo_root, rel_path, &import_ref, &hints, &resolver)
        {
            if target != rel_path {
                edges.insert(ImpactGraphEdge {
                    source: rel_path.to_string(),
                    target,
                    kind: Some(normalize_edge_kind(import_ref.kind).to_string()),
                });
            }
        } else if matches!(&import_ref.path, ImportPath::Pattern(_)) {
            unresolved.push(import_ref);
        }
    }
    if !unresolved.is_empty() {
        let samples: Vec<String> = unresolved
            .iter()
            .take(UNRESOLVED_IMPORT_SAMPLE_LIMIT)
            .map(|item| format_import_path(&item.path))
            .collect();
        info!(
            target: "docdexd",
            file = %rel_path,
            count = unresolved.len(),
            sample = ?samples,
            "unresolved dynamic imports skipped"
        );
    }
    let diagnostics = if unresolved.is_empty() {
        None
    } else {
        let samples = unresolved
            .iter()
            .take(UNRESOLVED_IMPORT_SAMPLE_LIMIT)
            .map(|item| format_import_path(&item.path))
            .collect();
        Some(ImpactDiagnostics {
            unresolved_imports_total: unresolved.len(),
            unresolved_imports_sample: samples,
        })
    };
    ImpactEdgeBuildResult {
        edges: edges.into_iter().collect(),
        diagnostics,
    }
}

fn resolve_import_ref<F>(
    repo_root: &Path,
    rel_path: &str,
    import_ref: &ImportRef,
    hints: &ImportHints,
    resolver: &F,
) -> Option<String>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    match &import_ref.path {
        ImportPath::Exact(path) => {
            if let Some(target) = resolver(repo_root, rel_path, path) {
                return Some(target);
            }
            resolve_import_map_target(repo_root, rel_path, import_ref, hints, resolver)
        }
        ImportPath::Pattern(pattern) => {
            if let Some(target) = resolve_import_map_target(repo_root, rel_path, import_ref, hints, resolver) {
                return Some(target);
            }
            resolve_unique_match(repo_root, rel_path, import_ref, pattern)
        }
    }
}

fn hint_edges_for_source<F>(
    repo_root: &Path,
    rel_path: &str,
    hints: &ImportHints,
    resolver: &F,
) -> Vec<ImpactGraphEdge>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let mut edges = Vec::new();
    for edge in &hints.edges {
        if edge.source != rel_path {
            continue;
        }
        if let Some(target) = resolve_hint_target(repo_root, rel_path, &edge.target, resolver) {
            edges.push(ImpactGraphEdge {
                source: rel_path.to_string(),
                target,
                kind: edge
                    .kind
                    .as_deref()
                    .map(normalize_edge_kind)
                    .map(|kind| kind.to_string()),
            });
        }
    }
    for trace in &hints.traces {
        if trace.source != rel_path {
            continue;
        }
        if let Some(target) = resolve_hint_target(repo_root, rel_path, &trace.target, resolver) {
            edges.push(ImpactGraphEdge {
                source: rel_path.to_string(),
                target,
                kind: trace
                    .kind
                    .as_deref()
                    .map(normalize_edge_kind)
                    .map(|kind| kind.to_string()),
            });
        }
    }
    edges
}

fn import_hints_for_repo(repo_root: &Path) -> ImportHints {
    let key = canonical_repo_root(repo_root);
    let map_path = key.join(IMPORT_MAP_FILE);
    let trace_path = key.join(IMPORT_TRACES_FILE);
    let map_mtime = file_mtime(&map_path);
    let trace_mtime = file_mtime(&trace_path);
    let mut cache = IMPORT_HINT_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let entry = cache.entry(key.clone()).or_default();
    if entry.map_mtime != map_mtime {
        let map = load_import_map(&key, &map_path);
        entry.hints.edges = map.edges;
        entry.hints.mappings = map.mappings;
        entry.map_mtime = map_mtime;
    }
    if entry.trace_mtime != trace_mtime {
        entry.hints.traces = load_import_traces(&key, &trace_path);
        entry.trace_mtime = trace_mtime;
    }
    entry.hints.clone()
}

fn canonical_repo_root(repo_root: &Path) -> PathBuf {
    repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf())
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|meta| meta.modified()).ok()
}

fn load_import_map(repo_root: &Path, path: &Path) -> ImportMapFile {
    if !path.is_file() {
        return ImportMapFile::default();
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = %err,
                "failed to read import map"
            );
            return ImportMapFile::default();
        }
    };
    let parsed: ImportMapFileRaw = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = %err,
                "failed to parse import map"
            );
            return ImportMapFile::default();
        }
    };
    normalize_import_map(repo_root, parsed)
}

fn normalize_import_map(repo_root: &Path, raw: ImportMapFileRaw) -> ImportMapFile {
    let mut edges = Vec::new();
    for entry in raw.edges {
        let source = match normalize_hint_path(repo_root, &entry.source) {
            Some(source) => source,
            None => continue,
        };
        let target = match normalize_hint_path(repo_root, &entry.target) {
            Some(target) => target,
            None => continue,
        };
        edges.push(ImportMapEdge {
            source,
            target,
            kind: entry.kind,
        });
    }
    let mut mappings = Vec::new();
    for entry in raw.mappings {
        let spec = entry.spec.trim().to_string();
        let target = entry.target.trim().to_string();
        if spec.is_empty() || target.is_empty() {
            continue;
        }
        let source = match entry.source.as_ref() {
            Some(source) => normalize_hint_path(repo_root, source),
            None => None,
        };
        if entry.source.is_some() && source.is_none() {
            continue;
        }
        mappings.push(ImportMapMapping {
            source,
            spec,
            target,
            kind: entry.kind,
        });
    }
    ImportMapFile { edges, mappings }
}

fn load_import_traces(repo_root: &Path, path: &Path) -> Vec<ImportTraceEntry> {
    if !path.is_file() {
        return Vec::new();
    }
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) => {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = %err,
                "failed to read import traces"
            );
            return Vec::new();
        }
    };
    let mut entries = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let record: ImportTraceEntry = match serde_json::from_str(trimmed) {
            Ok(record) => record,
            Err(err) => {
                warn!(
                    target: "docdexd",
                    path = %path.display(),
                    line = idx + 1,
                    error = %err,
                    "failed to parse import trace"
                );
                continue;
            }
        };
        let source = match normalize_hint_path(repo_root, &record.source) {
            Some(source) => source,
            None => continue,
        };
        let target = match normalize_hint_path(repo_root, &record.target) {
            Some(target) => target,
            None => continue,
        };
        entries.push(ImportTraceEntry {
            source,
            target,
            kind: record.kind,
        });
    }
    entries
}

fn normalize_hint_path(repo_root: &Path, value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let path = Path::new(value);
    if path.is_absolute() {
        let rel = path.strip_prefix(repo_root).ok()?;
        return normalize_hint_rel_path(rel);
    }
    normalize_hint_rel_path(path)
}

fn normalize_hint_rel_path(path: &Path) -> Option<String> {
    use std::path::Component;

    if path.components().any(|comp| matches!(comp, Component::ParentDir | Component::Prefix(_))) {
        return None;
    }
    let mut rel = normalize_rel_path(path);
    while rel.starts_with("./") {
        rel = rel.trim_start_matches("./").to_string();
    }
    if rel.starts_with("../") || rel.is_empty() {
        return None;
    }
    Some(rel)
}

fn resolve_hint_target<F>(
    repo_root: &Path,
    rel_path: &str,
    target: &str,
    resolver: &F,
) -> Option<String>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    if target.trim().is_empty() {
        return None;
    }
    if let Some(resolved) = resolver(repo_root, rel_path, target) {
        return Some(resolved);
    }
    normalize_hint_path(repo_root, target)
}

fn resolve_import_map_target<F>(
    repo_root: &Path,
    rel_path: &str,
    import_ref: &ImportRef,
    hints: &ImportHints,
    resolver: &F,
) -> Option<String>
where
    F: Fn(&Path, &str, &str) -> Option<String>,
{
    let spec = import_path_glob(&import_ref.path)?;
    for mapping in &hints.mappings {
        if let Some(source) = &mapping.source {
            if source != rel_path {
                continue;
            }
        }
        if !glob_matches(&mapping.spec, &spec) {
            continue;
        }
        if let Some(target) = resolve_hint_target(repo_root, rel_path, &mapping.target, resolver) {
            return Some(target);
        }
    }
    None
}

fn import_path_glob(path: &ImportPath) -> Option<String> {
    match path {
        ImportPath::Exact(value) => Some(value.clone()),
        ImportPath::Pattern(pattern) => pattern_to_glob(pattern),
    }
}

fn glob_matches(pattern: &str, candidate: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let anchored_start = !pattern.starts_with('*');
    let anchored_end = !pattern.ends_with('*');
    let parts: Vec<&str> = pattern.split('*').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return false;
    }
    let mut idx = 0usize;
    for (i, part) in parts.iter().enumerate() {
        if let Some(pos) = candidate[idx..].find(part) {
            if i == 0 && anchored_start && pos != 0 {
                return false;
            }
            idx += pos + part.len();
        } else {
            return false;
        }
    }
    if anchored_end {
        if let Some(last) = parts.last() {
            if !candidate.ends_with(last) {
                return false;
            }
        }
    }
    true
}

fn resolve_unique_match(
    repo_root: &Path,
    rel_path: &str,
    import_ref: &ImportRef,
    pattern: &StringPattern,
) -> Option<String> {
    match import_ref.language {
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            resolve_unique_match_js_ts(repo_root, rel_path, pattern)
        }
        SourceLanguage::Python => resolve_unique_match_python(repo_root, rel_path, pattern),
        _ => None,
    }
}

fn resolve_unique_match_js_ts(
    repo_root: &Path,
    rel_path: &str,
    pattern: &StringPattern,
) -> Option<String> {
    if !pattern.is_useful() {
        return None;
    }
    if pattern.anchored_start {
        if let Some(first) = pattern.first_part() {
            if !first.starts_with('.') {
                return None;
            }
        }
    } else {
        return None;
    }
    let index = repo_file_index(repo_root);
    if index.js_ts.len() > DYNAMIC_IMPORT_SCAN_LIMIT {
        return None;
    }
    let mut matched: Option<String> = None;
    for target in &index.js_ts {
        let specs = js_ts_candidate_specs(rel_path, target);
        if specs
            .iter()
            .any(|spec| pattern_matches(pattern, spec.as_str()))
        {
            if let Some(existing) = &matched {
                if existing != target {
                    return None;
                }
            } else {
                matched = Some(target.clone());
            }
        }
    }
    matched
}

fn resolve_unique_match_python(
    repo_root: &Path,
    rel_path: &str,
    pattern: &StringPattern,
) -> Option<String> {
    if !pattern.is_useful() {
        return None;
    }
    let index = repo_file_index(repo_root);
    if index.python.len() > DYNAMIC_IMPORT_SCAN_LIMIT {
        return None;
    }
    let mut matched: Option<String> = None;
    for target in &index.python {
        let specs = python_candidate_specs(rel_path, target);
        if specs
            .iter()
            .any(|spec| pattern_matches(pattern, spec.as_str()))
        {
            if let Some(existing) = &matched {
                if existing != target {
                    return None;
                }
            } else {
                matched = Some(target.clone());
            }
        }
    }
    matched
}

fn pattern_matches(pattern: &StringPattern, candidate: &str) -> bool {
    if !pattern.is_useful() {
        return false;
    }
    let mut idx = 0usize;
    let mut first = true;
    for part in &pattern.parts {
        if part.is_empty() {
            continue;
        }
        if let Some(pos) = candidate[idx..].find(part) {
            if first && pattern.anchored_start && pos != 0 {
                return false;
            }
            idx += pos + part.len();
            first = false;
        } else {
            return false;
        }
    }
    if pattern.anchored_end {
        if let Some(last) = pattern.last_part() {
            if !candidate.ends_with(last) {
                return false;
            }
        }
    }
    true
}

fn repo_file_index(repo_root: &Path) -> RepoFileIndex {
    let key = canonical_repo_root(repo_root);
    let mut cache = REPO_FILE_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(index) = cache.get(&key) {
        return index.clone();
    }
    let index = collect_repo_file_index(&key);
    cache.insert(key, index.clone());
    index
}

fn collect_repo_file_index(repo_root: &Path) -> RepoFileIndex {
    let mut index = RepoFileIndex::default();
    let walker = WalkDir::new(repo_root).into_iter().filter_entry(|entry| {
        if entry.file_type().is_dir() {
            return !should_skip_repo_dir(entry);
        }
        true
    });
    for entry in walker.flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let rel = match path.strip_prefix(repo_root) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let rel_str = normalize_rel_path(rel);
        let ext = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
        if matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            index.js_ts.push(rel_str);
        } else if ext == "py" {
            index.python.push(rel_str);
        }
    }
    index
}

fn should_skip_repo_dir(entry: &walkdir::DirEntry) -> bool {
    let name = entry.file_name().to_string_lossy();
    matches!(
        name.as_ref(),
        ".git" | ".docdex" | "node_modules" | "target" | ".idea" | ".vscode"
    )
}

fn js_ts_candidate_specs(importer_rel: &str, target_rel: &str) -> Vec<String> {
    let base_dir = Path::new(importer_rel).parent().unwrap_or(Path::new(""));
    let target_path = Path::new(target_rel);
    let rel = relative_path(base_dir, target_path);
    let mut rel_str = normalize_rel_path(&rel);
    if !rel_str.starts_with("../") && !rel_str.starts_with("./") {
        rel_str = format!("./{rel_str}");
    }
    let mut specs = Vec::new();
    if !rel_str.is_empty() {
        specs.push(rel_str.clone());
    }
    if let Some(stripped) = strip_known_extension(&rel_str) {
        specs.push(stripped);
    }
    if let Some(index_spec) = js_index_spec(&rel_str) {
        specs.push(index_spec);
    }
    let mut seen = HashSet::new();
    specs
        .into_iter()
        .filter(|spec| seen.insert(spec.clone()))
        .collect()
}

fn strip_known_extension(value: &str) -> Option<String> {
    let path = Path::new(value);
    let ext = path.extension()?.to_str()?;
    if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
        return None;
    }
    let mut trimmed = value.to_string();
    if let Some(pos) = trimmed.rfind('.') {
        trimmed.truncate(pos);
        if trimmed.is_empty() {
            return None;
        }
        return Some(trimmed);
    }
    None
}

fn js_index_spec(value: &str) -> Option<String> {
    let lowered = value.to_lowercase();
    for ext in ["js", "jsx", "ts", "tsx", "mjs", "cjs"] {
        let suffix = format!("/index.{ext}");
        if lowered.ends_with(&suffix) {
            let trimmed = value[..value.len() - suffix.len()].to_string();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed);
        }
    }
    None
}

fn python_candidate_specs(importer_rel: &str, target_rel: &str) -> Vec<String> {
    let mut specs = Vec::new();
    if let Some(module) = python_module_name(target_rel) {
        specs.push(module.clone());
        if let Some(relative) = python_relative_spec(importer_rel, &module) {
            specs.push(relative);
        }
    }
    let target_path = Path::new(target_rel);
    let mut rel_str = normalize_rel_path(target_path);
    if !rel_str.is_empty() {
        specs.push(rel_str.clone());
    }
    let base_dir = Path::new(importer_rel).parent().unwrap_or(Path::new(""));
    let rel = relative_path(base_dir, target_path);
    rel_str = normalize_rel_path(&rel);
    if !rel_str.starts_with("../") && !rel_str.starts_with("./") {
        rel_str = format!("./{rel_str}");
    }
    if !rel_str.is_empty() {
        specs.push(rel_str);
    }
    let mut seen = HashSet::new();
    specs
        .into_iter()
        .filter(|spec| seen.insert(spec.clone()))
        .collect()
}

fn python_module_name(rel_path: &str) -> Option<String> {
    if !rel_path.ends_with(".py") {
        return None;
    }
    let path = Path::new(rel_path);
    let file_stem = path.file_stem()?.to_string_lossy();
    let mut parts = Vec::new();
    if let Some(parent) = path.parent() {
        for comp in parent.components() {
            if let std::path::Component::Normal(os) = comp {
                parts.push(os.to_string_lossy().to_string());
            }
        }
    }
    if file_stem != "__init__" {
        parts.push(file_stem.to_string());
    }
    if parts.is_empty() {
        return None;
    }
    Some(parts.join("."))
}

fn python_relative_spec(importer_rel: &str, module: &str) -> Option<String> {
    let importer_path = Path::new(importer_rel);
    let importer_dir = importer_path.parent().unwrap_or(Path::new(""));
    let mut importer_parts = Vec::new();
    for comp in importer_dir.components() {
        if let std::path::Component::Normal(os) = comp {
            importer_parts.push(os.to_string_lossy().to_string());
        }
    }
    if importer_parts.is_empty() {
        return None;
    }
    let target_parts: Vec<&str> = module.split('.').collect();
    let mut common = 0usize;
    while common < importer_parts.len()
        && common < target_parts.len()
        && importer_parts[common] == target_parts[common]
    {
        common += 1;
    }
    let up = importer_parts.len().saturating_sub(common) + 1;
    let mut spec = ".".repeat(up);
    let remainder = target_parts[common..].join(".");
    if !remainder.is_empty() {
        spec.push_str(&remainder);
    }
    Some(spec)
}

fn relative_path(from: &Path, to: &Path) -> PathBuf {
    use std::path::Component;

    let from_components: Vec<Component<'_>> = from.components().collect();
    let to_components: Vec<Component<'_>> = to.components().collect();
    let mut common = 0usize;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }
    let mut result = PathBuf::new();
    for _ in common..from_components.len() {
        result.push("..");
    }
    for comp in to_components.into_iter().skip(common) {
        result.push(comp.as_os_str());
    }
    result
}

fn resolve_js_ts_import(repo_root: &Path, rel_path: &str, import_path: &str) -> Option<String> {
    if !import_path.starts_with('.') {
        return None;
    }
    let base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
    let raw = Path::new(import_path);
    let mut candidates = Vec::new();
    let base = base_dir.join(raw);
    if raw.extension().is_some() {
        candidates.push(base);
    } else {
        for ext in ["ts", "tsx", "js", "jsx"] {
            candidates.push(base.with_extension(ext));
        }
        for ext in ["ts", "tsx", "js", "jsx"] {
            candidates.push(base.join(format!("index.{ext}")));
        }
    }
    resolve_first_existing(repo_root, candidates)
}

fn resolve_python_import(repo_root: &Path, rel_path: &str, import_path: &str) -> Option<String> {
    let import_path = import_path.trim();
    if import_path.is_empty() {
        return None;
    }
    let import_path = if Path::new(import_path).is_absolute() {
        let rel = Path::new(import_path).strip_prefix(repo_root).ok()?;
        return Some(normalize_rel_path(rel));
    } else {
        import_path
    };
    let (dot_count, remainder) = split_leading_dots(import_path);
    let mut base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
    if dot_count == 0 {
        base_dir = Path::new("");
    } else {
        let mut up = dot_count.saturating_sub(1);
        while up > 0 {
            base_dir = base_dir.parent().unwrap_or(Path::new(""));
            up -= 1;
        }
    }
    if remainder.is_empty() {
        let candidate = base_dir.join("__init__.py");
        return resolve_first_existing(repo_root, vec![candidate]);
    }
    let module_path = if remainder.contains('/') || remainder.contains('\\') || remainder.ends_with(".py") {
        PathBuf::from(remainder)
    } else {
        PathBuf::from(remainder.replace('.', "/"))
    };
    let base = base_dir.join(module_path);
    if base.extension().is_some() {
        return resolve_first_existing(repo_root, vec![base]);
    }
    let mut candidates = vec![base.with_extension("py")];
    candidates.push(base.join("__init__.py"));
    resolve_first_existing(repo_root, candidates)
}

fn resolve_rust_mod(repo_root: &Path, rel_path: &str, module: &str) -> Option<String> {
    let base_dir = rust_module_base_dir(rel_path)?;
    let base = base_dir.join(module);
    let mut candidates = Vec::new();
    candidates.push(base.with_extension("rs"));
    candidates.push(base.join("mod.rs"));
    resolve_first_existing(repo_root, candidates)
}

fn resolve_rust_include(repo_root: &Path, rel_path: &str, include_path: &str) -> Option<String> {
    let base_dir = Path::new(rel_path).parent().unwrap_or(Path::new(""));
    let candidate = base_dir.join(include_path);
    resolve_first_existing(repo_root, vec![candidate])
}

fn resolve_go_import(
    repo_root: &Path,
    _rel_path: &str,
    import_path: &str,
    module_path: Option<&str>,
) -> Option<String> {
    let module_path = module_path?;
    if !import_path.starts_with(module_path) {
        return None;
    }
    let mut remainder = import_path[module_path.len()..].trim_start_matches('/');
    if remainder.is_empty() {
        return None;
    }
    if remainder.ends_with('/') {
        remainder = remainder.trim_end_matches('/');
    }
    let base = PathBuf::from(remainder);
    if base.extension().is_some() {
        return resolve_first_existing(repo_root, vec![base]);
    }
    let dir = repo_root.join(&base);
    if dir.is_dir() {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&dir)
            .ok()
            .into_iter()
            .flat_map(|iter| iter.filter_map(|e| e.ok().map(|e| e.path())))
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("go"))
            .collect();
        entries.sort();
        if let Some(path) = entries.first() {
            if let Ok(rel) = path.strip_prefix(repo_root) {
                return Some(normalize_rel_path(rel));
            }
        }
    }
    resolve_first_existing(repo_root, vec![base.with_extension("go")])
}

fn resolve_first_existing(repo_root: &Path, candidates: Vec<PathBuf>) -> Option<String> {
    for rel in candidates {
        let path = repo_root.join(&rel);
        if path.is_file() {
            if let Ok(canon) = path.canonicalize() {
                if !canon.starts_with(repo_root) {
                    continue;
                }
            }
            return Some(normalize_rel_path(&rel));
        }
    }
    None
}

fn normalize_rel_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn node_text<'a>(content: &'a str, node: Node) -> Option<&'a str> {
    content.get(node.start_byte()..node.end_byte())
}

fn string_literal_eval(content: &str, node: Node) -> Option<StringEval> {
    if !is_string_literal_kind(node.kind()) {
        return None;
    }
    let raw = node_text(content, node)?.trim();
    if raw.is_empty() {
        return None;
    }
    if raw.starts_with('`') && raw.contains("${") {
        let pattern = parse_template_string_pattern(raw)?;
        return Some(StringEval::Pattern(pattern));
    }
    let value = string_literal_value(content, node)?;
    Some(StringEval::Exact(value))
}

fn parse_template_string_pattern(raw: &str) -> Option<StringPattern> {
    let raw = strip_string_literal_prefix(raw.trim());
    let inner = raw.strip_prefix('`')?.strip_suffix('`')?;
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = inner.chars().peekable();
    let mut saw_dynamic = false;
    let mut anchored_start = true;
    let mut last_was_dynamic = false;
    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            chars.next();
            if !saw_dynamic && current.is_empty() {
                anchored_start = false;
            }
            if !current.is_empty() {
                parts.push(current.clone());
                current.clear();
            }
            saw_dynamic = true;
            last_was_dynamic = true;
            let mut depth = 1usize;
            while let Some(next) = chars.next() {
                if next == '{' {
                    depth = depth.saturating_add(1);
                } else if next == '}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        break;
                    }
                }
            }
            continue;
        }
        current.push(ch);
        last_was_dynamic = false;
    }
    if !saw_dynamic {
        return None;
    }
    if !current.is_empty() {
        parts.push(current);
    }
    let anchored_end = !last_was_dynamic;
    let pattern = StringPattern {
        parts,
        anchored_start,
        anchored_end,
    };
    Some(pattern.normalize())
}

fn string_literal_value(content: &str, node: Node) -> Option<String> {
    if !is_string_literal_kind(node.kind()) {
        return None;
    }
    let raw = node_text(content, node)?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(value) = parse_rust_raw_string(raw) {
        return Some(value);
    }
    let raw = strip_string_literal_prefix(raw);
    let first = raw.as_bytes().first().copied()?;
    if !matches!(first, b'"' | b'\'' | b'`') {
        return None;
    }
    if raw.starts_with('`') && raw.contains("${") {
        return None;
    }
    let trimmed = raw
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
        .or_else(|| raw.strip_prefix('`').and_then(|s| s.strip_suffix('`')))
        .unwrap_or(raw);
    let value = trimmed.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn is_string_literal_kind(kind: &str) -> bool {
    matches!(
        kind,
        "string"
            | "string_literal"
            | "template_string"
            | "raw_string_literal"
            | "byte_string_literal"
            | "raw_byte_string_literal"
            | "interpreted_string_literal"
    )
}

fn parse_rust_raw_string(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut idx = 0usize;
    if matches!(bytes.get(idx), Some(b'b') | Some(b'B')) {
        idx += 1;
    }
    if !matches!(bytes.get(idx), Some(b'r') | Some(b'R')) {
        return None;
    }
    idx += 1;
    let mut hash_count = 0usize;
    while bytes.get(idx) == Some(&b'#') {
        hash_count += 1;
        idx += 1;
    }
    if bytes.get(idx) != Some(&b'"') {
        return None;
    }
    let start = idx + 1;
    let closing = format!("\"{}", "#".repeat(hash_count));
    let tail = &raw[start..];
    let end = tail.find(&closing)?;
    Some(tail[..end].to_string())
}

fn strip_string_literal_prefix(raw: &str) -> &str {
    let raw = raw.strip_prefix("br").or_else(|| raw.strip_prefix("rb")).unwrap_or(raw);
    let raw = raw.strip_prefix("Br").or_else(|| raw.strip_prefix("bR")).unwrap_or(raw);
    let raw = raw.strip_prefix("BR").or_else(|| raw.strip_prefix("Rb")).unwrap_or(raw);
    let raw = raw.strip_prefix('b').unwrap_or(raw);
    let raw = raw.strip_prefix('B').unwrap_or(raw);
    let raw = raw.strip_prefix('r').unwrap_or(raw);
    raw.strip_prefix('R').unwrap_or(raw)
}

fn normalize_edge_kind(raw: &str) -> &'static str {
    match raw {
        "include" => "include",
        "require" => "require",
        _ => "import",
    }
}

fn static_string_eval_with_resolver<F>(content: &str, node: Node, resolver: &F) -> StringEval
where
    F: Fn(&str) -> Option<StringEval>,
{
    if let Some(eval) = string_literal_eval(content, node) {
        return eval;
    }
    if node.kind() == "identifier" {
        let name = node_text(content, node).unwrap_or_default().trim().to_string();
        if name.is_empty() {
            return StringEval::Unknown;
        }
        return resolver(&name).unwrap_or(StringEval::Unknown);
    }
    match node.kind() {
        "parenthesized_expression" => {
            let mut cursor = node.walk();
            let inner = match node.named_children(&mut cursor).next() {
                Some(inner) => inner,
                None => return StringEval::Unknown,
            };
            static_string_eval_with_resolver(content, inner, resolver)
        }
        "binary_expression" | "binary_operator" => {
            let op = match binary_operator_text(content, node) {
                Some(op) => op,
                None => return StringEval::Unknown,
            };
            if op != "+" {
                return StringEval::Unknown;
            }
            let left = match node.child_by_field_name("left") {
                Some(left) => left,
                None => return StringEval::Unknown,
            };
            let right = match node.child_by_field_name("right") {
                Some(right) => right,
                None => return StringEval::Unknown,
            };
            let left_val = static_string_eval_with_resolver(content, left, resolver);
            let right_val = static_string_eval_with_resolver(content, right, resolver);
            concat_eval(left_val, right_val)
        }
        "concatenated_string" => {
            let mut cursor = node.walk();
            let mut result: Option<StringEval> = None;
            for child in node.named_children(&mut cursor) {
                let value = static_string_eval_with_resolver(content, child, resolver);
                result = Some(match result {
                    Some(existing) => concat_eval(existing, value),
                    None => value,
                });
            }
            result.unwrap_or(StringEval::Unknown)
        }
        "call_expression" | "call" => {
            let name = match call_function_name(content, node) {
                Some(name) => name,
                None => return StringEval::Unknown,
            };
            let args = match call_argument_nodes(node) {
                Some(args) => args,
                None => return StringEval::Unknown,
            };
            let mut values = Vec::new();
            for arg in args {
                values.push(static_string_eval_with_resolver(content, arg, resolver));
            }
            resolve_path_call_eval(name.as_str(), &values)
        }
        _ => StringEval::Unknown,
    }
}

fn is_meaningful_eval(eval: &StringEval) -> bool {
    match eval {
        StringEval::Exact(value) => !value.trim().is_empty(),
        StringEval::Pattern(pattern) => pattern.is_useful(),
        StringEval::Unknown => false,
    }
}

fn eval_to_import_path(eval: StringEval) -> Option<ImportPath> {
    match eval {
        StringEval::Exact(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(ImportPath::Exact(trimmed.to_string()))
            }
        }
        StringEval::Pattern(pattern) => {
            let normalized = pattern.normalize();
            if normalized.is_useful() {
                Some(ImportPath::Pattern(normalized))
            } else {
                None
            }
        }
        StringEval::Unknown => None,
    }
}

fn format_import_path(path: &ImportPath) -> String {
    match path {
        ImportPath::Exact(value) => value.clone(),
        ImportPath::Pattern(pattern) => pattern_to_glob(pattern).unwrap_or_else(|| "*".to_string()),
    }
}

fn concat_eval(left: StringEval, right: StringEval) -> StringEval {
    match (left, right) {
        (StringEval::Exact(left), StringEval::Exact(right)) => {
            StringEval::Exact(format!("{left}{right}"))
        }
        (left, right) => {
            let merged = concat_patterns(pattern_from_eval(left), pattern_from_eval(right));
            if !merged.is_useful() {
                return StringEval::Unknown;
            }
            if let Some(exact) = pattern_to_exact(&merged) {
                return StringEval::Exact(exact);
            }
            StringEval::Pattern(merged)
        }
    }
}

fn pattern_from_eval(eval: StringEval) -> StringPattern {
    match eval {
        StringEval::Exact(value) => StringPattern {
            parts: vec![value],
            anchored_start: true,
            anchored_end: true,
        },
        StringEval::Pattern(pattern) => pattern.normalize(),
        StringEval::Unknown => StringPattern {
            parts: Vec::new(),
            anchored_start: false,
            anchored_end: false,
        },
    }
}

fn concat_patterns(left: StringPattern, right: StringPattern) -> StringPattern {
    let left = left.normalize();
    let right = right.normalize();
    let anchored_start = left.anchored_start;
    let anchored_end = right.anchored_end;
    if left.parts.is_empty() {
        return StringPattern {
            parts: right.parts,
            anchored_start,
            anchored_end,
        };
    }
    if right.parts.is_empty() {
        return StringPattern {
            parts: left.parts,
            anchored_start,
            anchored_end,
        };
    }
    let mut parts = if left.anchored_end && right.anchored_start {
        let mut merged = left.parts;
        if let Some(first) = right.parts.first() {
            let last_idx = merged.len().saturating_sub(1);
            merged[last_idx].push_str(first);
        }
        merged.extend(right.parts.into_iter().skip(1));
        merged
    } else {
        let mut merged = left.parts;
        merged.extend(right.parts);
        merged
    };
    parts.retain(|part| !part.is_empty());
    StringPattern {
        parts,
        anchored_start,
        anchored_end,
    }
}

fn pattern_to_exact(pattern: &StringPattern) -> Option<String> {
    if pattern.anchored_start && pattern.anchored_end && pattern.parts.len() == 1 {
        Some(pattern.parts[0].clone())
    } else {
        None
    }
}

fn pattern_to_glob(pattern: &StringPattern) -> Option<String> {
    if !pattern.is_useful() {
        return None;
    }
    let mut value = String::new();
    if !pattern.anchored_start {
        value.push('*');
    }
    for (idx, part) in pattern.parts.iter().enumerate() {
        if idx > 0 {
            value.push('*');
        }
        value.push_str(part);
    }
    if !pattern.anchored_end {
        value.push('*');
    }
    Some(value)
}

fn binary_operator_text(content: &str, node: Node) -> Option<String> {
    if let Some(op) = node.child_by_field_name("operator") {
        return node_text(content, op).map(|value| value.trim().to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        if let Some(text) = node_text(content, child) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn assignment_operator_is_eq(content: &str, node: Node) -> bool {
    if let Some(op) = node.child_by_field_name("operator") {
        if let Some(text) = node_text(content, op) {
            return text.trim() == "=";
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.is_named() {
            continue;
        }
        if let Some(text) = node_text(content, child) {
            if text.trim() == "=" {
                return true;
            }
        }
    }
    false
}

fn call_argument_nodes(node: Node) -> Option<Vec<Node>> {
    let args = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))?;
    if args.kind() == "arguments" {
        let mut cursor = args.walk();
        let list = args.named_children(&mut cursor).collect::<Vec<_>>();
        if list.is_empty() {
            None
        } else {
            Some(list)
        }
    } else {
        Some(vec![args])
    }
}

fn resolve_path_call_eval(name: &str, args: &[StringEval]) -> StringEval {
    if args.is_empty() {
        return StringEval::Unknown;
    }
    if args.iter().all(|arg| matches!(arg, StringEval::Exact(_))) {
        let values = args
            .iter()
            .map(|value| match value {
                StringEval::Exact(value) => value.clone(),
                _ => String::new(),
            })
            .collect::<Vec<_>>();
        if let Some(resolved) = resolve_path_call(name, &values) {
            return StringEval::Exact(resolved);
        }
    }
    let trimmed = name.trim();
    let is_join = matches!(
        trimmed,
        "path.join"
            | "path.posix.join"
            | "path.win32.join"
            | "os.path.join"
            | "posixpath.join"
            | "ntpath.join"
    );
    let is_resolve = matches!(
        trimmed,
        "path.resolve"
            | "path.posix.resolve"
            | "path.win32.resolve"
            | "os.path.abspath"
            | "pathlib.Path"
            | "Path"
    );
    if !is_join && !is_resolve {
        return StringEval::Unknown;
    }
    let mut force_dot = false;
    let mut result = StringEval::Unknown;
    for (idx, arg) in args.iter().enumerate() {
        if !eval_is_relative(arg) {
            return StringEval::Unknown;
        }
        if idx == 0 {
            if eval_has_relative_prefix(arg) {
                force_dot = true;
            }
            result = arg.clone();
        } else {
            result = concat_eval(result, StringEval::Exact("/".to_string()));
            result = concat_eval(result, arg.clone());
        }
    }
    if force_dot {
        result = prefix_eval(result, "./");
    }
    result
}

fn resolve_path_call(name: &str, args: &[String]) -> Option<String> {
    if args.is_empty() {
        return None;
    }
    let trimmed = name.trim();
    let is_join = matches!(
        trimmed,
        "path.join"
            | "path.posix.join"
            | "path.win32.join"
            | "os.path.join"
            | "posixpath.join"
            | "ntpath.join"
    );
    let is_resolve = matches!(
        trimmed,
        "path.resolve"
            | "path.posix.resolve"
            | "path.win32.resolve"
            | "os.path.abspath"
            | "pathlib.Path"
            | "Path"
    );
    if !is_join && !is_resolve {
        return None;
    }
    let mut force_dot = false;
    let mut path = PathBuf::new();
    for (idx, part) in args.iter().enumerate() {
        if part.starts_with('/') {
            return None;
        }
        if part.contains(':') {
            return None;
        }
        if idx == 0 && (part.starts_with("./") || part.starts_with(".\\")) {
            force_dot = true;
        }
        path.push(part);
    }
    let mut normalized = path.to_string_lossy().replace('\\', "/");
    if force_dot && !normalized.starts_with('.') {
        normalized = format!("./{normalized}");
    }
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn eval_is_relative(eval: &StringEval) -> bool {
    match eval {
        StringEval::Exact(value) => is_relative_path_fragment(value),
        StringEval::Pattern(pattern) => {
            if !pattern.anchored_start {
                return false;
            }
            if let Some(first) = pattern.first_part() {
                is_relative_path_fragment(first)
            } else {
                false
            }
        }
        StringEval::Unknown => false,
    }
}

fn is_relative_path_fragment(value: &str) -> bool {
    if value.starts_with('/') || value.contains(':') {
        return false;
    }
    true
}

fn eval_has_relative_prefix(eval: &StringEval) -> bool {
    match eval {
        StringEval::Exact(value) => value.starts_with("./") || value.starts_with(".\\"),
        StringEval::Pattern(pattern) => pattern
            .first_part()
            .map(|part| part.starts_with("./") || part.starts_with(".\\"))
            .unwrap_or(false),
        StringEval::Unknown => false,
    }
}

fn prefix_eval(eval: StringEval, prefix: &str) -> StringEval {
    match eval {
        StringEval::Exact(value) => StringEval::Exact(format!("{prefix}{value}")),
        StringEval::Pattern(pattern) => {
            let mut pattern = pattern.normalize();
            if let Some(first) = pattern.parts.first_mut() {
                first.insert_str(0, prefix);
            } else {
                pattern.parts.push(prefix.to_string());
                pattern.anchored_start = true;
            }
            StringEval::Pattern(pattern)
        }
        StringEval::Unknown => StringEval::Unknown,
    }
}

fn python_assignment_parts<'a>(content: &str, node: Node<'a>) -> Option<(String, Node<'a>)> {
    let left = node
        .child_by_field_name("left")
        .or_else(|| node.child_by_field_name("target"));
    let right = node
        .child_by_field_name("right")
        .or_else(|| node.child_by_field_name("value"));
    if let (Some(left), Some(right)) = (left, right) {
        if left.kind() == "identifier" {
            let name = node_text(content, left)?.trim().to_string();
            if !name.is_empty() {
                return Some((name, right));
            }
        }
    }
    let mut cursor = node.walk();
    let named: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
    if named.len() >= 2 {
        let left = named.first()?;
        let right = named.last()?;
        if left.kind() == "identifier" {
            let name = node_text(content, *left)?.trim().to_string();
            if !name.is_empty() {
                return Some((name, *right));
            }
        }
    }
    None
}

fn call_function_name(content: &str, node: Node) -> Option<String> {
    let func = node.child_by_field_name("function")?;
    let text = node_text(content, func)?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn js_dynamic_import_kind(name: &str) -> Option<&'static str> {
    let trimmed = name.trim();
    if trimmed == "import" {
        return Some("import");
    }
    if trimmed == "require" || trimmed.ends_with(".require") {
        return Some("require");
    }
    if trimmed == "require.resolve" || trimmed.ends_with(".require.resolve") {
        return Some("require");
    }
    None
}

fn python_dynamic_import_spec(name: &str) -> Option<(&'static str, usize)> {
    let trimmed = name.trim();
    if matches!(
        trimmed,
        "__import__" | "import_module" | "importlib.import_module"
    ) {
        return Some(("import", 0));
    }
    if matches!(
        trimmed,
        "importlib.util.spec_from_file_location" | "spec_from_file_location"
    ) {
        return Some(("import", 1));
    }
    None
}

fn first_argument_import_path<F>(content: &str, node: Node, resolver: &F) -> Option<ImportPath>
where
    F: Fn(&str) -> Option<StringEval>,
{
    argument_import_path(content, node, 0, resolver)
}

fn argument_import_path<F>(
    content: &str,
    node: Node,
    arg_index: usize,
    resolver: &F,
) -> Option<ImportPath>
where
    F: Fn(&str) -> Option<StringEval>,
{
    let args = node
        .child_by_field_name("arguments")
        .or_else(|| node.child_by_field_name("argument"))?;
    if args.kind() == "arguments" {
        let mut cursor = args.walk();
        let list = args.named_children(&mut cursor).collect::<Vec<_>>();
        let arg = list.get(arg_index)?;
        let eval = static_string_eval_with_resolver(content, *arg, resolver);
        return eval_to_import_path(eval);
    }
    if arg_index > 0 {
        return None;
    }
    let eval = static_string_eval_with_resolver(content, args, resolver);
    eval_to_import_path(eval)
}

fn node_name(content: &str, node: Node, field: &str) -> Option<String> {
    let name_node = node.child_by_field_name(field)?;
    let name = node_text(content, name_node)?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn rust_macro_name(content: &str, node: Node) -> Option<String> {
    let name_node = node.child_by_field_name("macro")?;
    let name = node_text(content, name_node)?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn first_string_literal_in_node(content: &str, node: Node) -> Option<String> {
    let kind = node.kind();
    if matches!(
        kind,
        "string_literal"
            | "raw_string_literal"
            | "byte_string_literal"
            | "raw_byte_string_literal"
    ) {
        return string_literal_value(content, node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(value) = first_string_literal_in_node(content, child) {
            return Some(value);
        }
    }
    None
}

fn split_leading_dots(input: &str) -> (usize, &str) {
    let mut count = 0usize;
    for ch in input.chars() {
        if ch == '.' {
            count += 1;
        } else {
            break;
        }
    }
    (count, input[count..].trim())
}

fn extract_rust_use_paths(text: &str) -> Vec<String> {
    let mut trimmed = text.trim();
    if let Some(rest) = trimmed.strip_prefix("use ") {
        trimmed = rest.trim();
    }
    if trimmed.ends_with(';') {
        trimmed = trimmed.trim_end_matches(';').trim();
    }
    if trimmed.contains('*') {
        return Vec::new();
    }
    if let Some(idx) = trimmed.find('{') {
        let prefix = trimmed[..idx].trim_end_matches("::").trim();
        let suffix = trimmed[idx + 1..]
            .split('}')
            .next()
            .unwrap_or("")
            .trim();
        let mut paths = Vec::new();
        for entry in suffix.split(',') {
            let entry = entry.trim();
            if entry.is_empty() || entry.contains('{') {
                continue;
            }
            let entry = entry.split(" as ").next().unwrap_or(entry).trim();
            if entry == "self" {
                if !prefix.is_empty() {
                    paths.push(prefix.to_string());
                }
                continue;
            }
            if prefix.is_empty() {
                paths.push(entry.to_string());
            } else {
                paths.push(format!("{prefix}::{entry}"));
            }
        }
        return paths;
    }
    let simple = trimmed.split(" as ").next().unwrap_or(trimmed).trim();
    if simple.is_empty() {
        Vec::new()
    } else {
        vec![simple.to_string()]
    }
}

fn resolve_rust_use(repo_root: &Path, rel_path: &str, use_path: &str) -> Option<String> {
    if use_path.starts_with("crate::") {
        let remainder = use_path.trim_start_matches("crate::");
        return resolve_rust_module_path(repo_root, Some(Path::new("src")), remainder);
    }
    if use_path.starts_with("self::") {
        let remainder = use_path.trim_start_matches("self::");
        let base_dir = rust_module_base_dir(rel_path)?;
        return resolve_rust_module_path(repo_root, Some(&base_dir), remainder);
    }
    if use_path.starts_with("super::") {
        let remainder = use_path.trim_start_matches("super::");
        let base_dir = rust_module_base_dir(rel_path)?.parent()?.to_path_buf();
        return resolve_rust_module_path(repo_root, Some(&base_dir), remainder);
    }
    None
}

fn resolve_rust_module_path(
    repo_root: &Path,
    base: Option<&Path>,
    module_path: &str,
) -> Option<String> {
    let cleaned = module_path.trim_matches(':').trim();
    if cleaned.is_empty() {
        return None;
    }
    let parts: Vec<&str> = cleaned.split("::").filter(|p| !p.is_empty()).collect();
    for len in (1..=parts.len()).rev() {
        let candidate = PathBuf::from(parts[..len].join("/"));
        let base_dir = base.map(|b| b.to_path_buf()).unwrap_or_default();
        let mut candidates = Vec::new();
        candidates.push(base_dir.join(&candidate).with_extension("rs"));
        candidates.push(base_dir.join(&candidate).join("mod.rs"));
        if let Some(found) = resolve_first_existing(repo_root, candidates) {
            return Some(found);
        }
    }
    None
}

fn rust_module_base_dir(rel_path: &str) -> Option<PathBuf> {
    let path = Path::new(rel_path);
    let file_name = path.file_name()?.to_string_lossy();
    let parent = path.parent().unwrap_or(Path::new(""));
    let base = if file_name == "mod.rs" || file_name == "lib.rs" || file_name == "main.rs" {
        parent.to_path_buf()
    } else {
        let stem = path.file_stem()?.to_string_lossy();
        parent.join(stem.to_string())
    };
    Some(base)
}

fn go_module_path(repo_root: &Path) -> Option<String> {
    let path = repo_root.join("go.mod");
    let content = std::fs::read_to_string(path).ok()?;
    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("module ") {
            let module = rest.trim();
            if !module.is_empty() {
                return Some(module.to_string());
            }
        }
    }
    None
}

pub fn build_impact_response(
    repo_id: &str,
    source: &str,
    traversal: ImpactTraversalResult,
    applied: &ImpactQueryControls,
    diagnostics: Option<ImpactDiagnostics>,
) -> ImpactGraphResponseV1 {
    let mut inbound_set: BTreeSet<String> = BTreeSet::new();
    let mut outbound_set: BTreeSet<String> = BTreeSet::new();

    for edge in &traversal.edges {
        if edge.source == source {
            outbound_set.insert(edge.target.clone());
        }
        if edge.target == source {
            inbound_set.insert(edge.source.clone());
        }
    }

    let edge_types = applied.edge_types.as_ref().map(|set| {
        let mut list = set.iter().cloned().collect::<Vec<_>>();
        list.sort();
        list
    });

    let applied_controls = AppliedImpactControls {
        max_edges: applied.max_edges,
        max_depth: applied.max_depth,
        edge_types,
    };

    ImpactGraphResponseV1 {
        schema: default_impact_schema(),
        repo_id: repo_id.to_string(),
        source: source.to_string(),
        inbound: inbound_set.into_iter().collect(),
        outbound: outbound_set.into_iter().collect(),
        edges: traversal.edges,
        truncated: traversal.truncated,
        applied: applied_controls.clone(),
        applied_limits: applied_controls,
        diagnostics,
    }
}

pub fn build_impact_diagnostics_response(
    repo_id: &str,
    diagnostics: Vec<ImpactDiagnosticsEntry>,
    total: usize,
    limit: usize,
    offset: usize,
) -> ImpactDiagnosticsResponseV1 {
    let truncated = offset.saturating_add(diagnostics.len()) < total;
    ImpactDiagnosticsResponseV1 {
        schema: default_impact_diagnostics_schema(),
        repo_id: repo_id.to_string(),
        total,
        limit,
        offset,
        truncated,
        diagnostics,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn fixture_edges() -> Vec<ImpactGraphEdge> {
        vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "c.ts".into(),
                target: "d.ts".into(),
                kind: Some("require".into()),
            },
            ImpactGraphEdge {
                source: "x.ts".into(),
                target: "a.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "z.ts".into(),
                kind: None,
            },
        ]
    }

    #[test]
    fn validate_controls_reports_multiple_fields() {
        let err = ImpactQueryControlsRaw {
            max_edges: Some(-1),
            max_depth: Some(-2),
            edge_types: Some(vec!["".into()]),
        }
        .validate()
        .unwrap_err();

        let mut fields = err
            .details
            .issues
            .iter()
            .map(|issue| issue.field)
            .collect::<Vec<_>>();
        fields.sort();
        assert_eq!(fields, vec!["edgeTypes", "maxDepth", "maxEdges"]);
    }

    #[test]
    fn traverse_respects_max_edges_and_sets_truncated() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(1),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.truncated);
        assert_eq!(res.edges.len(), 1);
    }

    #[test]
    fn traverse_max_edges_zero_returns_empty_and_marks_truncated_when_edges_exist() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(0),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.edges.is_empty());
        assert!(res.truncated);
    }

    #[test]
    fn traverse_max_edges_does_not_truncate_when_only_duplicates_remain() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("import".into()),
            },
        ];
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(1),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &edges, &controls);
        assert_eq!(res.edges.len(), 1);
        assert!(!res.truncated);
    }

    #[test]
    fn traverse_is_deterministic_across_input_order() {
        let edges_a = fixture_edges();
        let mut edges_b = fixture_edges();
        edges_b.reverse();

        let controls = ImpactQueryControlsRaw {
            max_edges: Some(3),
            max_depth: Some(10),
            edge_types: None,
        }
        .validate()
        .unwrap();

        let res_a = traverse_impact("a.ts", &edges_a, &controls);
        let res_b = traverse_impact("a.ts", &edges_b, &controls);
        assert_eq!(res_a, res_b);
    }

    #[test]
    fn traverse_respects_max_depth() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(1),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(!res
            .edges
            .iter()
            .any(|e| e.source == "b.ts" && e.target == "c.ts"));
    }

    #[test]
    fn traverse_max_depth_zero_returns_no_edges() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(0),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.edges.is_empty());
        assert!(res.truncated);
    }

    #[test]
    fn traverse_max_depth_two_includes_second_hop_but_not_third() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(2),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res
            .edges
            .iter()
            .any(|e| e.source == "b.ts" && e.target == "c.ts"));
        assert!(!res
            .edges
            .iter()
            .any(|e| e.source == "c.ts" && e.target == "d.ts"));
        assert!(res.truncated);
    }

    #[test]
    fn traverse_depth_limit_not_marked_truncated_when_fully_explored() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(3),
            edge_types: None,
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert_eq!(res.edges.len(), fixture_edges().len());
        assert!(!res.truncated);
    }

    #[test]
    fn traverse_filters_edge_types_by_kind() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res
            .edges
            .iter()
            .all(|e| e.kind.as_deref() == Some("include")));
        assert_eq!(res.edges.len(), 1);
        assert_eq!(res.edges[0].source, "x.ts");
        assert_eq!(res.edges[0].target, "a.ts");
    }

    #[test]
    fn traverse_edge_type_filter_marks_truncated_when_edges_are_excluded() {
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &fixture_edges(), &controls);
        assert!(res.truncated);
    }

    #[test]
    fn traverse_edge_type_filter_not_truncated_when_filter_excludes_nothing() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("include".into()),
            },
        ];
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &edges, &controls);
        assert!(!res.truncated);
    }

    #[test]
    fn traverse_does_not_expand_through_excluded_edge_types() {
        let edges = vec![
            ImpactGraphEdge {
                source: "a.ts".into(),
                target: "b.ts".into(),
                kind: Some("include".into()),
            },
            ImpactGraphEdge {
                source: "b.ts".into(),
                target: "c.ts".into(),
                kind: Some("require".into()),
            },
            ImpactGraphEdge {
                source: "c.ts".into(),
                target: "d.ts".into(),
                kind: Some("include".into()),
            },
        ];
        let controls = ImpactQueryControlsRaw {
            max_edges: Some(100),
            max_depth: Some(10),
            edge_types: Some(vec!["include".into()]),
        }
        .validate()
        .unwrap();
        let res = traverse_impact("a.ts", &edges, &controls);

        assert!(res
            .edges
            .iter()
            .all(|edge| edge.kind.as_deref() == Some("include")));
        assert!(
            !res.edges
                .iter()
                .any(|edge| edge.source == "c.ts" && edge.target == "d.ts"),
            "should not reach c.ts without traversing the excluded b.ts -> c.ts require edge"
        );
    }

    #[test]
    fn store_accepts_type_alias_for_kind() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        std::fs::write(
            state_root.join("impact_graph.json"),
            r#"{ "edges": [ { "source": "a.ts", "target": "b.ts", "type": "import" } ] }"#,
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let edges = store.read_edges().expect("read edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].kind.as_deref(), Some("import"));
    }

    #[test]
    fn store_rejects_future_schema_versions() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let payload = serde_json::json!({
            "graphs": [
                {
                    "schema": { "name": "docdex.impact_graph", "version": 99, "compatible": { "min": 99, "max": 99 } },
                    "repo_id": "test-repo",
                    "source": "a.ts",
                    "inbound": [],
                    "outbound": [],
                    "edges": []
                }
            ]
        });
        std::fs::write(
            state_root.join("impact_graph.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize impact_graph.json"),
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let err = store.read_edges().expect_err("expected schema version error");
        assert!(
            err.to_string().contains("unsupported impact graph schema version"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn store_migrates_entries_missing_schema() {
        let dir = TempDir::new().expect("tempdir");
        let state_root = dir.path().join(".docdex");
        let state_dir = state_root.join("index");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let payload = serde_json::json!([
            {
                "repo_id": "test-repo",
                "source": "a.ts",
                "inbound": [],
                "outbound": ["b.ts"],
                "edges": [
                    { "source": "a.ts", "target": "b.ts", "kind": "import" }
                ],
                "diagnostics": {
                    "unresolvedImportsTotal": 1,
                    "unresolvedImportsSample": ["./dyn.js"]
                }
            }
        ]);
        std::fs::write(
            state_root.join("impact_graph.json"),
            serde_json::to_vec_pretty(&payload).expect("serialize impact_graph.json"),
        )
        .expect("write impact_graph.json");

        let store = ImpactGraphStore::new(&state_dir);
        let edges = store.read_edges().expect("read edges");
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].source, "a.ts");
        let diagnostics = store
            .read_diagnostics("a.ts")
            .expect("read diagnostics")
            .expect("missing diagnostics");
        assert_eq!(diagnostics.unresolved_imports_total, 1);
        assert_eq!(diagnostics.unresolved_imports_sample, vec!["./dyn.js"]);
    }
}
