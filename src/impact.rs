use crate::symbols::{language_for_path, SchemaCompatibleRange, SchemaInfo, SourceLanguage};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;
use tracing::{info, warn};
use tree_sitter::{Node, Parser};
use tree_sitter_c as ts_c;
use tree_sitter_c_sharp as ts_c_sharp;
use tree_sitter_cpp as ts_cpp;
use tree_sitter_dart as ts_dart;
use tree_sitter_go as ts_go;
use tree_sitter_java as ts_java;
use tree_sitter_javascript as ts_javascript;
use tree_sitter_kotlin as ts_kotlin;
use tree_sitter_lua as ts_lua;
use tree_sitter_php as ts_php;
use tree_sitter_python as ts_python;
use tree_sitter_ruby as ts_ruby;
use tree_sitter_rust as ts_rust;
use tree_sitter_swift as ts_swift;
use tree_sitter_typescript as ts_typescript;
use walkdir::WalkDir;

mod parser;
mod store;
mod traversal;

const HARD_MAX_EDGES: usize = 10_000;
const HARD_MAX_DEPTH: usize = 100;
pub const DEFAULT_DYNAMIC_IMPORT_SCAN_LIMIT: usize = 50_000;
pub const DEFAULT_IMPORT_TRACES_ENABLED: bool = true;
const IMPORT_MAP_FILE: &str = "docdex.import_map.json";
const IMPORT_TRACES_FILE: &str = "docdex.import_traces.jsonl";
const IMPORT_TRACES_STATE_FILE: &str = "import_traces.jsonl";
const UNRESOLVED_IMPORT_SAMPLE_LIMIT: usize = 5;
const IMPACT_GRAPH_SCHEMA_NAME: &str = "docdex.impact_graph";
const IMPACT_GRAPH_SCHEMA_VERSION: u32 = 2;

use parser::{env_boolish, env_usize};

pub use parser::{build_impact_diagnostics_response, build_impact_response};
pub(crate) use parser::{
    extract_import_edges, impact_graph_path, normalize_edge_kind, normalize_hint_rel_path,
};
pub use store::{ImpactDiagnostics, ImpactGraphStore};
pub use traversal::{
    assemble_impact_context, expand_impact_from_diff_files, expand_impact_from_edges,
    traverse_impact, traverse_impact_multi, ImpactContextAssembly, ImpactContextPruneTrace,
    ImpactExpansionResult, ImpactTraversalResult,
};

#[derive(Debug, Clone, Copy)]
pub struct ImpactSettings {
    pub dynamic_import_scan_limit: usize,
    pub import_traces_enabled: bool,
}

impl Default for ImpactSettings {
    fn default() -> Self {
        Self {
            dynamic_import_scan_limit: DEFAULT_DYNAMIC_IMPORT_SCAN_LIMIT,
            import_traces_enabled: DEFAULT_IMPORT_TRACES_ENABLED,
        }
    }
}

impl ImpactSettings {
    fn with_env_overrides(mut self) -> Self {
        if let Some(limit) = env_usize("DOCDEX_DYNAMIC_IMPORT_SCAN_LIMIT") {
            if limit == 0 {
                warn!(
                    target: "docdexd",
                    value = limit,
                    "DOCDEX_DYNAMIC_IMPORT_SCAN_LIMIT must be > 0; using default"
                );
            } else {
                self.dynamic_import_scan_limit = limit;
            }
        }
        if let Some(enabled) = env_boolish("DOCDEX_ENABLE_IMPORT_TRACES") {
            self.import_traces_enabled = enabled;
        }
        self
    }
}

static IMPACT_SETTINGS: Lazy<Mutex<ImpactSettings>> =
    Lazy::new(|| Mutex::new(ImpactSettings::default().with_env_overrides()));

pub fn apply_impact_settings(settings: ImpactSettings) {
    let settings = settings.with_env_overrides();
    let mut guard = IMPACT_SETTINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = settings;
}

fn impact_settings() -> ImpactSettings {
    IMPACT_SETTINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

fn dynamic_import_scan_limit() -> usize {
    impact_settings().dynamic_import_scan_limit.max(1)
}

fn import_traces_enabled() -> bool {
    impact_settings().import_traces_enabled
}

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

pub fn detect_cycles(edges: &[ImpactGraphEdge]) -> Vec<Vec<String>> {
    let mut graph: HashMap<String, Vec<String>> = HashMap::new();
    for edge in edges {
        graph
            .entry(edge.source.clone())
            .or_default()
            .push(edge.target.clone());
        graph.entry(edge.target.clone()).or_default();
    }

    fn canonicalize_cycle(cycle: &[String]) -> Vec<String> {
        if cycle.is_empty() {
            return Vec::new();
        }
        let len = cycle.len();
        let mut best: Option<Vec<String>> = None;
        for start in 0..len {
            let rotated = (0..len)
                .map(|offset| cycle[(start + offset) % len].clone())
                .collect::<Vec<_>>();
            if best.as_ref().map_or(true, |current| rotated < *current) {
                best = Some(rotated);
            }
        }
        best.unwrap_or_default()
    }

    fn dfs(
        node: &str,
        graph: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        stack: &mut Vec<String>,
        in_stack: &mut HashSet<String>,
        seen: &mut BTreeSet<String>,
        cycles: &mut Vec<Vec<String>>,
    ) {
        visited.insert(node.to_string());
        stack.push(node.to_string());
        in_stack.insert(node.to_string());

        if let Some(neighbors) = graph.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    dfs(neighbor, graph, visited, stack, in_stack, seen, cycles);
                } else if in_stack.contains(neighbor) {
                    if let Some(pos) = stack.iter().position(|item| item == neighbor) {
                        let cycle = canonicalize_cycle(&stack[pos..].to_vec());
                        let key = cycle.join("->");
                        if seen.insert(key) {
                            cycles.push(cycle);
                        }
                    }
                }
            }
        }

        stack.pop();
        in_stack.remove(node);
    }

    let mut visited = HashSet::new();
    let mut stack = Vec::new();
    let mut in_stack = HashSet::new();
    let mut seen = BTreeSet::new();
    let mut cycles = Vec::new();

    let mut nodes: Vec<String> = graph.keys().cloned().collect();
    nodes.sort();
    for node in nodes {
        if !visited.contains(&node) {
            dfs(
                &node,
                &graph,
                &mut visited,
                &mut stack,
                &mut in_stack,
                &mut seen,
                &mut cycles,
            );
        }
    }
    cycles
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
