use crate::symbols::{SchemaCompatibleRange, SchemaInfo};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};

const HARD_MAX_EDGES: usize = 10_000;
const HARD_MAX_DEPTH: usize = 100;

fn default_impact_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.impact_graph".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImpactGraphEdge {
    pub source: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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

#[derive(Deserialize)]
#[serde(untagged)]
enum ImpactGraphStoreFile {
    Edges(Vec<ImpactGraphEdge>),
    Container { edges: Vec<ImpactGraphEdge> },
}

impl ImpactGraphStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("impact_graph.json"),
        }
    }

    pub fn read_edges(&self) -> Result<Vec<ImpactGraphEdge>> {
        let raw = match std::fs::read_to_string(&self.path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).with_context(|| format!("read {}", self.path.display())),
        };

        let parsed: ImpactGraphStoreFile =
            serde_json::from_str(&raw).context("parse impact_graph.json")?;
        Ok(match parsed {
            ImpactGraphStoreFile::Edges(edges) => edges,
            ImpactGraphStoreFile::Container { edges } => edges,
        })
    }
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
        (edge.source.as_str(), edge.target.as_str(), edge.kind.as_deref())
    }

    let mut outgoing: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut incoming: HashMap<&str, Vec<usize>> = HashMap::new();
    for (idx, edge) in all_edges.iter().enumerate() {
        if !edge_kind_matches(edge, &controls.edge_types) {
            continue;
        }
        outgoing.entry(edge.source.as_str()).or_default().push(idx);
        incoming.entry(edge.target.as_str()).or_default().push(idx);
    }

    let mut seen_edges: HashSet<(&str, &str, Option<&str>)> = HashSet::new();
    let mut result: Vec<ImpactGraphEdge> = Vec::new();
    let mut truncated = false;

    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(root.to_string());
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    queue.push_back((root.to_string(), 0));

    let incident_edges =
        |node: &str,
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
            if depth == controls.max_depth && !truncated {
                let incident = incident_edges(node.as_str(), &outgoing, &incoming);
                for edge_idx in incident {
                    let edge = &all_edges[edge_idx];
                    let key = edge_sort_key(edge);
                    if !seen_edges.contains(&key) {
                        truncated = true;
                        break;
                    }
                }
                if truncated {
                    break;
                }
            }
            continue;
        }

        let incident = incident_edges(node.as_str(), &outgoing, &incoming);

        for edge_idx in incident {
            let edge = &all_edges[edge_idx];
            let key = edge_sort_key(edge);
            if !seen_edges.insert(key) {
                continue;
            }
            if result.len() >= controls.max_edges {
                truncated = true;
                break;
            }
            result.push(edge.clone());

            let neighbor = if edge.source == node { &edge.target } else { &edge.source };
            if depth + 1 <= controls.max_depth && visited.insert(neighbor.clone()) {
                queue.push_back((neighbor.clone(), depth + 1));
            }
        }

        if truncated {
            break;
        }
    }

    ImpactTraversalResult {
        edges: result,
        truncated,
    }
}

pub fn build_impact_response(
    repo_id: &str,
    source: &str,
    traversal: ImpactTraversalResult,
    applied: &ImpactQueryControls,
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

    ImpactGraphResponseV1 {
        schema: default_impact_schema(),
        repo_id: repo_id.to_string(),
        source: source.to_string(),
        inbound: inbound_set.into_iter().collect(),
        outbound: outbound_set.into_iter().collect(),
        edges: traversal.edges,
        truncated: traversal.truncated,
        applied: AppliedImpactControls {
            max_edges: applied.max_edges,
            max_depth: applied.max_depth,
            edge_types,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(res.edges.iter().all(|e| e.kind.as_deref() == Some("include")));
        assert_eq!(res.edges.len(), 1);
        assert_eq!(res.edges[0].source, "x.ts");
        assert_eq!(res.edges[0].target, "a.ts");
    }
}
