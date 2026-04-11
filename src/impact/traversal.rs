use super::{normalize_hint_rel_path, ImpactGraphEdge, ImpactGraphStore, ImpactQueryControls};
use anyhow::Result;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactTraversalResult {
    pub edges: Vec<ImpactGraphEdge>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactContextAssembly {
    pub sources: Vec<String>,
    pub expanded_files: Vec<String>,
    pub edges: Vec<ImpactGraphEdge>,
    pub prune_trace: ImpactContextPruneTrace,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImpactContextPruneTrace {
    pub requested_sources: usize,
    pub normalized_sources: usize,
    pub dropped_sources: usize,
    pub expanded_files: usize,
    pub max_edges: usize,
    pub max_depth: usize,
    pub edges: usize,
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
    traverse_impact_roots(std::iter::once(root), all_edges, controls)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImpactExpansionResult {
    pub sources: Vec<String>,
    pub edges: Vec<ImpactGraphEdge>,
    pub truncated: bool,
}

pub fn expand_impact_from_diff_files(
    state_dir: &Path,
    diff_files: &[String],
    controls: &ImpactQueryControls,
) -> Result<ImpactExpansionResult> {
    let store = ImpactGraphStore::new(state_dir);
    let edges = store.read_edges()?;
    Ok(expand_impact_from_edges(diff_files, &edges, controls))
}

pub fn expand_impact_from_edges(
    diff_files: &[String],
    all_edges: &[ImpactGraphEdge],
    controls: &ImpactQueryControls,
) -> ImpactExpansionResult {
    let sources = normalize_diff_sources(diff_files);
    if sources.is_empty() || all_edges.is_empty() {
        return ImpactExpansionResult {
            sources,
            edges: Vec::new(),
            truncated: false,
        };
    }
    let traversal = traverse_impact_multi(&sources, all_edges, controls);
    ImpactExpansionResult {
        sources,
        edges: traversal.edges,
        truncated: traversal.truncated,
    }
}

pub fn assemble_impact_context(
    diff_files: &[String],
    expansion: ImpactExpansionResult,
    controls: &ImpactQueryControls,
) -> ImpactContextAssembly {
    let requested_sources = diff_files.len();
    let mut sources_set: BTreeSet<String> = BTreeSet::new();
    for source in &expansion.sources {
        sources_set.insert(source.clone());
    }
    let mut expanded_set: BTreeSet<String> = BTreeSet::new();
    for edge in &expansion.edges {
        expanded_set.insert(edge.source.clone());
        expanded_set.insert(edge.target.clone());
    }
    for source in &sources_set {
        expanded_set.remove(source);
    }
    let expanded_files: Vec<String> = expanded_set.into_iter().collect();
    let edges_count = expansion.edges.len();
    let expanded_count = expanded_files.len();
    let sources = expansion.sources.clone();
    let dropped_sources = requested_sources.saturating_sub(sources.len());
    let prune_trace = ImpactContextPruneTrace {
        requested_sources,
        normalized_sources: sources.len(),
        dropped_sources,
        expanded_files: expanded_count,
        max_edges: controls.max_edges,
        max_depth: controls.max_depth,
        edges: edges_count,
        truncated: expansion.truncated,
    };
    ImpactContextAssembly {
        sources,
        expanded_files,
        edges: expansion.edges,
        prune_trace,
    }
}

fn normalize_diff_sources(diff_files: &[String]) -> Vec<String> {
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for file in diff_files {
        if let Some(normalized) = normalize_hint_rel_path(Path::new(file)) {
            sources.insert(normalized);
        }
    }
    sources.into_iter().collect()
}

pub fn traverse_impact_multi(
    roots: &[String],
    all_edges: &[ImpactGraphEdge],
    controls: &ImpactQueryControls,
) -> ImpactTraversalResult {
    traverse_impact_roots(roots.iter().map(String::as_str), all_edges, controls)
}

fn traverse_impact_roots<'a>(
    roots: impl IntoIterator<Item = &'a str>,
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

    fn incident_edges(
        node: &str,
        all_edges: &[ImpactGraphEdge],
        outgoing: &HashMap<&str, Vec<usize>>,
        incoming: &HashMap<&str, Vec<usize>>,
    ) -> Vec<usize> {
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
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    for root in roots {
        let root = root.trim();
        if root.is_empty() {
            continue;
        }
        if visited.insert(root.to_string()) {
            queue.push_back((root.to_string(), 0));
        }
    }
    if queue.is_empty() {
        return ImpactTraversalResult {
            edges: Vec::new(),
            truncated: false,
        };
    }

    while let Some((node, depth)) = queue.pop_front() {
        if depth >= controls.max_depth {
            if depth == controls.max_depth && !hard_truncated {
                let incident = incident_edges(node.as_str(), all_edges, &outgoing, &incoming);
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

        let incident = incident_edges(node.as_str(), all_edges, &outgoing, &incoming);

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
