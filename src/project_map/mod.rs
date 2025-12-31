use crate::index::Indexer;
use crate::memory::repo_state_root_from_state_dir;
use crate::metrics;
use crate::profiles::{PreferenceCategory, ProfileManager};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const MAP_DIR_NAME: &str = "maps";
const MAP_SEARCH_LIMIT: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMap {
    pub agent_id: String,
    pub keywords: Vec<String>,
    pub generated_at_ms: i64,
    pub nodes: Vec<ProjectMapNode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectMapNode {
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<ProjectMapNode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hidden: Option<usize>,
}

#[derive(Default)]
struct TreeNode {
    children: BTreeMap<String, TreeNode>,
    hidden: usize,
}

pub fn build_project_map(
    indexer: &Indexer,
    profile_manager: &ProfileManager,
    agent_id: &str,
) -> Result<ProjectMap> {
    let keywords = extract_keywords(profile_manager, agent_id)?;
    let query = keywords.join(" ");
    let hits = if query.trim().is_empty() {
        Vec::new()
    } else {
        indexer.search(&query, MAP_SEARCH_LIMIT).unwrap_or_default()
    };

    let mut paths = Vec::new();
    let mut seen = HashSet::new();
    for hit in hits {
        if seen.insert(hit.rel_path.clone()) {
            paths.push(hit.rel_path);
        }
    }

    let mut root = TreeNode::default();
    for path in &paths {
        let components: Vec<&str> = path.split('/').filter(|value| !value.is_empty()).collect();
        root.insert_path(&components);
    }
    let repo_root = indexer.repo_root();
    annotate_hidden_counts(&mut root, repo_root);

    Ok(ProjectMap {
        agent_id: agent_id.to_string(),
        keywords,
        generated_at_ms: now_epoch_ms(),
        nodes: to_project_nodes(&root),
    })
}

pub fn load_cached_project_map(state_dir: &Path, agent_id: &str) -> Option<ProjectMap> {
    let path = project_map_path(state_dir, agent_id);
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => {
            metrics::global().inc_project_map_cache_miss();
            return None;
        }
    };
    match serde_json::from_str(&raw) {
        Ok(map) => {
            metrics::global().inc_project_map_cache_hit();
            Some(map)
        }
        Err(_) => {
            metrics::global().inc_project_map_cache_miss();
            None
        }
    }
}

pub fn write_project_map_cache(state_dir: &Path, map: &ProjectMap) -> Result<()> {
    let path = project_map_path(state_dir, &map.agent_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_string_pretty(map)?;
    fs::write(path, payload)?;
    Ok(())
}

pub fn project_map_path(state_dir: &Path, agent_id: &str) -> PathBuf {
    let repo_root = repo_state_root_from_state_dir(state_dir);
    repo_root
        .join(MAP_DIR_NAME)
        .join(format!("{agent_id}.json"))
}

pub fn render_project_map(map: &ProjectMap) -> String {
    let mut lines = Vec::new();
    lines.push("Project map:".to_string());
    for node in &map.nodes {
        render_node(node, 0, &mut lines);
    }
    lines.join("\n")
}

pub fn invalidate_project_map_cache(state_dir: &Path) -> Result<()> {
    let repo_root = repo_state_root_from_state_dir(state_dir);
    let path = repo_root.join(MAP_DIR_NAME);
    if path.exists() {
        fs::remove_dir_all(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

fn render_node(node: &ProjectMapNode, depth: usize, lines: &mut Vec<String>) {
    let indent = "  ".repeat(depth);
    let mut line = format!("{indent}- {}", node.name);
    if let Some(hidden) = node.hidden {
        if hidden > 0 {
            line.push_str(&format!(" (+{hidden} hidden)"));
        }
    }
    lines.push(line);
    for child in &node.children {
        render_node(child, depth + 1, lines);
    }
}

fn extract_keywords(profile_manager: &ProfileManager, agent_id: &str) -> Result<Vec<String>> {
    let mut keywords = HashSet::new();
    if let Ok(Some(agent)) = profile_manager.get_agent(agent_id) {
        keywords.extend(tokenize_keywords(&agent.role));
    }
    for pref in profile_manager.list_preferences(Some(agent_id))? {
        if pref.category != PreferenceCategory::Tooling {
            continue;
        }
        keywords.extend(tokenize_keywords(&pref.content));
    }
    let mut list: Vec<String> = keywords.into_iter().collect();
    list.sort();
    Ok(list)
}

fn tokenize_keywords(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in text
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(|token| token.trim().to_ascii_lowercase())
    {
        if raw.len() < 3 || is_stopword(&raw) {
            continue;
        }
        out.push(raw);
    }
    out
}

fn is_stopword(token: &str) -> bool {
    matches!(
        token,
        "the"
            | "and"
            | "with"
            | "for"
            | "use"
            | "using"
            | "prefer"
            | "avoid"
            | "from"
            | "that"
            | "this"
            | "your"
            | "you"
            | "are"
            | "into"
            | "than"
            | "then"
            | "its"
            | "our"
            | "out"
            | "via"
            | "set"
            | "when"
            | "not"
            | "but"
            | "all"
            | "any"
            | "types"
    )
}

fn annotate_hidden_counts(node: &mut TreeNode, path: &Path) {
    if !node.children.is_empty() {
        let mut hidden = 0usize;
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !node.children.contains_key(&name) {
                    hidden += 1;
                }
            }
        }
        node.hidden = hidden;
        for (name, child) in node.children.iter_mut() {
            annotate_hidden_counts(child, &path.join(name));
        }
    }
}

#[cfg(test)]
mod tests;

fn to_project_nodes(root: &TreeNode) -> Vec<ProjectMapNode> {
    root.children
        .iter()
        .map(|(name, child)| ProjectMapNode {
            name: name.clone(),
            children: to_project_nodes(child),
            hidden: if child.hidden > 0 {
                Some(child.hidden)
            } else {
                None
            },
        })
        .collect()
}

impl TreeNode {
    fn insert_path(&mut self, components: &[&str]) {
        let Some((head, tail)) = components.split_first() else {
            return;
        };
        let child = self.children.entry((*head).to_string()).or_default();
        if tail.is_empty() {
            return;
        }
        child.insert_path(tail);
    }
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}
