use crate::cli::http_client::CliHttpClient;
use crate::config::RepoArgs;
use crate::error::{AppError, ERR_REPO_ENCRYPTION_UNSUPPORTED};
use crate::impact::{
    build_impact_diagnostics_response, ImpactDiagnosticsEntry, ImpactGraphStore,
    ImpactQueryControlsRaw,
};
use crate::index;
use crate::repo_encryption::RepoEncryptionConfig;
use crate::symbols;
use crate::util;
use anyhow::Result;
use reqwest::Method;

const DIAGNOSTICS_DEFAULT_LIMIT: usize = 200;
const DIAGNOSTICS_MAX_LIMIT: usize = 1000;

pub async fn run_diagnostics(
    repo: RepoArgs,
    file: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        return run_diagnostics_via_http(repo, file, limit, offset).await;
    }
    let repo_root = repo.repo_root();
    let repo_encryption = crate::config::AppConfig::load_default()
        .ok()
        .map(|config| config.repo_encryption)
        .unwrap_or_default();
    ensure_impact_allowed(&repo_encryption)?;
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    index::ensure_state_dir_secure(index_config.state_dir())?;

    let repo_id = symbols::repo_id_for_root(&repo_root)?;
    let store = ImpactGraphStore::new(index_config.state_dir());
    let diagnostics_map = store.read_diagnostics_map()?;

    let file = match file {
        Some(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                anyhow::bail!("file must not be empty");
            }
            match normalize_rel_path(trimmed) {
                Some(path) => Some(path),
                None => anyhow::bail!("file must be repo-relative"),
            }
        }
        None => None,
    };

    let (entries, total, limit, offset) = if let Some(file) = file {
        let entry = diagnostics_map
            .get(&file)
            .cloned()
            .map(|diag| ImpactDiagnosticsEntry {
                file: file.clone(),
                diagnostics: diag,
            });
        let diagnostics = entry.into_iter().collect::<Vec<_>>();
        let count = diagnostics.len();
        (diagnostics, count, 1, 0)
    } else {
        let mut entries = diagnostics_map
            .into_iter()
            .map(|(file, diagnostics)| ImpactDiagnosticsEntry { file, diagnostics })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.file.cmp(&b.file));
        let total = entries.len();
        let limit = limit
            .unwrap_or(DIAGNOSTICS_DEFAULT_LIMIT)
            .min(DIAGNOSTICS_MAX_LIMIT)
            .max(1);
        let offset = offset.unwrap_or(0);
        let diagnostics = entries
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        (diagnostics, total, limit, offset)
    };

    let response = build_impact_diagnostics_response(&repo_id, entries, total, limit, offset);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn run_graph(
    repo: RepoArgs,
    file: String,
    max_edges: Option<i64>,
    max_depth: Option<i64>,
    edge_types: Option<String>,
) -> Result<()> {
    let trimmed = file.trim();
    if trimmed.is_empty() {
        anyhow::bail!("file must not be empty");
    }
    let file = match normalize_rel_path(trimmed) {
        Some(path) => path,
        None => anyhow::bail!("file must be repo-relative"),
    };
    if !crate::cli::cli_local_mode() {
        return run_graph_via_http(repo, file, max_edges, max_depth, edge_types).await;
    }

    let repo_root = repo.repo_root();
    let repo_encryption = crate::config::AppConfig::load_default()
        .ok()
        .map(|config| config.repo_encryption)
        .unwrap_or_default();
    ensure_impact_allowed(&repo_encryption)?;
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    index::ensure_state_dir_secure(index_config.state_dir())?;

    let repo_id = symbols::repo_id_for_root(&repo_root)?;
    let store = ImpactGraphStore::new(index_config.state_dir());
    let all_edges = store.read_edges()?;
    let controls = ImpactQueryControlsRaw {
        max_edges,
        max_depth,
        edge_types: parse_edge_types(edge_types),
    }
    .validate()?;
    let traversal = crate::impact::traverse_impact(&file, &all_edges, &controls);
    let diagnostics = match store.read_diagnostics(&file) {
        Ok(value) => value,
        Err(err) => {
            eprintln!("impact diagnostics unavailable: {err}");
            None
        }
    };
    let response =
        crate::impact::build_impact_response(&repo_id, &file, traversal, &controls, diagnostics);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn ensure_impact_allowed(repo_encryption: &RepoEncryptionConfig) -> Result<()> {
    if repo_encryption.is_enabled() {
        return Err(AppError::new(
            ERR_REPO_ENCRYPTION_UNSUPPORTED,
            "impact graph access is disabled when repository encryption is enabled",
        )
        .into());
    }
    Ok(())
}

async fn run_diagnostics_via_http(
    repo: RepoArgs,
    file: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client.request(Method::GET, "/v1/graph/impact/diagnostics");
    if let Some(file) = file {
        req = req.query(&[("file", file)]);
    }
    if let Some(limit) = limit {
        req = req.query(&[("limit", limit)]);
    }
    if let Some(offset) = offset {
        req = req.query(&[("offset", offset)]);
    }
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd impact diagnostics failed ({}): {}", status, text);
    }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

async fn run_graph_via_http(
    repo: RepoArgs,
    file: String,
    max_edges: Option<i64>,
    max_depth: Option<i64>,
    edge_types: Option<String>,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client.request(Method::GET, "/v1/graph/impact");
    let mut params: Vec<(&str, String)> = vec![("file", file)];
    if let Some(max_edges) = max_edges {
        params.push(("maxEdges", max_edges.to_string()));
    }
    if let Some(max_depth) = max_depth {
        params.push(("maxDepth", max_depth.to_string()));
    }
    if let Some(edge_types) = edge_types {
        params.push(("edgeTypes", edge_types));
    }
    req = req.query(&params);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd impact graph failed ({}): {}", status, text);
    }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn normalize_rel_path(input: &str) -> Option<String> {
    crate::path_utils::normalize_repo_relative_string(input)
}

fn parse_edge_types(input: Option<String>) -> Option<Vec<String>> {
    input.map(|raw| raw.split(',').map(|item| item.to_string()).collect())
}

#[cfg(test)]
mod tests {
    use super::normalize_rel_path;

    #[test]
    fn normalize_rel_path_rejects_absolute() {
        assert_eq!(normalize_rel_path("/abs/path"), None);
    }

    #[test]
    fn normalize_rel_path_rejects_parent_segments() {
        assert_eq!(normalize_rel_path("../escape.txt"), None);
        assert_eq!(normalize_rel_path("foo/../bar.txt"), None);
    }

    #[test]
    fn normalize_rel_path_cleans_current_dir() {
        assert_eq!(
            normalize_rel_path("foo/./bar.txt"),
            Some("foo/bar.txt".to_string())
        );
    }
}
