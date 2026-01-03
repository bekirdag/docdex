use crate::cli::http_client::CliHttpClient;
use crate::config::RepoArgs;
use crate::impact::{build_impact_diagnostics_response, ImpactDiagnosticsEntry, ImpactGraphStore};
use crate::index;
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

async fn run_diagnostics_via_http(
    repo: RepoArgs,
    file: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
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

fn normalize_rel_path(input: &str) -> Option<String> {
    let path = std::path::Path::new(input);
    if path.is_absolute() {
        return None;
    }
    let mut clean = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(part) => clean.push(part),
            _ => return None,
        }
    }
    let clean_str = clean.to_string_lossy().replace('\\', "/");
    if clean_str.is_empty() {
        None
    } else {
        Some(clean_str)
    }
}
