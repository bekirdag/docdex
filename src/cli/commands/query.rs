use crate::config::RepoArgs;
use crate::index;
use crate::libs;
use crate::index::Hit;
use crate::orchestrator::{run_waterfall, MemoryBudget, WaterfallRequest, WebGateConfig};
use crate::tier2::Tier2Config;
use crate::util;
use anyhow::Result;
use std::io::{self, Write};

pub async fn run(
    repo: RepoArgs,
    query: String,
    limit: usize,
    repo_only: bool,
    stream: bool,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let server = index::Indexer::with_config_read_only(repo_root, index_config)?;
    let libs_indexer = if repo_only {
        None
    } else {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(server.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir).ok().flatten()
    };
    let web_gate = WebGateConfig::from_env();
    let request = WaterfallRequest {
        request_id: "cli-query",
        query: &query,
        limit,
        force_web: false,
        indexer: &server,
        libs_indexer: libs_indexer.as_ref(),
        web_gate: &web_gate,
        tier2_config: Tier2Config::enabled(),
        tier2_limiter: None,
        memory: None,
        memory_budget: MemoryBudget::default(),
    };
    let waterfall = run_waterfall(request).await?;
    if stream {
        let completion = build_completion(&query, &waterfall.search_response.hits);
        stream_text(&completion)?;
        return Ok(());
    }
    let tier2_status = waterfall.tier2.status;
    let memory_context = waterfall.memory_context;
    let mut response = waterfall.search_response;
    response.web_discovery = Some(tier2_status);
    response.memory_context = memory_context;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub(crate) fn stream_completion(query: &str, hits: &[Hit]) -> Result<()> {
    let completion = build_completion(query, hits);
    stream_text(&completion)
}

fn build_completion(query: &str, hits: &[Hit]) -> String {
    if hits.is_empty() {
        return format!("No local documents matched query: {}", query.trim());
    }

    let mut lines = Vec::new();
    let trimmed = query.trim();
    if trimmed.is_empty() {
        lines.push("Top local matches:".to_string());
    } else {
        lines.push(format!("Top local matches for query: {}", trimmed));
    }
    for hit in hits.iter().take(5) {
        let summary = hit.summary.trim();
        if summary.is_empty() {
            lines.push(format!("- {}", hit.rel_path));
        } else {
            lines.push(format!("- {}: {}", hit.rel_path, summary));
        }
    }
    lines.join("\n")
}

fn stream_text(text: &str) -> Result<()> {
    let mut stdout = io::stdout();
    for (idx, line) in text.lines().enumerate() {
        if idx > 0 {
            writeln!(stdout)?;
        }
        write!(stdout, "{line}")?;
        stdout.flush()?;
    }
    writeln!(stdout)?;
    Ok(())
}
