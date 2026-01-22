use crate::cli::http_client::{resolve_http_timeout_ms, CliHttpClient};
use crate::cli::CliDiffMode;
use crate::config::{self, RepoArgs};
use crate::dag::logging as dag_logging;
use crate::diff;
use crate::index;
use crate::index::Hit;
use crate::libs;
use crate::memory::repo_state_root_from_state_dir;
use crate::memory::MemoryStore;
use crate::ollama::OllamaEmbedder;
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, ProfileBudget, WaterfallPlan,
    WaterfallRequest, WaterfallResult, WebGateConfig,
};
use crate::repo_manager;
use crate::search::MemoryState;
use crate::tier2::Tier2Config;
use crate::util;
use anyhow::{anyhow, Result};
use futures::StreamExt;
use reqwest::header::ACCEPT;
use reqwest::Method;
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

pub(crate) async fn run(
    repo: RepoArgs,
    query: Option<String>,
    model: Option<String>,
    agent: Option<String>,
    agent_id: Option<String>,
    limit: usize,
    max_web_results: Option<usize>,
    repo_only: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
    stream: bool,
    diff_mode: Option<CliDiffMode>,
    diff_base: Option<String>,
    diff_head: Option<String>,
    diff_path: Vec<std::path::PathBuf>,
) -> Result<()> {
    if let Some(query) = query {
        return run_single(
            &repo,
            query,
            model,
            agent,
            agent_id,
            limit,
            max_web_results,
            repo_only,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            compress_results,
            stream,
            diff_mode,
            diff_base,
            diff_head,
            diff_path,
        )
        .await;
    }
    run_repl(
        &repo,
        model,
        agent,
        agent_id,
        limit,
        max_web_results,
        repo_only,
        skip_local_search,
        no_cache,
        llm_filter_local_results,
        compress_results,
        stream,
        diff_mode,
        diff_base,
        diff_head,
        diff_path,
    )
    .await
}

async fn run_single(
    repo: &RepoArgs,
    query: String,
    model: Option<String>,
    agent: Option<String>,
    agent_id: Option<String>,
    limit: usize,
    max_web_results: Option<usize>,
    repo_only: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
    stream: bool,
    diff_mode: Option<CliDiffMode>,
    diff_base: Option<String>,
    diff_head: Option<String>,
    diff_path: Vec<std::path::PathBuf>,
) -> Result<()> {
    let use_local = crate::cli::cli_local_mode();
    let repo_root = repo.repo_root();
    let diff_mode = diff_mode.map(|mode| match mode {
        CliDiffMode::WorkingTree => diff::DiffMode::WorkingTree,
        CliDiffMode::Staged => diff::DiffMode::Staged,
        CliDiffMode::Range => diff::DiffMode::Range,
    });
    let diff_request = diff::resolve_diff_request(
        diff_mode,
        diff_base.clone(),
        diff_head.clone(),
        diff_path.clone(),
    )?;
    if stream {
        return stream_via_http(
            &repo_root,
            &query,
            model.as_deref(),
            agent.as_deref(),
            agent_id.as_deref(),
            limit,
            max_web_results,
            false,
            !repo_only,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            compress_results,
            diff_mode,
            diff_base,
            diff_head,
            diff_path,
        )
        .await;
    }
    if !use_local {
        return run_via_http(
            &repo_root,
            &query,
            model.as_deref(),
            agent.as_deref(),
            agent_id.as_deref(),
            limit,
            max_web_results,
            !repo_only,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            compress_results,
            diff_mode,
            diff_base,
            diff_head,
            diff_path,
        )
        .await;
    }
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let server = Arc::new(index::Indexer::with_config_read_only(
        repo_root,
        index_config,
    )?);
    let libs_indexer = if repo_only {
        None
    } else {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(server.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir)
            .ok()
            .flatten()
            .map(Arc::new)
    };
    let web_gate = WebGateConfig::from_env();
    let config = config::AppConfig::load_default().ok();
    let max_answer_tokens = config
        .as_ref()
        .map(|cfg| cfg.llm.max_answer_tokens)
        .unwrap_or(1024);
    let memory_state =
        resolve_memory_state(config.as_ref(), server.state_dir(), server.repo_root())?;
    let plan = WaterfallPlan::new(
        web_gate,
        Tier2Config::enabled(),
        memory_budget_from_max_answer_tokens(max_answer_tokens),
        ProfileBudget::default(),
    );
    let request_id = format!("cli-query-{}", Uuid::new_v4());
    let repo_state_root = repo_state_root_from_state_dir(server.state_dir());
    let _ = dag_logging::log_node(
        &repo_state_root,
        &request_id,
        "UserRequest",
        &json!({
            "query": query.as_str(),
            "limit": limit,
            "force_web": false,
            "skip_local_search": skip_local_search,
            "repo_only": repo_only,
        }),
    );
    let request = WaterfallRequest {
        request_id: &request_id,
        dag_session_id: None,
        query: &query,
        limit,
        diff: diff_request,
        web_limit: max_web_results,
        force_web: false,
        skip_local_search,
        disable_web_cache: no_cache,
        llm_filter_local_results,
        llm_model: model.as_deref(),
        llm_agent: agent.as_deref(),
        indexer: server.clone(),
        libs_indexer: libs_indexer.clone(),
        plan,
        tier2_limiter: None,
        memory: memory_state.as_ref(),
        profile_state: None,
        profile_agent_id: agent_id.as_deref(),
        ranking_surface: crate::search::RankingSurface::Search,
        async_web: false,
    };
    let waterfall = run_waterfall(request).await?;
    let _ = dag_logging::log_node(
        &repo_state_root,
        &request_id,
        "Decision",
        &json!({
            "hits": waterfall.search_response.hits.len(),
            "top_score": waterfall.search_response.top_score,
            "web_status": waterfall.tier2.status.status,
        }),
    );
    if stream {
        let completion = build_completion(&query, &waterfall.search_response.hits);
        stream_text(&completion)?;
        return Ok(());
    }
    if compress_results {
        println!(
            "{}",
            serde_json::to_string_pretty(&build_compressed_response(&waterfall))?
        );
    } else {
        let tier2_status = waterfall.tier2.status;
        let memory_context = waterfall.memory_context;
        let impact_context = waterfall.impact_context;
        let mut response = waterfall.search_response;
        response.web_discovery = Some(tier2_status);
        response.memory_context = memory_context;
        response.impact_context = impact_context;
        println!("{}", serde_json::to_string_pretty(&response)?);
    }
    Ok(())
}

async fn run_repl(
    repo: &RepoArgs,
    model: Option<String>,
    agent: Option<String>,
    agent_id: Option<String>,
    limit: usize,
    max_web_results: Option<usize>,
    repo_only: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
    stream: bool,
    diff_mode: Option<CliDiffMode>,
    diff_base: Option<String>,
    diff_head: Option<String>,
    diff_path: Vec<std::path::PathBuf>,
) -> Result<()> {
    let stdin = io::stdin();
    let mut reader = io::BufReader::new(stdin.lock());
    let mut line = String::new();
    loop {
        print!("docdex> ");
        io::stdout().flush()?;
        line.clear();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if matches!(trimmed, "exit" | "quit") {
            break;
        }
        run_single(
            repo,
            trimmed.to_string(),
            model.clone(),
            agent.clone(),
            agent_id.clone(),
            limit,
            max_web_results,
            repo_only,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            compress_results,
            stream,
            diff_mode,
            diff_base.clone(),
            diff_head.clone(),
            diff_path.clone(),
        )
        .await?;
    }
    Ok(())
}

async fn run_via_http(
    repo_root: &Path,
    query: &str,
    model: Option<&str>,
    agent: Option<&str>,
    agent_id: Option<&str>,
    limit: usize,
    max_web_results: Option<usize>,
    include_libs: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
    diff_mode: Option<diff::DiffMode>,
    diff_base: Option<String>,
    diff_head: Option<String>,
    diff_path: Vec<std::path::PathBuf>,
) -> Result<()> {
    let payload = search_via_http(
        repo_root,
        query,
        limit,
        include_libs,
        false,
        skip_local_search,
        no_cache,
        llm_filter_local_results,
        max_web_results,
        model,
        agent,
        agent_id,
        diff_mode,
        diff_base,
        diff_head,
        diff_path,
    )
    .await?;
    if compress_results {
        let compressed = build_compressed_from_value(&payload);
        println!("{}", serde_json::to_string_pretty(&compressed)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    }
    Ok(())
}

pub(crate) fn resolve_memory_state(
    config: Option<&config::AppConfig>,
    state_dir: &Path,
    repo_root: &Path,
) -> Result<Option<MemoryState>> {
    let env_enabled = env_boolish("DOCDEX_ENABLE_MEMORY");
    let config_enabled = config.map(|cfg| cfg.memory.enabled).unwrap_or(false);
    if !env_enabled.unwrap_or(config_enabled) {
        return Ok(None);
    }

    let base_url = env_non_empty("DOCDEX_EMBEDDING_BASE_URL")
        .or_else(|| env_non_empty("DOCDEX_OLLAMA_BASE_URL"))
        .or_else(|| config.map(|cfg| cfg.llm.base_url.clone()))
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
    let model = env_non_empty("DOCDEX_EMBEDDING_MODEL")
        .or_else(|| config.map(|cfg| cfg.llm.embedding_model.clone()))
        .unwrap_or_else(|| "nomic-embed-text".to_string());
    if model.trim().is_empty() {
        anyhow::bail!("embedding model is not configured");
    }
    let timeout_ms = env_u64("DOCDEX_EMBEDDING_TIMEOUT_MS").unwrap_or(0);
    let timeout = Duration::from_millis(timeout_ms);
    let embedder = OllamaEmbedder::new(base_url, model, timeout)?;
    let repo_id = crate::repo_manager::repo_fingerprint_sha256(repo_root)?;
    Ok(Some(MemoryState {
        store: MemoryStore::new(state_dir),
        embedder,
        repo_id,
    }))
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = env_non_empty(key)?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_u64(key: &str) -> Option<u64> {
    env_non_empty(key)?.parse::<u64>().ok()
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

fn build_compressed_response(waterfall: &WaterfallResult) -> CompressedResponse {
    let search = &waterfall.search_response;
    let local = build_compressed_local(search);
    let web = best_web_summary(search.web_context.as_deref());
    CompressedResponse {
        results: CompressedResults { local, web },
    }
}

fn build_compressed_from_value(payload: &Value) -> CompressedResponse {
    let local = compressed_local_from_value(payload);
    let web = compressed_web_from_value(payload);
    CompressedResponse {
        results: CompressedResults { local, web },
    }
}

fn build_compressed_local(search: &crate::search::SearchResponse) -> Option<CompressedLocal> {
    let hit = search.hits.first()?;
    let score = search
        .top_score_normalized
        .unwrap_or_else(|| crate::search::normalize_score(hit.score));
    let summary = if !hit.summary.trim().is_empty() {
        Some(truncate_compressed_text(hit.summary.trim()))
    } else if !hit.snippet.trim().is_empty() {
        Some(truncate_compressed_text(hit.snippet.trim()))
    } else {
        None
    };
    Some(CompressedLocal {
        score,
        path: hit.rel_path.clone(),
        summary,
    })
}

fn compressed_local_from_value(payload: &Value) -> Option<CompressedLocal> {
    let hits = payload.get("hits")?.as_array()?;
    let hit = hits.first()?;
    let path = hit
        .get("path")
        .or_else(|| hit.get("rel_path"))
        .and_then(|value| value.as_str())?
        .to_string();
    let score = payload
        .get("top_score_normalized")
        .or_else(|| payload.get("topScoreNormalized"))
        .and_then(|value| value.as_f64())
        .map(|value| value as f32)
        .or_else(|| {
            hit.get("score")
                .and_then(|value| value.as_f64())
                .map(|value| crate::search::normalize_score(value as f32))
        })?;
    let summary = hit
        .get("summary")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(truncate_compressed_text)
        .or_else(|| {
            hit.get("snippet")
                .and_then(|value| value.as_str())
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(truncate_compressed_text)
        });
    Some(CompressedLocal {
        score,
        path,
        summary,
    })
}

fn best_web_summary(
    web_context: Option<&[crate::orchestrator::web::WebFetchResult]>,
) -> Option<CompressedWeb> {
    let items = web_context?;
    let mut best: Option<&crate::orchestrator::web::WebFetchResult> = None;
    for item in items {
        if item.relevance_score.is_none() && item.ai_digested_content.is_none() {
            continue;
        }
        match best {
            Some(current) => {
                if item.relevance_score.unwrap_or(0.0) > current.relevance_score.unwrap_or(0.0) {
                    best = Some(item);
                }
            }
            None => best = Some(item),
        }
    }
    let best = best?;
    let score = best.relevance_score.unwrap_or(0.0);
    let ai_digested_content = best.ai_digested_content.clone();
    let content_snippet = if ai_digested_content.is_none() {
        best.content
            .as_ref()
            .map(|content| truncate_compressed_text(content.trim()))
    } else {
        None
    };
    Some(CompressedWeb {
        score,
        url: best.url.clone(),
        ai_digested_content,
        content_snippet,
    })
}

fn compressed_web_from_value(payload: &Value) -> Option<CompressedWeb> {
    let items = payload
        .get("web_context")
        .or_else(|| payload.get("webContext"))
        .and_then(|value| value.as_array())?;
    let mut best: Option<&Value> = None;
    let mut best_score = 0.0;
    for item in items {
        let ai = item
            .get("ai_digested_content")
            .or_else(|| item.get("aiDigestedContent"))
            .and_then(|value| value.as_str());
        let content = item.get("content").and_then(|value| value.as_str());
        if ai.is_none() && content.is_none() {
            continue;
        }
        let score = item
            .get("relevance_score")
            .or_else(|| item.get("relevanceScore"))
            .and_then(|value| value.as_f64())
            .unwrap_or(0.0) as f32;
        if best.is_none() || score > best_score {
            best = Some(item);
            best_score = score;
        }
    }
    let best = best?;
    let url = best.get("url")?.as_str()?.to_string();
    let ai_digested_content = best
        .get("ai_digested_content")
        .or_else(|| best.get("aiDigestedContent"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    let content_snippet = if ai_digested_content.is_none() {
        best.get("content")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(truncate_compressed_text)
    } else {
        None
    };
    Some(CompressedWeb {
        score: best_score,
        url,
        ai_digested_content,
        content_snippet,
    })
}

fn truncate_compressed_text(text: &str) -> String {
    const MAX_COMPRESS_CHARS: usize = 280;
    let (snippet, _) = crate::max_size::truncate_utf8_chars(text, MAX_COMPRESS_CHARS);
    snippet
}

#[derive(Serialize)]
struct SearchRequest {
    q: String,
    limit: usize,
    include_libs: bool,
    force_web: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_web_results: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_mode: Option<diff::DiffMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_base: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff_head: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diff_path: Vec<String>,
}

pub(crate) async fn search_via_http(
    repo_root: &Path,
    query: &str,
    limit: usize,
    include_libs: bool,
    force_web: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    max_web_results: Option<usize>,
    llm_model: Option<&str>,
    llm_agent: Option<&str>,
    agent_id: Option<&str>,
    diff_mode: Option<diff::DiffMode>,
    diff_base: Option<String>,
    diff_head: Option<String>,
    diff_path: Vec<std::path::PathBuf>,
) -> Result<Value> {
    let client = CliHttpClient::new()?;
    client.ensure_repo(repo_root).await.map_err(|err| {
        anyhow!(
            "docdexd search failed: {err}; ensure `docdexd daemon` (or `docdexd serve --repo {}`) is running",
            repo_root.display()
        )
    })?;
    let payload = SearchRequest {
        q: query.to_string(),
        limit,
        include_libs,
        force_web,
        skip_local_search,
        no_cache,
        llm_filter_local_results,
        max_web_results,
        llm_model: llm_model.map(|value| value.to_string()),
        llm_agent: llm_agent.map(|value| value.to_string()),
        diff_mode,
        diff_base,
        diff_head,
        diff_path: diff_path
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect(),
    };
    let mut req = client.request(Method::GET, "/search").query(&payload);
    req = client.with_repo(req, repo_root)?;
    if let Some(agent_id) = agent_id {
        req = req.header("x-docdex-agent-id", agent_id);
    }
    let timeout_ms = resolve_http_timeout_ms();
    let timeout = Duration::from_millis(timeout_ms);
    let raw = tokio::time::timeout(timeout, async {
        let resp = req.send().await.map_err(|err| {
            anyhow!(
                "docdexd search failed: {err}; ensure `docdexd daemon` (or `docdexd serve --repo {}`) is running",
                repo_root.display()
            )
        })?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "docdexd search failed ({status}): {body}; ensure `docdexd daemon` (or `docdexd serve --repo {}`) is running",
                repo_root.display()
            );
        }
        Ok::<_, anyhow::Error>(resp.text().await?)
    })
    .await
    .map_err(|_| {
        anyhow!(
            "docdexd search failed: request timed out after {timeout_ms}ms; ensure `docdexd daemon` (or `docdexd serve --repo {}`) is running",
            repo_root.display()
        )
    })??;
    Ok(serde_json::from_str(&raw)?)
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent: Option<String>,
    messages: Vec<ChatMessage>,
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    repo_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    docdex: Option<DocdexOptions>,
}

#[derive(Serialize)]
struct ChatMessage {
    role: &'static str,
    content: String,
}

#[derive(Serialize)]
struct DocdexOptions {
    limit: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_web_results: Option<usize>,
    force_web: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    skip_local_search: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    no_cache: Option<bool>,
    include_libs: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    llm_filter_local_results: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compress_results: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    diff: Option<diff::DiffOptions>,
}

#[derive(Serialize)]
struct CompressedResponse {
    results: CompressedResults,
}

#[derive(Serialize)]
struct CompressedResults {
    #[serde(skip_serializing_if = "Option::is_none")]
    local: Option<CompressedLocal>,
    #[serde(skip_serializing_if = "Option::is_none")]
    web: Option<CompressedWeb>,
}

#[derive(Serialize)]
struct CompressedLocal {
    score: f32,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
}

#[derive(Serialize)]
struct CompressedWeb {
    score: f32,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_digested_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_snippet: Option<String>,
}

pub(crate) async fn stream_via_http(
    repo_root: &Path,
    query: &str,
    model: Option<&str>,
    agent: Option<&str>,
    agent_id: Option<&str>,
    limit: usize,
    max_web_results: Option<usize>,
    force_web: bool,
    include_libs: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
    diff_mode: Option<diff::DiffMode>,
    diff_base: Option<String>,
    diff_head: Option<String>,
    diff_path: Vec<std::path::PathBuf>,
) -> Result<()> {
    let client = CliHttpClient::new_streaming()?;
    client.ensure_repo(repo_root).await?;
    let repo_id = repo_manager::repo_fingerprint_sha256(repo_root).ok();
    let diff_payload = if diff_mode.is_some()
        || diff_base.is_some()
        || diff_head.is_some()
        || !diff_path.is_empty()
    {
        Some(diff::DiffOptions {
            mode: diff_mode,
            base: diff_base,
            head: diff_head,
            paths: diff_path
                .iter()
                .map(|path| path.to_string_lossy().to_string())
                .collect(),
        })
    } else {
        None
    };
    let payload = ChatCompletionRequest {
        model: model.map(|value| value.to_string()),
        agent: agent.map(|value| value.to_string()),
        messages: vec![ChatMessage {
            role: "user",
            content: query.to_string(),
        }],
        stream: true,
        repo_id,
        docdex: Some(DocdexOptions {
            limit: Some(limit),
            max_web_results,
            force_web: Some(force_web),
            skip_local_search: Some(skip_local_search),
            no_cache: Some(no_cache),
            include_libs: Some(include_libs),
            llm_filter_local_results: Some(llm_filter_local_results),
            compress_results: Some(compress_results),
            agent_id: agent_id.map(|value| value.to_string()),
            diff: diff_payload,
        }),
    };

    let mut request = client
        .request(Method::POST, "/v1/chat/completions")
        .header(ACCEPT, "text/event-stream")
        .json(&payload);
    request = client.with_repo(request, repo_root)?;
    let response = request.send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "docdexd chat stream failed ({status}): {body}; ensure `docdexd daemon` (or `docdexd serve --repo {}`) is running",
            repo_root.display()
        );
    }

    let mut buffer = String::new();
    let mut stdout = io::stdout();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        for event in drain_sse_events(&mut buffer) {
            for data in extract_sse_data(&event) {
                let trimmed = data.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if trimmed == "[DONE]" {
                    writeln!(stdout)?;
                    stdout.flush()?;
                    return Ok(());
                }
                let value: serde_json::Value = serde_json::from_str(trimmed)?;
                if let Some(content) = value
                    .pointer("/choices/0/delta/content")
                    .and_then(|v| v.as_str())
                {
                    write!(stdout, "{content}")?;
                    stdout.flush()?;
                }
            }
        }
    }
    writeln!(stdout)?;
    Ok(())
}

fn drain_sse_events(buffer: &mut String) -> Vec<String> {
    let mut events = Vec::new();
    loop {
        let Some(pos) = buffer.find("\n\n") else {
            break;
        };
        let event = buffer[..pos].to_string();
        buffer.drain(..pos + 2);
        events.push(event);
    }
    events
}

fn extract_sse_data(event: &str) -> Vec<String> {
    let mut data = Vec::new();
    for line in event.lines() {
        let trimmed = line.trim_end();
        if let Some(payload) = trimmed.strip_prefix("data:") {
            data.push(payload.trim_start().to_string());
        }
    }
    data
}
