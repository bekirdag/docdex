use crate::config::{self, RepoArgs};
use crate::index;
use crate::libs;
use crate::index::Hit;
use crate::orchestrator::{
    run_waterfall, MemoryBudget, WaterfallPlan, WaterfallRequest, WaterfallResult, WebGateConfig,
};
use crate::repo_manager;
use crate::tier2::Tier2Config;
use crate::util;
use anyhow::Result;
use futures::StreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION};
use serde::Serialize;
use std::io::{self, Write};
use std::path::Path;

pub async fn run(
    repo: RepoArgs,
    query: String,
    model: Option<String>,
    limit: usize,
    max_web_results: Option<usize>,
    repo_only: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
    stream: bool,
) -> Result<()> {
    let repo_root = repo.repo_root();
    if stream {
        return stream_via_http(
            &repo_root,
            &query,
            model.as_deref(),
            limit,
            max_web_results,
            false,
            !repo_only,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            compress_results,
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
    let server = index::Indexer::with_config_read_only(repo_root, index_config)?;
    let libs_indexer = if repo_only {
        None
    } else {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(server.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir).ok().flatten()
    };
    let web_gate = WebGateConfig::from_env();
    let plan = WaterfallPlan::new(web_gate, Tier2Config::enabled(), MemoryBudget::default());
    let request = WaterfallRequest {
        request_id: "cli-query",
        query: &query,
        limit,
        web_limit: max_web_results,
        force_web: false,
        skip_local_search,
        disable_web_cache: no_cache,
        llm_filter_local_results,
        llm_model: model.as_deref(),
        indexer: &server,
        libs_indexer: libs_indexer.as_ref(),
        plan,
        tier2_limiter: None,
        memory: None,
    };
    let waterfall = run_waterfall(request).await?;
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
        let mut response = waterfall.search_response;
        response.web_discovery = Some(tier2_status);
        response.memory_context = memory_context;
        println!("{}", serde_json::to_string_pretty(&response)?);
    }
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

fn build_compressed_response(waterfall: &WaterfallResult) -> CompressedResponse {
    let search = &waterfall.search_response;
    let local = build_compressed_local(search);
    let web = best_web_summary(search.web_context.as_deref());
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
                if item.relevance_score.unwrap_or(0.0)
                    > current.relevance_score.unwrap_or(0.0)
                {
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

fn truncate_compressed_text(text: &str) -> String {
    const MAX_COMPRESS_CHARS: usize = 280;
    let (snippet, _) = crate::max_size::truncate_utf8_chars(text, MAX_COMPRESS_CHARS);
    snippet
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: Option<String>,
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
    limit: usize,
    max_web_results: Option<usize>,
    force_web: bool,
    include_libs: bool,
    skip_local_search: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    compress_results: bool,
) -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let bind_addr = config.server.http_bind_addr.trim();
    if bind_addr.is_empty() {
        anyhow::bail!("server.http_bind_addr is empty; set it in ~/.docdex/config.toml");
    }
    let base = if bind_addr.contains("://") {
        bind_addr.to_string()
    } else {
        format!("http://{bind_addr}")
    };
    let url = format!("{}/v1/chat/completions", base.trim_end_matches('/'));
    let repo_id = repo_manager::repo_fingerprint_sha256(repo_root).ok();
    let payload = ChatCompletionRequest {
        model: model.map(|value| value.to_string()),
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
        }),
    };

    let client = reqwest::Client::new();
    let mut request = client.post(url).header(ACCEPT, "text/event-stream").json(&payload);
    if let Ok(token) = std::env::var("DOCDEX_AUTH_TOKEN") {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            request = request.header(AUTHORIZATION, format!("Bearer {trimmed}"));
        }
    }
    let response = request.send().await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "docdexd chat stream failed ({status}): {body}; ensure `docdexd serve --repo {}` is running",
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
                if let Some(content) = value.pointer("/choices/0/delta/content").and_then(|v| v.as_str()) {
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
