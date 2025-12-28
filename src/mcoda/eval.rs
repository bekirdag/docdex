use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use crate::config::RepoArgs;
use crate::index;
use crate::libs;
use crate::max_size::truncate_utf8_chars;
use crate::mcoda::registry::{McodaAgent, McodaRegistry};
use crate::orchestrator::web::web_context_from_status;
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, WaterfallPlan, WaterfallRequest,
    WebGateConfig,
};
use crate::config;
use crate::tier2::Tier2Config;
use crate::util;

const OUTPUT_RESULTS_FILE: &str = "mcoda_agent_eval_results.jsonl";
const OUTPUT_SUMMARY_FILE: &str = "mcoda_agent_eval_summary.json";
const LOCAL_SUMMARY_MAX_CHARS: usize = 240;
const WEB_SUMMARY_MAX_CHARS: usize = 360;

#[derive(Clone, Debug)]
struct EvalQuery {
    id: &'static str,
    text: &'static str,
    force_web: bool,
}

#[derive(Serialize)]
struct EvalLocalResult {
    path: String,
    score: f32,
    summary: Option<String>,
}

#[derive(Serialize)]
struct EvalWebResult {
    score: Option<f32>,
    url: Option<String>,
    cached: Option<bool>,
    kind: Option<String>,
    ai_digested_content: Option<String>,
}

#[derive(Serialize)]
struct EvalRunResult {
    query_id: String,
    query: String,
    force_web: bool,
    agent_id: String,
    agent_slug: String,
    adapter: String,
    model: Option<String>,
    elapsed_ms: u128,
    ok: bool,
    error: Option<String>,
    local: Option<EvalLocalResult>,
    web: Option<EvalWebResult>,
    web_status: Option<String>,
    web_reason: Option<String>,
}

#[derive(Serialize)]
struct AgentSummary {
    agent_id: String,
    agent_slug: String,
    adapter: String,
    model: Option<String>,
    runs: usize,
    success: usize,
    avg_latency_ms: u128,
    local_hits: usize,
    web_hits: usize,
}

#[derive(Clone)]
pub struct EvalOptions {
    pub repo: RepoArgs,
    pub limit: usize,
    pub max_web_results: Option<usize>,
    pub repo_only: bool,
    pub web_only: bool,
    pub no_cache: bool,
    pub llm_filter_local_results: bool,
    pub max_queries: Option<usize>,
}

pub async fn run_eval(options: EvalOptions) -> Result<()> {
    let registry = McodaRegistry::load_default()?.ok_or_else(|| {
        anyhow!("mcoda registry not found (expected ~/.mcoda/mcoda.db)")
    })?;
    let mut agents = registry.agents.clone();
    agents.sort_by(|a, b| a.slug.cmp(&b.slug));
    if agents.is_empty() {
        return Err(anyhow!("mcoda registry has no agents"));
    }

    let repo_root = options.repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        options.repo.state_dir_override(),
        options.repo.exclude_dir_overrides(),
        options.repo.exclude_prefix_overrides(),
        options.repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let indexer = index::Indexer::with_config_read_only(repo_root, index_config)?;
    let libs_indexer = if options.repo_only {
        None
    } else {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir).ok().flatten()
    };

    let queries = eval_queries(options.max_queries);
    let max_answer_tokens = config::AppConfig::load_default()
        .map(|cfg| cfg.llm.max_answer_tokens)
        .unwrap_or(1024);
    let mut results = Vec::new();
    for query in queries {
        for agent in &agents {
            let agent_key = agent_lookup_key(agent);
            let plan = WaterfallPlan::new(
                WebGateConfig::from_env(),
                Tier2Config::enabled(),
                memory_budget_from_max_answer_tokens(max_answer_tokens),
            );
            let request_id = format!("agent-eval:{}:{}", agent_key, query.id);
            let start = Instant::now();
            let request = WaterfallRequest {
                request_id: &request_id,
                query: query.text,
                limit: options.limit,
                diff: None,
                web_limit: options.max_web_results,
                force_web: query.force_web,
                skip_local_search: options.web_only,
                disable_web_cache: options.no_cache,
                llm_filter_local_results: options.llm_filter_local_results,
                llm_model: None,
                llm_agent: Some(agent_key),
                indexer: &indexer,
                libs_indexer: libs_indexer.as_ref(),
                plan,
                tier2_limiter: None,
                memory: None,
                ranking_surface: crate::search::RankingSurface::Chat,
            };
            let mut run = EvalRunResult {
                query_id: query.id.to_string(),
                query: query.text.to_string(),
                force_web: query.force_web,
                agent_id: agent.id.clone(),
                agent_slug: agent.slug.clone(),
                adapter: agent.adapter.clone(),
                model: resolve_agent_model(agent),
                elapsed_ms: 0,
                ok: false,
                error: None,
                local: None,
                web: None,
                web_status: None,
                web_reason: None,
            };
            match run_waterfall(request).await {
                Ok(result) => {
                    run.ok = true;
                    run.elapsed_ms = start.elapsed().as_millis();
                    run.web_status = Some(format!("{:?}", result.tier2.status.status).to_lowercase());
                    run.web_reason = result.tier2.status.reason.clone();

                    if let Some(hit) = result.search_response.hits.first() {
                        let summary = if !hit.summary.trim().is_empty() {
                            Some(truncate_text(&hit.summary, LOCAL_SUMMARY_MAX_CHARS))
                        } else if !hit.snippet.trim().is_empty() {
                            Some(truncate_text(&hit.snippet, LOCAL_SUMMARY_MAX_CHARS))
                        } else {
                            None
                        };
                        run.local = Some(EvalLocalResult {
                            path: hit.rel_path.clone(),
                            score: hit.score,
                            summary,
                        });
                    }

                    let web_context = result
                        .search_response
                        .web_context
                        .or_else(|| web_context_from_status(&result.tier2.status));
                    if let Some(items) = web_context {
                        if let Some(first) = items.first() {
                            let content = first
                                .ai_digested_content
                                .as_ref()
                                .map(|text| truncate_text(text, WEB_SUMMARY_MAX_CHARS));
                            run.web = Some(EvalWebResult {
                                score: first.relevance_score,
                                url: if first.url.trim().is_empty() {
                                    None
                                } else {
                                    Some(first.url.clone())
                                },
                                cached: Some(first.cached),
                                kind: first.ai_digested_kind.clone(),
                                ai_digested_content: content,
                            });
                        }
                    }
                }
                Err(err) => {
                    run.elapsed_ms = start.elapsed().as_millis();
                    run.error = Some(err.to_string());
                }
            }
            results.push(run);
        }
    }

    let output_dir = std::env::current_dir()?.join("tmp");
    fs::create_dir_all(&output_dir)
        .with_context(|| format!("create eval output dir {}", output_dir.display()))?;
    let results_path = output_dir.join(OUTPUT_RESULTS_FILE);
    let summary_path = output_dir.join(OUTPUT_SUMMARY_FILE);

    write_results(&results_path, &results)?;
    write_summary(&summary_path, &results)?;

    println!(
        "mcoda eval complete: {} runs, results at {}, summary at {}",
        results.len(),
        results_path.display(),
        summary_path.display()
    );
    Ok(())
}

fn eval_queries(max_queries: Option<usize>) -> Vec<EvalQuery> {
    let mut queries = vec![
        EvalQuery { id: "q01", text: "how to disable web cache for a query", force_web: false },
        EvalQuery { id: "q02", text: "where is the mcoda registry reader implemented", force_web: false },
        EvalQuery { id: "q03", text: "where is llm agent option threaded through chat", force_web: false },
        EvalQuery { id: "q04", text: "function that builds query category prompt", force_web: false },
        EvalQuery { id: "q05", text: "where is web cache ttl configured", force_web: false },
        EvalQuery { id: "q06", text: "how to flush web cache", force_web: false },
        EvalQuery { id: "q07", text: "where is default llm provider defined", force_web: false },
        EvalQuery { id: "q08", text: "where is ollama base url configured", force_web: false },
        EvalQuery { id: "q09", text: "how to enable web discovery", force_web: false },
        EvalQuery { id: "q10", text: "memory backend configuration", force_web: false },
        EvalQuery { id: "q11", text: "where is the waterfall request defined", force_web: false },
        EvalQuery { id: "q12", text: "where is web_context_from_status used", force_web: false },
        EvalQuery { id: "q13", text: "docdex default http bind address", force_web: false },
        EvalQuery { id: "q14", text: "llm adapter interface trait", force_web: false },
        EvalQuery { id: "q15", text: "how to override embedding model", force_web: false },
        EvalQuery { id: "q16", text: "java oauth2 code sample", force_web: true },
        EvalQuery { id: "q17", text: "python read csv example", force_web: true },
        EvalQuery { id: "q18", text: "kubernetes readiness probe example", force_web: true },
        EvalQuery { id: "q19", text: "postgres create index example", force_web: true },
        EvalQuery { id: "q20", text: "nginx reverse proxy config example", force_web: true },
        EvalQuery { id: "q21", text: "rust async mutex example", force_web: true },
        EvalQuery { id: "q22", text: "curl post json example", force_web: true },
        EvalQuery { id: "q23", text: "docker compose healthcheck example", force_web: true },
        EvalQuery { id: "q24", text: "git rebase vs merge", force_web: true },
        EvalQuery { id: "q25", text: "javascript fetch timeout example", force_web: true },
        EvalQuery { id: "q26", text: "how to generate ssh key", force_web: true },
        EvalQuery { id: "q27", text: "sql join types", force_web: true },
        EvalQuery { id: "q28", text: "what is oauth2 pkce", force_web: true },
        EvalQuery { id: "q29", text: "how to decode jwt", force_web: true },
        EvalQuery { id: "q30", text: "go http server example", force_web: true },
    ];

    if let Some(max) = max_queries {
        if max > 0 && max < queries.len() {
            queries.truncate(max);
        }
    }
    queries
}

fn write_results(path: &PathBuf, results: &[EvalRunResult]) -> Result<()> {
    let mut out = String::new();
    for result in results {
        let line = serde_json::to_string(result)?;
        out.push_str(&line);
        out.push('\n');
    }
    fs::write(path, out).with_context(|| format!("write eval results {}", path.display()))?;
    Ok(())
}

fn write_summary(path: &PathBuf, results: &[EvalRunResult]) -> Result<()> {
    let mut buckets: HashMap<String, AgentSummary> = HashMap::new();
    for run in results {
        let entry = buckets.entry(run.agent_id.clone()).or_insert_with(|| AgentSummary {
            agent_id: run.agent_id.clone(),
            agent_slug: run.agent_slug.clone(),
            adapter: run.adapter.clone(),
            model: run.model.clone(),
            runs: 0,
            success: 0,
            avg_latency_ms: 0,
            local_hits: 0,
            web_hits: 0,
        });
        entry.runs += 1;
        if run.ok {
            entry.success += 1;
        }
        entry.avg_latency_ms = entry.avg_latency_ms.saturating_add(run.elapsed_ms);
        if run.local.is_some() {
            entry.local_hits += 1;
        }
        if run.web.is_some() {
            entry.web_hits += 1;
        }
    }

    let mut summaries: Vec<AgentSummary> = buckets.into_values().collect();
    for entry in &mut summaries {
        if entry.runs > 0 {
            entry.avg_latency_ms /= entry.runs as u128;
        }
    }
    summaries.sort_by(|a, b| a.agent_slug.cmp(&b.agent_slug));
    let payload = serde_json::to_vec_pretty(&summaries)?;
    fs::write(path, payload).with_context(|| format!("write eval summary {}", path.display()))?;
    Ok(())
}

fn agent_lookup_key(agent: &McodaAgent) -> &str {
    if !agent.slug.trim().is_empty() {
        agent.slug.trim()
    } else {
        agent.id.trim()
    }
}

fn resolve_agent_model(agent: &McodaAgent) -> Option<String> {
    if let Some(model) = agent.default_model.as_ref() {
        let trimmed = model.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    agent
        .models
        .iter()
        .find(|model| model.is_default)
        .map(|model| model.model_name.clone())
}

fn truncate_text(text: &str, limit: usize) -> String {
    if limit == 0 {
        return text.trim().to_string();
    }
    let trimmed = text.trim();
    let (snippet, _) = truncate_utf8_chars(trimmed, limit);
    snippet
}
