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
    tags: &'static [&'static str],
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
    query_tags: Vec<String>,
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
    avg_local_score: Option<f32>,
    avg_web_score: Option<f32>,
    category_stats: Vec<CategorySummary>,
}

#[derive(Serialize)]
struct CategorySummary {
    tag: String,
    runs: usize,
    success: usize,
    avg_latency_ms: u128,
    local_hits: usize,
    web_hits: usize,
    avg_local_score: Option<f32>,
    avg_web_score: Option<f32>,
}

#[derive(Default)]
struct ScoreAggregate {
    runs: usize,
    success: usize,
    latency_sum_ms: u128,
    local_hits: usize,
    web_hits: usize,
    local_score_sum: f64,
    local_score_count: usize,
    web_score_sum: f64,
    web_score_count: usize,
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
            if !agent_matches_query(agent, &query) {
                continue;
            }
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
                query_tags: query.tags.iter().map(|tag| tag.to_string()).collect(),
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
        EvalQuery {
            id: "q01",
            text: "where is web trigger threshold configured",
            force_web: false,
            tags: &["docdex_query", "legacy_codebase_analysis"],
        },
        EvalQuery {
            id: "q02",
            text: "how to flush web cache",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q03",
            text: "where is docdex_web_research tool registered",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q04",
            text: "where is docdexd preflight check implemented",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q05",
            text: "where does search handler read repo_id header",
            force_web: false,
            tags: &["docdex_query", "cross_file_dependency_mapping"],
        },
        EvalQuery {
            id: "q06",
            text: "where are web summary prompts loaded",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q07",
            text: "where is memory enabled by default",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q08",
            text: "where is embedding timeout configured",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q09",
            text: "where is the waterfall request defined",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q10",
            text: "where is impact graph diagnostics endpoint wired",
            force_web: false,
            tags: &["docdex_query"],
        },
        EvalQuery {
            id: "q11",
            text: "unity c# throw an object with force code sample",
            force_web: true,
            tags: &["code_write"],
        },
        EvalQuery {
            id: "q12",
            text: "rust async mutex example",
            force_web: true,
            tags: &["code_write"],
        },
        EvalQuery {
            id: "q13",
            text: "python read csv example",
            force_web: true,
            tags: &["code_write", "csv_parsing"],
        },
        EvalQuery {
            id: "q14",
            text: "postgres create index concurrently example",
            force_web: true,
            tags: &["backend_logic", "code_write"],
        },
        EvalQuery {
            id: "q15",
            text: "nginx reverse proxy websocket config example",
            force_web: true,
            tags: &["backend_logic", "code_write"],
        },
        EvalQuery {
            id: "q16",
            text: "kubernetes readiness probe example",
            force_web: true,
            tags: &["backend_logic"],
        },
        EvalQuery {
            id: "q17",
            text: "docker compose healthcheck example",
            force_web: true,
            tags: &["backend_logic"],
        },
        EvalQuery {
            id: "q18",
            text: "go http server graceful shutdown example",
            force_web: true,
            tags: &["code_write", "backend_logic"],
        },
        EvalQuery {
            id: "q19",
            text: "javascript fetch timeout example",
            force_web: true,
            tags: &["code_write", "debugging"],
        },
        EvalQuery {
            id: "q20",
            text: "bash command to find files larger than 100MB",
            force_web: true,
            tags: &["bash_scripting", "file_manipulation"],
        },
        EvalQuery {
            id: "q21",
            text: "terraform s3 bucket versioning example",
            force_web: true,
            tags: &["backend_logic", "code_write"],
        },
        EvalQuery {
            id: "q22",
            text: "pytest fixture with temporary postgres example",
            force_web: true,
            tags: &["unit_test_generation", "integration_test_design"],
        },
        EvalQuery {
            id: "q23",
            text: "table driven tests in go example",
            force_web: true,
            tags: &["unit_test_generation"],
        },
        EvalQuery {
            id: "q24",
            text: "integration test plan for oauth login flow",
            force_web: true,
            tags: &["integration_test_design", "test_plan_creation"],
        },
        EvalQuery {
            id: "q25",
            text: "edge cases for CSV import pipeline",
            force_web: true,
            tags: &["edge_case_identification", "test_plan_creation"],
        },
        EvalQuery {
            id: "q26",
            text: "mocking http requests in rust reqwest example",
            force_web: true,
            tags: &["unit_test_generation", "code_write"],
        },
        EvalQuery {
            id: "q27",
            text: "interpret error log: connection reset by peer during upload",
            force_web: true,
            tags: &["log_analysis", "problem_solving"],
        },
        EvalQuery {
            id: "q28",
            text: "root cause analysis for intermittent 500 timeouts",
            force_web: true,
            tags: &["root_cause_analysis", "problem_solving"],
        },
        EvalQuery {
            id: "q29",
            text: "debug null pointer exception in java servlet",
            force_web: true,
            tags: &["debugging", "problem_solving"],
        },
        EvalQuery {
            id: "q30",
            text: "sql error ESCAPE expression must be a single character",
            force_web: true,
            tags: &["logic_debugging", "bug_hunting", "problem_solving"],
        },
        EvalQuery {
            id: "q31",
            text: "owasp ssrf mitigation checklist",
            force_web: true,
            tags: &["security_hardening", "vulnerability_check", "security_scan"],
        },
        EvalQuery {
            id: "q32",
            text: "how to validate jwt signature in go",
            force_web: true,
            tags: &["security_hardening", "code_write"],
        },
        EvalQuery {
            id: "q33",
            text: "secure headers for nginx",
            force_web: true,
            tags: &["security_hardening"],
        },
        EvalQuery {
            id: "q34",
            text: "pci log retention requirements summary",
            force_web: true,
            tags: &["compliance_checking", "policy_verification"],
        },
        EvalQuery {
            id: "q35",
            text: "draft a README quickstart outline for a CLI tool",
            force_web: true,
            tags: &["doc_generation", "readme_cleanup"],
        },
        EvalQuery {
            id: "q36",
            text: "rewrite release notes into 5 bullet summary",
            force_web: true,
            tags: &["summarization", "meeting_notes_cleanup", "text_summarization"],
        },
        EvalQuery {
            id: "q37",
            text: "fix grammar in a changelog paragraph",
            force_web: true,
            tags: &["grammar_check", "spelling_correction", "tone_adjustment"],
        },
        EvalQuery {
            id: "q38",
            text: "format JSON keys in snake_case",
            force_web: true,
            tags: &["json_formatting", "text_cleanup"],
        },
        EvalQuery {
            id: "q39",
            text: "write rust doc comment for a public function",
            force_web: true,
            tags: &["docstring_writing", "comment_formatting"],
        },
        EvalQuery {
            id: "q40",
            text: "design data model for multi-tenant billing system",
            force_web: true,
            tags: &["system_architecture", "database_normalization"],
        },
        EvalQuery {
            id: "q41",
            text: "alternative architecture to reduce api latency",
            force_web: true,
            tags: &["alternative_architecture", "system_architecture"],
        },
        EvalQuery {
            id: "q42",
            text: "create migration plan from monolith to services",
            force_web: true,
            tags: &["plan", "dependency_analysis", "system_architecture"],
        },
        EvalQuery {
            id: "q43",
            text: "triage tasks for adding auth, caching, and audit logs",
            force_web: true,
            tags: &["task_triage", "plan"],
        },
        EvalQuery {
            id: "q44",
            text: "choose best agent for writing tests vs code review",
            force_web: true,
            tags: &["agent_routing", "complexity_scoring"],
        },
        EvalQuery {
            id: "q45",
            text: "code review checklist for auth middleware",
            force_web: true,
            tags: &["code_review", "pull_request_review", "standard_compliance"],
        },
        EvalQuery {
            id: "q46",
            text: "refactor verification steps after large rename",
            force_web: true,
            tags: &["refactor_verification", "minimal_diff_generation"],
        },
        EvalQuery {
            id: "q47",
            text: "syntax checking rules for SQL migrations",
            force_web: true,
            tags: &["syntax_checking"],
        },
        EvalQuery {
            id: "q48",
            text: "write SQL migration to backfill a new column safely",
            force_web: true,
            tags: &["migration_scripts", "migration_assist", "code_write"],
        },
        EvalQuery {
            id: "q49",
            text: "java 8 stream filter example",
            force_web: true,
            tags: &["older_language_support_java8_cpp98", "code_write"],
        },
        EvalQuery {
            id: "q50",
            text: "extract keywords from an incident report",
            force_web: true,
            tags: &["keyword_extraction", "summarization", "text_cleanup"],
        },
        EvalQuery {
            id: "q51",
            text: "classify a log line as error or warning",
            force_web: true,
            tags: &["simple_classification", "log_analysis"],
        },
    ];

    if let Some(max) = max_queries {
        if max > 0 && max < queries.len() {
            queries.truncate(max);
        }
    }
    queries
}

fn agent_matches_query(agent: &McodaAgent, query: &EvalQuery) -> bool {
    if agent.capabilities.is_empty() {
        return false;
    }
    if is_embedding_agent(agent) {
        return false;
    }
    let caps: std::collections::HashSet<&str> =
        agent.capabilities.iter().map(|cap| cap.as_str()).collect();
    if query.tags.is_empty() {
        return true;
    }
    query.tags.iter().any(|tag| caps.contains(tag))
}

fn is_embedding_agent(agent: &McodaAgent) -> bool {
    let embed_caps = [
        "embedding_generation",
        "semantic_search",
        "similarity_matching",
        "vector_indexing",
    ];
    let mut seen = false;
    for cap in &agent.capabilities {
        if embed_caps.contains(&cap.as_str()) {
            seen = true;
        } else {
            return false;
        }
    }
    seen
}

impl ScoreAggregate {
    fn record(&mut self, run: &EvalRunResult) {
        self.runs += 1;
        if run.ok {
            self.success += 1;
        }
        self.latency_sum_ms = self.latency_sum_ms.saturating_add(run.elapsed_ms);
        if let Some(local) = run.local.as_ref() {
            self.local_hits += 1;
            self.local_score_sum += local.score as f64;
            self.local_score_count += 1;
        }
        if let Some(web) = run.web.as_ref() {
            self.web_hits += 1;
            if let Some(score) = web.score {
                self.web_score_sum += score as f64;
                self.web_score_count += 1;
            }
        }
    }

    fn avg_latency_ms(&self) -> u128 {
        if self.runs == 0 {
            0
        } else {
            self.latency_sum_ms / self.runs as u128
        }
    }

    fn avg_local_score(&self) -> Option<f32> {
        if self.local_score_count == 0 {
            None
        } else {
            Some((self.local_score_sum / self.local_score_count as f64) as f32)
        }
    }

    fn avg_web_score(&self) -> Option<f32> {
        if self.web_score_count == 0 {
            None
        } else {
            Some((self.web_score_sum / self.web_score_count as f64) as f32)
        }
    }
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
    let mut buckets: HashMap<String, (AgentSummary, ScoreAggregate, HashMap<String, ScoreAggregate>)> =
        HashMap::new();
    for run in results {
        let entry = buckets.entry(run.agent_id.clone()).or_insert_with(|| {
            (
                AgentSummary {
                    agent_id: run.agent_id.clone(),
                    agent_slug: run.agent_slug.clone(),
                    adapter: run.adapter.clone(),
                    model: run.model.clone(),
                    runs: 0,
                    success: 0,
                    avg_latency_ms: 0,
                    local_hits: 0,
                    web_hits: 0,
                    avg_local_score: None,
                    avg_web_score: None,
                    category_stats: Vec::new(),
                },
                ScoreAggregate::default(),
                HashMap::new(),
            )
        });
        entry.1.record(run);
        for tag in &run.query_tags {
            entry
                .2
                .entry(tag.clone())
                .or_default()
                .record(run);
        }
    }

    let mut summaries: Vec<AgentSummary> = Vec::new();
    for (_, (mut summary, aggregate, tag_buckets)) in buckets {
        summary.runs = aggregate.runs;
        summary.success = aggregate.success;
        summary.local_hits = aggregate.local_hits;
        summary.web_hits = aggregate.web_hits;
        summary.avg_latency_ms = aggregate.avg_latency_ms();
        summary.avg_local_score = aggregate.avg_local_score();
        summary.avg_web_score = aggregate.avg_web_score();
        let mut categories = Vec::new();
        for (tag, agg) in tag_buckets {
            categories.push(CategorySummary {
                tag,
                runs: agg.runs,
                success: agg.success,
                avg_latency_ms: agg.avg_latency_ms(),
                local_hits: agg.local_hits,
                web_hits: agg.web_hits,
                avg_local_score: agg.avg_local_score(),
                avg_web_score: agg.avg_web_score(),
            });
        }
        categories.sort_by(|a, b| a.tag.cmp(&b.tag));
        summary.category_stats = categories;
        summaries.push(summary);
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
