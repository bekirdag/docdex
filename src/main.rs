mod audit;
mod browser_session;
mod chrome_watchdog;
mod config;
mod daemon;
mod error;
<<<<<<< HEAD
mod explainability;
=======
mod max_size;
>>>>>>> mcoda/task/bck-05-us-10-t25
mod metrics;
mod tier2;
mod waterfall_trace;
mod impact;
mod index;
mod libs;
mod libs_source_resolver;
mod limits;
mod memory;
mod mcp;
mod ollama;
mod ratelimit;
mod repo_identity;
mod search;
mod state_layout;
mod symbols;
mod state_paths;
mod util;
mod watcher;

use crate::config::RepoArgs;
use crate::error::StartupError;
use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use serde_json::json;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "docdexd",
    version,
    about = "Local documentation index/search daemon",
<<<<<<< HEAD
    long_about = "Docdex indexes plain-text/markdown documentation under a workspace and serves top-k search/snippet results over HTTP or CLI. Defaults store data under ~/.docdex/state/repos/<fingerprint>/index and avoid common tool caches; override paths and exclusions with --state-dir/--exclude-* or matching env vars. Optional MCP server (`docdexd mcp`) exposes docdex_search/index/files/open/stats tools over stdio for MCP-aware clients; register it in your MCP client as server \"docdex\" with command: docdexd mcp --repo <repo> --log warn."
=======
    long_about = "Docdex indexes plain-text/markdown documentation under a workspace and serves top-k search/snippet results over HTTP or CLI. Defaults store data under ~/.docdex/state/repos/<fingerprint>/index; override the global state root and exclusions with --state-dir/--exclude-* or matching env vars. Optional MCP server (`docdexd mcp`) exposes docdex_search/index/files/open/stats tools over stdio for MCP-aware clients; register it in your MCP client as server \"docdex\" with command: docdexd mcp --repo <repo> --log warn."
>>>>>>> mcoda/task/ops-01-us-03-t02
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve HTTP API for search/snippets.
    Serve {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 46137)]
        port: u16,
        #[arg(long, default_value = "info")]
        log: String,
        #[arg(
            long,
            env = "DOCDEX_TLS_CERT",
            requires = "tls_key",
            help = "TLS certificate PEM file for HTTPS (requires --tls-key)"
        )]
        tls_cert: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_TLS_KEY",
            requires = "tls_cert",
            help = "TLS private key PEM file for HTTPS (requires --tls-cert)"
        )]
        tls_key: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_CERTBOT_DOMAIN",
            conflicts_with_all = ["tls_cert", "tls_key", "certbot_live_dir"],
            help = "Use certbot live dir at /etc/letsencrypt/live/<domain> for TLS (implies HTTPS)"
        )]
        certbot_domain: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_CERTBOT_LIVE_DIR",
            value_name = "PATH",
            conflicts_with_all = ["tls_cert", "tls_key", "certbot_domain"],
            help = "Use explicit certbot live dir containing fullchain.pem and privkey.pem (implies HTTPS)"
        )]
        certbot_live_dir: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_INSECURE_HTTP",
            default_value_t = false,
            help = "Allow plain HTTP on non-loopback binds (use only behind a trusted proxy)"
        )]
        insecure: bool,
        #[arg(
            long,
            env = "DOCDEX_REQUIRE_TLS",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Require TLS for non-loopback binds (set to false when TLS is already terminated by a trusted proxy)"
        )]
        require_tls: bool,
        #[arg(
            long,
            env = "DOCDEX_AUTH_TOKEN",
            help = "Optional bearer token required on HTTP requests (Authorization: Bearer ...)"
        )]
        auth_token: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_MAX_LIMIT",
            default_value_t = 8,
            help = "Maximum allowed `limit` on search/snippet requests"
        )]
        max_limit: usize,
        #[arg(
            long,
            env = "DOCDEX_MAX_QUERY_BYTES",
            default_value_t = 4096,
            help = "Maximum allowed query string size in bytes"
        )]
        max_query_bytes: usize,
        #[arg(
            long,
            env = "DOCDEX_MAX_REQUEST_BYTES",
            default_value_t = 16384,
            help = "Maximum allowed request size (Content-Length or body hint) in bytes"
        )]
        max_request_bytes: usize,
        #[arg(
            long,
            env = "DOCDEX_RATE_LIMIT_PER_MIN",
            default_value_t = 0u32,
            help = "Optional per-IP request rate limit per minute (0 disables rate limiting; defaults on in secure mode)"
        )]
        rate_limit_per_min: u32,
        #[arg(
            long,
            env = "DOCDEX_RATE_LIMIT_BURST",
            default_value_t = 0u32,
            help = "Optional burst size for rate limiting (defaults to per-minute limit when unset/0; defaults on in secure mode)"
        )]
        rate_limit_burst: u32,
        #[arg(
            long,
            env = "DOCDEX_STRIP_SNIPPET_HTML",
            default_value_t = false,
            action = ArgAction::SetTrue,
            help = "Omit snippet HTML in responses (serves text-only snippets)"
        )]
        strip_snippet_html: bool,
        #[arg(
            long,
            env = "DOCDEX_SECURE_MODE",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Secure defaults: require auth token, default rate limits, loopback allow-list when none provided"
        )]
        secure_mode: bool,
        #[arg(
            long,
            env = "DOCDEX_DISABLE_SNIPPET_TEXT",
            default_value_t = false,
            help = "Omit snippet text/html from responses (only doc metadata is returned)"
        )]
        disable_snippet_text: bool,
        #[arg(
            long,
            env = "DOCDEX_ENABLE_MEMORY",
            default_value_t = false,
            action = ArgAction::Set,
            help = "Enable repo-scoped memory endpoints (/v1/memory/store, /v1/memory/recall)"
        )]
        enable_memory: bool,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_BASE_URL",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (memory); takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (memory) (legacy; prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Ollama embedding model identifier"
        )]
        embedding_model: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
            default_value_t = 5000u64,
            help = "Embedding request timeout in milliseconds"
        )]
        embedding_timeout_ms: u64,
        #[arg(
            long,
            env = "DOCDEX_ACCESS_LOG",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Emit structured access logs (redacts query values; disable with --access-log=false)"
        )]
        access_log: bool,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_LOG_PATH",
<<<<<<< HEAD
            help = "Audit log path (JSON lines with hash chain; defaults to <repo_state_dir>/audit.log)"
=======
            help = "Audit log path (JSON lines with hash chain; defaults to <repo-state-root>/audit.log)"
>>>>>>> mcoda/task/ops-01-us-03-t02
        )]
        audit_log_path: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_MAX_BYTES",
            default_value_t = 5_000_000_u64,
            help = "Rotate audit log after this many bytes"
        )]
        audit_max_bytes: u64,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_MAX_FILES",
            default_value_t = 5_usize,
            help = "How many rotated audit log files to keep"
        )]
        audit_max_files: usize,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_DISABLE",
            default_value_t = false,
            help = "Disable audit logging"
        )]
        audit_disable: bool,
        #[arg(
            long,
            env = "DOCDEX_RUN_AS_UID",
            help = "(Unix only) Drop privileges to this numeric UID after startup preparation"
        )]
        run_as_uid: Option<u32>,
        #[arg(
            long,
            env = "DOCDEX_RUN_AS_GID",
            help = "(Unix only) Drop privileges to this numeric GID after startup preparation"
        )]
        run_as_gid: Option<u32>,
        #[arg(
            long,
            env = "DOCDEX_CHROOT",
            value_name = "PATH",
            help = "(Unix only) chroot to PATH before serving; repo/state paths must be reachable inside the jail"
        )]
        chroot_dir: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_UNSHARE_NET",
            default_value_t = false,
            help = "(Linux only) unshare network namespace before serving (requires CAP_SYS_ADMIN/root; no-op elsewhere)"
        )]
        unshare_net: bool,
        #[arg(
            long,
            env = "DOCDEX_ALLOW_IPS",
            value_delimiter = ',',
            value_parser = config::non_empty_string,
            help = "Optional comma-separated IPs/CIDRs allowed to access the HTTP API (default: loopback-only in secure mode; allow all when secure mode is disabled)"
        )]
        allow_ip: Vec<String>,
    },
    /// Print help for all commands and flags.
    HelpAll,
    /// Scan the index for sensitive terms before enabling access.
    SelfCheck {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_delimiter = ',',
            value_parser = config::non_empty_string,
            required = true,
            help = "Comma-separated sensitive terms to scan for"
        )]
        terms: Vec<String>,
        #[arg(
            long,
            default_value_t = 5,
            help = "Max hits to return per term; reports if more exist"
        )]
        limit: usize,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            help = "Include built-in sensitive patterns (tokens/keys/passwords) in the scan"
        )]
        include_default_patterns: bool,
    },
    /// Build or rebuild the entire index for a repo.
    Index {
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// Ingest a single document file (incremental update).
    Ingest {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long)]
        file: PathBuf,
    },
    /// Run an ad-hoc query via CLI (JSON output).
    Query {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(short, long)]
        query: String,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(
            long,
            default_value_t = false,
            help = "Only search the repo index (ignore any repo-scoped libs index, if present)"
        )]
        repo_only: bool,
    },
    /// Ingest library documentation sources into the repo-scoped libs index.
    LibsIngest {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Path to a JSON file containing `{ \"sources\": [...] }` entries"
        )]
        sources: PathBuf,
    },
    /// Discover eligible library documentation sources for a repo (dependency manifests + optional configured sources).
    LibsDiscover {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Optional JSON file containing `{ \"sources\": [...] }` entries to merge as explicit configured sources"
        )]
        sources: Option<PathBuf>,
    },
    /// Store a memory item (requires Ollama embeddings).
    MemoryStore {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string, help = "Text to store in memory")]
        text: String,
        #[arg(long, help = "Optional JSON object metadata (stringified)")]
        metadata: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_BASE_URL",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls; takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (legacy; prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Ollama embedding model identifier"
        )]
        embedding_model: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
            default_value_t = 5000u64,
            help = "Embedding request timeout in milliseconds"
        )]
        embedding_timeout_ms: u64,
    },
    /// Recall memory items by semantic similarity (requires Ollama embeddings).
    MemoryRecall {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string, help = "Query text to embed")]
        query: String,
        #[arg(long, default_value_t = 5, help = "Max results to return (1..=50)")]
        top_k: usize,
        #[arg(
            long,
            help = "Optional max items to keep after deterministic pruning (0..=50). Defaults to --top-k."
        )]
        max_items: Option<usize>,
        #[arg(
            long,
            help = "Optional token budget for deterministic memory context truncation (whitespace token estimate)."
        )]
        max_tokens: Option<usize>,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_BASE_URL",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls; takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (legacy; prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Ollama embedding model identifier"
        )]
        embedding_model: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
            default_value_t = 5000u64,
            help = "Embedding request timeout in milliseconds"
        )]
        embedding_timeout_ms: u64,
    },
    /// Manage explicit repo identity mappings for shared state dirs.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Run an MCP (Model Context Protocol) server over stdio.
    Mcp {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, default_value = "warn")]
        log: String,
        #[arg(
            long,
            visible_alias = "mcp-max-results",
            default_value_t = 8,
            help = "Maximum results to return from docdex_search tool"
        )]
        max_results: usize,
        #[arg(
            long,
            env = "DOCDEX_MCP_RATE_LIMIT_PER_MIN",
            default_value_t = 0u32,
            help = "Optional global tool-call rate limit per minute for MCP (0 disables)"
        )]
        rate_limit_per_min: u32,
        #[arg(
            long,
            env = "DOCDEX_MCP_RATE_LIMIT_BURST",
            default_value_t = 0u32,
            help = "Optional burst size for MCP rate limiting (defaults to per-minute limit when 0)"
        )]
        rate_limit_burst: u32,
    },
    /// Helper to register or remove Docdex MCP in supported agent CLIs.
    McpAdd {
        /// Agent to configure (currently automates Codex; others print commands to run).
        #[arg(
            long,
            value_parser = [
                "codex",
                "cursor",
                "cursor-cli",
                "continue",
                "cline",
                "claude",
                "claude-cli",
                "grok",
                "droid",
                "factory",
                "gemini",
                "vscode",
                "amp",
                "forge",
                "copilot",
                "warp"
            ],
            default_value = "codex"
        )]
        agent: String,
        /// Repo/workspace root for the MCP server; defaults to current directory.
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Max results clamp for docdex_search.
        #[arg(long, default_value_t = 8)]
        max_results: usize,
        /// Log level for the MCP server.
        #[arg(long, default_value = "warn")]
        log: String,
        /// Remove the MCP entry instead of adding it (where supported).
        #[arg(long, default_value_t = false)]
        remove: bool,
        /// Add to all known agents that are detected on this system.
        #[arg(long, default_value_t = false)]
        all: bool,
    },
}

#[derive(Subcommand, Debug)]
enum RepoCommand {
    /// Explicitly re-associate a moved/renamed repo path to existing state under a shared `--state-dir`.
    Reassociate {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            required_unless_present = "old_path",
            help = "Target repo fingerprint (SHA-256 hex) to associate with --repo"
        )]
        fingerprint: Option<String>,
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "fingerprint",
            help = "Previous canonical repo path (may no longer exist); used to find the existing mapping"
        )]
        old_path: Option<PathBuf>,
    },
    /// Inspect how Docdex resolves repo identity and any shared-state mapping.
    Inspect {
        #[command(flatten)]
        repo: RepoArgs,
    },
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        render_error_and_exit(err);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::try_parse().map_err(|err| {
        StartupError::new("startup_config_invalid", err.to_string())
            .with_hint("Run `docdexd help-all` for full usage.")
    })?;
    match cli.command {
        Command::Serve {
            repo,
            host,
            port,
            log,
            tls_cert,
            tls_key,
            certbot_domain,
            certbot_live_dir,
            insecure,
            require_tls,
            auth_token,
            max_limit,
            max_query_bytes,
            max_request_bytes,
            rate_limit_per_min,
            rate_limit_burst,
            strip_snippet_html,
            secure_mode,
            disable_snippet_text,
            enable_memory,
            embedding_base_url,
            ollama_base_url,
            embedding_model,
            embedding_timeout_ms,
            access_log,
            audit_log_path,
            audit_max_bytes,
            audit_max_files,
            audit_disable,
            run_as_uid,
            run_as_gid,
            chroot_dir,
            unshare_net,
            allow_ip,
        } => {
            if let Some(ref dir) = chroot_dir {
                daemon::enter_chroot(dir).map_err(|err| {
                    StartupError::new("startup_state_invalid", err.to_string()).with_hint(
                        "Verify the chroot path exists and is accessible (Unix only).",
                    )
                })?;
            }
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )
            .map_err(|err| {
                StartupError::new(
                    "startup_state_invalid",
                    format!("failed to resolve state directory/identity: {err}"),
                )
                .with_hint("Verify repo/state-dir paths and permissions; consider removing --state-dir or running `docdexd index` once to initialize metadata.")
            })?;
            let tls = daemon::TlsConfig::from_options(
                tls_cert,
                tls_key,
                certbot_domain,
                certbot_live_dir,
            )
            .map_err(|err| {
                StartupError::new("startup_config_invalid", err.to_string()).with_hint(
                    "Fix TLS flags (provide both --tls-cert/--tls-key or use --certbot-* options).",
                )
            })?;
            let audit_logger = if audit_disable {
                None
            } else {
                let path = audit_log_path
                    .clone()
                    .unwrap_or_else(|| index_config.repo_state_dir().join("audit.log"));
                Some(audit::AuditLogger::new(
                    path,
                    audit_max_bytes,
                    audit_max_files,
                )
                .map_err(|err| {
                    StartupError::new("startup_state_invalid", err.to_string())
                        .with_hint("Verify the state dir is writable or set --audit-disable.")
                })?)
            };
            let security = search::SecurityConfig::from_options(
                auth_token,
                allow_ip.as_slice(),
                max_limit,
                max_query_bytes,
                max_request_bytes,
                rate_limit_per_min,
                rate_limit_burst,
                strip_snippet_html,
                secure_mode,
                disable_snippet_text,
            )?;
            let embedding_base_url = embedding_base_url.unwrap_or(ollama_base_url);
            let _ = chrome_watchdog::init_global_from_env();
            daemon::serve(
                repo_root,
                host,
                port,
                log,
                index_config,
                security,
                tls,
                insecure,
                require_tls,
                access_log,
                audit_logger,
                run_as_uid,
                run_as_gid,
                unshare_net,
                enable_memory,
                embedding_base_url,
                embedding_model,
                embedding_timeout_ms,
            )
            .await?;
        }
        Command::HelpAll => {
            print_full_help()?;
        }
        Command::SelfCheck {
            repo,
            terms,
            limit,
            include_default_patterns,
        } => {
            const DEFAULT_SELF_CHECK_TERMS: &[&str] = &[
                "SECRET",
                "TOKEN",
                "PASSWORD",
                "API_KEY",
                "PRIVATE KEY",
                "-----BEGIN PRIVATE KEY-----",
            ];
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging("warn")?;
            let indexer =
                index::Indexer::with_config_read_only(repo_root.clone(), index_config.clone())?;
            let mut findings = Vec::new();
            let mut all_terms: Vec<String> = terms
                .into_iter()
                .filter(|t| !t.trim().is_empty())
                .map(|t| t.trim().to_string())
                .collect();
            if include_default_patterns {
                for default in DEFAULT_SELF_CHECK_TERMS {
                    if !all_terms.iter().any(|t| t.eq_ignore_ascii_case(default)) {
                        all_terms.push(default.to_string());
                    }
                }
            }
            for term in all_terms {
                let search_limit = limit.saturating_add(1);
                let hits = search::run_query(&indexer, None, &term, search_limit).await?;
                if !hits.hits.is_empty() {
                    let more = hits.hits.len() > limit;
                    let sample: Vec<String> = hits
                        .hits
                        .iter()
                        .take(limit)
                        .map(|hit| hit.rel_path.clone())
                        .collect();
                    findings.push((term, sample, more));
                }
            }
            if findings.is_empty() {
                let report_path = index_config.repo_state_dir().join("self_check_report.json");
                let empty: Vec<serde_json::Value> = Vec::new();
                let report = serde_json::json!({
                    "repo": repo_root,
                    "checked_at": chrono::Utc::now().to_rfc3339(),
                    "findings": empty,
                });
                let _ = fs::write(&report_path, serde_json::to_string_pretty(&report)?);
                println!(
                    "no sensitive terms found (report: {})",
                    report_path.display()
                );
                // best-effort audit log for admin self-check action
                let _ = audit::AuditLogger::new(
                    index_config.repo_state_dir().join("audit.log"),
                    5_000_000,
                    5,
                )
                .map(|logger| logger.log("self_check", "pass", None, None, None, None, None, None));
                return Ok(());
            }
            let report_path = index_config.repo_state_dir().join("self_check_report.json");
            let report = serde_json::json!({
                "repo": repo_root,
                "checked_at": chrono::Utc::now().to_rfc3339(),
                "findings": findings.iter().map(|(term, sample, more)| serde_json::json!({
                    "term": term,
                    "sample_paths": sample,
                    "truncated": *more,
                })).collect::<Vec<_>>(),
            });
            let _ = fs::write(&report_path, serde_json::to_string_pretty(&report)?);
            eprintln!("sensitive terms found (report: {}):", report_path.display());
            for (term, sample, more) in findings {
                let count_hint = if more {
                    format!("{}+", sample.len())
                } else {
                    sample.len().to_string()
                };
                let mut line = format!(
                    "- {term}: {count_hint} hits (sample: {})",
                    sample.join(", ")
                );
                if more {
                    line.push_str("; more matches exist");
                }
                eprintln!("{line}");
            }
<<<<<<< HEAD
            let _ =
                audit::AuditLogger::new(index_config.repo_state_dir().join("audit.log"), 5_000_000, 5)
                    .map(|logger| {
                        logger.log(
                            "self_check",
                            "fail",
                            None,
                            None,
                            None,
                            None,
                            None,
                            Some("sensitive terms found"),
                        )
                    });
=======
            let _ = audit::AuditLogger::new(
                index_config.repo_state_dir().join("audit.log"),
                5_000_000,
                5,
            )
            .map(|logger| {
                logger.log(
                    "self_check",
                    "fail",
                    None,
                    None,
                    None,
                    None,
                    None,
                    Some("sensitive terms found"),
                )
            });
>>>>>>> mcoda/task/ops-01-us-03-t02
            return Err(anyhow!("sensitive terms detected in index"));
        }
        Command::Index { repo } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging("info")?;
            info!("Rebuilding index for {}", repo_root.display());
            index::Indexer::with_config(repo_root, index_config)?
                .reindex_all()
                .await?;
        }
        Command::Ingest { repo, file } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging("warn")?;
            let _ = index::Indexer::with_config(repo_root, index_config)?
                .ingest_file(file)
                .await?;
        }
        Command::Query {
            repo,
            query,
            limit,
            repo_only,
        } => {
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
                let libs_dir =
                    libs::libs_state_dir_from_index_state_dir(server.repo_root(), server.state_dir());
                libs::LibsIndexer::open_read_only(libs_dir).ok().flatten()
            };
            let hits = search::run_query(&server, libs_indexer.as_ref(), &query, limit).await?;
            println!("{}", serde_json::to_string_pretty(&hits)?);
        }
        Command::Repo { command } => match command {
            RepoCommand::Reassociate {
                repo,
                fingerprint,
                old_path,
            } => {
                let repo_root = repo.repo_root();
                let Some(state_dir) = repo.state_dir_override() else {
                    return Err(error::AppError::new(
                        error::ERR_INVALID_ARGUMENT,
                        "`repo reassociate` requires an explicit shared --state-dir base directory",
                    )
                    .into());
                };
                let state_dir = if state_dir.is_absolute() {
                    state_dir
                } else {
                    repo_root.join(state_dir)
                };

                match crate::repo_identity::reassociate_repo_path(
                    &repo_root,
                    &state_dir,
                    fingerprint.as_deref(),
                    old_path.as_deref(),
                ) {
                    Ok(result) => println!("{}", serde_json::to_string_pretty(&result)?),
                    Err(err) => {
                        if let Some(identity) =
                            err.downcast_ref::<crate::repo_identity::RepoIdentityError>()
                        {
                            let normalized = repo_root.to_string_lossy().replace('\\', "/");
                            let attempted =
                                crate::repo_identity::repo_fingerprint_sha256(&repo_root).ok();
                            let mut known_canonical: Option<String> = None;
                            let mut code = error::ERR_REPO_STATE_MISMATCH;
                            let mut message = "repo re-association refused".to_string();
                            let mut extra_details: Option<serde_json::Value> = None;

                            match identity {
                                crate::repo_identity::RepoIdentityError::AmbiguousOldPath {
                                    old_path,
                                    candidate_fingerprints,
                                } => {
                                    code = error::ERR_INVALID_ARGUMENT;
                                    message = "ambiguous old path; multiple candidates".to_string();
                                    extra_details = Some(json!({
                                        "oldPath": old_path,
                                        "candidateFingerprints": candidate_fingerprints,
                                    }));
                                }
                                crate::repo_identity::RepoIdentityError::UnknownFingerprint { .. } => {
                                    code = error::ERR_INVALID_ARGUMENT;
                                    message = "unknown fingerprint; no registry entry found".to_string();
                                }
                                crate::repo_identity::RepoIdentityError::ReassociationRequired {
                                    registered_canonical_path,
                                    ..
                                } => {
                                    known_canonical = Some(registered_canonical_path.clone());
                                }
                                crate::repo_identity::RepoIdentityError::CanonicalPathCollision {
                                    canonical_path,
                                    ..
                                } => {
                                    known_canonical = Some(canonical_path.clone());
                                }
                                _ => {}
                            }

                            let mut steps = vec![
                                "Verify `--repo` points at the moved repo’s current path.".to_string(),
                                "Verify `--state-dir` points at the same shared base directory used previously.".to_string(),
                            ];
                            if matches!(
                                identity,
                                crate::repo_identity::RepoIdentityError::AmbiguousOldPath { .. }
                            ) {
                                steps.push(
                                    "Re-run with `--fingerprint <sha256>` to select the intended repo entry."
                                        .to_string(),
                                );
                            }

                            let mut details = crate::error::repo_resolution_details(
                                normalized,
                                attempted,
                                known_canonical,
                                steps,
                            );
                            if let (Some(extra), Some(obj)) =
                                (extra_details, details.as_object_mut())
                            {
                                if let Some(extra_obj) = extra.as_object() {
                                    for (k, v) in extra_obj {
                                        obj.insert(k.clone(), v.clone());
                                    }
                                }
                            }
                            return Err(error::AppError::new(code, message).with_details(details).into());
                        }
                        return Err(err);
                    }
                }
            }
            RepoCommand::Inspect { repo } => {
                let repo_root = repo.repo_root();
                let state_dir = repo.state_dir_override();
                let report = crate::repo_identity::inspect_repo(&repo_root, state_dir.as_deref())?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
        },
        Command::LibsIngest { repo, sources } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging("warn")?;
            let libs_dir =
                libs::libs_state_dir_from_index_state_dir(&repo_root, index_config.state_dir());
            let indexer = libs::LibsIndexer::open_or_create(libs_dir)?;
            let raw = fs::read_to_string(&sources)
                .with_context(|| format!("read libs sources file {}", sources.display()))?;
            let sources_file: libs::LibSourcesFile =
                serde_json::from_str(&raw).context("parse libs sources json")?;
            let report = indexer.ingest_sources(&sources_file.sources)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::LibsDiscover { repo, sources } => {
            let repo_root = repo.repo_root();
            util::init_logging("warn")?;
            let explicit = match sources {
                None => None,
                Some(path) => {
                    let raw = fs::read_to_string(&path)
                        .with_context(|| format!("read libs sources file {}", path.display()))?;
                    let parsed: libs::LibSourcesFile =
                        serde_json::from_str(&raw).context("parse libs sources json")?;
                    Some(parsed)
                }
            };
            let resolver = libs_source_resolver::LibsSourceResolver::new(repo_root);
            let resolution = resolver.resolve(explicit.as_ref())?;
            println!("{}", serde_json::to_string_pretty(&resolution)?);
        }
        Command::MemoryStore {
            repo,
            text,
            metadata,
            embedding_base_url,
            ollama_base_url,
            embedding_model,
            embedding_timeout_ms,
        } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging("warn")?;
<<<<<<< HEAD
            index::ensure_state_dir_secure(index_config.repo_state_dir())?;
=======
            state_layout::ensure_state_dir_secure(index_config.state_dir())?;
>>>>>>> mcoda/task/ops-01-us-03-t02

            let timeout = std::time::Duration::from_millis(embedding_timeout_ms.max(1));
            let embedding_base_url = embedding_base_url.unwrap_or(ollama_base_url);
            let embedder =
                ollama::OllamaEmbedder::new(embedding_base_url, embedding_model, timeout)?;
            let embedding = embedder.embed(&text).await?;
            let user_metadata = match metadata {
                None => None,
                Some(raw) => Some(
                    serde_json::from_str::<serde_json::Value>(&raw).map_err(|err| {
                        error::AppError::new(
                            error::ERR_INVALID_ARGUMENT,
                            format!("invalid --metadata JSON: {err}"),
                        )
                    })?,
                ),
            };
            let metadata = memory::inject_embedding_metadata(
                user_metadata,
                embedder.provider(),
                embedder.model(),
            );
            let store = memory::MemoryStore::new(index_config.repo_state_dir());
            let created_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_millis() as i64;
            let text_owned = text.clone();
            let stored = tokio::task::spawn_blocking(move || {
                store.store(&text_owned, &embedding, metadata, created_at)
            })
            .await??;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "id": stored.0.to_string(),
                    "created_at": stored.1
                }))?
            );
        }
        Command::MemoryRecall {
            repo,
            query,
            top_k,
            max_items,
            max_tokens,
            embedding_base_url,
            ollama_base_url,
            embedding_model,
            embedding_timeout_ms,
        } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging("warn")?;
<<<<<<< HEAD
            index::ensure_state_dir_secure(index_config.repo_state_dir())?;
=======
            state_layout::ensure_state_dir_secure(index_config.state_dir())?;
>>>>>>> mcoda/task/ops-01-us-03-t02

            let timeout = std::time::Duration::from_millis(embedding_timeout_ms.max(1));
            let embedding_base_url = embedding_base_url.unwrap_or(ollama_base_url);
            let embedder =
                ollama::OllamaEmbedder::new(embedding_base_url, embedding_model, timeout)?;
            let embedding = embedder.embed(&query).await?;
            let store = memory::MemoryStore::new(index_config.repo_state_dir());
            let top_k = top_k.max(1).min(50);
            let max_items = max_items.unwrap_or(top_k).min(50);
            let max_tokens = max_tokens;
            let results = tokio::task::spawn_blocking(move || {
                let candidates = store.recall_candidates(&embedding, top_k)?;
                let budget = max_tokens.unwrap_or(usize::MAX);
                let (kept, _trace) = memory::prune_and_truncate_memory_context(
                    &candidates,
                    max_items,
                    budget,
                );
                Ok::<_, anyhow::Error>(kept)
            })
            .await??;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "results": results.into_iter().map(|item| {
                        serde_json::json!({
                            "content": item.content,
                            "score": item.score,
                            "metadata": item.metadata
                        })
                    }).collect::<Vec<_>>()
                }))?
            );
        }
        Command::Mcp {
            repo,
            log,
            max_results,
            rate_limit_per_min,
            rate_limit_burst,
        } => {
            let max_results = std::env::var("DOCDEX_MCP_MAX_RESULTS")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(max_results)
                .max(1);
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
                repo.symbols_enabled(),
            )?;
            util::init_logging(&log)?;
            let _ = chrome_watchdog::init_global_from_env();
            mcp::serve(
                repo_root,
                index_config,
                max_results,
                rate_limit_per_min,
                rate_limit_burst,
            )
            .await?;
        }
        Command::McpAdd {
            agent,
            repo,
            max_results,
            log,
            remove,
            all,
        } => {
            let repo_root = repo
                .unwrap_or(std::env::current_dir().context("determine current directory")?)
                .canonicalize()
                .context("resolve repo root")?;
            let targets: Vec<&str> = if all {
                vec![
                    "codex",
                    "continue",
                    "cline",
                    "cursor-cli",
                    "cursor",
                    "claude-cli",
                    "claude",
                    "droid",
                    "factory",
                    "gemini",
                    "vscode",
                    "amp",
                    "forge",
                    "copilot",
                    "warp",
                    "grok",
                ]
            } else {
                vec![agent.as_str()]
            };
            for target in targets {
                let installed = agent_available(target, &repo_root);
                println!(
                    "[docdexd mcp-add] {} {}",
                    if remove { "removing from" } else { "adding to" },
                    target
                );
                handle_mcp_add(target, &repo_root, &log, max_results, remove, installed)?;
            }
        }
    }
    Ok(())
}

fn render_error_and_exit(err: anyhow::Error) -> ! {
    if let Some(startup) = err.downcast_ref::<StartupError>() {
        let mut body = serde_json::Map::new();
        body.insert("code".to_string(), json!(startup.code));
        body.insert("message".to_string(), json!(startup.message.as_str()));
        if let Some(hint) = startup.hint.as_ref() {
            body.insert("hint".to_string(), json!(hint));
        }
        if let Some(steps) = startup.remediation.as_ref() {
            body.insert("remediation".to_string(), json!(steps));
        }
        let payload = serde_json::Value::Object({
            let mut root = serde_json::Map::new();
            root.insert("error".to_string(), serde_json::Value::Object(body));
            root
        });
        match serde_json::to_string(&payload) {
            Ok(line) => eprintln!("{line}"),
            Err(_) => eprintln!("{}", startup.message),
        }
        std::process::exit(1);
    }
    if let Some(app) = err.downcast_ref::<crate::error::AppError>() {
        let mut body = serde_json::Map::new();
        body.insert("code".to_string(), json!(app.code));
        body.insert("message".to_string(), json!(app.message.as_str()));
        if let Some(details) = app.details.as_ref() {
            body.insert("details".to_string(), details.clone());
        }
        let payload = serde_json::Value::Object({
            let mut root = serde_json::Map::new();
            root.insert("error".to_string(), serde_json::Value::Object(body));
            root
        });
        match serde_json::to_string(&payload) {
            Ok(line) => eprintln!("{line}"),
            Err(_) => eprintln!("{}", app.message),
        }
        std::process::exit(1);
    }

    eprintln!("{err}");
    std::process::exit(1);
}

fn print_full_help() -> Result<()> {
    let mut root = Cli::command();
    root.print_long_help()?;
    println!();
    for name in [
        "serve",
        "self-check",
        "index",
        "ingest",
        "query",
        "repo",
        "memory-store",
        "memory-recall",
    ] {
        let mut cmd = Cli::command();
        if let Some(sub) = cmd.find_subcommand_mut(name) {
            println!("\n{name}:\n");
            sub.print_long_help()?;
            println!();
        }
    }
    // include MCP server help
    if let Some(sub) = Cli::command().find_subcommand_mut("mcp") {
        println!("\nmcp:\n");
        sub.print_long_help()?;
        println!();
    }
    println!("MCP tools (docdexd mcp):");
    println!("  - docdex_search: search repo docs; args: query (required), limit (<= max_results), project_root (optional)");
    println!("  - docdex_index: reindex all or ingest provided paths; args: paths[], project_root (optional)");
    println!("  - docdex_files: list indexed docs with pagination; args: limit (<=1000), offset (<=50000), project_root (optional)");
    println!("  - docdex_stats: index metadata; args: project_root (optional)");
    println!("  - docdex_explainability_record: persist explainability record; args: record (required), project_root (optional)");
    println!("  Notes: set DOCDEX_MCP_MAX_RESULTS to clamp docdex_search; run `docdexd mcp --help` for full MCP flags.");
    Ok(())
}

fn continue_config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = Path::new(&home).join(".continue").join("config.json");
    Ok(path)
}

fn upsert_mcp_entry(path: &Path, command: &str, args: Vec<String>) -> Result<()> {
    let mut contents = json!({});
    if path.exists() {
        let data = fs::read_to_string(path)?;
        contents = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
    }
    let obj = contents
        .as_object_mut()
        .ok_or_else(|| anyhow!("config root is not an object"))?;
    let mcp_servers = obj
        .entry("mcpServers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcpServers is not an object"))?;
    mcp_servers.insert(
        "docdex".to_string(),
        json!({
            "command": command,
            "args": args
        }),
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let pretty = serde_json::to_string_pretty(&contents)?;
    fs::write(path, pretty)?;
    Ok(())
}

fn remove_mcp_entry(path: &Path, warn_only: bool) -> Result<()> {
    if !path.exists() {
        if warn_only {
            return Ok(());
        }
        return Err(anyhow!("config file not found: {}", path.display()));
    }
    let data = fs::read_to_string(path)?;
    let mut contents: serde_json::Value = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
    if let Some(obj) = contents.as_object_mut() {
        if let Some(mcp_servers) = obj.get_mut("mcpServers").and_then(|v| v.as_object_mut()) {
            mcp_servers.remove("docdex");
            let pretty = serde_json::to_string_pretty(&contents)?;
            fs::write(path, pretty)?;
            return Ok(());
        }
    }
    if warn_only {
        Ok(())
    } else {
        Err(anyhow!("mcpServers.docdex not found in {}", path.display()))
    }
}

fn is_cmd_available(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

fn agent_available(agent: &str, repo_root: &Path) -> bool {
    match agent {
        "codex" => is_cmd_available("codex"),
        "cursor" | "cursor-cli" => is_cmd_available("cursor"),
        "claude" | "claude-cli" => is_cmd_available("claude"),
        "continue" => continue_config_path().map(|p| p.exists()).unwrap_or(false),
        "cline" => repo_root.join(".vscode").exists(),
        "droid" | "factory" => is_cmd_available("droid"),
        "gemini" => is_cmd_available("gemini"),
        "vscode" => is_cmd_available("code"),
        "amp" => is_cmd_available("amp"),
        "forge" => is_cmd_available("forge"),
        "copilot" => is_cmd_available("copilot"),
        "warp" => is_cmd_available("warp"),
        "grok" => false,
        _ => false,
    }
}

fn handle_mcp_add(
    agent: &str,
    repo_root: &Path,
    log: &str,
    max_results: usize,
    remove: bool,
    installed: bool,
) -> Result<()> {
    match agent {
        "codex" => {
            if !installed {
                println!(
                    "Codex not detected; run manually: codex mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
                return Ok(());
            }
            let mut cmd = std::process::Command::new("codex");
            if remove {
                cmd.args(["mcp", "remove", "docdex"]);
            } else {
                cmd.args([
                    "mcp",
                    "add",
                    "docdex",
                    "--",
                    "docdexd",
                    "mcp",
                    "--repo",
                    &repo_root.display().to_string(),
                    "--log",
                    log,
                    "--max-results",
                    &max_results.to_string(),
                ]);
            }
            let status = cmd.status().context("run codex mcp command")?;
            if status.success() {
                println!(
                    "Codex MCP {} complete for repo {}",
                    if remove { "remove" } else { "add" },
                    repo_root.display()
                );
            } else {
                println!(
                    "Codex MCP {} failed with status {}; run manually: codex mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    status,
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "continue" => {
            let path = continue_config_path()?;
            if remove {
                remove_mcp_entry(&path, false)?;
                println!("Removed docdex from Continue config at {}", path.display());
            } else {
                let args = vec![
                    "mcp".to_string(),
                    "--repo".to_string(),
                    repo_root.display().to_string(),
                    "--log".to_string(),
                    log.to_string(),
                    "--max-results".to_string(),
                    max_results.to_string(),
                ];
                upsert_mcp_entry(&path, "docdexd", args)?;
                println!("Added docdex to Continue config at {}", path.display());
            }
        }
        "cline" => {
            let path = repo_root.join(".vscode").join("settings.json");
            if remove {
                remove_mcp_entry(&path, true)?;
                println!(
                    "Removed docdex from Cline settings at {} (if it existed)",
                    path.display()
                );
            } else {
                let args = vec![
                    "mcp".to_string(),
                    "--repo".to_string(),
                    repo_root.display().to_string(),
                    "--log".to_string(),
                    log.to_string(),
                    "--max-results".to_string(),
                    max_results.to_string(),
                ];
                upsert_mcp_entry(&path, "docdexd", args)?;
                println!("Added docdex to Cline settings at {}", path.display());
            }
        }
        "cursor" => {
            if remove {
                println!(
                    "Cursor UI: remove the MCP server named docdex from Settings → MCP Servers."
                );
            } else {
                println!(
                    "Cursor UI: add docdex with command: docdexd mcp --repo {} --log {} --max-results {}",
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "cursor-cli" => {
            if installed {
                let mut cmd = std::process::Command::new("cursor");
                if remove {
                    cmd.args(["mcp", "remove", "docdex"]);
                } else {
                    cmd.args([
                        "mcp",
                        "add",
                        "docdex",
                        "--",
                        "docdexd",
                        "mcp",
                        "--repo",
                        &repo_root.display().to_string(),
                        "--log",
                        log,
                        "--max-results",
                        &max_results.to_string(),
                    ]);
                }
                let status = cmd.status().context("run cursor mcp command")?;
                if status.success() {
                    println!(
                        "Cursor CLI MCP {} complete for repo {}",
                        if remove { "remove" } else { "add" },
                        repo_root.display()
                    );
                } else {
                    println!(
                        "Cursor CLI MCP {} failed with status {}; run manually: cursor mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                        if remove { "remove" } else { "add" },
                        status,
                        if remove { "remove" } else { "add" },
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Cursor CLI not detected; run manually: cursor mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "claude" => {
            if remove {
                println!("Claude Desktop: remove the docdex entry from Developer → MCP Servers.");
            } else {
                println!(
                    "Claude Desktop: Developer → MCP Servers → Add, command: docdexd mcp --repo {} --log {} --max-results {}",
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "claude-cli" => {
            if installed {
                let mut cmd = std::process::Command::new("claude");
                if remove {
                    cmd.args(["mcp", "remove", "docdex"]);
                } else {
                    cmd.args([
                        "mcp",
                        "add",
                        "--transport",
                        "stdio",
                        "docdex",
                        "--",
                        "docdexd",
                        "mcp",
                        "--repo",
                        &repo_root.display().to_string(),
                        "--log",
                        log,
                        "--max-results",
                        &max_results.to_string(),
                    ]);
                }
                let status = cmd.status().context("run claude mcp command")?;
                if status.success() {
                    println!(
                        "Claude CLI MCP {} complete for repo {}",
                        if remove { "remove" } else { "add" },
                        repo_root.display()
                    );
                } else {
                    println!(
                        "Claude CLI MCP {} failed with status {}; run manually: claude mcp add --transport stdio docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                        if remove { "remove" } else { "add" },
                        status,
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Claude CLI not detected; run manually: claude mcp add --transport stdio docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "droid" | "factory" => {
            if installed && !remove {
                let mut cmd = std::process::Command::new("droid");
                cmd.args([
                    "mcp",
                    "add",
                    "docdex",
                    &format!(
                        "docdexd mcp --repo {} --log {} --max-results {}",
                        repo_root.display(),
                        log,
                        max_results
                    ),
                ]);
                let status = cmd.status().context("run droid mcp command")?;
                if status.success() {
                    println!(
                        "Factory/Kiro MCP add complete for repo {}",
                        repo_root.display()
                    );
                } else {
                    println!(
                        "Factory/Kiro MCP add failed with status {}; run manually: droid mcp add docdex \"docdexd mcp --repo {} --log {} --max-results {}\"",
                        status,
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Factory/Kiro CLI: run manually {} docdex with `droid mcp add docdex \"docdexd mcp --repo {} --log {} --max-results {}\"`",
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "gemini" => {
            if installed && !remove {
                let mut cmd = std::process::Command::new("gemini");
                cmd.args([
                    "mcp",
                    "add",
                    "docdex",
                    "docdexd",
                    "mcp",
                    "--repo",
                    &repo_root.display().to_string(),
                    "--log",
                    log,
                    "--max-results",
                    &max_results.to_string(),
                ]);
                let status = cmd.status().context("run gemini mcp command")?;
                if status.success() {
                    println!("Gemini MCP add complete for repo {}", repo_root.display());
                } else {
                    println!(
                        "Gemini MCP add failed with status {}; run manually: gemini mcp add docdex docdexd mcp --repo {} --log {} --max-results {}",
                        status,
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Gemini CLI {} manually: gemini mcp {} docdex docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "vscode" => {
            let payload = format!(
                "{{\"name\":\"docdex\",\"command\":\"docdexd\",\"args\":[\"mcp\",\"--repo\",\"{}\",\"--log\",\"{}\",\"--max-results\",\"{}\"]}}",
                repo_root.display(),
                log,
                max_results
            );
            if installed && !remove {
                let status = std::process::Command::new("code")
                    .args(["--add-mcp", &payload])
                    .status()
                    .context("run code --add-mcp")?;
                if status.success() {
                    println!("VS Code MCP add complete via CLI.");
                } else {
                    println!(
                        "VS Code CLI add failed with status {}; add manually with `code --add-mcp '{payload}'`",
                        status
                    );
                }
            } else {
                println!(
                    "VS Code CLI {} manually with: code --add-mcp '{}'",
                    if remove { "remove" } else { "add" },
                    payload
                );
            }
        }
        "amp" => {
            println!("Sourcegraph amp expects HTTP/SSE; register your HTTP endpoint, e.g., `amp mcp add docdex http://localhost:5273/.mcp/v1`.");
        }
        "forge" => {
            println!(
                "Forge Code CLI: forge mcp import '[{{\"name\":\"docdex\",\"type\":\"stdio\",\"command\":\"docdexd\",\"args\":[\"mcp\",\"--repo\",\"{}\",\"--log\",\"{}\",\"--max-results\",\"{}\"]}}]'",
                repo_root.display(),
                log,
                max_results
            );
        }
        "copilot" => {
            println!("GitHub Copilot CLI: start a session and run `/mcp add docdex`, command: docdexd mcp --repo {} --log {} --max-results {}", repo_root.display(), log, max_results);
        }
        "warp" => {
            println!("Warp: add docdex in settings pointing to `docdexd mcp --repo {} --log {} --max-results {}`", repo_root.display(), log, max_results);
        }
        "grok" => {
            println!(
                "Grok MCP client: register docdex with command: docdexd mcp --repo {} --log {} --max-results {}",
                repo_root.display(),
                log,
                max_results
            );
        }
        _ => println!("Unsupported agent: {agent}"),
    }
    Ok(())
}
