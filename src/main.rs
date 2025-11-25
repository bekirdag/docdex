mod audit;
mod config;
mod daemon;
mod index;
mod mcp;
mod search;
mod util;
mod watcher;

use crate::config::RepoArgs;
use anyhow::{anyhow, Result};
use clap::{ArgAction, CommandFactory, Parser, Subcommand};
use std::fs;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(
    name = "docdexd",
    version,
    about = "Local documentation index/search daemon",
    long_about = "Docdex indexes plain-text/markdown documentation under a workspace and serves top-k search/snippet results over HTTP or CLI. Defaults store data in <repo>/.docdex/index and avoid common tool caches; override paths and exclusions with --state-dir/--exclude-* or matching env vars. Optional MCP server (`docdexd mcp`) exposes docdex.search/index/files/open/stats tools over stdio for MCP-aware clients; register it in your MCP client as server \"docdex\" with command: docdexd mcp --repo <repo> --log warn."
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
            env = "DOCDEX_ACCESS_LOG",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Emit structured access logs (redacts query values; disable with --access-log=false)"
        )]
        access_log: bool,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_LOG_PATH",
            help = "Audit log path (JSON lines with hash chain; defaults to <state-dir>/audit.log)"
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
    },
    /// Run an MCP (Model Context Protocol) server over stdio.
    Mcp {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, default_value = "info")]
        log: String,
        #[arg(
            long,
            visible_alias = "mcp-max-results",
            default_value_t = 8,
            help = "Maximum results to return from docdex.search tool"
        )]
        max_results: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
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
                daemon::enter_chroot(dir)?;
            }
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
            );
            let tls = daemon::TlsConfig::from_options(
                tls_cert,
                tls_key,
                certbot_domain,
                certbot_live_dir,
            )?;
            let audit_logger = if audit_disable {
                None
            } else {
                let path = audit_log_path
                    .clone()
                    .unwrap_or_else(|| index_config.state_dir().join("audit.log"));
                Some(audit::AuditLogger::new(
                    path,
                    audit_max_bytes,
                    audit_max_files,
                )?)
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
            util::init_logging(&log)?;
            info!(
                "Starting docdex daemon on {host}:{port} (repo={})",
                repo_root.display()
            );
            daemon::serve(
                repo_root,
                host,
                port,
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
            );
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
                let hits = search::run_query(&indexer, &term, search_limit).await?;
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
                let report_path = index_config.state_dir().join("self_check_report.json");
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
                    index_config.state_dir().join("audit.log"),
                    5_000_000,
                    5,
                )
                .map(|logger| logger.log("self_check", "pass", None, None, None, None, None, None));
                return Ok(());
            }
            let report_path = index_config.state_dir().join("self_check_report.json");
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
            let _ =
                audit::AuditLogger::new(index_config.state_dir().join("audit.log"), 5_000_000, 5)
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
            return Err(anyhow!("sensitive terms detected in index"));
        }
        Command::Index { repo } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
            );
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
            );
            util::init_logging("warn")?;
            index::Indexer::with_config(repo_root, index_config)?
                .ingest_file(file)
                .await?;
        }
        Command::Query { repo, query, limit } => {
            let repo_root = repo.repo_root();
            let index_config = index::IndexConfig::with_overrides(
                &repo_root,
                repo.state_dir_override(),
                repo.exclude_dir_overrides(),
                repo.exclude_prefix_overrides(),
            );
            util::init_logging("warn")?;
            let server = index::Indexer::with_config_read_only(repo_root, index_config)?;
            let hits = search::run_query(&server, &query, limit).await?;
            println!("{}", serde_json::to_string_pretty(&hits)?);
        }
        Command::Mcp {
            repo,
            log,
            max_results,
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
            );
            util::init_logging(&log)?;
            mcp::serve(repo_root, index_config, max_results).await?;
        }
    }
    Ok(())
}

fn print_full_help() -> Result<()> {
    let mut root = Cli::command();
    root.print_long_help()?;
    println!();
    for name in ["serve", "self-check", "index", "ingest", "query"] {
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
    println!("  - docdex.search: search repo docs; args: query (required), limit (<= max_results), project_root (optional)");
    println!("  - docdex.index: reindex all or ingest provided paths; args: paths[], project_root (optional)");
    println!("  - docdex.files: list indexed docs with pagination; args: limit (<=1000), offset (<=50000), project_root (optional)");
    println!("  - docdex.stats: index metadata; args: project_root (optional)");
    println!("  Notes: set DOCDEX_MCP_MAX_RESULTS to clamp docdex.search; run `docdexd mcp --help` for full MCP flags.");
    Ok(())
}
