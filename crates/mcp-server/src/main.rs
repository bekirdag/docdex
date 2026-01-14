use anyhow::Result;
use clap::Parser;
use docdexd::daemon::lock;

#[derive(Debug, Parser)]
#[command(name = "docdex-mcp-server")]
struct Cli {
    #[command(flatten)]
    repo: docdexd::config::RepoArgs,
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
    #[arg(
        long,
        env = "DOCDEX_AUTH_TOKEN",
        help = "Optional bearer token required by MCP initialize"
    )]
    auth_token: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Ok(Some(metadata)) = lock::read_running_metadata() {
        if let Ok(path) = lock::default_lock_path() {
            eprintln!(
                "docdexd already running (pid={} port={}, lock={}); refusing to start docdex-mcp-server",
                metadata.pid,
                metadata.port,
                path.display()
            );
        } else {
            eprintln!(
                "docdexd already running (pid={} port={}); refusing to start docdex-mcp-server",
                metadata.pid,
                metadata.port
            );
        }
        if metadata.port != 0 {
            eprintln!(
                "Use the existing daemon at http://127.0.0.1:{} (/v1/mcp/sse).",
                metadata.port
            );
        }
        return Ok(());
    }

    let _mcp_lock = match lock::acquire_or_reuse_mcp_server() {
        Ok(lock::DaemonLockOutcome::Acquired(lock)) => Some(lock),
        Ok(lock::DaemonLockOutcome::AlreadyRunning(metadata)) => {
            if let Ok(path) = lock::default_mcp_server_lock_path() {
                eprintln!(
                    "docdex-mcp-server already running (pid={}, lock={})",
                    metadata.pid,
                    path.display()
                );
            } else {
                eprintln!("docdex-mcp-server already running (pid={})", metadata.pid);
            }
            return Ok(());
        }
        Err(err) => {
            eprintln!("docdex-mcp-server lock unavailable: {err}");
            return Err(err);
        }
    };

    let web_env = std::env::var("DOCDEX_WEB_ENABLED").ok();
    if web_env
        .as_deref()
        .map(|value| value.trim().is_empty())
        .unwrap_or(true)
    {
        std::env::set_var("DOCDEX_WEB_ENABLED", "1");
    }
    let max_results = std::env::var("DOCDEX_MCP_MAX_RESULTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(cli.max_results)
        .max(1);

    docdexd::util::init_logging(&cli.log)?;
    let _ = docdexd::web::scraper::init_global_from_env();

    let repo_root = cli.repo.repo_root();
    let index_config = docdexd::index::IndexConfig::with_overrides(
        &repo_root,
        cli.repo.state_dir_override(),
        cli.repo.exclude_dir_overrides(),
        cli.repo.exclude_prefix_overrides(),
        cli.repo.symbols_enabled(),
    )?;

    docdex_mcp_server::serve(
        repo_root,
        index_config,
        max_results,
        cli.rate_limit_per_min,
        cli.rate_limit_burst,
        cli.auth_token,
    )
    .await
}
