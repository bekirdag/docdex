use anyhow::Result;
use clap::CommandFactory;

use super::super::Cli;
use super::mcp_add::{mcp_endpoint_urls, resolve_mcp_endpoint_info};

pub fn run() -> Result<()> {
    let mut root = Cli::command();
    root.print_long_help()?;
    println!();
    for name in [
        "check",
        "daemon",
        "serve",
        "self-check",
        "setup",
        "index",
        "ingest",
        "chat",
        "agent",
        "web-search",
        "web-fetch",
        "web-rag",
        "web-cache-flush",
        "libs",
        "dag",
        "run-tests",
        "tui",
        "repo",
        "memory-store",
        "memory-recall",
        "impact-diagnostics",
        "symbols-status",
    ] {
        let mut cmd = Cli::command();
        if let Some(sub) = cmd.find_subcommand_mut(name) {
            println!("\n{name}:\n");
            sub.print_long_help()?;
            println!();
        }
    }
    if let Some(sub) = Cli::command().find_subcommand_mut("mcp") {
        println!("\nmcp:\n");
        sub.print_long_help()?;
        println!();
    }
    println!("MCP tools (shared HTTP/SSE + docdexd mcp):");
    println!("  - docdex_search: search repo docs; args: query (required), limit (<= max_results), project_root (optional)");
    println!("  - docdex_web_research: search repo + web; args: query (required), limit/web_limit, project_root (optional)");
    println!("  - docdex_index: reindex all or ingest provided paths; args: paths[], project_root (optional)");
    println!("  - docdex_files: list indexed docs with pagination; args: limit (<=1000), offset (<=50000), project_root (optional)");
    println!("  - docdex_stats: index metadata; args: project_root (optional)");
    let endpoint_info = resolve_mcp_endpoint_info();
    let urls = mcp_endpoint_urls(&endpoint_info.base_url);
    println!("  Shared MCP endpoint (HTTP/SSE): {}", urls.sse_url);
    println!("  MCP JSON-RPC endpoint: {}", urls.http_url);
    if !endpoint_info.running {
        println!("  Daemon not running; start with: docdexd daemon --repo <path>");
        println!("  Default MCP base URL: {}", endpoint_info.base_url);
    }
    println!("  Legacy stdio proxy: docdexd mcp --repo <path> --log warn --max-results 8");
    println!("  Notes: DOCDEX_MCP_MAX_RESULTS clamps docdex_search; run `docdexd mcp --help` for stdio flags.");
    Ok(())
}
