use anyhow::Result;
use clap::CommandFactory;

use super::super::Cli;

pub fn run() -> Result<()> {
    let mut root = Cli::command();
    root.print_long_help()?;
    println!();
    for name in [
        "serve",
        "self-check",
        "index",
        "ingest",
        "query",
        "web-search",
        "web-fetch",
        "web-rag",
        "libs",
        "dag",
        "run-tests",
        "tui",
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
    println!("  Notes: set DOCDEX_MCP_MAX_RESULTS to clamp docdex_search; run `docdexd mcp --help` for full MCP flags.");
    Ok(())
}
