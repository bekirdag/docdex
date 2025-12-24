mod api;
mod audit;
mod browser_session;
mod cli;
mod config;
mod daemon;
mod dag;
mod error;
mod hardware;
mod impact;
mod index;
mod libs;
mod libs_source_resolver;
mod llm;
mod mcp;
mod memory;
mod metrics;
mod ollama;
mod orchestrator;
mod ratelimit;
mod repo_manager;
mod search;
mod symbols;
mod tier2;
mod util;
mod watcher;
mod web;

#[tokio::main]
async fn main() {
    if let Err(err) = cli::run().await {
        cli::render_error_and_exit(err);
    }
}
