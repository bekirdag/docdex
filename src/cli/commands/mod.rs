pub mod agent;
pub mod browser;
pub mod check;
pub mod dag;
pub mod help_all;
pub mod hook;
pub mod impact;
pub mod index;
pub mod libs;
pub mod llm;
pub mod mcoda_eval;
pub mod mcp_add;
pub mod memory;
pub mod profile;
pub mod query;
pub mod repo;
pub mod run_tests;
pub mod self_check;
pub mod serve;
pub mod symbols;
pub mod tui;
pub mod web;

use anyhow::Result;

pub(crate) async fn dispatch(command: super::Command) -> Result<()> {
    match command {
        super::Command::Check => check::run().await,
        super::Command::Serve { args } => serve::run(args).await,
        super::Command::Daemon { args } => serve::run_daemon(args).await,
        super::Command::HelpAll => help_all::run(),
        super::Command::Browser { command } => browser::run(command).await,
        super::Command::SelfCheck {
            repo,
            terms,
            limit,
            include_default_patterns,
        } => self_check::run(repo, terms, limit, include_default_patterns).await,
        super::Command::LlmList => llm::run_list(),
        super::Command::Setup { args } => crate::setup::run(args),
        super::Command::Index { repo, libs_sources } => index::run_index(repo, libs_sources).await,
        super::Command::Ingest { repo, file } => index::run_ingest(repo, file).await,
        super::Command::Chat {
            repo,
            query,
            model,
            agent,
            agent_id,
            limit,
            max_web_results,
            repo_only,
            web_only,
            no_cache,
            llm_filter_local_results,
            compress_results,
            stream,
            diff_mode,
            diff_base,
            diff_head,
            diff_path,
        } => {
            query::run(
                repo,
                query,
                model,
                agent,
                agent_id,
                limit,
                max_web_results,
                repo_only,
                web_only,
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
        super::Command::Agent { command } => agent::run(command).await,
        super::Command::Repo { command } => repo::run(command),
        super::Command::LibsIngest { repo, sources } => libs::run_ingest(repo, sources).await,
        super::Command::LibsDiscover { repo, sources } => libs::run_discover(repo, sources).await,
        super::Command::Libs { command } => libs::run_command(command).await,
        super::Command::WebSearch { query, limit } => web::run_search(query, limit).await,
        super::Command::WebFetch { url } => web::run_fetch(url).await,
        super::Command::WebRag {
            repo,
            query,
            limit,
            repo_only,
            stream,
        } => web::run_rag(repo, query, limit, repo_only, stream).await,
        super::Command::WebCacheFlush => web::run_cache_flush().await,
        super::Command::Dag { command } => dag::run(command).await,
        super::Command::RunTests { repo, target } => run_tests::run(repo, target),
        super::Command::Tui { repo } => tui::run(repo),
        super::Command::MemoryStore {
            repo,
            text,
            metadata,
            embedding_base_url,
            ollama_base_url,
            embedding_model,
            embedding_timeout_ms,
        } => {
            memory::run_store(
                repo,
                text,
                metadata,
                embedding_base_url,
                ollama_base_url,
                embedding_model,
                embedding_timeout_ms,
            )
            .await
        }
        super::Command::MemoryRecall {
            repo,
            query,
            top_k,
            embedding_base_url,
            ollama_base_url,
            embedding_model,
            embedding_timeout_ms,
        } => {
            memory::run_recall(
                repo,
                query,
                top_k,
                embedding_base_url,
                ollama_base_url,
                embedding_model,
                embedding_timeout_ms,
            )
            .await
        }
        super::Command::Profile { command } => profile::run(command).await,
        super::Command::Hook { command } => hook::run(command).await,
        super::Command::SymbolsStatus { repo } => symbols::run_status(repo).await,
        super::Command::ImpactDiagnostics {
            repo,
            file,
            limit,
            offset,
        } => impact::run_diagnostics(repo, file, limit, offset).await,
        super::Command::McpAdd {
            agent,
            repo,
            remove,
            all,
        } => mcp_add::run(agent, repo, remove, all),
    }
}
