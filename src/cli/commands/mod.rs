pub mod agent;
pub mod browser;
pub mod check;
pub mod conversations;
pub mod dag;
pub mod diary;
pub mod file;
pub mod help_all;
pub mod hook;
pub mod impact;
pub mod index;
pub mod libs;
pub mod llm;
pub mod mcoda_eval;
pub mod mcp_add;
pub mod memory;
pub mod memory_layers;
pub mod mswarm;
pub mod open;
pub mod personal_preferences;
pub mod profile;
pub mod query;
pub mod repo;
pub mod run_tests;
pub mod search;
pub mod self_check;
pub mod serve;
pub mod symbols;
pub mod telemetry;
pub mod test;
pub mod tree;
pub mod tui;
pub mod web;

use anyhow::Result;

pub(super) async fn decode_json_or_error(
    resp: reqwest::Response,
    label: &str,
) -> Result<serde_json::Value> {
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd {} failed ({}): {}", label, status, text);
    }
    Ok(serde_json::from_str(&text)?)
}

pub(super) async fn emit_json_or_error(resp: reqwest::Response, label: &str) -> Result<()> {
    let value = decode_json_or_error(resp, label).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

pub(crate) async fn dispatch(command: super::Command) -> Result<()> {
    match command {
        super::Command::Check => check::run().await,
        super::Command::Serve { args } => serve::run(args).await,
        super::Command::Daemon { args } => serve::run_daemon(args).await,
        super::Command::HelpAll => help_all::run(),
        super::Command::Browser { command } => browser::run(command).await,
        super::Command::Mswarm { command } => mswarm::run(command).await,
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
        super::Command::Search {
            repo,
            query,
            limit,
            include_libs,
            snippets,
            max_tokens,
            force_web,
            skip_local_search,
            no_cache,
            max_web_results,
            llm_filter_local_results,
            async_web,
        } => {
            search::run(
                repo,
                query,
                limit,
                include_libs,
                snippets,
                max_tokens,
                force_web,
                skip_local_search,
                no_cache,
                max_web_results,
                llm_filter_local_results,
                async_web,
            )
            .await
        }
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
        super::Command::Repo { command } => repo::run(command).await,
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
        super::Command::MemoryCompact { repo, apply } => memory::run_compact(repo, apply).await,
        super::Command::MemoryLayers { scope } => memory_layers::run(scope).await,
        super::Command::Conversations { command } => conversations::run(command).await,
        super::Command::Diary { command } => diary::run(command).await,
        super::Command::Profile { command } => profile::run(command).await,
        super::Command::PersonalPreferences { command } => personal_preferences::run(command).await,
        super::Command::Hook { command } => hook::run(command).await,
        super::Command::SymbolsStatus { repo } => symbols::run_status(repo).await,
        super::Command::ImpactDiagnostics {
            repo,
            file,
            limit,
            offset,
        } => impact::run_diagnostics(repo, file, limit, offset).await,
        super::Command::ImpactGraph {
            repo,
            file,
            max_edges,
            max_depth,
            edge_types,
        } => impact::run_graph(repo, file, max_edges, max_depth, edge_types).await,
        super::Command::Tree {
            repo,
            path,
            max_depth,
            dirs_only,
            include_hidden,
            extra_excludes,
        } => {
            tree::run(
                repo,
                path,
                max_depth,
                dirs_only,
                include_hidden,
                extra_excludes,
            )
            .await
        }
        super::Command::Open {
            repo,
            file,
            start,
            end,
            head,
            clamp,
        } => open::run(repo, file, start, end, head, clamp),
        super::Command::File { command } => file::run(command),
        super::Command::Test { command } => test::run(command),
        super::Command::Delegation { command } => telemetry::run(command).await,
        super::Command::McpAdd {
            agent,
            transport,
            repo,
            remove,
            all,
        } => mcp_add::run(agent, transport, repo, remove, all),
    }
}
