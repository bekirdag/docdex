pub mod help_all;
pub mod dag;
pub mod index;
pub mod libs;
pub mod llm;
pub mod mcp;
pub mod mcp_add;
pub mod memory;
pub mod query;
pub mod repo;
pub mod self_check;
pub mod serve;
pub mod run_tests;
pub mod tui;
pub mod web;

use anyhow::Result;

pub async fn dispatch(command: super::Command) -> Result<()> {
    match command {
        super::Command::Serve {
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
            serve::run(
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
            )
            .await
        }
        super::Command::HelpAll => help_all::run(),
        super::Command::SelfCheck {
            repo,
            terms,
            limit,
            include_default_patterns,
        } => self_check::run(repo, terms, limit, include_default_patterns).await,
        super::Command::LlmList => llm::run_list(),
        super::Command::LlmSetup { ollama_path } => llm::run_setup(ollama_path),
        super::Command::Index { repo } => index::run_index(repo).await,
        super::Command::Ingest { repo, file } => index::run_ingest(repo, file).await,
        super::Command::Query {
            repo,
            query,
            limit,
            repo_only,
        } => query::run(repo, query, limit, repo_only).await,
        super::Command::Repo { command } => repo::run(command),
        super::Command::LibsIngest { repo, sources } => libs::run_ingest(repo, sources),
        super::Command::LibsDiscover { repo, sources } => libs::run_discover(repo, sources),
        super::Command::Libs { command } => libs::run_command(command),
        super::Command::WebSearch { query, limit } => web::run_search(query, limit).await,
        super::Command::WebFetch { url } => web::run_fetch(url).await,
        super::Command::WebRag {
            repo,
            query,
            limit,
            repo_only,
        } => web::run_rag(repo, query, limit, repo_only).await,
        super::Command::Dag { command } => dag::run(command),
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
        super::Command::Mcp {
            repo,
            log,
            max_results,
            rate_limit_per_min,
            rate_limit_burst,
        } => mcp::run(repo, log, max_results, rate_limit_per_min, rate_limit_burst).await,
        super::Command::McpAdd {
            agent,
            repo,
            max_results,
            log,
            remove,
            all,
        } => mcp_add::run(agent, repo, max_results, log, remove, all),
    }
}
