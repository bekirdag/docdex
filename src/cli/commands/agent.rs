use anyhow::Result;

use crate::cli::AgentCommand;

use super::mcoda_eval;

pub async fn run(command: AgentCommand) -> Result<()> {
    match command {
        AgentCommand::Eval {
            repo,
            limit,
            max_web_results,
            repo_only,
            web_only,
            no_cache,
            llm_filter_local_results,
            max_queries,
        } => {
            mcoda_eval::run(
                repo,
                limit,
                max_web_results,
                repo_only,
                web_only,
                no_cache,
                llm_filter_local_results,
                max_queries,
            )
            .await
        }
    }
}
