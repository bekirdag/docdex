use anyhow::Result;

use crate::config::RepoArgs;
use crate::mcoda::eval::{run_eval, EvalOptions};

pub async fn run(
    repo: RepoArgs,
    limit: usize,
    max_web_results: Option<usize>,
    repo_only: bool,
    web_only: bool,
    no_cache: bool,
    llm_filter_local_results: bool,
    max_queries: Option<usize>,
) -> Result<()> {
    let options = EvalOptions {
        repo,
        limit,
        max_web_results,
        repo_only,
        web_only,
        no_cache,
        llm_filter_local_results,
        max_queries,
    };
    run_eval(options).await
}
