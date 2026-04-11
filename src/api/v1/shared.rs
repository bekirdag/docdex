use axum::{
    http::{HeaderMap, StatusCode},
    response::Response,
};
use tracing::warn;

use crate::error::{AppError, ERR_INTERNAL_ERROR};
use crate::http_api::{app_error_response, json_error, repo_error_response, resolve_repo_context};
use crate::search::{AppState, RepoContext};

pub(crate) fn resolve_repo_request(
    state: &AppState,
    headers: &HeaderMap,
    query_repo_id: Option<&str>,
    body_repo_id: Option<&str>,
    require_repo: bool,
) -> Result<RepoContext, Response> {
    resolve_repo_context(state, headers, query_repo_id, body_repo_id, require_repo)
        .map_err(repo_error_response)
}

pub(crate) async fn resolve_repo_with_index(
    state: &AppState,
    headers: &HeaderMap,
    query_repo_id: Option<&str>,
    body_repo_id: Option<&str>,
    require_repo: bool,
) -> Result<RepoContext, Response> {
    let repo = resolve_repo_request(state, headers, query_repo_id, body_repo_id, require_repo)?;
    ensure_repo_index_ready(state, &repo).await?;
    Ok(repo)
}

pub(crate) async fn ensure_repo_index_ready(
    state: &AppState,
    repo: &RepoContext,
) -> Result<(), Response> {
    if let Err(err) = crate::index::ensure_indexed(repo.indexer.clone()).await {
        state.metrics.inc_error();
        if let Some(app) = err.downcast_ref::<AppError>() {
            return Err(app_error_response(app));
        }
        warn!(target: "docdexd", error = ?err, "indexing failed");
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "indexing failed",
        ));
    }
    Ok(())
}
