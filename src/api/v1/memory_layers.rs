use crate::http_api::{repo_error_response, resolve_conversation_context};
use crate::memory_layers::{
    build_memory_layers_map, build_memory_route, MemoryLayerScopeInput, MemoryLayersInput,
};
use crate::search::{AppState, ConversationRequestContext, RepoIdQuery, RequestId};
use axum::{
    extract::{Extension, Query, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use tracing::info;

#[derive(Debug, Deserialize)]
pub struct MemoryRouteRequest {
    pub query: String,
    #[serde(default)]
    pub intent: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

pub(crate) async fn memory_layers_handler(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        repo_id.conversation_namespace.as_deref(),
        None,
        false,
    ) {
        Ok(scope) => scope,
        Err(err) => return repo_error_response(err),
    };

    let conversations = scope.conversations();
    let response = match &scope {
        ConversationRequestContext::Repo(repo) => build_memory_layers_map(MemoryLayersInput {
            scope: MemoryLayerScopeInput::Repo {
                repo_id: &repo.repo_id,
                repo_root: repo.indexer.repo_root(),
            },
            default_agent_id: state.default_agent_id.as_deref(),
            repo_memory: repo.memory.as_ref().map(|memory| &memory.store),
            profile: state.profile_state.as_ref().map(|profile| &profile.manager),
            conversations: conversations.as_ref().map(|value| &value.store),
            knowledge: conversations.as_ref().map(|value| &value.knowledge),
            conversation_config: conversations.as_ref().map(|value| &value.config),
            personal_preferences: state
                .personal_preferences
                .as_ref()
                .map(|value| &value.store),
            personal_preferences_config: state
                .personal_preferences
                .as_ref()
                .map(|value| &value.config),
        }),
        ConversationRequestContext::Namespace(namespace) => {
            build_memory_layers_map(MemoryLayersInput {
                scope: MemoryLayerScopeInput::Namespace {
                    namespace: &namespace.namespace,
                },
                default_agent_id: state.default_agent_id.as_deref(),
                repo_memory: None,
                profile: state.profile_state.as_ref().map(|profile| &profile.manager),
                conversations: conversations.as_ref().map(|value| &value.store),
                knowledge: conversations.as_ref().map(|value| &value.knowledge),
                conversation_config: conversations.as_ref().map(|value| &value.config),
                personal_preferences: state
                    .personal_preferences
                    .as_ref()
                    .map(|value| &value.store),
                personal_preferences_config: state
                    .personal_preferences
                    .as_ref()
                    .map(|value| &value.config),
            })
        }
    };

    info!(
        target: "docdexd",
        request_id = %request_id.0,
        scope = %response.scope.scope_label,
        "memory layers requested"
    );
    Json(response).into_response()
}

pub(crate) async fn memory_route_handler(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<MemoryRouteRequest>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        repo_id.conversation_namespace.as_deref(),
        req.conversation_namespace.as_deref(),
        false,
    ) {
        Ok(scope) => scope,
        Err(err) => return repo_error_response(err),
    };

    let conversations = scope.conversations();
    let response = match &scope {
        ConversationRequestContext::Repo(repo) => build_memory_route(
            MemoryLayersInput {
                scope: MemoryLayerScopeInput::Repo {
                    repo_id: &repo.repo_id,
                    repo_root: repo.indexer.repo_root(),
                },
                default_agent_id: state.default_agent_id.as_deref(),
                repo_memory: repo.memory.as_ref().map(|memory| &memory.store),
                profile: state.profile_state.as_ref().map(|profile| &profile.manager),
                conversations: conversations.as_ref().map(|value| &value.store),
                knowledge: conversations.as_ref().map(|value| &value.knowledge),
                conversation_config: conversations.as_ref().map(|value| &value.config),
                personal_preferences: state
                    .personal_preferences
                    .as_ref()
                    .map(|value| &value.store),
                personal_preferences_config: state
                    .personal_preferences
                    .as_ref()
                    .map(|value| &value.config),
            },
            &req.query,
            req.intent.as_deref(),
        ),
        ConversationRequestContext::Namespace(namespace) => build_memory_route(
            MemoryLayersInput {
                scope: MemoryLayerScopeInput::Namespace {
                    namespace: &namespace.namespace,
                },
                default_agent_id: state.default_agent_id.as_deref(),
                repo_memory: None,
                profile: state.profile_state.as_ref().map(|profile| &profile.manager),
                conversations: conversations.as_ref().map(|value| &value.store),
                knowledge: conversations.as_ref().map(|value| &value.knowledge),
                conversation_config: conversations.as_ref().map(|value| &value.config),
                personal_preferences: state
                    .personal_preferences
                    .as_ref()
                    .map(|value| &value.store),
                personal_preferences_config: state
                    .personal_preferences
                    .as_ref()
                    .map(|value| &value.config),
            },
            &req.query,
            req.intent.as_deref(),
        ),
    };

    info!(
        target: "docdexd",
        request_id = %request_id.0,
        scope = %response.scope.scope_label,
        intent = %response.intent,
        "memory route requested"
    );
    Json(response).into_response()
}
