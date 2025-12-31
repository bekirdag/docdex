use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::error::{
    ERR_EMBEDDING_FAILED, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_PROFILE_DISABLED,
};
use crate::profiles::evolution::{build_ollama_evolution_client, EvolutionEngine};
use crate::profiles::{Agent, Preference, PreferenceCategory};
use crate::search::{json_error, AppState};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ProfileListQuery {
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Deserialize)]
pub struct ProfileAddRequest {
    pub agent_id: String,
    pub content: String,
    pub category: PreferenceCategory,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Deserialize)]
pub struct ProfileSearchRequest {
    pub agent_id: String,
    pub query: String,
    #[serde(default)]
    pub top_k: Option<usize>,
}

#[derive(Deserialize)]
pub struct ProfileSaveRequest {
    pub agent_id: String,
    pub content: String,
    pub category: PreferenceCategory,
    #[serde(default)]
    pub role: Option<String>,
}

#[derive(Serialize)]
pub struct ProfileListResponse {
    pub agents: Vec<Agent>,
    pub preferences: Vec<PreferenceRecord>,
}

#[derive(Serialize)]
pub struct ProfileAddResponse {
    pub preference: PreferenceRecord,
}

#[derive(Serialize)]
pub struct ProfileSearchResponse {
    pub query: String,
    pub results: Vec<ProfileSearchHit>,
}

#[derive(Serialize)]
pub struct ProfileSearchHit {
    pub score: f32,
    pub preference: PreferenceRecord,
}

#[derive(Serialize)]
pub struct ProfileSaveResponse {
    pub request_id: String,
    pub status: &'static str,
}

#[derive(Serialize, Deserialize)]
pub struct ProfileSyncManifest {
    pub schema_version: u32,
    pub embedding_dim: usize,
    pub agents: Vec<Agent>,
    pub preferences: Vec<PreferenceRecord>,
}

#[derive(Serialize)]
pub struct ProfileImportResponse {
    pub agents: usize,
    pub inserted: usize,
    pub updated: usize,
    pub skipped: usize,
}

#[derive(Serialize, Deserialize)]
pub struct PreferenceRecord {
    pub id: String,
    pub agent_id: String,
    pub content: String,
    pub category: PreferenceCategory,
    pub last_updated: i64,
}

impl From<Preference> for PreferenceRecord {
    fn from(pref: Preference) -> Self {
        PreferenceRecord {
            id: pref.id,
            agent_id: pref.agent_id,
            content: pref.content,
            category: pref.category,
            last_updated: pref.last_updated,
        }
    }
}

pub async fn profile_list_handler(
    State(state): State<AppState>,
    Query(query): Query<ProfileListQuery>,
) -> Response {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_PROFILE_DISABLED,
            "profile memory disabled",
        );
    };
    let mut agents = match profile_state.manager.list_agents() {
        Ok(agents) => agents,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile list agents failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile list failed",
            );
        }
    };
    if let Some(agent_id) = query.agent_id.as_ref() {
        agents.retain(|agent| agent.id == *agent_id);
    }
    let preferences = match profile_state
        .manager
        .list_preferences(query.agent_id.as_deref())
    {
        Ok(preferences) => preferences,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile list preferences failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile list failed",
            );
        }
    };
    Json(ProfileListResponse {
        agents,
        preferences: preferences
            .into_iter()
            .map(PreferenceRecord::from)
            .collect(),
    })
    .into_response()
}

pub async fn profile_add_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProfileAddRequest>,
) -> Response {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_PROFILE_DISABLED,
            "profile memory disabled",
        );
    };
    let agent_id = payload.agent_id.trim();
    let content = payload.content.trim();
    if agent_id.is_empty() || content.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "agent_id and content are required",
        );
    }
    let now_ms = now_epoch_ms();
    if let Ok(None) = profile_state.manager.get_agent(agent_id) {
        let role = payload.role.as_deref().unwrap_or("custom");
        if let Err(err) = profile_state.manager.create_agent(agent_id, role, now_ms) {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile add agent failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile add failed",
            );
        }
    }
    let Some(embedder) = profile_state.embedder.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_EMBEDDING_FAILED,
            "profile embedder unavailable",
        );
    };
    let embedding = match embedder.embed(content).await {
        Ok(embedding) => embedding,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile embedding failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_EMBEDDING_FAILED,
                "profile embedding failed",
            );
        }
    };
    let preference = match profile_state.manager.add_preference(
        agent_id,
        content,
        &embedding,
        payload.category,
        now_ms,
    ) {
        Ok(pref) => pref,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile add failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile add failed",
            );
        }
    };
    Json(ProfileAddResponse {
        preference: PreferenceRecord::from(preference),
    })
    .into_response()
}

pub async fn profile_search_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProfileSearchRequest>,
) -> Response {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_PROFILE_DISABLED,
            "profile memory disabled",
        );
    };
    let agent_id = payload.agent_id.trim();
    let query = payload.query.trim();
    if agent_id.is_empty() || query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "agent_id and query are required",
        );
    }
    let Some(embedder) = profile_state.embedder.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_EMBEDDING_FAILED,
            "profile embedder unavailable",
        );
    };
    let embedding = match embedder.embed(query).await {
        Ok(embedding) => embedding,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile embedding failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_EMBEDDING_FAILED,
                "profile embedding failed",
            );
        }
    };
    let top_k = payload.top_k.unwrap_or(8).max(1);
    let results = match profile_state
        .manager
        .search_preferences(agent_id, &embedding, top_k)
    {
        Ok(results) => results,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile search failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile search failed",
            );
        }
    };
    Json(ProfileSearchResponse {
        query: query.to_string(),
        results: results
            .into_iter()
            .map(|result| ProfileSearchHit {
                score: result.score,
                preference: PreferenceRecord::from(result.preference),
            })
            .collect(),
    })
    .into_response()
}

pub async fn profile_export_handler(State(state): State<AppState>) -> Response {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_PROFILE_DISABLED,
            "profile memory disabled",
        );
    };
    let agents = match profile_state.manager.list_agents() {
        Ok(agents) => agents,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile export failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile export failed",
            );
        }
    };
    let preferences = match profile_state.manager.list_preferences(None) {
        Ok(preferences) => preferences,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile export failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile export failed",
            );
        }
    };
    Json(ProfileSyncManifest {
        schema_version: profile_state.manager.schema_version(),
        embedding_dim: profile_state.manager.embedding_dim(),
        agents,
        preferences: preferences
            .into_iter()
            .map(PreferenceRecord::from)
            .collect(),
    })
    .into_response()
}

pub async fn profile_save_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProfileSaveRequest>,
) -> Response {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_PROFILE_DISABLED,
            "profile memory disabled",
        );
    };
    let agent_id = payload.agent_id.trim();
    let content = payload.content.trim();
    if agent_id.is_empty() || content.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "agent_id and content are required",
        );
    }
    let now_ms = now_epoch_ms();
    if let Ok(None) = profile_state.manager.get_agent(agent_id) {
        let role = payload.role.as_deref().unwrap_or("custom");
        if let Err(err) = profile_state.manager.create_agent(agent_id, role, now_ms) {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile save agent failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile save failed",
            );
        }
    }
    let llm_client =
        match build_ollama_evolution_client(&state.llm_base_url, &state.llm_default_model) {
            Ok(client) => client,
            Err(err) => {
                state.metrics.inc_error();
                warn!(target: "docdexd", error = ?err, "profile evolution LLM unavailable");
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "profile evolution unavailable",
                );
            }
        };
    let Some(embedder) = profile_state.embedder.clone() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_EMBEDDING_FAILED,
            "profile embedder unavailable",
        );
    };
    let engine = EvolutionEngine::new(profile_state.manager.clone(), embedder, llm_client);
    let request_id = Uuid::new_v4().to_string();
    let agent_id = agent_id.to_string();
    let content = content.to_string();
    let category = payload.category;
    let request_id_log = request_id.clone();
    tokio::spawn(async move {
        match engine.evolve(&agent_id, category, &content).await {
            Ok(outcome) => info!(
                target: "docdexd",
                request_id = %request_id_log,
                agent_id = %agent_id,
                action = ?outcome.action,
                preference_id = outcome.preference_id.as_deref(),
                "profile evolution completed"
            ),
            Err(err) => warn!(
                target: "docdexd",
                request_id = %request_id_log,
                agent_id = %agent_id,
                error = ?err,
                "profile evolution failed"
            ),
        }
    });
    Json(ProfileSaveResponse {
        request_id,
        status: "queued",
    })
    .into_response()
}

pub async fn profile_import_handler(
    State(state): State<AppState>,
    Json(payload): Json<ProfileSyncManifest>,
) -> Response {
    let Some(profile_state) = state.profile_state.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_PROFILE_DISABLED,
            "profile memory disabled",
        );
    };
    if payload.schema_version != profile_state.manager.schema_version() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "profile schema_version mismatch",
        );
    }
    if payload.embedding_dim != profile_state.manager.embedding_dim() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "profile embedding_dim mismatch",
        );
    }
    let Some(embedder) = profile_state.embedder.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_EMBEDDING_FAILED,
            "profile embedder unavailable",
        );
    };
    let mut preferences = Vec::with_capacity(payload.preferences.len());
    for pref in payload.preferences {
        let embedding = match embedder.embed(pref.content.trim()).await {
            Ok(embedding) => embedding,
            Err(err) => {
                state.metrics.inc_error();
                warn!(target: "docdexd", error = ?err, "profile embedding failed");
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_EMBEDDING_FAILED,
                    "profile embedding failed",
                );
            }
        };
        preferences.push(Preference {
            id: pref.id,
            agent_id: pref.agent_id,
            content: pref.content,
            embedding: Some(embedding),
            category: pref.category,
            last_updated: pref.last_updated,
        });
    }
    let summary = match profile_state
        .manager
        .import_preferences(&payload.agents, &preferences)
    {
        Ok(summary) => summary,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "profile import failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "profile import failed",
            );
        }
    };
    Json(ProfileImportResponse {
        agents: summary.agents,
        inserted: summary.inserted,
        updated: summary.updated,
        skipped: summary.skipped,
    })
    .into_response()
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}
