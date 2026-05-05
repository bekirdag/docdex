use axum::http::{header::AUTHORIZATION, HeaderMap};
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use reqwest::StatusCode as ReqwestStatusCode;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::error::{
    AppError, ERR_AMBIGUOUS_CREDENTIALS, ERR_INTROSPECTION_UNAVAILABLE, ERR_INVALID_CREDENTIALS,
    ERR_MISSING_CREDENTIALS, ERR_REPO_ACCESS_DENIED, ERR_SCOPE_DENIED,
};

const DEFAULT_AUTH_MODE: AuthMode = AuthMode::LocalOrExternal;
const DEFAULT_REJECT_AMBIGUOUS_CREDENTIALS: bool = true;
const DEFAULT_STATIC_TOKEN_ENV: &str = "DOCDEX_AUTH_TOKEN";
const DEFAULT_STATIC_TOKEN_ISSUER: &str = "docdex_static_token";
const DEFAULT_STATIC_TOKEN_PRINCIPAL: &str = "static_token";
const DEFAULT_EXTERNAL_ISSUER: &str = "external";
const DEFAULT_EXTERNAL_SERVICE_TOKEN_ENV: &str = "DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN";
const DEFAULT_EXTERNAL_CACHE_TTL_SECONDS: u64 = 60;
const DEFAULT_EXTERNAL_NEGATIVE_CACHE_TTL_SECONDS: u64 = 10;
const DEFAULT_EXTERNAL_TIMEOUT_MS: u64 = 3_000;
const DEFAULT_EXTERNAL_REQUIRED_STATUS: &str = "active";
const DEFAULT_SERVICE_TOKEN_ENV: &str = "DOCDEX_ADMIN_SERVICE_TOKEN";
const API_KEY_HEADER: &str = "x-api-key";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    LocalOnly,
    LocalOrExternal,
    ExternalOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_auth_mode")]
    pub mode: AuthMode,
    #[serde(default = "default_reject_ambiguous_credentials")]
    pub reject_ambiguous_credentials: bool,
    #[serde(default)]
    pub static_token: StaticTokenAuthConfig,
    #[serde(default)]
    pub external_api_key_introspection: ExternalApiKeyIntrospectionConfig,
    #[serde(default)]
    pub service_token: ServiceTokenAuthConfig,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            mode: default_auth_mode(),
            reject_ambiguous_credentials: default_reject_ambiguous_credentials(),
            static_token: StaticTokenAuthConfig::default(),
            external_api_key_introspection: ExternalApiKeyIntrospectionConfig::default(),
            service_token: ServiceTokenAuthConfig::default(),
        }
    }
}

impl AuthConfig {
    pub fn apply_defaults(&mut self) {
        if self.static_token.token_env.trim().is_empty() {
            self.static_token.token_env = DEFAULT_STATIC_TOKEN_ENV.to_string();
        }
        if self.external_api_key_introspection.issuer.trim().is_empty() {
            self.external_api_key_introspection.issuer = DEFAULT_EXTERNAL_ISSUER.to_string();
        }
        if self
            .external_api_key_introspection
            .service_token_env
            .trim()
            .is_empty()
        {
            self.external_api_key_introspection.service_token_env =
                DEFAULT_EXTERNAL_SERVICE_TOKEN_ENV.to_string();
        }
        if self.external_api_key_introspection.cache_ttl_seconds == 0 {
            self.external_api_key_introspection.cache_ttl_seconds =
                DEFAULT_EXTERNAL_CACHE_TTL_SECONDS;
        }
        if self
            .external_api_key_introspection
            .negative_cache_ttl_seconds
            == 0
        {
            self.external_api_key_introspection
                .negative_cache_ttl_seconds = DEFAULT_EXTERNAL_NEGATIVE_CACHE_TTL_SECONDS;
        }
        if self.external_api_key_introspection.timeout_ms == 0 {
            self.external_api_key_introspection.timeout_ms = DEFAULT_EXTERNAL_TIMEOUT_MS;
        }
        if self
            .external_api_key_introspection
            .required_status
            .trim()
            .is_empty()
        {
            self.external_api_key_introspection.required_status =
                DEFAULT_EXTERNAL_REQUIRED_STATUS.to_string();
        }
        self.external_api_key_introspection.accepted_headers =
            normalized_accepted_headers(&self.external_api_key_introspection.accepted_headers);
        if self.service_token.token_env.trim().is_empty() {
            self.service_token.token_env = DEFAULT_SERVICE_TOKEN_ENV.to_string();
        }
    }

    pub fn provider_names(&self) -> Vec<&'static str> {
        let mut providers = Vec::new();
        if self.static_token.enabled {
            providers.push("static_token");
        }
        if self.external_api_key_introspection.enabled {
            providers.push("external_api_key_introspection");
        }
        if self.service_token.enabled {
            providers.push("service_token");
        }
        providers
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticTokenAuthConfig {
    #[serde(default = "default_static_token_enabled")]
    pub enabled: bool,
    #[serde(default = "default_static_token_env")]
    pub token_env: String,
    #[serde(default)]
    pub encrypted_repo_data_access: bool,
}

impl Default for StaticTokenAuthConfig {
    fn default() -> Self {
        Self {
            enabled: default_static_token_enabled(),
            token_env: default_static_token_env(),
            encrypted_repo_data_access: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalApiKeyIntrospectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_external_issuer")]
    pub issuer: String,
    #[serde(default)]
    pub url: String,
    #[serde(default = "default_external_service_token_env")]
    pub service_token_env: String,
    #[serde(default = "default_external_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
    #[serde(default = "default_external_negative_cache_ttl_seconds")]
    pub negative_cache_ttl_seconds: u64,
    #[serde(default = "default_external_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_external_fail_closed")]
    pub fail_closed: bool,
    #[serde(default = "default_external_accepted_headers")]
    pub accepted_headers: Vec<String>,
    #[serde(default = "default_external_required_status")]
    pub required_status: String,
}

impl Default for ExternalApiKeyIntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            issuer: default_external_issuer(),
            url: String::new(),
            service_token_env: default_external_service_token_env(),
            cache_ttl_seconds: default_external_cache_ttl_seconds(),
            negative_cache_ttl_seconds: default_external_negative_cache_ttl_seconds(),
            timeout_ms: default_external_timeout_ms(),
            fail_closed: default_external_fail_closed(),
            accepted_headers: default_external_accepted_headers(),
            required_status: default_external_required_status(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceTokenAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_service_token_env")]
    pub token_env: String,
    #[serde(default)]
    pub encrypted_repo_data_access: bool,
}

impl Default for ServiceTokenAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            token_env: default_service_token_env(),
            encrypted_repo_data_access: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthCapabilities {
    pub mode: AuthMode,
    pub providers: Vec<&'static str>,
    pub static_token_enabled: bool,
    pub external_introspection_enabled: bool,
    pub service_token_enabled: bool,
    pub repo_access_policy_enabled: bool,
    pub reject_ambiguous_credentials: bool,
}

impl AuthCapabilities {
    pub fn from_config(config: &AuthConfig) -> Self {
        Self {
            mode: config.mode,
            providers: config.provider_names(),
            static_token_enabled: config.static_token.enabled,
            external_introspection_enabled: config.external_api_key_introspection.enabled,
            service_token_enabled: config.service_token.enabled,
            repo_access_policy_enabled: true,
            reject_ambiguous_credentials: config.reject_ambiguous_credentials,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMethod {
    StaticToken,
    ExternalApiKeyIntrospection,
    ServiceToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalStatus {
    Active,
    Inactive,
    Revoked,
    Expired,
    Unknown,
}

impl PrincipalStatus {
    fn from_raw(raw: Option<&str>) -> Self {
        match raw.unwrap_or_default().trim().to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "inactive" => Self::Inactive,
            "revoked" => Self::Revoked,
            "expired" => Self::Expired,
            _ => Self::Unknown,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Inactive => "inactive",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthContext {
    pub auth_method: AuthMethod,
    pub issuer: String,
    pub subject: Option<String>,
    pub credential_id: String,
    pub principal_id: String,
    pub scopes: Vec<String>,
    pub status: PrincipalStatus,
    pub expires_at_ms: Option<i64>,
    pub credential_fingerprint: String,
    pub claims_json: Option<Value>,
}

impl AuthContext {
    fn validate_active(&self) -> Result<(), AppError> {
        if self.status != PrincipalStatus::Active {
            return Err(
                AppError::new(ERR_INVALID_CREDENTIALS, "credential is not active")
                    .with_details(json!({ "status": self.status.as_str() })),
            );
        }
        if let Some(expires_at_ms) = self.expires_at_ms {
            if expires_at_ms <= now_epoch_ms() {
                return Err(AppError::new(
                    ERR_INVALID_CREDENTIALS,
                    "credential has expired",
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct CredentialMaterial {
    raw: String,
    source: String,
    fingerprint: String,
}

impl CredentialMaterial {
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoOperation {
    Capabilities,
    Search,
    Snippet,
    Open,
    ChatContext,
    Index,
    Admin,
    AuditRead,
}

impl RepoOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Capabilities => "capabilities",
            Self::Search => "search",
            Self::Snippet => "snippet",
            Self::Open => "open",
            Self::ChatContext => "chat_context",
            Self::Index => "index",
            Self::Admin => "admin",
            Self::AuditRead => "audit_read",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoAccessBinding {
    pub id: String,
    pub repo_id: String,
    pub issuer: String,
    pub principal_type: String,
    pub principal_id: String,
    pub credential_id: Option<String>,
    pub required_scopes: Vec<String>,
    pub allowed_operations: Vec<String>,
    pub status: String,
    pub expires_at_ms: Option<i64>,
    pub metadata_json: Value,
}

impl RepoAccessBinding {
    pub fn normalize(mut self) -> Self {
        if self.id.trim().is_empty() {
            self.id = Uuid::new_v4().to_string();
        }
        self.repo_id = self.repo_id.trim().to_string();
        self.issuer = self.issuer.trim().to_string();
        if self.principal_type.trim().is_empty() {
            self.principal_type = "principal".to_string();
        } else {
            self.principal_type = self.principal_type.trim().to_string();
        }
        self.principal_id = self.principal_id.trim().to_string();
        self.credential_id = self
            .credential_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        self.required_scopes = normalize_string_list(self.required_scopes);
        self.allowed_operations = normalize_string_list(self.allowed_operations);
        if self.status.trim().is_empty() {
            self.status = "active".to_string();
        } else {
            self.status = self.status.trim().to_ascii_lowercase();
        }
        if !self.metadata_json.is_object() {
            self.metadata_json = json!({});
        }
        self
    }
}

#[derive(Clone)]
pub struct RepoAccessStore {
    path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl RepoAccessStore {
    pub fn open(state_dir: &Path) -> anyhow::Result<Self> {
        let auth_dir = state_dir.join("auth");
        std::fs::create_dir_all(&auth_dir)?;
        let path = auth_dir.join("repo_access.sqlite");
        let conn = Connection::open(&path)?;
        let store = Self {
            path,
            conn: Arc::new(Mutex::new(conn)),
        };
        store.migrate()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn migrate(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS repo_access_bindings (
                id TEXT PRIMARY KEY,
                repo_id TEXT NOT NULL,
                issuer TEXT NOT NULL,
                principal_type TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                credential_id TEXT,
                required_scopes_json TEXT NOT NULL DEFAULT '[]',
                allowed_operations_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'active',
                expires_at_ms INTEGER,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                created_at_ms INTEGER NOT NULL,
                updated_at_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS repo_access_bindings_repo_idx
                ON repo_access_bindings(repo_id);
            CREATE INDEX IF NOT EXISTS repo_access_bindings_principal_idx
                ON repo_access_bindings(issuer, principal_type, principal_id);
            CREATE INDEX IF NOT EXISTS repo_access_bindings_credential_idx
                ON repo_access_bindings(issuer, credential_id);
            "#,
        )?;
        Ok(())
    }

    pub fn upsert_binding(
        &self,
        binding: RepoAccessBinding,
    ) -> Result<RepoAccessBinding, AppError> {
        let binding = binding.normalize();
        validate_binding(&binding)?;
        let now = now_epoch_ms();
        let required_scopes_json =
            serde_json::to_string(&binding.required_scopes).map_err(|err| {
                AppError::new(ERR_INVALID_CREDENTIALS, format!("serialize scopes: {err}"))
            })?;
        let allowed_operations_json =
            serde_json::to_string(&binding.allowed_operations).map_err(|err| {
                AppError::new(
                    ERR_INVALID_CREDENTIALS,
                    format!("serialize allowed operations: {err}"),
                )
            })?;
        let metadata_json = serde_json::to_string(&binding.metadata_json).map_err(|err| {
            AppError::new(
                ERR_INVALID_CREDENTIALS,
                format!("serialize metadata: {err}"),
            )
        })?;
        let conn = self.conn.lock();
        conn.execute(
            r#"
            INSERT INTO repo_access_bindings (
                id, repo_id, issuer, principal_type, principal_id, credential_id,
                required_scopes_json, allowed_operations_json, status, expires_at_ms,
                metadata_json, created_at_ms, updated_at_ms
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?12)
            ON CONFLICT(id) DO UPDATE SET
                repo_id = excluded.repo_id,
                issuer = excluded.issuer,
                principal_type = excluded.principal_type,
                principal_id = excluded.principal_id,
                credential_id = excluded.credential_id,
                required_scopes_json = excluded.required_scopes_json,
                allowed_operations_json = excluded.allowed_operations_json,
                status = excluded.status,
                expires_at_ms = excluded.expires_at_ms,
                metadata_json = excluded.metadata_json,
                updated_at_ms = excluded.updated_at_ms
            "#,
            params![
                binding.id,
                binding.repo_id,
                binding.issuer,
                binding.principal_type,
                binding.principal_id,
                binding.credential_id,
                required_scopes_json,
                allowed_operations_json,
                binding.status,
                binding.expires_at_ms,
                metadata_json,
                now,
            ],
        )
        .map_err(|err| AppError::new(ERR_REPO_ACCESS_DENIED, format!("store binding: {err}")))?;
        Ok(binding)
    }

    pub fn list_bindings(&self, repo_id: &str) -> Result<Vec<RepoAccessBinding>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                r#"
                SELECT id, repo_id, issuer, principal_type, principal_id, credential_id,
                       required_scopes_json, allowed_operations_json, status, expires_at_ms,
                       metadata_json
                FROM repo_access_bindings
                WHERE repo_id = ?1
                ORDER BY updated_at_ms DESC, id ASC
                "#,
            )
            .map_err(|err| {
                AppError::new(ERR_REPO_ACCESS_DENIED, format!("list bindings: {err}"))
            })?;
        let rows = stmt
            .query_map(params![repo_id], row_to_binding)
            .map_err(|err| {
                AppError::new(ERR_REPO_ACCESS_DENIED, format!("list bindings: {err}"))
            })?;
        let mut bindings = Vec::new();
        for row in rows {
            bindings.push(row.map_err(|err| {
                AppError::new(ERR_REPO_ACCESS_DENIED, format!("read binding: {err}"))
            })?);
        }
        Ok(bindings)
    }

    pub fn delete_bindings_for_repo(&self, repo_id: &str) -> Result<usize, AppError> {
        let conn = self.conn.lock();
        conn.execute(
            "DELETE FROM repo_access_bindings WHERE repo_id = ?1",
            params![repo_id],
        )
        .map_err(|err| AppError::new(ERR_REPO_ACCESS_DENIED, format!("delete bindings: {err}")))
    }

    pub fn authorize(
        &self,
        ctx: &AuthContext,
        repo_id: &str,
        operation: RepoOperation,
    ) -> Result<RepoAccessBinding, AppError> {
        ctx.validate_active()?;
        let bindings = self.candidate_bindings(repo_id, &ctx.issuer, &ctx.credential_id)?;
        let now = now_epoch_ms();
        let mut saw_binding = false;
        for binding in bindings {
            if !binding_matches_context(&binding, ctx) {
                continue;
            }
            saw_binding = true;
            if binding.status != "active" {
                continue;
            }
            if binding
                .expires_at_ms
                .map(|expires_at| expires_at <= now)
                .unwrap_or(false)
            {
                continue;
            }
            if !operation_allowed(&binding.allowed_operations, operation) {
                continue;
            }
            if !required_scopes_satisfied(&binding.required_scopes, &ctx.scopes) {
                return Err(AppError::new(
                    ERR_SCOPE_DENIED,
                    "credential lacks required scopes for repository access",
                ));
            }
            return Ok(binding);
        }
        if saw_binding {
            Err(AppError::new(
                ERR_SCOPE_DENIED,
                "repository access binding does not allow this operation",
            ))
        } else {
            Err(AppError::new(
                ERR_REPO_ACCESS_DENIED,
                "credential is not bound to this repository",
            ))
        }
    }

    fn candidate_bindings(
        &self,
        repo_id: &str,
        issuer: &str,
        credential_id: &str,
    ) -> Result<Vec<RepoAccessBinding>, AppError> {
        let conn = self.conn.lock();
        let mut stmt = conn
            .prepare(
                r#"
                SELECT id, repo_id, issuer, principal_type, principal_id, credential_id,
                       required_scopes_json, allowed_operations_json, status, expires_at_ms,
                       metadata_json
                FROM repo_access_bindings
                WHERE repo_id = ?1
                  AND issuer = ?2
                  AND (credential_id = ?3 OR credential_id IS NULL)
                "#,
            )
            .map_err(|err| {
                AppError::new(ERR_REPO_ACCESS_DENIED, format!("query bindings: {err}"))
            })?;
        let rows = stmt
            .query_map(params![repo_id, issuer, credential_id], row_to_binding)
            .map_err(|err| {
                AppError::new(ERR_REPO_ACCESS_DENIED, format!("query bindings: {err}"))
            })?;
        let mut bindings = Vec::new();
        for row in rows {
            bindings.push(row.map_err(|err| {
                AppError::new(ERR_REPO_ACCESS_DENIED, format!("read binding: {err}"))
            })?);
        }
        Ok(bindings)
    }
}

#[derive(Clone)]
pub struct AuthRuntime {
    config: AuthConfig,
    access_store: RepoAccessStore,
    client: reqwest::Client,
    introspection_cache: Arc<Mutex<HashMap<String, CachedAuth>>>,
}

impl AuthRuntime {
    pub fn new(mut config: AuthConfig, state_dir: &Path) -> anyhow::Result<Self> {
        config.apply_defaults();
        let timeout = Duration::from_millis(config.external_api_key_introspection.timeout_ms);
        let client = reqwest::Client::builder().timeout(timeout).build()?;
        Ok(Self {
            config,
            access_store: RepoAccessStore::open(state_dir)?,
            client,
            introspection_cache: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    #[cfg(test)]
    pub fn new_for_tests(config: AuthConfig, state_dir: &Path) -> Self {
        Self::new(config, state_dir).expect("auth runtime")
    }

    pub fn config(&self) -> &AuthConfig {
        &self.config
    }

    pub fn access_store(&self) -> &RepoAccessStore {
        &self.access_store
    }

    pub fn invalidate_cache(&self) -> usize {
        let mut cache = self.introspection_cache.lock();
        let count = cache.len();
        cache.clear();
        count
    }

    pub fn has_deferred_route_credential(&self, headers: &HeaderMap) -> bool {
        extract_credential(
            headers,
            &self.config.external_api_key_introspection.accepted_headers,
            false,
        )
        .ok()
        .flatten()
        .is_some()
            || extract_authorization_bearer(headers).is_some()
    }

    pub fn may_defer_route_auth(
        &self,
        headers: &HeaderMap,
        path: &str,
        encrypted_repo: bool,
    ) -> bool {
        if path.starts_with("/v1/admin/") {
            return self.config.service_token.enabled
                && self.has_deferred_route_credential(headers);
        }
        if !encrypted_repo {
            return false;
        }
        if !matches!(
            path,
            "/search"
                | "/v1/search/batch"
                | "/v1/search/rerank"
                | "/v1/chat/completions"
                | "/v1/mcp"
                | "/v1/mcp/message"
                | "/sse"
        ) && !path.starts_with("/snippet/")
            && path != "/v1/mcp/sse"
        {
            return false;
        }
        (self.config.external_api_key_introspection.enabled
            || self.config.static_token.encrypted_repo_data_access
            || self.config.service_token.encrypted_repo_data_access)
            && self.has_deferred_route_credential(headers)
    }

    pub async fn authorize_repo_access(
        &self,
        headers: &HeaderMap,
        repo_id: &str,
        operation: RepoOperation,
    ) -> Result<AuthContext, AppError> {
        let material = extract_credential(
            headers,
            &self.config.external_api_key_introspection.accepted_headers,
            self.config.reject_ambiguous_credentials,
        )?
        .ok_or_else(|| AppError::new(ERR_MISSING_CREDENTIALS, "missing API credential"))?;

        if let Some(ctx) = self.authenticate_service_token(&material)? {
            if !self.config.service_token.encrypted_repo_data_access {
                return Err(AppError::new(
                    ERR_SCOPE_DENIED,
                    "service tokens are restricted to administrative operations",
                )
                .with_details(json!({ "auth_method": format!("{:?}", ctx.auth_method) })));
            }
            self.access_store.authorize(&ctx, repo_id, operation)?;
            return Ok(ctx);
        }

        if let Some(ctx) = self.authenticate_static_token(&material)? {
            if !self.config.static_token.encrypted_repo_data_access {
                return Err(AppError::new(
                    ERR_SCOPE_DENIED,
                    "static bearer token is not sufficient for encrypted repository data access",
                ));
            }
            self.access_store.authorize(&ctx, repo_id, operation)?;
            return Ok(ctx);
        }

        if !self.config.external_api_key_introspection.enabled
            || matches!(self.config.mode, AuthMode::LocalOnly)
        {
            return Err(AppError::new(
                ERR_INVALID_CREDENTIALS,
                "credential did not match an enabled auth provider",
            ));
        }
        let ctx = self.introspect_external(&material, repo_id).await?;
        self.access_store.authorize(&ctx, repo_id, operation)?;
        Ok(ctx)
    }

    pub fn authorize_service_admin(&self, headers: &HeaderMap) -> Result<AuthContext, AppError> {
        if !self.config.service_token.enabled {
            return Err(AppError::new(
                ERR_INVALID_CREDENTIALS,
                "service-token authentication is disabled",
            ));
        }
        let material = extract_credential(headers, &default_external_accepted_headers(), true)?
            .ok_or_else(|| AppError::new(ERR_MISSING_CREDENTIALS, "missing service token"))?;
        self.authenticate_service_token(&material)?
            .ok_or_else(|| AppError::new(ERR_INVALID_CREDENTIALS, "invalid service token"))
    }

    fn authenticate_static_token(
        &self,
        material: &CredentialMaterial,
    ) -> Result<Option<AuthContext>, AppError> {
        if !self.config.static_token.enabled || matches!(self.config.mode, AuthMode::ExternalOnly) {
            return Ok(None);
        }
        let Some(expected) = token_from_env_chain(&[
            self.config.static_token.token_env.as_str(),
            DEFAULT_STATIC_TOKEN_ENV,
        ]) else {
            return Ok(None);
        };
        if material.raw != expected {
            return Ok(None);
        }
        Ok(Some(AuthContext {
            auth_method: AuthMethod::StaticToken,
            issuer: DEFAULT_STATIC_TOKEN_ISSUER.to_string(),
            subject: Some(DEFAULT_STATIC_TOKEN_PRINCIPAL.to_string()),
            credential_id: DEFAULT_STATIC_TOKEN_PRINCIPAL.to_string(),
            principal_id: DEFAULT_STATIC_TOKEN_PRINCIPAL.to_string(),
            scopes: vec!["docdex:*".to_string()],
            status: PrincipalStatus::Active,
            expires_at_ms: None,
            credential_fingerprint: material.fingerprint.clone(),
            claims_json: None,
        }))
    }

    fn authenticate_service_token(
        &self,
        material: &CredentialMaterial,
    ) -> Result<Option<AuthContext>, AppError> {
        if !self.config.service_token.enabled {
            return Ok(None);
        }
        let Some(expected) = token_from_env_chain(&[
            self.config.service_token.token_env.as_str(),
            "DOCDEX_AUTH_SERVICE_TOKEN",
            DEFAULT_SERVICE_TOKEN_ENV,
        ]) else {
            return Ok(None);
        };
        if material.raw != expected {
            return Ok(None);
        }
        Ok(Some(AuthContext {
            auth_method: AuthMethod::ServiceToken,
            issuer: "docdex_service_token".to_string(),
            subject: Some("service".to_string()),
            credential_id: "service_token".to_string(),
            principal_id: "service".to_string(),
            scopes: vec!["docdex:admin".to_string()],
            status: PrincipalStatus::Active,
            expires_at_ms: None,
            credential_fingerprint: material.fingerprint.clone(),
            claims_json: None,
        }))
    }

    async fn introspect_external(
        &self,
        material: &CredentialMaterial,
        repo_id: &str,
    ) -> Result<AuthContext, AppError> {
        if let Some(cached) = self.cached_introspection(material.fingerprint()) {
            return cached;
        }
        let external = &self.config.external_api_key_introspection;
        if external.url.trim().is_empty() {
            return Err(AppError::new(
                ERR_INTROSPECTION_UNAVAILABLE,
                "external API-key introspection URL is not configured",
            ));
        }
        let service_token = token_from_env_chain(&[
            external.service_token_env.as_str(),
            DEFAULT_EXTERNAL_SERVICE_TOKEN_ENV,
        ]);
        let mut request = self.client.post(external.url.trim()).json(&json!({
            "api_key": material.raw,
            "requested_resource": {
                "type": "docdex_repo",
                "id": repo_id
            }
        }));
        if let Some(token) = service_token.as_deref() {
            request = request.bearer_auth(token);
        }
        let result = match request.send().await {
            Ok(response) => self.handle_introspection_response(response, material).await,
            Err(err) => Err(AppError::new(
                ERR_INTROSPECTION_UNAVAILABLE,
                format!("external API-key introspection unavailable: {err}"),
            )),
        };
        self.store_cached_introspection(material.fingerprint(), result.clone());
        result
    }

    fn cached_introspection(&self, fingerprint: &str) -> Option<Result<AuthContext, AppError>> {
        let mut cache = self.introspection_cache.lock();
        let Some(cached) = cache.get(fingerprint) else {
            return None;
        };
        if cached.expires_at <= Instant::now() {
            cache.remove(fingerprint);
            return None;
        }
        Some(cached.result.clone())
    }

    fn store_cached_introspection(&self, fingerprint: &str, result: Result<AuthContext, AppError>) {
        let ttl_seconds = if result.is_ok() {
            self.config.external_api_key_introspection.cache_ttl_seconds
        } else {
            self.config
                .external_api_key_introspection
                .negative_cache_ttl_seconds
        };
        if ttl_seconds == 0 {
            return;
        }
        let mut cache = self.introspection_cache.lock();
        cache.insert(
            fingerprint.to_string(),
            CachedAuth {
                expires_at: Instant::now() + Duration::from_secs(ttl_seconds),
                result,
            },
        );
    }

    async fn handle_introspection_response(
        &self,
        response: reqwest::Response,
        material: &CredentialMaterial,
    ) -> Result<AuthContext, AppError> {
        if response.status() == ReqwestStatusCode::UNAUTHORIZED
            || response.status() == ReqwestStatusCode::FORBIDDEN
        {
            return Err(AppError::new(
                ERR_INVALID_CREDENTIALS,
                "external authority rejected credential",
            ));
        }
        if !response.status().is_success() {
            return Err(AppError::new(
                ERR_INTROSPECTION_UNAVAILABLE,
                format!(
                    "external API-key introspection returned HTTP {}",
                    response.status().as_u16()
                ),
            ));
        }
        let payload = response
            .json::<IntrospectionResponse>()
            .await
            .map_err(|err| {
                AppError::new(
                    ERR_INTROSPECTION_UNAVAILABLE,
                    format!("invalid introspection response: {err}"),
                )
            })?;
        normalize_introspection_response(
            payload,
            &self.config.external_api_key_introspection,
            material,
        )
    }
}

#[derive(Clone)]
struct CachedAuth {
    expires_at: Instant,
    result: Result<AuthContext, AppError>,
}

#[derive(Debug, Clone, Deserialize)]
struct IntrospectionResponse {
    #[serde(default, alias = "api_key_id")]
    credential_id: Option<String>,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    principal_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default)]
    expires_at_ms: Option<i64>,
    #[serde(default)]
    expires_at: Option<String>,
    #[serde(default)]
    cache_ttl_seconds: Option<u64>,
    #[serde(default, alias = "claims")]
    claims_json: Option<Value>,
}

fn normalize_introspection_response(
    payload: IntrospectionResponse,
    config: &ExternalApiKeyIntrospectionConfig,
    material: &CredentialMaterial,
) -> Result<AuthContext, AppError> {
    let required = config.required_status.trim().to_ascii_lowercase();
    let status_raw = payload.status.as_deref().unwrap_or_default();
    if status_raw.trim().to_ascii_lowercase() != required {
        return Err(
            AppError::new(ERR_INVALID_CREDENTIALS, "external credential is not active")
                .with_details(json!({ "status": status_raw })),
        );
    }
    let credential_id = payload
        .credential_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| {
            AppError::new(
                ERR_INVALID_CREDENTIALS,
                "external introspection response did not include a stable credential id",
            )
        })?;
    let subject = payload
        .subject
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| Some(credential_id.clone()));
    let principal_id = payload
        .principal_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .or_else(|| subject.clone())
        .unwrap_or_else(|| credential_id.clone());
    let expires_at_ms = payload
        .expires_at_ms
        .or_else(|| parse_expires_at_ms(payload.expires_at.as_deref()));
    let ctx = AuthContext {
        auth_method: AuthMethod::ExternalApiKeyIntrospection,
        issuer: config.issuer.trim().to_string(),
        subject,
        credential_id,
        principal_id,
        scopes: normalize_string_list(payload.scopes),
        status: PrincipalStatus::from_raw(Some(status_raw)),
        expires_at_ms,
        credential_fingerprint: material.fingerprint.clone(),
        claims_json: payload.claims_json,
    };
    ctx.validate_active()?;
    let _ = payload.cache_ttl_seconds;
    Ok(ctx)
}

pub fn extract_credential(
    headers: &HeaderMap,
    accepted_headers: &[String],
    reject_ambiguous: bool,
) -> Result<Option<CredentialMaterial>, AppError> {
    let headers_to_read = normalized_accepted_headers(accepted_headers);
    let mut found: Vec<(String, String)> = Vec::new();
    for header in headers_to_read {
        if header == "authorization" {
            if let Some(token) = extract_authorization_bearer(headers) {
                found.push((header, token));
            }
            continue;
        }
        if let Some(value) = headers
            .get(header.as_str())
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            found.push((header, value.to_string()));
        }
    }
    if found.is_empty() {
        return Ok(None);
    }
    found.dedup_by(|left, right| left.1 == right.1);
    if reject_ambiguous {
        let first = &found[0].1;
        if found.iter().any(|(_, value)| value != first) {
            return Err(AppError::new(
                ERR_AMBIGUOUS_CREDENTIALS,
                "multiple different API credentials were supplied",
            ));
        }
    }
    let (source, raw) = found
        .into_iter()
        .min_by_key(|(source, _)| credential_source_priority(source))
        .expect("found is non-empty");
    let fingerprint = credential_fingerprint(&raw);
    Ok(Some(CredentialMaterial {
        raw,
        source,
        fingerprint,
    }))
}

fn extract_authorization_bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .strip_prefix("Bearer ")
                .or_else(|| value.strip_prefix("bearer "))
                .unwrap_or(value)
                .trim()
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

pub fn credential_fingerprint(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    hex::encode(hasher.finalize())
}

fn credential_source_priority(source: &str) -> u8 {
    match source {
        API_KEY_HEADER => 0,
        "authorization" => 1,
        _ => 2,
    }
}

fn normalized_accepted_headers(headers: &[String]) -> Vec<String> {
    let mut values = if headers.is_empty() {
        default_external_accepted_headers()
    } else {
        headers
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>()
    };
    if values.is_empty() {
        values = default_external_accepted_headers();
    }
    values.sort();
    values.dedup();
    values
}

fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut normalized = values
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort();
    normalized.dedup();
    normalized
}

fn token_from_env_chain(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        std::env::var(name).ok().and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
    })
}

fn validate_binding(binding: &RepoAccessBinding) -> Result<(), AppError> {
    if binding.repo_id.is_empty() {
        return Err(AppError::new(
            ERR_REPO_ACCESS_DENIED,
            "repo access binding requires repo_id",
        ));
    }
    if binding.issuer.is_empty() {
        return Err(AppError::new(
            ERR_REPO_ACCESS_DENIED,
            "repo access binding requires issuer",
        ));
    }
    if binding.principal_id.is_empty() && binding.credential_id.is_none() {
        return Err(AppError::new(
            ERR_REPO_ACCESS_DENIED,
            "repo access binding requires principal_id or credential_id",
        ));
    }
    if binding.allowed_operations.is_empty() {
        return Err(AppError::new(
            ERR_SCOPE_DENIED,
            "repo access binding requires at least one allowed operation",
        ));
    }
    Ok(())
}

fn binding_matches_context(binding: &RepoAccessBinding, ctx: &AuthContext) -> bool {
    binding.issuer == ctx.issuer
        && (binding
            .credential_id
            .as_deref()
            .map(|credential_id| credential_id == ctx.credential_id)
            .unwrap_or(false)
            || binding.principal_id == ctx.principal_id
            || ctx
                .subject
                .as_deref()
                .map(|subject| binding.principal_id == subject)
                .unwrap_or(false))
}

fn operation_allowed(allowed: &[String], operation: RepoOperation) -> bool {
    allowed.iter().any(|value| {
        let value = value.trim();
        value == "*" || value.eq_ignore_ascii_case("all") || value == operation.as_str()
    })
}

fn required_scopes_satisfied(required: &[String], actual: &[String]) -> bool {
    required
        .iter()
        .all(|required| actual.iter().any(|scope| scope_satisfies(scope, required)))
}

fn scope_satisfies(actual: &str, required: &str) -> bool {
    actual == "*"
        || actual == required
        || actual
            .strip_suffix(":*")
            .map(|prefix| required.starts_with(&format!("{prefix}:")))
            .unwrap_or(false)
}

fn row_to_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<RepoAccessBinding> {
    let scopes_json: String = row.get(6)?;
    let operations_json: String = row.get(7)?;
    let metadata_json: String = row.get(10)?;
    Ok(RepoAccessBinding {
        id: row.get(0)?,
        repo_id: row.get(1)?,
        issuer: row.get(2)?,
        principal_type: row.get(3)?,
        principal_id: row.get(4)?,
        credential_id: row.get(5)?,
        required_scopes: serde_json::from_str(&scopes_json).unwrap_or_default(),
        allowed_operations: serde_json::from_str(&operations_json).unwrap_or_default(),
        status: row.get(8)?,
        expires_at_ms: row.get(9)?,
        metadata_json: serde_json::from_str(&metadata_json).unwrap_or_else(|_| json!({})),
    })
}

fn parse_expires_at_ms(raw: Option<&str>) -> Option<i64> {
    let raw = raw?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(value) = raw.parse::<i64>() {
        return Some(value);
    }
    DateTime::parse_from_rfc3339(raw)
        .ok()
        .map(|value| value.with_timezone(&Utc).timestamp_millis())
}

fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or_default()
}

fn default_auth_mode() -> AuthMode {
    DEFAULT_AUTH_MODE
}

fn default_reject_ambiguous_credentials() -> bool {
    DEFAULT_REJECT_AMBIGUOUS_CREDENTIALS
}

fn default_static_token_enabled() -> bool {
    true
}

fn default_static_token_env() -> String {
    DEFAULT_STATIC_TOKEN_ENV.to_string()
}

fn default_external_issuer() -> String {
    DEFAULT_EXTERNAL_ISSUER.to_string()
}

fn default_external_service_token_env() -> String {
    DEFAULT_EXTERNAL_SERVICE_TOKEN_ENV.to_string()
}

fn default_external_cache_ttl_seconds() -> u64 {
    DEFAULT_EXTERNAL_CACHE_TTL_SECONDS
}

fn default_external_negative_cache_ttl_seconds() -> u64 {
    DEFAULT_EXTERNAL_NEGATIVE_CACHE_TTL_SECONDS
}

fn default_external_timeout_ms() -> u64 {
    DEFAULT_EXTERNAL_TIMEOUT_MS
}

fn default_external_fail_closed() -> bool {
    true
}

fn default_external_accepted_headers() -> Vec<String> {
    vec![API_KEY_HEADER.to_string(), "authorization".to_string()]
}

fn default_external_required_status() -> String {
    DEFAULT_EXTERNAL_REQUIRED_STATUS.to_string()
}

fn default_service_token_env() -> String {
    DEFAULT_SERVICE_TOKEN_ENV.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn credential_extraction_rejects_ambiguous_values() {
        let mut headers = HeaderMap::new();
        headers.insert(API_KEY_HEADER, HeaderValue::from_static("api-key"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer bearer-key"));

        let err = extract_credential(&headers, &default_external_accepted_headers(), true)
            .expect_err("ambiguous credentials should fail");
        assert_eq!(err.code, ERR_AMBIGUOUS_CREDENTIALS);
    }

    #[test]
    fn credential_extraction_prefers_api_key_header_when_not_rejecting() {
        let mut headers = HeaderMap::new();
        headers.insert(API_KEY_HEADER, HeaderValue::from_static("api-key"));
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer bearer-key"));

        let credential = extract_credential(&headers, &default_external_accepted_headers(), false)
            .expect("extract")
            .expect("credential");
        assert_eq!(credential.source(), API_KEY_HEADER);
        assert_eq!(credential.fingerprint(), credential_fingerprint("api-key"));
    }

    #[test]
    fn binding_authorizes_matching_credential_scope_and_operation() {
        let temp = tempfile::tempdir().expect("tempdir");
        let store = RepoAccessStore::open(temp.path()).expect("store");
        store
            .upsert_binding(RepoAccessBinding {
                id: "binding-1".to_string(),
                repo_id: "repo-1".to_string(),
                issuer: "external".to_string(),
                principal_type: "credential".to_string(),
                principal_id: "principal-1".to_string(),
                credential_id: Some("cred-1".to_string()),
                required_scopes: vec!["docdex:repo:search".to_string()],
                allowed_operations: vec!["search".to_string()],
                status: "active".to_string(),
                expires_at_ms: None,
                metadata_json: json!({}),
            })
            .expect("upsert");
        let ctx = AuthContext {
            auth_method: AuthMethod::ExternalApiKeyIntrospection,
            issuer: "external".to_string(),
            subject: Some("principal-1".to_string()),
            credential_id: "cred-1".to_string(),
            principal_id: "principal-1".to_string(),
            scopes: vec!["docdex:repo:search".to_string()],
            status: PrincipalStatus::Active,
            expires_at_ms: None,
            credential_fingerprint: credential_fingerprint("secret"),
            claims_json: None,
        };

        let binding = store
            .authorize(&ctx, "repo-1", RepoOperation::Search)
            .expect("authorized");
        assert_eq!(binding.id, "binding-1");
    }

    #[test]
    fn static_token_is_not_data_plane_authorized_by_default() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_STATIC_TOKEN_ENV, "static-secret");
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = AuthRuntime::new_for_tests(AuthConfig::default(), temp.path());
        let material = CredentialMaterial {
            raw: "static-secret".to_string(),
            source: "authorization".to_string(),
            fingerprint: credential_fingerprint("static-secret"),
        };
        let ctx = runtime
            .authenticate_static_token(&material)
            .expect("static")
            .expect("ctx");
        assert_eq!(ctx.auth_method, AuthMethod::StaticToken);
        assert!(!runtime.config().static_token.encrypted_repo_data_access);
        std::env::remove_var(DEFAULT_STATIC_TOKEN_ENV);
    }

    #[tokio::test]
    async fn service_token_is_not_data_plane_authorized_by_default() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var("DOCDEX_AUTH_SERVICE_TOKEN", "service-secret");
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = AuthConfig::default();
        config.service_token.enabled = true;
        let runtime = AuthRuntime::new_for_tests(config, temp.path());
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer service-secret"),
        );

        let err = runtime
            .authorize_repo_access(&headers, "repo-1", RepoOperation::Search)
            .await
            .expect_err("service token data access should fail by default");
        assert_eq!(err.code, ERR_SCOPE_DENIED);
        assert!(!runtime.config().service_token.encrypted_repo_data_access);
        std::env::remove_var("DOCDEX_AUTH_SERVICE_TOKEN");
    }

    #[tokio::test]
    async fn service_token_data_plane_access_requires_repo_binding() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var("DOCDEX_AUTH_SERVICE_TOKEN", "service-secret");
        let temp = tempfile::tempdir().expect("tempdir");
        let mut config = AuthConfig::default();
        config.service_token.enabled = true;
        config.service_token.encrypted_repo_data_access = true;
        let runtime = AuthRuntime::new_for_tests(config, temp.path());
        runtime
            .access_store()
            .upsert_binding(RepoAccessBinding {
                id: "service-binding-1".to_string(),
                repo_id: "repo-1".to_string(),
                issuer: "docdex_service_token".to_string(),
                principal_type: "service".to_string(),
                principal_id: "service".to_string(),
                credential_id: Some("service_token".to_string()),
                required_scopes: vec!["docdex:admin".to_string()],
                allowed_operations: vec!["search".to_string()],
                status: "active".to_string(),
                expires_at_ms: None,
                metadata_json: json!({}),
            })
            .expect("upsert");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer service-secret"),
        );

        assert!(runtime.may_defer_route_auth(&headers, "/v1/search/batch", true));
        let ctx = runtime
            .authorize_repo_access(&headers, "repo-1", RepoOperation::Search)
            .await
            .expect("service token should be authorized by repo binding");
        assert_eq!(ctx.auth_method, AuthMethod::ServiceToken);

        let err = runtime
            .authorize_repo_access(&headers, "repo-2", RepoOperation::Search)
            .await
            .expect_err("unbound repo should fail");
        assert_eq!(err.code, ERR_REPO_ACCESS_DENIED);
        std::env::remove_var("DOCDEX_AUTH_SERVICE_TOKEN");
    }

    #[test]
    fn introspection_response_requires_stable_credential_id() {
        let material = CredentialMaterial {
            raw: "secret".to_string(),
            source: API_KEY_HEADER.to_string(),
            fingerprint: credential_fingerprint("secret"),
        };
        let config = ExternalApiKeyIntrospectionConfig {
            enabled: true,
            ..ExternalApiKeyIntrospectionConfig::default()
        };
        let err = normalize_introspection_response(
            IntrospectionResponse {
                credential_id: None,
                subject: Some("subject-1".to_string()),
                principal_id: None,
                status: Some("active".to_string()),
                scopes: vec![],
                expires_at_ms: None,
                expires_at: None,
                cache_ttl_seconds: None,
                claims_json: None,
            },
            &config,
            &material,
        )
        .expect_err("missing credential id should fail");
        assert_eq!(err.code, ERR_INVALID_CREDENTIALS);
    }
}
