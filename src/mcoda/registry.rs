use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::warn;
use url::Url;

const MCODA_DIR: &str = ".mcoda";
const MCODA_DB: &str = "mcoda.db";
const MCODA_KEY: &str = "mcoda.key";
const MCODA_AGENT_LIST_JSON_REFRESH_ARGS: [&str; 4] =
    ["agent", "list", "--json", "--refresh-health"];
const MCODA_AGENT_LIST_JSON_ARGS: [&str; 3] = ["agent", "list", "--json"];
const AUTH_IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct McodaRegistry {
    pub db_path: PathBuf,
    pub agents: Vec<McodaAgent>,
}

#[derive(Debug, Clone)]
pub struct McodaAgent {
    pub id: String,
    pub slug: String,
    pub adapter: String,
    pub default_model: Option<String>,
    pub config: Option<Value>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub rating: Option<f64>,
    pub cost_per_million: Option<f64>,
    pub max_complexity: Option<i64>,
    pub best_usage: Option<String>,
    pub reasoning_rating: Option<f64>,
    pub health_status: Option<String>,
    pub cli_binary: Option<String>,
    pub capabilities: Vec<String>,
    pub models: Vec<McodaAgentModel>,
    pub auth: Option<McodaAgentAuth>,
}

#[derive(Debug, Clone)]
pub struct McodaAgentModel {
    pub model_name: String,
    pub is_default: bool,
    pub config: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct McodaAgentAuth {
    pub encrypted_secret: String,
    pub decrypted_secret: Option<String>,
    pub last_verified_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McodaCliAgentRecord {
    id: Option<String>,
    slug: Option<String>,
    adapter: Option<String>,
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default)]
    config: Option<Value>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    rating: Option<f64>,
    #[serde(default)]
    cost_per_million: Option<f64>,
    #[serde(default)]
    max_complexity: Option<i64>,
    #[serde(default)]
    best_usage: Option<String>,
    #[serde(default)]
    reasoning_rating: Option<f64>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    models: Vec<McodaCliModelRecord>,
    #[serde(default)]
    health: Option<McodaCliHealthRecord>,
    #[serde(default)]
    health_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McodaCliModelRecord {
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    default: Option<bool>,
    #[serde(default)]
    is_default: Option<bool>,
    #[serde(default)]
    config: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McodaCliHealthRecord {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    details: Option<Value>,
}

impl McodaRegistry {
    pub fn load_default() -> Result<Option<Self>> {
        if let Some(registry) = Self::load_from_cli()? {
            return Ok(Some(registry));
        }
        let db_path = default_db_path()?;
        if !db_path.exists() {
            return Ok(None);
        }
        let key_path = default_key_path()?;
        Ok(Some(Self::load_from_paths(&db_path, &key_path)?))
    }

    pub fn load_from_cli() -> Result<Option<Self>> {
        let Some(stdout) = run_mcoda_agent_list_json()? else {
            return Ok(None);
        };
        let mut agents =
            parse_mcoda_cli_agents(&stdout).context("parse mcoda agent list --json")?;
        let db_path = default_db_path()?;
        let key_path = default_key_path()?;
        hydrate_cli_agents_from_db(&mut agents, &db_path, &key_path);
        Ok(Some(Self { db_path, agents }))
    }

    pub fn load_from_paths(db_path: &Path, key_path: &Path) -> Result<Self> {
        let conn = open_readonly_immutable(db_path)
            .with_context(|| format!("open mcoda registry {}", db_path.display()))?;

        let mut agents = load_agents(&conn)?;
        let mut capabilities = load_capabilities(&conn)?;
        let mut models = load_models(&conn)?;
        let mut auth = load_auth(&conn, key_path)?;
        let mut health = load_health(&conn)?;

        for agent in &mut agents {
            if let Some(values) = capabilities.remove(&agent.id) {
                agent.capabilities = values;
            }
            if let Some(values) = models.remove(&agent.id) {
                agent.models = values;
            }
            if let Some(value) = auth.remove(&agent.id) {
                agent.auth = Some(value);
            }
            if let Some(value) = health.remove(&agent.id) {
                agent.health_status = Some(value);
            }
        }

        Ok(Self {
            db_path: db_path.to_path_buf(),
            agents,
        })
    }

    pub fn agent_by_id(&self, id: &str) -> Option<&McodaAgent> {
        self.agents.iter().find(|agent| agent.id == id)
    }

    pub fn agent_by_slug(&self, slug: &str) -> Option<&McodaAgent> {
        self.agents.iter().find(|agent| agent.slug == slug)
    }
}

pub(crate) fn default_db_path() -> Result<PathBuf> {
    Ok(default_mcoda_dir()?.join(MCODA_DB))
}

fn default_key_path() -> Result<PathBuf> {
    Ok(default_mcoda_dir()?.join(MCODA_KEY))
}

fn default_mcoda_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            Some(PathBuf::from(drive).join(path))
        })
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(home.join(MCODA_DIR))
}

fn trim_non_empty(input: Option<String>) -> Option<String> {
    let value = input?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn trim_non_empty_str(input: Option<&str>) -> Option<String> {
    let value = input?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn cli_binary_from_health_details(details: Option<&Value>) -> Option<String> {
    let details = details?.as_object()?;
    trim_non_empty_str(details.get("binary").and_then(Value::as_str))
}

fn cli_binary_from_config(config: Option<&Value>) -> Option<String> {
    let config = config?.as_object()?;
    for key in ["binary", "cliBinary", "cli_path", "cliPath"] {
        let Some(value) = config.get(key) else {
            continue;
        };
        if let Some(binary) = trim_non_empty_str(value.as_str()) {
            return Some(binary);
        }
    }
    None
}

fn run_mcoda_agent_list_json() -> Result<Option<String>> {
    let cli_disabled = std::env::var("DOCDEX_DISABLE_MCODA_CLI")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false);
    if cli_disabled {
        return Ok(None);
    }

    let attempts: [&[&str]; 2] = [
        &MCODA_AGENT_LIST_JSON_REFRESH_ARGS,
        &MCODA_AGENT_LIST_JSON_ARGS,
    ];
    for args in attempts {
        let output = match Command::new("mcoda").args(args).output() {
            Ok(output) => output,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).context("spawn mcoda agent list --json"),
        };
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                target: "docdexd",
                args = ?args,
                status = ?output.status.code(),
                stderr = %stderr.trim(),
                "mcoda agent list failed"
            );
            continue;
        }
        let stdout = String::from_utf8(output.stdout).context("decode mcoda agent list --json")?;
        if stdout.trim().is_empty() {
            continue;
        }
        return Ok(Some(stdout));
    }
    Ok(None)
}

fn parse_mcoda_cli_agents(raw: &str) -> Result<Vec<McodaAgent>> {
    let records: Vec<McodaCliAgentRecord> =
        serde_json::from_str(raw).context("decode mcoda CLI payload")?;
    let mut agents = Vec::new();
    for record in records {
        let Some(id) = trim_non_empty(record.id) else {
            continue;
        };
        let Some(slug) = trim_non_empty(record.slug) else {
            continue;
        };
        let Some(adapter) = trim_non_empty(record.adapter) else {
            continue;
        };

        let mut models = Vec::new();
        for model in record.models {
            let model_name =
                trim_non_empty(model.model_name).or_else(|| trim_non_empty(model.name));
            let Some(model_name) = model_name else {
                continue;
            };
            models.push(McodaAgentModel {
                model_name,
                is_default: model.default.unwrap_or(false) || model.is_default.unwrap_or(false),
                config: model.config,
            });
        }
        let default_model = trim_non_empty(record.default_model).or_else(|| {
            models
                .iter()
                .find(|model| model.is_default)
                .map(|model| model.model_name.clone())
        });
        let config = record.config;
        let health = record.health;
        let cli_binary = health
            .as_ref()
            .and_then(|health| cli_binary_from_health_details(health.details.as_ref()))
            .or_else(|| cli_binary_from_config(config.as_ref()));
        let health_status = trim_non_empty(record.health_status)
            .or_else(|| health.and_then(|health| trim_non_empty(health.status)));

        agents.push(McodaAgent {
            id,
            slug,
            adapter,
            default_model,
            config,
            created_at: trim_non_empty(record.created_at),
            updated_at: trim_non_empty(record.updated_at),
            rating: record.rating,
            cost_per_million: record.cost_per_million,
            max_complexity: record.max_complexity,
            best_usage: trim_non_empty(record.best_usage),
            reasoning_rating: record.reasoning_rating,
            health_status,
            cli_binary,
            capabilities: record.capabilities,
            models,
            auth: None,
        });
    }
    Ok(agents)
}

fn hydrate_cli_agents_from_db(agents: &mut [McodaAgent], db_path: &Path, key_path: &Path) {
    if agents.is_empty() || !db_path.exists() {
        return;
    }
    let conn = match open_readonly_immutable(db_path) {
        Ok(conn) => conn,
        Err(err) => {
            warn!(
                "failed to open mcoda db {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            return;
        }
    };

    let mut auth_by_id = match load_auth(&conn, key_path) {
        Ok(auth) => auth,
        Err(err) => {
            warn!(
                "failed to load mcoda auth from {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            HashMap::new()
        }
    };
    let db_agents = match load_agents(&conn) {
        Ok(agents) => agents,
        Err(err) => {
            warn!(
                "failed to load mcoda agents from {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            Vec::new()
        }
    };
    if auth_by_id.is_empty() && db_agents.is_empty() {
        return;
    }

    let mut db_agents_by_id: HashMap<String, McodaAgent> = HashMap::new();
    let mut db_id_by_slug: HashMap<String, String> = HashMap::new();
    for agent in db_agents {
        db_id_by_slug.insert(agent.slug.clone(), agent.id.clone());
        db_agents_by_id.insert(agent.id.clone(), agent);
    }

    for agent in agents.iter_mut() {
        let db_agent = db_agents_by_id.get(&agent.id).or_else(|| {
            db_id_by_slug
                .get(&agent.slug)
                .and_then(|db_id| db_agents_by_id.get(db_id))
        });
        if let Some(db_agent) = db_agent {
            if agent.config.is_none() {
                agent.config = db_agent.config.clone();
            }
            if agent.default_model.is_none() {
                agent.default_model = db_agent.default_model.clone();
            }
            if agent.cli_binary.is_none() {
                agent.cli_binary = db_agent.cli_binary.clone();
            }
            if agent.adapter.trim().is_empty() {
                agent.adapter = db_agent.adapter.clone();
            }
        }

        if agent.auth.is_none() {
            if let Some(auth) = auth_by_id.remove(&agent.id) {
                agent.auth = Some(auth);
            } else if let Some(db_id) = db_id_by_slug.get(&agent.slug) {
                if let Some(auth) = auth_by_id.remove(db_id) {
                    agent.auth = Some(auth);
                }
            }
        }
    }
}

fn open_readonly_immutable(path: &Path) -> Result<Connection> {
    let url = Url::from_file_path(path)
        .map_err(|_| anyhow!("invalid mcoda db path: {}", path.display()))?;
    let mut uri = url.to_string();
    let separator = if uri.contains('?') { "&" } else { "?" };
    uri.push_str(separator);
    uri.push_str("immutable=1&mode=ro");
    Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .context("open sqlite connection")
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    if !table_exists(conn, table)? {
        return Ok(HashSet::new());
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = HashSet::new();
    for row in rows {
        columns.insert(row?);
    }
    Ok(columns)
}

fn load_agents(conn: &Connection) -> Result<Vec<McodaAgent>> {
    if !table_exists(conn, "agents")? {
        return Ok(Vec::new());
    }
    let columns = table_columns(conn, "agents")?;
    let rating_sql = if columns.contains("rating") {
        "rating"
    } else {
        "NULL"
    };
    let cost_sql = if columns.contains("cost_per_million") {
        "cost_per_million"
    } else {
        "NULL"
    };
    let complexity_sql = if columns.contains("max_complexity") {
        "max_complexity"
    } else {
        "NULL"
    };
    let usage_sql = if columns.contains("best_usage") {
        "best_usage"
    } else {
        "NULL"
    };
    let reasoning_sql = if columns.contains("reasoning_rating") {
        "reasoning_rating"
    } else {
        "NULL"
    };
    let mut stmt = conn.prepare(
        &format!(
            "SELECT id, slug, adapter, default_model, config_json, created_at, updated_at,
                    {rating_sql} as rating, {cost_sql} as cost_per_million, {complexity_sql} as max_complexity,
                    {usage_sql} as best_usage, {reasoning_sql} as reasoning_rating
             FROM agents
             ORDER BY slug ASC"
        ),
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<f64>>(7)?,
            row.get::<_, Option<f64>>(8)?,
            row.get::<_, Option<i64>>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<f64>>(11)?,
        ))
    })?;

    let mut agents = Vec::new();
    for row in rows {
        let (
            id,
            slug,
            adapter,
            default_model,
            config_raw,
            created_at,
            updated_at,
            rating,
            cost_per_million,
            max_complexity,
            best_usage,
            reasoning_rating,
        ) = row?;
        let config = match config_raw {
            Some(raw) => Some(serde_json::from_str(&raw).context("parse agents.config_json")?),
            None => None,
        };
        let cli_binary = cli_binary_from_config(config.as_ref());
        agents.push(McodaAgent {
            id,
            slug,
            adapter,
            default_model,
            config,
            created_at,
            updated_at,
            rating,
            cost_per_million,
            max_complexity,
            best_usage,
            reasoning_rating,
            capabilities: Vec::new(),
            models: Vec::new(),
            auth: None,
            health_status: None,
            cli_binary,
        });
    }
    Ok(agents)
}

fn load_capabilities(conn: &Connection) -> Result<HashMap<String, Vec<String>>> {
    if !table_exists(conn, "agent_capabilities")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, capability
         FROM agent_capabilities
         ORDER BY capability ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        let (agent_id, capability) = row?;
        map.entry(agent_id).or_default().push(capability);
    }
    Ok(map)
}

fn load_models(conn: &Connection) -> Result<HashMap<String, Vec<McodaAgentModel>>> {
    if !table_exists(conn, "agent_models")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, model_name, is_default, config_json
         FROM agent_models
         ORDER BY model_name ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut map: HashMap<String, Vec<McodaAgentModel>> = HashMap::new();
    for row in rows {
        let (agent_id, model_name, is_default, config_raw) = row?;
        let config = match config_raw {
            Some(raw) => {
                Some(serde_json::from_str(&raw).context("parse agent_models.config_json")?)
            }
            None => None,
        };
        let model = McodaAgentModel {
            model_name,
            is_default: is_default != 0,
            config,
        };
        map.entry(agent_id).or_default().push(model);
    }
    Ok(map)
}

fn load_auth(conn: &Connection, key_path: &Path) -> Result<HashMap<String, McodaAgentAuth>> {
    if !table_exists(conn, "agent_auth")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, encrypted_secret, last_verified_at, updated_at
         FROM agent_auth",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;

    let mut raw = Vec::new();
    for row in rows {
        raw.push(row?);
    }

    let needs_key = raw
        .iter()
        .any(|(_, secret, _, _)| !secret.trim().is_empty());
    let key = if needs_key {
        match load_mcoda_key(key_path) {
            Ok(key) => Some(key),
            Err(err) => {
                warn!("failed to load mcoda key {}: {err}", key_path.display());
                None
            }
        }
    } else {
        None
    };

    let mut map: HashMap<String, McodaAgentAuth> = HashMap::new();
    for (agent_id, encrypted_secret, last_verified_at, updated_at) in raw {
        let decrypted_secret = if encrypted_secret.trim().is_empty() {
            None
        } else if let Some(key) = key.as_ref() {
            match decrypt_secret(&encrypted_secret, key) {
                Ok(secret) => {
                    let trimmed = secret.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }
                Err(err) => {
                    warn!(
                        "failed to decrypt mcoda agent_auth secret for agent {}: {err}",
                        agent_id
                    );
                    None
                }
            }
        } else {
            warn!(
                "mcoda key missing; cannot decrypt agent_auth secret for agent {}",
                agent_id
            );
            None
        };
        map.insert(
            agent_id,
            McodaAgentAuth {
                encrypted_secret,
                decrypted_secret,
                last_verified_at,
                updated_at,
            },
        );
    }
    Ok(map)
}

fn load_health(conn: &Connection) -> Result<HashMap<String, String>> {
    if !table_exists(conn, "agent_health")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, status
         FROM agent_health
         ORDER BY agent_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut map: HashMap<String, String> = HashMap::new();
    for row in rows {
        let (agent_id, status) = row?;
        let trimmed = status.trim();
        if !trimmed.is_empty() {
            map.insert(agent_id, trimmed.to_string());
        }
    }
    Ok(map)
}

fn load_mcoda_key(path: &Path) -> Result<Vec<u8>> {
    let key = fs::read(path).with_context(|| format!("read mcoda key {}", path.display()))?;
    if key.len() != KEY_LEN {
        return Err(anyhow!(
            "mcoda key must be {KEY_LEN} bytes, got {}",
            key.len()
        ));
    }
    Ok(key)
}

fn decrypt_secret(payload: &str, key: &[u8]) -> Result<String> {
    let decoded = Base64Engine
        .decode(payload.trim())
        .context("base64 decode agent_auth secret")?;
    if decoded.len() < AUTH_IV_LEN + AUTH_TAG_LEN {
        return Err(anyhow!(
            "agent_auth secret is too short ({} bytes)",
            decoded.len()
        ));
    }
    let (iv, rest) = decoded.split_at(AUTH_IV_LEN);
    let (tag, ciphertext) = rest.split_at(AUTH_TAG_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).context("init AES-256-GCM")?;
    let nonce = Nonce::from_slice(iv);
    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| anyhow!("decrypt agent_auth secret"))?;
    let decoded = String::from_utf8(plaintext).context("decode agent_auth secret utf8")?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mcoda_cli_agents_maps_health_and_models() -> Result<()> {
        let raw = r#"
[
  {
    "id":"agent-1",
    "slug":"devstral-local",
    "adapter":"ollama-remote",
    "defaultModel":"devstral-small-2",
    "rating":7.8,
    "costPerMillion":0,
    "maxComplexity":5,
    "bestUsage":"code_write",
    "reasoningRating":8.1,
    "capabilities":["code_write","code_review"],
    "health":{"status":"healthy","details":{"binary":"/Users/test/.local/bin/claude"}},
    "models":[{"modelName":"devstral-small-2","isDefault":true}]
  },
  {
    "id":"agent-2",
    "slug":"qa-json",
    "adapter":"codex-cli",
    "defaultModel":"gpt-5.2-codex",
    "capabilities":[],
    "health":{"status":"unhealthy"},
    "models":[{"name":"gpt-5.2-codex","default":true}]
  },
  {
    "slug":"missing-id",
    "adapter":"ollama-remote"
  }
]
"#;

        let agents = parse_mcoda_cli_agents(raw)?;
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].id, "agent-1");
        assert_eq!(agents[0].health_status.as_deref(), Some("healthy"));
        assert_eq!(
            agents[0].cli_binary.as_deref(),
            Some("/Users/test/.local/bin/claude")
        );
        assert_eq!(agents[0].models.len(), 1);
        assert_eq!(agents[0].models[0].model_name, "devstral-small-2");
        assert!(agents[0].models[0].is_default);
        assert_eq!(agents[1].id, "agent-2");
        assert_eq!(agents[1].health_status.as_deref(), Some("unhealthy"));
        assert_eq!(agents[1].default_model.as_deref(), Some("gpt-5.2-codex"));
        assert_eq!(agents[1].cli_binary, None);
        Ok(())
    }
}
