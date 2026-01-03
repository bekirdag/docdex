use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde_json::Value;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;
use url::Url;

const MCODA_DIR: &str = ".mcoda";
const MCODA_DB: &str = "mcoda.db";
const MCODA_KEY: &str = "mcoda.key";
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

impl McodaRegistry {
    pub fn load_default() -> Result<Option<Self>> {
        let db_path = default_db_path()?;
        if !db_path.exists() {
            return Ok(None);
        }
        let key_path = default_key_path()?;
        Ok(Some(Self::load_from_paths(&db_path, &key_path)?))
    }

    pub fn load_from_paths(db_path: &Path, key_path: &Path) -> Result<Self> {
        let conn = open_readonly_immutable(db_path)
            .with_context(|| format!("open mcoda registry {}", db_path.display()))?;

        let mut agents = load_agents(&conn)?;
        let mut capabilities = load_capabilities(&conn)?;
        let mut models = load_models(&conn)?;
        let mut auth = load_auth(&conn, key_path)?;

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

fn default_db_path() -> Result<PathBuf> {
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

fn load_agents(conn: &Connection) -> Result<Vec<McodaAgent>> {
    if !table_exists(conn, "agents")? {
        return Ok(Vec::new());
    }
    let mut stmt = conn.prepare(
        "SELECT id, slug, adapter, default_model, config_json, created_at, updated_at
         FROM agents
         ORDER BY slug ASC",
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
        ))
    })?;

    let mut agents = Vec::new();
    for row in rows {
        let (id, slug, adapter, default_model, config_raw, created_at, updated_at) = row?;
        let config = match config_raw {
            Some(raw) => Some(serde_json::from_str(&raw).context("parse agents.config_json")?),
            None => None,
        };
        agents.push(McodaAgent {
            id,
            slug,
            adapter,
            default_model,
            config,
            created_at,
            updated_at,
            capabilities: Vec::new(),
            models: Vec::new(),
            auth: None,
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
