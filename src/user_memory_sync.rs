use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const USER_MEMORY_SYNC_SCHEMA_VERSION: &str = "user-memory-sync.v1";
pub const USER_MEMORY_SYNC_LEDGER_DIR: &str = "user_memory_sync";
pub const USER_MEMORY_SYNC_LEDGER_DB: &str = "ledger.sqlite3";
pub const USER_MEMORY_SYNC_SERVER_DB: &str = "server.sqlite3";
pub const USER_MEMORY_SYNC_CURSOR_PREFIX: &str = "cursor_";
pub const USER_MEMORY_SYNC_LEDGER_STATUS_UPLOADED: &str = "uploaded";
pub const USER_MEMORY_SYNC_LEDGER_STATUS_ACKED: &str = "acked";
pub const USER_MEMORY_SYNC_LEDGER_STATUS_APPLIED: &str = "applied";
pub const USER_MEMORY_SYNC_LEDGER_STATUS_SKIPPED: &str = "skipped";
pub const USER_MEMORY_SYNC_IDENTITY_SOURCE_MSWARM_API_KEY: &str = "integrations.mswarm.api_key";
pub const USER_MEMORY_SYNC_IDENTITY_SOURCE_API_KEY_ENV: &str =
    "memory.user_memory_sync.api_key_env";
pub const USER_MEMORY_SYNC_IDENTITY_SOURCE_UNCONFIGURED: &str = "unconfigured";
pub const USER_MEMORY_SYNC_PRINCIPAL_RESOLUTION_MSWARM_INTROSPECTION: &str =
    "mswarm_api_key_server_introspection";
pub const USER_MEMORY_SYNC_PRINCIPAL_RESOLUTION_UNRESOLVED: &str = "unresolved_no_api_key";
pub const USER_MEMORY_SYNC_PAYLOAD_MODE_SUMMARY_ONLY: &str = "summary_only";
pub const USER_MEMORY_SYNC_PAYLOAD_MODE_ENCRYPTED: &str = "encrypted";
pub const USER_MEMORY_SYNC_PAYLOAD_MODE_CLEARTEXT: &str = "cleartext";
pub const USER_MEMORY_SYNC_MAX_ENCRYPTED_PAYLOAD_B64_BYTES: usize = 5_000_000;
pub const USER_MEMORY_SYNC_PAYLOAD_ENCRYPTION_ALGORITHM: &str = "AES-256-GCM";
const USER_MEMORY_SYNC_PAYLOAD_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserMemorySyncLane {
    RepoMemory,
    ProfileMemory,
    PersonalPreferences,
    MindClone,
    Diary,
    ConversationSummaries,
    TemporalKg,
    GeneratedSkills,
}

impl UserMemorySyncLane {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RepoMemory => "repo_memory",
            Self::ProfileMemory => "profile_memory",
            Self::PersonalPreferences => "personal_preferences",
            Self::MindClone => "mind_clone",
            Self::Diary => "diary",
            Self::ConversationSummaries => "conversation_summaries",
            Self::TemporalKg => "temporal_kg",
            Self::GeneratedSkills => "generated_skills",
        }
    }

    pub fn supported_lanes() -> Vec<Self> {
        vec![
            Self::RepoMemory,
            Self::ProfileMemory,
            Self::PersonalPreferences,
            Self::MindClone,
            Self::Diary,
            Self::ConversationSummaries,
            Self::TemporalKg,
            Self::GeneratedSkills,
        ]
    }
}

impl FromStr for UserMemorySyncLane {
    type Err = UserMemorySyncLaneParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let normalized = normalize_lane_name(value);
        match normalized.as_str() {
            "repo" | "repo_memory" | "memory" => Ok(Self::RepoMemory),
            "profile" | "profile_memory" | "profile_preferences" => Ok(Self::ProfileMemory),
            "personal" | "preferences" | "personal_preferences" => Ok(Self::PersonalPreferences),
            "clone" | "mind_clone" | "mindclone" => Ok(Self::MindClone),
            "diary" | "diary_notes" => Ok(Self::Diary),
            "conversation" | "conversation_memory" | "conversation_summaries" => {
                Ok(Self::ConversationSummaries)
            }
            "kg" | "knowledge_graph" | "temporal_kg" | "temporal_graph" => Ok(Self::TemporalKg),
            "skills" | "generated_skills" | "generated_skill" => Ok(Self::GeneratedSkills),
            _ => Err(UserMemorySyncLaneParseError {
                lane: value.trim().to_string(),
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMemorySyncLaneParseError {
    pub lane: String,
}

impl fmt::Display for UserMemorySyncLaneParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unsupported user-memory sync lane: {}", self.lane)
    }
}

impl std::error::Error for UserMemorySyncLaneParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UserMemorySyncLaneClass {
    OptIn,
    OptionalSensitive,
    NeverSync,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncLanePolicy {
    pub lane: UserMemorySyncLane,
    pub class: UserMemorySyncLaneClass,
    pub default_direction: &'static str,
    pub default_payload: &'static str,
    pub merge_rule: &'static str,
    pub downsync_policy: &'static str,
    pub sensitive_exclusions: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncExcludedPayloadPolicy {
    pub local_data: &'static str,
    pub default_policy: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncPolicyMatrix {
    pub schema_version: &'static str,
    pub sync_by_default: Vec<UserMemorySyncLane>,
    pub lane_policies: Vec<UserMemorySyncLanePolicy>,
    pub excluded_local_data: Vec<UserMemorySyncExcludedPayloadPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserMemorySyncIdentity {
    pub source: String,
    pub configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_fingerprint: Option<String>,
    pub principal_resolution: String,
    pub raw_credential_returned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserMemorySyncPayloadEncryptionKey {
    pub key_id: String,
    key_bytes: [u8; USER_MEMORY_SYNC_PAYLOAD_KEY_LEN],
}

impl Default for UserMemorySyncIdentity {
    fn default() -> Self {
        Self {
            source: USER_MEMORY_SYNC_IDENTITY_SOURCE_UNCONFIGURED.to_string(),
            configured: false,
            credential_fingerprint: None,
            principal_resolution: USER_MEMORY_SYNC_PRINCIPAL_RESOLUTION_UNRESOLVED.to_string(),
            raw_credential_returned: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserMemorySyncOperation {
    Upsert,
    Tombstone,
}

impl UserMemorySyncOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upsert => "upsert",
            Self::Tombstone => "tombstone",
        }
    }

    pub fn from_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "upsert" => Some(Self::Upsert),
            "tombstone" => Some(Self::Tombstone),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserMemorySyncSensitivity {
    Low,
    Normal,
    Sensitive,
}

impl UserMemorySyncSensitivity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Normal => "normal",
            Self::Sensitive => "sensitive",
        }
    }

    pub fn from_name(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "normal" => Some(Self::Normal),
            "sensitive" => Some(Self::Sensitive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMemorySyncProvenance {
    pub source_device_id: String,
    pub source_store: String,
    pub source_record_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserMemorySyncPayloadEnvelope {
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aad_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
}

impl UserMemorySyncPayloadEnvelope {
    pub fn summary_only() -> Self {
        Self {
            mode: USER_MEMORY_SYNC_PAYLOAD_MODE_SUMMARY_ONLY.to_string(),
            algorithm: None,
            key_id: None,
            nonce_b64: None,
            ciphertext_b64: None,
            aad_b64: None,
            payload_hash: None,
        }
    }

    pub fn encrypted(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        nonce_b64: impl Into<String>,
        ciphertext_b64: impl Into<String>,
        payload_hash: impl Into<String>,
    ) -> Self {
        Self {
            mode: USER_MEMORY_SYNC_PAYLOAD_MODE_ENCRYPTED.to_string(),
            algorithm: Some(algorithm.into()),
            key_id: Some(key_id.into()),
            nonce_b64: Some(nonce_b64.into()),
            ciphertext_b64: Some(ciphertext_b64.into()),
            aad_b64: None,
            payload_hash: Some(payload_hash.into()),
        }
    }

    pub fn mode_name(&self) -> &str {
        self.mode.trim()
    }

    pub fn is_encrypted(&self) -> bool {
        self.mode_name() == USER_MEMORY_SYNC_PAYLOAD_MODE_ENCRYPTED
    }

    pub fn is_summary_only(&self) -> bool {
        self.mode_name().is_empty()
            || self.mode_name() == USER_MEMORY_SYNC_PAYLOAD_MODE_SUMMARY_ONLY
    }

    pub fn is_cleartext(&self) -> bool {
        matches!(
            self.mode_name(),
            USER_MEMORY_SYNC_PAYLOAD_MODE_CLEARTEXT | "plaintext" | "raw" | "json"
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMemorySyncEvent {
    pub event_id: String,
    pub lane: UserMemorySyncLane,
    pub operation: UserMemorySyncOperation,
    pub object_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_version: Option<String>,
    pub content_hash: String,
    pub sensitivity: UserMemorySyncSensitivity,
    pub payload_kind: String,
    #[serde(default)]
    pub payload_summary: BTreeMap<String, Value>,
    #[serde(default, alias = "payload", skip_serializing_if = "Option::is_none")]
    pub payload_envelope: Option<UserMemorySyncPayloadEnvelope>,
    pub provenance: UserMemorySyncProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserMemorySyncBundle {
    pub schema_version: &'static str,
    pub bundle_id: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_cursor: Option<String>,
    pub created_at_ms: i64,
    pub lanes: Vec<UserMemorySyncLane>,
    pub events: Vec<UserMemorySyncEvent>,
}

impl UserMemorySyncBundle {
    pub fn new(
        device_id: String,
        base_cursor: Option<String>,
        created_at_ms: i64,
        lanes: Vec<UserMemorySyncLane>,
        events: Vec<UserMemorySyncEvent>,
    ) -> Self {
        let bundle_id = stable_bundle_id(&device_id, base_cursor.as_deref(), &lanes, &events);
        Self {
            schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
            bundle_id,
            device_id,
            base_cursor,
            created_at_ms,
            lanes,
            events,
        }
    }
}

pub fn user_memory_sync_payload_envelope_mode(
    envelope: Option<&UserMemorySyncPayloadEnvelope>,
) -> String {
    envelope
        .map(|envelope| {
            let mode = envelope.mode_name();
            if mode.is_empty() {
                USER_MEMORY_SYNC_PAYLOAD_MODE_SUMMARY_ONLY.to_string()
            } else {
                mode.to_string()
            }
        })
        .unwrap_or_else(|| USER_MEMORY_SYNC_PAYLOAD_MODE_SUMMARY_ONLY.to_string())
}

pub fn validate_user_memory_sync_payload_envelope(
    envelope: Option<&UserMemorySyncPayloadEnvelope>,
) -> Result<()> {
    let Some(envelope) = envelope else {
        return Ok(());
    };
    if envelope.is_summary_only() {
        let has_payload_material = [
            envelope.algorithm.as_deref(),
            envelope.key_id.as_deref(),
            envelope.nonce_b64.as_deref(),
            envelope.ciphertext_b64.as_deref(),
            envelope.aad_b64.as_deref(),
            envelope.payload_hash.as_deref(),
        ]
        .into_iter()
        .any(|field| field.and_then(nonempty_trimmed).is_some());
        if has_payload_material {
            return Err(anyhow!(
                "summary-only user-memory sync payload envelope must not include encrypted payload fields"
            ));
        }
        return Ok(());
    }
    if envelope.is_cleartext() {
        return Err(anyhow!(
            "cleartext user-memory sync payload envelopes are not accepted"
        ));
    }
    if !envelope.is_encrypted() {
        let mode = envelope.mode_name();
        return Err(anyhow!(
            "unsupported user-memory sync payload envelope mode: {}",
            mode
        ));
    }

    require_payload_envelope_field(envelope.algorithm.as_deref(), "algorithm")?;
    require_payload_envelope_field(envelope.key_id.as_deref(), "key_id")?;
    require_payload_envelope_field(envelope.nonce_b64.as_deref(), "nonce_b64")?;
    let ciphertext =
        require_payload_envelope_field(envelope.ciphertext_b64.as_deref(), "ciphertext_b64")?;
    let payload_hash =
        require_payload_envelope_field(envelope.payload_hash.as_deref(), "payload_hash")?;
    if ciphertext.len() > USER_MEMORY_SYNC_MAX_ENCRYPTED_PAYLOAD_B64_BYTES {
        return Err(anyhow!(
            "encrypted user-memory sync payload envelope exceeds the maximum ciphertext size"
        ));
    }
    if !payload_hash.starts_with("sha256:") {
        return Err(anyhow!(
            "encrypted user-memory sync payload envelope payload_hash must be sha256-prefixed"
        ));
    }
    Ok(())
}

pub fn resolve_user_memory_sync_payload_encryption_key(
    env_name: Option<&str>,
) -> Result<Option<UserMemorySyncPayloadEncryptionKey>> {
    let Some(env_name) = env_name.and_then(nonempty_trimmed) else {
        return Ok(None);
    };
    let raw = env::var(env_name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("user-memory sync encryption key material is unavailable"))?;
    let key_bytes = decode_user_memory_sync_payload_key_material(&raw)?;
    let key_id = derived_user_memory_sync_payload_key_id(&key_bytes);
    Ok(Some(UserMemorySyncPayloadEncryptionKey {
        key_id,
        key_bytes,
    }))
}

pub fn user_memory_sync_payload_encryption_key_configured(env_name: Option<&str>) -> bool {
    env_name.and_then(nonempty_trimmed).is_some()
}

pub fn encrypt_user_memory_sync_payload_envelope<T: Serialize>(
    key: &UserMemorySyncPayloadEncryptionKey,
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: &str,
    object_version: Option<&str>,
    payload_kind: &str,
    payload: &T,
) -> Result<UserMemorySyncPayloadEnvelope> {
    let payload_bytes =
        serde_json::to_vec(payload).context("serialize user-memory sync encrypted payload")?;
    let payload_hash = format!("sha256:{}", hex::encode(Sha256::digest(&payload_bytes)));
    let aes = Aes256Gcm::new_from_slice(&key.key_bytes)
        .context("initialize user-memory sync payload cipher")?;
    let nonce_seed = Uuid::new_v4().into_bytes();
    let nonce_bytes = &nonce_seed[..12];
    let nonce = Nonce::from_slice(nonce_bytes);
    let aad = user_memory_sync_payload_aad(
        lane,
        operation,
        object_id,
        object_version,
        payload_kind,
        &payload_hash,
        &key.key_id,
    );
    let ciphertext = aes
        .encrypt(
            nonce,
            Payload {
                msg: payload_bytes.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|err| anyhow!("encrypt user-memory sync payload: {err}"))?;
    let mut envelope = UserMemorySyncPayloadEnvelope::encrypted(
        USER_MEMORY_SYNC_PAYLOAD_ENCRYPTION_ALGORITHM,
        key.key_id.clone(),
        Base64Engine.encode(nonce_bytes),
        Base64Engine.encode(ciphertext),
        payload_hash,
    );
    envelope.aad_b64 = Some(Base64Engine.encode(aad.as_bytes()));
    Ok(envelope)
}

pub fn decrypt_user_memory_sync_payload_envelope<T: DeserializeOwned>(
    key: &UserMemorySyncPayloadEncryptionKey,
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: &str,
    object_version: Option<&str>,
    payload_kind: &str,
    envelope: &UserMemorySyncPayloadEnvelope,
) -> Result<T> {
    let payload_bytes = decrypt_user_memory_sync_payload_bytes(
        key,
        lane,
        operation,
        object_id,
        object_version,
        payload_kind,
        envelope,
    )?;
    serde_json::from_slice(&payload_bytes).context("deserialize user-memory sync payload")
}

fn decrypt_user_memory_sync_payload_bytes(
    key: &UserMemorySyncPayloadEncryptionKey,
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: &str,
    object_version: Option<&str>,
    payload_kind: &str,
    envelope: &UserMemorySyncPayloadEnvelope,
) -> Result<Vec<u8>> {
    validate_user_memory_sync_payload_envelope(Some(envelope))?;
    if !envelope.is_encrypted() {
        return Err(anyhow!(
            "user-memory sync payload must be encrypted before local apply"
        ));
    }
    let algorithm = require_payload_envelope_field(envelope.algorithm.as_deref(), "algorithm")?;
    if algorithm != USER_MEMORY_SYNC_PAYLOAD_ENCRYPTION_ALGORITHM {
        return Err(anyhow!(
            "unsupported user-memory sync payload encryption algorithm: {}",
            algorithm
        ));
    }
    let key_id = require_payload_envelope_field(envelope.key_id.as_deref(), "key_id")?;
    if key_id != key.key_id {
        return Err(anyhow!(
            "user-memory sync payload key_id does not match configured local key"
        ));
    }
    let nonce_b64 = require_payload_envelope_field(envelope.nonce_b64.as_deref(), "nonce_b64")?;
    let ciphertext_b64 =
        require_payload_envelope_field(envelope.ciphertext_b64.as_deref(), "ciphertext_b64")?;
    let payload_hash =
        require_payload_envelope_field(envelope.payload_hash.as_deref(), "payload_hash")?;
    let nonce_bytes = Base64Engine
        .decode(nonce_b64)
        .context("decode user-memory sync payload nonce")?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!(
            "user-memory sync payload nonce must be 12 bytes, got {}",
            nonce_bytes.len()
        ));
    }
    let ciphertext = Base64Engine
        .decode(ciphertext_b64)
        .context("decode user-memory sync payload ciphertext")?;
    let aad = user_memory_sync_payload_aad(
        lane,
        operation,
        object_id,
        object_version,
        payload_kind,
        payload_hash,
        key_id,
    );
    if let Some(encoded_aad) = envelope.aad_b64.as_deref().and_then(nonempty_trimmed) {
        let decoded_aad = Base64Engine
            .decode(encoded_aad)
            .context("decode user-memory sync payload aad")?;
        if decoded_aad != aad.as_bytes() {
            return Err(anyhow!(
                "user-memory sync payload aad does not match event identity"
            ));
        }
    }
    let aes = Aes256Gcm::new_from_slice(&key.key_bytes)
        .context("initialize user-memory sync payload cipher")?;
    let plaintext = aes
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: ciphertext.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|err| anyhow!("decrypt user-memory sync payload: {err}"))?;
    let actual_hash = format!("sha256:{}", hex::encode(Sha256::digest(&plaintext)));
    if actual_hash != payload_hash {
        return Err(anyhow!(
            "user-memory sync payload hash mismatch after decrypt"
        ));
    }
    Ok(plaintext)
}

fn require_payload_envelope_field<'a>(field: Option<&'a str>, field_name: &str) -> Result<&'a str> {
    field
        .and_then(nonempty_trimmed)
        .ok_or_else(|| anyhow!("encrypted user-memory sync payload envelope requires {field_name}"))
}

fn decode_user_memory_sync_payload_key_material(
    raw: &str,
) -> Result<[u8; USER_MEMORY_SYNC_PAYLOAD_KEY_LEN]> {
    let value = raw.trim();
    let decoded = if let Some(rest) = value.strip_prefix("base64:") {
        Base64Engine
            .decode(rest.trim())
            .context("decode base64 user-memory sync encryption key")?
    } else if let Some(rest) = value.strip_prefix("hex:") {
        hex::decode(rest.trim()).context("decode hex user-memory sync encryption key")?
    } else if value.len() == USER_MEMORY_SYNC_PAYLOAD_KEY_LEN * 2
        && value.chars().all(|ch| ch.is_ascii_hexdigit())
    {
        hex::decode(value).context("decode hex user-memory sync encryption key")?
    } else if value.as_bytes().len() == USER_MEMORY_SYNC_PAYLOAD_KEY_LEN {
        value.as_bytes().to_vec()
    } else {
        Base64Engine
            .decode(value)
            .context("decode base64 user-memory sync encryption key")?
    };
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "user-memory sync encryption key must be {USER_MEMORY_SYNC_PAYLOAD_KEY_LEN} bytes, got {}",
            bytes.len()
        )
    })
}

fn derived_user_memory_sync_payload_key_id(
    key_bytes: &[u8; USER_MEMORY_SYNC_PAYLOAD_KEY_LEN],
) -> String {
    let digest = Sha256::digest(key_bytes);
    format!("sha256:{}", hex::encode(&digest[..8]))
}

fn user_memory_sync_payload_aad(
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: &str,
    object_version: Option<&str>,
    payload_kind: &str,
    payload_hash: &str,
    key_id: &str,
) -> String {
    [
        USER_MEMORY_SYNC_SCHEMA_VERSION,
        "payload",
        lane.as_str(),
        operation.as_str(),
        object_id,
        object_version.unwrap_or_default(),
        payload_kind,
        payload_hash,
        key_id,
    ]
    .join("\0")
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncLedgerSnapshot {
    pub path: String,
    pub exists: bool,
    pub known_events: usize,
    pub unknown_events: usize,
    pub uploaded_events: usize,
    pub acked_events: usize,
    pub applied_events: usize,
    pub skipped_events: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncLedgerEventState {
    pub event_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uploaded_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acked_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerSnapshot {
    pub path: String,
    pub exists: bool,
    pub devices: usize,
    pub events: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerDevice {
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub enabled_lanes: Vec<UserMemorySyncLane>,
    pub schema_version: String,
    pub registered_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerStoredEvent {
    pub cursor: String,
    pub bundle_id: String,
    pub device_id: String,
    pub received_at_ms: i64,
    pub event: UserMemorySyncEvent,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerRejectedEvent {
    pub event_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerPushResult {
    pub accepted_event_ids: Vec<String>,
    pub duplicate_event_ids: Vec<String>,
    pub rejected_events: Vec<UserMemorySyncServerRejectedEvent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerFeed {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub events: Vec<UserMemorySyncServerStoredEvent>,
    pub has_more: bool,
    pub server_time_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserMemorySyncServerAckResult {
    pub acked_event_ids: Vec<String>,
    pub unknown_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    pub acked_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct UserMemorySyncLedger {
    path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct UserMemorySyncServerStore {
    path: PathBuf,
}

impl UserMemorySyncLedger {
    pub fn path_for_state_dir(state_dir: &Path) -> PathBuf {
        state_dir
            .join(USER_MEMORY_SYNC_LEDGER_DIR)
            .join(USER_MEMORY_SYNC_LEDGER_DB)
    }

    pub fn open_or_create(path: impl Into<PathBuf>) -> Result<Self> {
        let ledger = Self { path: path.into() };
        if let Some(parent) = ledger.path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let conn = open_ledger_db(&ledger.path, true)?;
        ensure_ledger_schema(&conn)?;
        Ok(ledger)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn record_uploaded(
        &self,
        events: &[UserMemorySyncEvent],
        uploaded_at_ms: i64,
    ) -> Result<usize> {
        let mut conn = open_ledger_db(&self.path, true)?;
        ensure_ledger_schema(&conn)?;
        let tx = conn
            .transaction()
            .context("start user-memory sync ledger tx")?;
        for event in events {
            tx.execute(
                "INSERT INTO user_memory_sync_ledger(
                    event_id, lane, object_id, content_hash, status,
                    first_seen_at_ms, last_seen_at_ms, uploaded_at_ms, acked_at_ms, upload_attempts
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, ?6, NULL, 1)
                 ON CONFLICT(event_id) DO UPDATE SET
                    lane = excluded.lane,
                    object_id = excluded.object_id,
                    content_hash = excluded.content_hash,
                    status = excluded.status,
                    last_seen_at_ms = excluded.last_seen_at_ms,
                    uploaded_at_ms = excluded.uploaded_at_ms,
                    upload_attempts = user_memory_sync_ledger.upload_attempts + 1",
                params![
                    event.event_id.as_str(),
                    event.lane.as_str(),
                    event.object_id.as_str(),
                    event.content_hash.as_str(),
                    USER_MEMORY_SYNC_LEDGER_STATUS_UPLOADED,
                    uploaded_at_ms,
                ],
            )
            .context("record uploaded user-memory sync event")?;
        }
        tx.commit().context("commit user-memory sync ledger tx")?;
        Ok(events.len())
    }

    pub fn record_acked(&self, event_ids: &[String], acked_at_ms: i64) -> Result<usize> {
        let conn = open_ledger_db(&self.path, true)?;
        ensure_ledger_schema(&conn)?;
        let mut updated = 0usize;
        for event_id in event_ids {
            updated += conn
                .execute(
                    "UPDATE user_memory_sync_ledger
                     SET status = ?2, acked_at_ms = ?3, last_seen_at_ms = ?3
                     WHERE event_id = ?1",
                    params![event_id, USER_MEMORY_SYNC_LEDGER_STATUS_ACKED, acked_at_ms],
                )
                .context("record acked user-memory sync event")?;
        }
        Ok(updated)
    }

    pub fn record_applied(
        &self,
        events: &[UserMemorySyncServerStoredEvent],
        applied_at_ms: i64,
    ) -> Result<usize> {
        self.record_downsync_status(
            events,
            USER_MEMORY_SYNC_LEDGER_STATUS_APPLIED,
            applied_at_ms,
        )
    }

    pub fn record_skipped(
        &self,
        events: &[UserMemorySyncServerStoredEvent],
        skipped_at_ms: i64,
    ) -> Result<usize> {
        self.record_downsync_status(
            events,
            USER_MEMORY_SYNC_LEDGER_STATUS_SKIPPED,
            skipped_at_ms,
        )
    }

    fn record_downsync_status(
        &self,
        events: &[UserMemorySyncServerStoredEvent],
        status: &str,
        seen_at_ms: i64,
    ) -> Result<usize> {
        let mut conn = open_ledger_db(&self.path, true)?;
        ensure_ledger_schema(&conn)?;
        let tx = conn
            .transaction()
            .context("start user-memory sync ledger down-sync tx")?;
        for stored in events {
            let event = &stored.event;
            tx.execute(
                "INSERT INTO user_memory_sync_ledger(
                    event_id, lane, object_id, content_hash, status,
                    first_seen_at_ms, last_seen_at_ms, uploaded_at_ms, acked_at_ms, upload_attempts
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6, NULL, ?6, 0)
                 ON CONFLICT(event_id) DO UPDATE SET
                    lane = excluded.lane,
                    object_id = excluded.object_id,
                    content_hash = excluded.content_hash,
                    status = excluded.status,
                    last_seen_at_ms = excluded.last_seen_at_ms,
                    acked_at_ms = excluded.acked_at_ms",
                params![
                    event.event_id.as_str(),
                    event.lane.as_str(),
                    event.object_id.as_str(),
                    event.content_hash.as_str(),
                    status,
                    seen_at_ms,
                ],
            )
            .context("record down-synced user-memory sync event")?;
        }
        tx.commit()
            .context("commit user-memory sync ledger down-sync tx")?;
        Ok(events.len())
    }

    pub fn snapshot_for_events_read_only(
        path: impl AsRef<Path>,
        events: &[UserMemorySyncEvent],
    ) -> Result<UserMemorySyncLedgerSnapshot> {
        let path = path.as_ref();
        let states = ledger_event_states_read_only(path, events)?;
        let known_events = states.len();
        let uploaded_events = states
            .values()
            .filter(|state| {
                matches!(
                    state.status.as_deref(),
                    Some(USER_MEMORY_SYNC_LEDGER_STATUS_UPLOADED)
                        | Some(USER_MEMORY_SYNC_LEDGER_STATUS_ACKED)
                )
            })
            .count();
        let acked_events = states
            .values()
            .filter(|state| state.status.as_deref() == Some(USER_MEMORY_SYNC_LEDGER_STATUS_ACKED))
            .count();
        let applied_events = states
            .values()
            .filter(|state| state.status.as_deref() == Some(USER_MEMORY_SYNC_LEDGER_STATUS_APPLIED))
            .count();
        let skipped_events = states
            .values()
            .filter(|state| state.status.as_deref() == Some(USER_MEMORY_SYNC_LEDGER_STATUS_SKIPPED))
            .count();
        Ok(UserMemorySyncLedgerSnapshot {
            path: path.display().to_string(),
            exists: path.exists(),
            known_events,
            unknown_events: events.len().saturating_sub(known_events),
            uploaded_events,
            acked_events,
            applied_events,
            skipped_events,
        })
    }

    pub fn event_states_read_only(
        path: impl AsRef<Path>,
        events: &[UserMemorySyncEvent],
    ) -> Result<BTreeMap<String, UserMemorySyncLedgerEventState>> {
        ledger_event_states_read_only(path.as_ref(), events)
    }
}

impl UserMemorySyncServerStore {
    pub fn path_for_state_dir(state_dir: &Path) -> PathBuf {
        state_dir
            .join(USER_MEMORY_SYNC_LEDGER_DIR)
            .join(USER_MEMORY_SYNC_SERVER_DB)
    }

    pub fn open_or_create(path: impl Into<PathBuf>) -> Result<Self> {
        let store = Self { path: path.into() };
        if let Some(parent) = store.path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let conn = open_user_memory_sync_db(&store.path, true)?;
        ensure_server_schema(&conn)?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn snapshot_read_only(
        path: impl AsRef<Path>,
        principal_key: &str,
    ) -> Result<UserMemorySyncServerSnapshot> {
        let path = path.as_ref();
        if !path.exists() {
            return Ok(UserMemorySyncServerSnapshot {
                path: path.display().to_string(),
                exists: false,
                devices: 0,
                events: 0,
                latest_cursor: None,
            });
        }
        let conn = open_user_memory_sync_db(path, false)?;
        if !server_tables_exist(&conn)? {
            return Ok(UserMemorySyncServerSnapshot {
                path: path.display().to_string(),
                exists: true,
                devices: 0,
                events: 0,
                latest_cursor: None,
            });
        }
        let devices = conn
            .query_row(
                "SELECT COUNT(*) FROM user_memory_sync_devices WHERE principal_key = ?1",
                params![principal_key],
                |row| row.get::<_, i64>(0),
            )
            .context("count user-memory sync server devices")?
            .max(0) as usize;
        let events = conn
            .query_row(
                "SELECT COUNT(*) FROM user_memory_sync_server_events WHERE principal_key = ?1",
                params![principal_key],
                |row| row.get::<_, i64>(0),
            )
            .context("count user-memory sync server events")?
            .max(0) as usize;
        let latest_cursor = latest_server_cursor(&conn, principal_key)?;
        Ok(UserMemorySyncServerSnapshot {
            path: path.display().to_string(),
            exists: true,
            devices,
            events,
            latest_cursor,
        })
    }

    pub fn register_device(
        &self,
        principal_key: &str,
        device_id: &str,
        display_name: Option<String>,
        enabled_lanes: Vec<UserMemorySyncLane>,
        now_ms: i64,
    ) -> Result<UserMemorySyncServerDevice> {
        let principal_key =
            nonempty_trimmed(principal_key).ok_or_else(|| anyhow!("principal key is required"))?;
        let device_id =
            nonempty_trimmed(device_id).ok_or_else(|| anyhow!("device_id is required"))?;
        let conn = open_user_memory_sync_db(&self.path, true)?;
        ensure_server_schema(&conn)?;
        let registered_at_ms = conn
            .query_row(
                "SELECT registered_at_ms
                 FROM user_memory_sync_devices
                 WHERE principal_key = ?1 AND device_id = ?2",
                params![principal_key, device_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .context("read existing user-memory sync device")?
            .unwrap_or(now_ms);
        let enabled_lanes_json =
            serde_json::to_string(&enabled_lanes).context("serialize enabled lanes")?;
        conn.execute(
            "INSERT INTO user_memory_sync_devices(
                principal_key, device_id, display_name, enabled_lanes_json,
                schema_version, registered_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(principal_key, device_id) DO UPDATE SET
                display_name = excluded.display_name,
                enabled_lanes_json = excluded.enabled_lanes_json,
                schema_version = excluded.schema_version,
                updated_at_ms = excluded.updated_at_ms",
            params![
                principal_key,
                device_id,
                display_name.as_deref(),
                enabled_lanes_json,
                USER_MEMORY_SYNC_SCHEMA_VERSION,
                registered_at_ms,
                now_ms,
            ],
        )
        .context("register user-memory sync device")?;
        Ok(UserMemorySyncServerDevice {
            device_id: device_id.to_string(),
            display_name,
            enabled_lanes,
            schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION.to_string(),
            registered_at_ms,
            updated_at_ms: now_ms,
        })
    }

    pub fn push_bundle(
        &self,
        principal_key: &str,
        bundle: &UserMemorySyncBundle,
        received_at_ms: i64,
    ) -> Result<UserMemorySyncServerPushResult> {
        let principal_key =
            nonempty_trimmed(principal_key).ok_or_else(|| anyhow!("principal key is required"))?;
        if bundle.schema_version != USER_MEMORY_SYNC_SCHEMA_VERSION {
            return Err(anyhow!(
                "unsupported user-memory sync schema version: {}",
                bundle.schema_version
            ));
        }
        nonempty_trimmed(&bundle.bundle_id).ok_or_else(|| anyhow!("bundle_id is required"))?;
        nonempty_trimmed(&bundle.device_id).ok_or_else(|| anyhow!("device_id is required"))?;

        let mut conn = open_user_memory_sync_db(&self.path, true)?;
        ensure_server_schema(&conn)?;
        let tx = conn
            .transaction()
            .context("start user-memory sync server push tx")?;
        let mut accepted_event_ids = Vec::new();
        let mut duplicate_event_ids = Vec::new();
        let mut rejected_events = Vec::new();
        let mut max_cursor = None;

        for event in &bundle.events {
            if nonempty_trimmed(&event.event_id).is_none() {
                rejected_events.push(UserMemorySyncServerRejectedEvent {
                    event_id: String::new(),
                    reason: "event_id is required".to_string(),
                });
                continue;
            }
            if nonempty_trimmed(&event.object_id).is_none() {
                rejected_events.push(UserMemorySyncServerRejectedEvent {
                    event_id: event.event_id.clone(),
                    reason: "object_id is required".to_string(),
                });
                continue;
            }
            if event.provenance.source_device_id != bundle.device_id {
                rejected_events.push(UserMemorySyncServerRejectedEvent {
                    event_id: event.event_id.clone(),
                    reason: "event source_device_id must match bundle device_id".to_string(),
                });
                continue;
            }
            if let Err(err) =
                validate_user_memory_sync_payload_envelope(event.payload_envelope.as_ref())
            {
                rejected_events.push(UserMemorySyncServerRejectedEvent {
                    event_id: event.event_id.clone(),
                    reason: err.to_string(),
                });
                continue;
            }
            let payload_summary_json = serde_json::to_string(&event.payload_summary)
                .context("serialize user-memory sync payload summary")?;
            let payload_envelope_json = event
                .payload_envelope
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .context("serialize user-memory sync payload envelope")?;
            let provenance_json = serde_json::to_string(&event.provenance)
                .context("serialize user-memory sync provenance")?;
            let inserted = tx
                .execute(
                    "INSERT OR IGNORE INTO user_memory_sync_server_events(
                        principal_key, event_id, bundle_id, device_id, lane, operation,
                        object_id, object_version, content_hash, sensitivity, payload_kind,
                        payload_summary_json, payload_envelope_json, provenance_json,
                        created_at_ms, received_at_ms
                     ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
                    params![
                        principal_key,
                        event.event_id.as_str(),
                        bundle.bundle_id.as_str(),
                        bundle.device_id.as_str(),
                        event.lane.as_str(),
                        event.operation.as_str(),
                        event.object_id.as_str(),
                        event.object_version.as_deref(),
                        event.content_hash.as_str(),
                        event.sensitivity.as_str(),
                        event.payload_kind.as_str(),
                        payload_summary_json,
                        payload_envelope_json.as_deref(),
                        provenance_json,
                        bundle.created_at_ms,
                        received_at_ms,
                    ],
                )
                .context("store user-memory sync server event")?;
            if inserted == 0 {
                duplicate_event_ids.push(event.event_id.clone());
                continue;
            }
            let cursor = tx
                .query_row(
                    "SELECT cursor
                     FROM user_memory_sync_server_events
                     WHERE principal_key = ?1 AND event_id = ?2",
                    params![principal_key, event.event_id.as_str()],
                    |row| row.get::<_, i64>(0),
                )
                .context("read inserted user-memory sync event cursor")?;
            max_cursor = Some(max_cursor.map_or(cursor, |existing: i64| existing.max(cursor)));
            accepted_event_ids.push(event.event_id.clone());
        }

        tx.commit()
            .context("commit user-memory sync server push tx")?;
        let next_cursor = match max_cursor {
            Some(cursor) => Some(format_user_memory_sync_cursor(cursor)),
            None => {
                let conn = open_user_memory_sync_db(&self.path, false)?;
                latest_server_cursor(&conn, principal_key)?
            }
        };
        Ok(UserMemorySyncServerPushResult {
            accepted_event_ids,
            duplicate_event_ids,
            rejected_events,
            next_cursor,
        })
    }

    pub fn feed(
        &self,
        principal_key: &str,
        cursor: Option<&str>,
        lanes: &[UserMemorySyncLane],
        limit: usize,
        exclude_device_id: Option<&str>,
    ) -> Result<UserMemorySyncServerFeed> {
        let principal_key =
            nonempty_trimmed(principal_key).ok_or_else(|| anyhow!("principal key is required"))?;
        let cursor_value = parse_user_memory_sync_cursor(cursor)?.unwrap_or(0);
        let limit = limit.clamp(1, 500);
        if !self.path.exists() {
            return Ok(UserMemorySyncServerFeed {
                cursor: cursor.map(ToOwned::to_owned),
                next_cursor: cursor.map(ToOwned::to_owned),
                events: Vec::new(),
                has_more: false,
                server_time_ms: user_memory_sync_now_ms(),
            });
        }
        let conn = open_user_memory_sync_db(&self.path, false)?;
        if !server_tables_exist(&conn)? {
            return Ok(UserMemorySyncServerFeed {
                cursor: cursor.map(ToOwned::to_owned),
                next_cursor: cursor.map(ToOwned::to_owned),
                events: Vec::new(),
                has_more: false,
                server_time_ms: user_memory_sync_now_ms(),
            });
        }
        let lane_filter: BTreeSet<_> = lanes.iter().copied().collect();
        let mut stmt = conn
            .prepare(
                "SELECT
                    cursor, bundle_id, device_id, event_id, lane, operation, object_id,
                    object_version, content_hash, sensitivity, payload_kind,
                    payload_summary_json, payload_envelope_json, provenance_json, received_at_ms
                 FROM user_memory_sync_server_events
                 WHERE principal_key = ?1 AND cursor > ?2
                 ORDER BY cursor ASC
                 LIMIT ?3",
            )
            .context("prepare user-memory sync feed query")?;
        let scan_limit = limit.saturating_mul(10).saturating_add(1).min(5_001) as i64;
        let rows = stmt
            .query_map(params![principal_key, cursor_value, scan_limit], |row| {
                row_to_server_event(row)
            })
            .context("query user-memory sync feed")?;
        let mut events = Vec::new();
        let mut has_more = false;
        for row in rows {
            let event = row.context("read user-memory sync feed row")?;
            let excluded_device = match exclude_device_id.and_then(nonempty_trimmed) {
                Some(device_id) => device_id == event.device_id,
                None => false,
            };
            if excluded_device {
                continue;
            }
            if !lane_filter.is_empty() && !lane_filter.contains(&event.event.lane) {
                continue;
            }
            if events.len() >= limit {
                has_more = true;
                break;
            }
            events.push(event);
        }
        let next_cursor = events
            .last()
            .map(|event| event.cursor.clone())
            .or_else(|| cursor.map(ToOwned::to_owned));
        Ok(UserMemorySyncServerFeed {
            cursor: cursor.map(ToOwned::to_owned),
            next_cursor,
            events,
            has_more,
            server_time_ms: user_memory_sync_now_ms(),
        })
    }

    pub fn ack(
        &self,
        principal_key: &str,
        device_id: &str,
        event_ids: &[String],
        cursor: Option<String>,
        acked_at_ms: i64,
    ) -> Result<UserMemorySyncServerAckResult> {
        let principal_key =
            nonempty_trimmed(principal_key).ok_or_else(|| anyhow!("principal key is required"))?;
        let device_id =
            nonempty_trimmed(device_id).ok_or_else(|| anyhow!("device_id is required"))?;
        if let Some(cursor) = cursor.as_deref() {
            parse_user_memory_sync_cursor(Some(cursor))?;
        }
        let mut conn = open_user_memory_sync_db(&self.path, true)?;
        ensure_server_schema(&conn)?;
        let tx = conn
            .transaction()
            .context("start user-memory sync ack tx")?;
        let mut acked_event_ids = Vec::new();
        let mut unknown_event_ids = Vec::new();
        for event_id in event_ids {
            let Some(event_id) = nonempty_trimmed(event_id) else {
                continue;
            };
            let exists = tx
                .query_row(
                    "SELECT 1
                     FROM user_memory_sync_server_events
                     WHERE principal_key = ?1 AND event_id = ?2",
                    params![principal_key, event_id],
                    |_| Ok(()),
                )
                .optional()
                .context("check acked user-memory sync event")?
                .is_some();
            if !exists {
                unknown_event_ids.push(event_id.to_string());
                continue;
            }
            tx.execute(
                "INSERT INTO user_memory_sync_server_acks(
                    principal_key, device_id, event_id, cursor, acked_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(principal_key, device_id, event_id) DO UPDATE SET
                    cursor = excluded.cursor,
                    acked_at_ms = excluded.acked_at_ms",
                params![
                    principal_key,
                    device_id,
                    event_id,
                    cursor.as_deref(),
                    acked_at_ms
                ],
            )
            .context("record user-memory sync server ack")?;
            acked_event_ids.push(event_id.to_string());
        }
        tx.commit().context("commit user-memory sync ack tx")?;
        Ok(UserMemorySyncServerAckResult {
            acked_event_ids,
            unknown_event_ids,
            cursor,
            acked_at_ms,
        })
    }
}

pub fn user_memory_sync_policy_matrix() -> UserMemorySyncPolicyMatrix {
    UserMemorySyncPolicyMatrix {
        schema_version: USER_MEMORY_SYNC_SCHEMA_VERSION,
        sync_by_default: Vec::new(),
        lane_policies: UserMemorySyncLane::supported_lanes()
            .into_iter()
            .map(user_memory_sync_lane_policy)
            .collect(),
        excluded_local_data: vec![
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "raw_conversation_transcripts",
                default_policy: "excluded_by_default",
                reason: "raw transcript content needs explicit user consent and stronger review",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "full_evidence_blobs",
                default_policy: "excluded_by_default",
                reason: "evidence should sync as hashes, labels, or short summaries unless explicitly enabled",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "repo_source_files",
                default_policy: "never_sync_from_memory_sync",
                reason: "source sync belongs to encrypted repo/source APIs, not user-memory sync",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "terminal_logs",
                default_policy: "never_sync_by_default",
                reason: "terminal output may contain secrets and unrelated local machine data",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "secrets_and_raw_api_keys",
                default_policy: "never_sync",
                reason: "credentials must never be uploaded as memory payloads",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "raw_connector_payloads",
                default_policy: "never_sync_by_default",
                reason: "connector payloads require connector-specific consent and retention controls",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "local_indexes_embeddings_caches",
                default_policy: "never_sync",
                reason: "these are rebuildable machine-local artifacts",
            },
            UserMemorySyncExcludedPayloadPolicy {
                local_data: "build_test_artifacts",
                default_policy: "never_sync",
                reason: "generated artifacts are outside durable memory semantics",
            },
        ],
    }
}

pub fn user_memory_sync_lane_policy(lane: UserMemorySyncLane) -> UserMemorySyncLanePolicy {
    match lane {
        UserMemorySyncLane::RepoMemory => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull_per_repo",
            default_payload: "structured technical facts, repo fingerprint, content hash, supersession metadata",
            merge_rule: "merge by repo fingerprint, stable memory id, content hash, and supersedes chain",
            downsync_policy: "apply only to matching repo identity; keep separate namespaces when identity is ambiguous",
            sensitive_exclusions: vec!["repo source files", "raw terminal output", "secret values"],
        },
        UserMemorySyncLane::ProfileMemory => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull",
            default_payload: "global agent and user preference records with categories and timestamps",
            merge_rule: "merge by stable preference id and agent id; conflicting live records require review",
            downsync_policy: "upsert exact preference records idempotently; tombstones and redactions win",
            sensitive_exclusions: vec!["raw embeddings are optional", "secret-bearing preferences"],
        },
        UserMemorySyncLane::PersonalPreferences => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull",
            default_payload: "captures metadata, derived records, claims, feedback, review state, retention and redaction controls",
            merge_rule: "merge by stable claim/version ids, evidence hashes, truth status, review status, and provenance",
            downsync_policy: "apply claims and control records idempotently; user review decisions override inferred facts",
            sensitive_exclusions: vec!["raw transcript text", "full evidence blobs", "high-sensitivity claims without review"],
        },
        UserMemorySyncLane::MindClone => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull",
            default_payload: "identity snapshots, clone profiles, routines, style signals, decision patterns, goal graph, evaluations",
            merge_rule: "merge by canonical object id, version, provenance, sensitivity label, and review status",
            downsync_policy: "apply reviewed or low-risk projections; preserve conflicting versions for review",
            sensitive_exclusions: vec!["autonomy actions without explicit approval", "sensitive identity claims without review"],
        },
        UserMemorySyncLane::Diary => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull",
            default_payload: "concise handoff notes and session outcomes",
            merge_rule: "append-only by diary entry id; tombstones win",
            downsync_policy: "append remote entries after cursor ack; do not rewrite local notes unless tombstoned",
            sensitive_exclusions: vec!["raw transcripts", "secrets"],
        },
        UserMemorySyncLane::ConversationSummaries => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptionalSensitive,
            default_direction: "push_pull_summaries_only",
            default_payload: "episodic summaries, rollups, selected facts, source metadata",
            merge_rule: "append summaries by episode id and provenance; raw transcript events require explicit lane option",
            downsync_policy: "feed summaries and redactions; raw transcript down-sync is disabled by default",
            sensitive_exclusions: vec!["raw transcripts by default", "verbatim snippets by default"],
        },
        UserMemorySyncLane::TemporalKg => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull",
            default_payload: "nodes, edges, episodes, entity links, provenance, tombstones",
            merge_rule: "merge by entity/edge ids and provenance; tombstones and redactions win",
            downsync_policy: "apply graph deltas by lane cursor after local validation",
            sensitive_exclusions: vec!["raw episode transcript payloads", "unreviewed sensitive entities"],
        },
        UserMemorySyncLane::GeneratedSkills => UserMemorySyncLanePolicy {
            lane,
            class: UserMemorySyncLaneClass::OptIn,
            default_direction: "push_pull",
            default_payload: "generated skill metadata, versions, validations, install policy, activation feedback, provenance",
            merge_rule: "merge by generated skill id and version id; quarantine and review states win over install states",
            downsync_policy: "never install remotely learned skills automatically; stage them for local review",
            sensitive_exclusions: vec!["rendered files outside Docdex-managed roots", "raw terminal context used to derive skills"],
        },
    }
}

pub fn parse_lane_names_lossy(names: &[String]) -> (Vec<UserMemorySyncLane>, Vec<String>) {
    let mut seen = BTreeSet::new();
    let mut lanes = Vec::new();
    let mut invalid = Vec::new();
    for name in names {
        match UserMemorySyncLane::from_str(name) {
            Ok(lane) => {
                if seen.insert(lane) {
                    lanes.push(lane);
                }
            }
            Err(_) => invalid.push(name.clone()),
        }
    }
    (lanes, invalid)
}

pub fn user_memory_sync_identity_from_config(
    mswarm_api_key: Option<&str>,
    api_key_env: Option<&str>,
) -> UserMemorySyncIdentity {
    if let Some(env_key) = api_key_env.and_then(nonempty_trimmed) {
        if let Some(api_key) = env::var(env_key).ok().and_then(nonempty_owned) {
            return configured_user_memory_sync_identity(
                USER_MEMORY_SYNC_IDENTITY_SOURCE_API_KEY_ENV,
                &api_key,
            );
        }
    }
    if let Some(api_key) = mswarm_api_key.and_then(nonempty_trimmed) {
        return configured_user_memory_sync_identity(
            USER_MEMORY_SYNC_IDENTITY_SOURCE_MSWARM_API_KEY,
            api_key,
        );
    }
    UserMemorySyncIdentity::default()
}

pub fn user_memory_sync_credential_fingerprint(api_key: &str) -> Option<String> {
    let api_key = nonempty_trimmed(api_key)?;
    let mut hasher = Sha256::new();
    hasher.update(b"docdex.user_memory_sync.identity.v1\0");
    hasher.update(api_key.as_bytes());
    let digest = hex::encode(hasher.finalize());
    Some(format!("sha256:{}", &digest[..16]))
}

pub fn user_memory_sync_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

pub fn stable_content_hash<T: Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value).context("serialize user-memory sync hash payload")?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(&bytes))))
}

pub fn stable_event_id(
    lane: UserMemorySyncLane,
    operation: UserMemorySyncOperation,
    object_id: &str,
    object_version: Option<&str>,
    content_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(USER_MEMORY_SYNC_SCHEMA_VERSION.as_bytes());
    hasher.update([0]);
    hasher.update(lane.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(operation.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(object_id.as_bytes());
    hasher.update([0]);
    hasher.update(object_version.unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(content_hash.as_bytes());
    format!("evt_{}", hex::encode(hasher.finalize()))
}

pub fn stable_bundle_id(
    device_id: &str,
    base_cursor: Option<&str>,
    lanes: &[UserMemorySyncLane],
    events: &[UserMemorySyncEvent],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(USER_MEMORY_SYNC_SCHEMA_VERSION.as_bytes());
    hasher.update([0]);
    hasher.update(device_id.as_bytes());
    hasher.update([0]);
    hasher.update(base_cursor.unwrap_or_default().as_bytes());
    for lane in lanes {
        hasher.update([0]);
        hasher.update(lane.as_str().as_bytes());
    }
    for event in events {
        hasher.update([0]);
        hasher.update(event.event_id.as_bytes());
        hasher.update([0]);
        hasher.update(event.content_hash.as_bytes());
    }
    format!("bundle_{}", hex::encode(hasher.finalize()))
}

pub fn user_memory_sync_server_principal_key(identity: &UserMemorySyncIdentity) -> Option<String> {
    if !identity.configured {
        return None;
    }
    identity
        .credential_fingerprint
        .as_deref()
        .and_then(nonempty_trimmed)
        .map(ToOwned::to_owned)
}

fn open_ledger_db(path: &Path, create: bool) -> Result<Connection> {
    open_user_memory_sync_db(path, create)
}

fn open_user_memory_sync_db(path: &Path, create: bool) -> Result<Connection> {
    let flags = if create {
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX
    };
    let conn = Connection::open_with_flags(path, flags)
        .with_context(|| format!("open {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

fn ensure_ledger_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_memory_sync_ledger(
            event_id TEXT PRIMARY KEY,
            lane TEXT NOT NULL,
            object_id TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            status TEXT NOT NULL,
            first_seen_at_ms INTEGER NOT NULL,
            last_seen_at_ms INTEGER NOT NULL,
            uploaded_at_ms INTEGER,
            acked_at_ms INTEGER,
            upload_attempts INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_ledger_lane
            ON user_memory_sync_ledger(lane);
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_ledger_object
            ON user_memory_sync_ledger(lane, object_id);
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_ledger_status
            ON user_memory_sync_ledger(status);",
    )
    .context("ensure user-memory sync ledger schema")?;
    Ok(())
}

fn ensure_server_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS user_memory_sync_devices(
            principal_key TEXT NOT NULL,
            device_id TEXT NOT NULL,
            display_name TEXT,
            enabled_lanes_json TEXT NOT NULL,
            schema_version TEXT NOT NULL,
            registered_at_ms INTEGER NOT NULL,
            updated_at_ms INTEGER NOT NULL,
            PRIMARY KEY(principal_key, device_id)
        );
        CREATE TABLE IF NOT EXISTS user_memory_sync_server_events(
            cursor INTEGER PRIMARY KEY AUTOINCREMENT,
            principal_key TEXT NOT NULL,
            event_id TEXT NOT NULL,
            bundle_id TEXT NOT NULL,
            device_id TEXT NOT NULL,
            lane TEXT NOT NULL,
            operation TEXT NOT NULL,
            object_id TEXT NOT NULL,
            object_version TEXT,
            content_hash TEXT NOT NULL,
            sensitivity TEXT NOT NULL,
            payload_kind TEXT NOT NULL,
            payload_summary_json TEXT NOT NULL,
            payload_envelope_json TEXT,
            provenance_json TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            received_at_ms INTEGER NOT NULL,
            UNIQUE(principal_key, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_server_events_principal_cursor
            ON user_memory_sync_server_events(principal_key, cursor);
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_server_events_principal_lane_cursor
            ON user_memory_sync_server_events(principal_key, lane, cursor);
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_server_events_principal_object
            ON user_memory_sync_server_events(principal_key, lane, object_id);
        CREATE TABLE IF NOT EXISTS user_memory_sync_server_acks(
            principal_key TEXT NOT NULL,
            device_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            cursor TEXT,
            acked_at_ms INTEGER NOT NULL,
            PRIMARY KEY(principal_key, device_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_user_memory_sync_server_acks_principal_device
            ON user_memory_sync_server_acks(principal_key, device_id);",
    )
    .context("ensure user-memory sync server schema")?;
    ensure_server_payload_envelope_column(conn)?;
    Ok(())
}

fn ensure_server_payload_envelope_column(conn: &Connection) -> Result<()> {
    if !sqlite_column_exists(
        conn,
        "user_memory_sync_server_events",
        "payload_envelope_json",
    )? {
        conn.execute(
            "ALTER TABLE user_memory_sync_server_events ADD COLUMN payload_envelope_json TEXT",
            [],
        )
        .context("add user-memory sync server payload envelope column")?;
    }
    Ok(())
}

fn ledger_event_states_read_only(
    path: &Path,
    events: &[UserMemorySyncEvent],
) -> Result<BTreeMap<String, UserMemorySyncLedgerEventState>> {
    let mut states = BTreeMap::new();
    if !path.exists() || events.is_empty() {
        return Ok(states);
    }
    let conn = open_ledger_db(path, false)?;
    if !ledger_table_exists(&conn)? {
        return Ok(states);
    }
    for event in events {
        let row = conn
            .query_row(
                "SELECT status, uploaded_at_ms, acked_at_ms
                 FROM user_memory_sync_ledger
                 WHERE event_id = ?1",
                params![event.event_id.as_str()],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                    ))
                },
            )
            .optional()
            .context("read user-memory sync ledger event state")?;
        if let Some((status, uploaded_at_ms, acked_at_ms)) = row {
            states.insert(
                event.event_id.clone(),
                UserMemorySyncLedgerEventState {
                    event_id: event.event_id.clone(),
                    status: Some(status),
                    uploaded_at_ms,
                    acked_at_ms,
                },
            );
        }
    }
    Ok(states)
}

fn ledger_table_exists(conn: &Connection) -> Result<bool> {
    sqlite_table_exists(conn, "user_memory_sync_ledger")
}

fn server_tables_exist(conn: &Connection) -> Result<bool> {
    Ok(sqlite_table_exists(conn, "user_memory_sync_devices")?
        && sqlite_table_exists(conn, "user_memory_sync_server_events")?)
}

fn sqlite_table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table_name],
            |_| Ok(()),
        )
        .optional()
        .context("inspect user-memory sync ledger schema")?
        .is_some();
    Ok(exists)
}

fn sqlite_column_exists(conn: &Connection, table_name: &str, column_name: &str) -> Result<bool> {
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info({table_name})"))
        .context("inspect user-memory sync table columns")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .context("read user-memory sync table columns")?;
    for row in rows {
        if row.context("read user-memory sync column name")? == column_name {
            return Ok(true);
        }
    }
    Ok(false)
}

fn latest_server_cursor(conn: &Connection, principal_key: &str) -> Result<Option<String>> {
    let cursor = conn
        .query_row(
            "SELECT MAX(cursor)
             FROM user_memory_sync_server_events
             WHERE principal_key = ?1",
            params![principal_key],
            |row| row.get::<_, Option<i64>>(0),
        )
        .context("read latest user-memory sync server cursor")?;
    Ok(cursor.map(format_user_memory_sync_cursor))
}

fn format_user_memory_sync_cursor(cursor: i64) -> String {
    format!("{USER_MEMORY_SYNC_CURSOR_PREFIX}{cursor}")
}

fn parse_user_memory_sync_cursor(cursor: Option<&str>) -> Result<Option<i64>> {
    let Some(cursor) = cursor.and_then(nonempty_trimmed) else {
        return Ok(None);
    };
    let numeric = cursor
        .strip_prefix(USER_MEMORY_SYNC_CURSOR_PREFIX)
        .unwrap_or(cursor);
    let parsed = numeric
        .parse::<i64>()
        .with_context(|| format!("invalid user-memory sync cursor: {cursor}"))?;
    if parsed < 0 {
        return Err(anyhow!("user-memory sync cursor must be non-negative"));
    }
    Ok(Some(parsed))
}

fn row_to_server_event(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<UserMemorySyncServerStoredEvent> {
    let cursor = row.get::<_, i64>(0)?;
    let bundle_id = row.get::<_, String>(1)?;
    let device_id = row.get::<_, String>(2)?;
    let event_id = row.get::<_, String>(3)?;
    let lane_name = row.get::<_, String>(4)?;
    let operation_name = row.get::<_, String>(5)?;
    let object_id = row.get::<_, String>(6)?;
    let object_version = row.get::<_, Option<String>>(7)?;
    let content_hash = row.get::<_, String>(8)?;
    let sensitivity_name = row.get::<_, String>(9)?;
    let payload_kind = row.get::<_, String>(10)?;
    let payload_summary_json = row.get::<_, String>(11)?;
    let payload_envelope_json = row.get::<_, Option<String>>(12)?;
    let provenance_json = row.get::<_, String>(13)?;
    let received_at_ms = row.get::<_, i64>(14)?;
    let lane = UserMemorySyncLane::from_str(&lane_name).map_err(|err| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(err))
    })?;
    let operation = UserMemorySyncOperation::from_name(&operation_name).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            5,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported user-memory sync operation: {operation_name}"),
            )),
        )
    })?;
    let sensitivity = UserMemorySyncSensitivity::from_name(&sensitivity_name).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            9,
            rusqlite::types::Type::Text,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported user-memory sync sensitivity: {sensitivity_name}"),
            )),
        )
    })?;
    let payload_summary = serde_json::from_str::<BTreeMap<String, Value>>(&payload_summary_json)
        .map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                11,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })?;
    let payload_envelope = match payload_envelope_json.as_deref() {
        Some(value) => Some(
            serde_json::from_str::<UserMemorySyncPayloadEnvelope>(value).map_err(|err| {
                rusqlite::Error::FromSqlConversionFailure(
                    12,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                )
            })?,
        ),
        None => None,
    };
    let provenance =
        serde_json::from_str::<UserMemorySyncProvenance>(&provenance_json).map_err(|err| {
            rusqlite::Error::FromSqlConversionFailure(
                13,
                rusqlite::types::Type::Text,
                Box::new(err),
            )
        })?;
    Ok(UserMemorySyncServerStoredEvent {
        cursor: format_user_memory_sync_cursor(cursor),
        bundle_id,
        device_id,
        received_at_ms,
        event: UserMemorySyncEvent {
            event_id,
            lane,
            operation,
            object_id,
            object_version,
            content_hash,
            sensitivity,
            payload_kind,
            payload_summary,
            payload_envelope,
            provenance,
        },
    })
}

fn normalize_lane_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| match ch {
            '-' | ' ' | '/' | '.' => '_',
            _ => ch,
        })
        .collect()
}

fn configured_user_memory_sync_identity(source: &str, api_key: &str) -> UserMemorySyncIdentity {
    UserMemorySyncIdentity {
        source: source.to_string(),
        configured: true,
        credential_fingerprint: user_memory_sync_credential_fingerprint(api_key),
        principal_resolution: USER_MEMORY_SYNC_PRINCIPAL_RESOLUTION_MSWARM_INTROSPECTION
            .to_string(),
        raw_credential_returned: false,
    }
}

fn nonempty_trimmed(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

fn nonempty_owned(value: String) -> Option<String> {
    let value = value.trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_event(
        object_id: &str,
        object_version: Option<&str>,
        content: Value,
    ) -> UserMemorySyncEvent {
        let content_hash = stable_content_hash(&content).unwrap();
        let operation = UserMemorySyncOperation::Upsert;
        let event_id = stable_event_id(
            UserMemorySyncLane::ProfileMemory,
            operation,
            object_id,
            object_version,
            &content_hash,
        );
        UserMemorySyncEvent {
            event_id,
            lane: UserMemorySyncLane::ProfileMemory,
            operation,
            object_id: object_id.to_string(),
            object_version: object_version.map(ToOwned::to_owned),
            content_hash,
            sensitivity: UserMemorySyncSensitivity::Normal,
            payload_kind: "profile_preference".to_string(),
            payload_summary: BTreeMap::new(),
            payload_envelope: None,
            provenance: UserMemorySyncProvenance {
                source_device_id: "test-device".to_string(),
                source_store: "profile_memory".to_string(),
                source_record_id: object_id.to_string(),
                repo_id: None,
            },
        }
    }

    fn test_encrypted_envelope() -> UserMemorySyncPayloadEnvelope {
        UserMemorySyncPayloadEnvelope::encrypted(
            "AES-256-GCM",
            "local-device-key:v1",
            "bm9uY2U=",
            "Y2lwaGVydGV4dA==",
            "sha256:0123456789abcdef",
        )
    }

    #[test]
    fn lane_parser_accepts_common_aliases() {
        assert_eq!(
            UserMemorySyncLane::from_str("profile").unwrap(),
            UserMemorySyncLane::ProfileMemory
        );
        assert_eq!(
            UserMemorySyncLane::from_str("generated-skills").unwrap(),
            UserMemorySyncLane::GeneratedSkills
        );
        assert_eq!(
            UserMemorySyncLane::from_str("temporal kg").unwrap(),
            UserMemorySyncLane::TemporalKg
        );
    }

    #[test]
    fn policy_matrix_keeps_sync_opt_in_and_excludes_sensitive_local_data() {
        let policy = user_memory_sync_policy_matrix();
        assert!(policy.sync_by_default.is_empty());
        assert!(policy
            .excluded_local_data
            .iter()
            .any(|item| item.local_data == "secrets_and_raw_api_keys"
                && item.default_policy == "never_sync"));
        assert!(policy
            .excluded_local_data
            .iter()
            .any(|item| item.local_data == "raw_conversation_transcripts"));
    }

    #[test]
    fn identity_uses_mswarm_api_key_without_returning_raw_secret() {
        let identity = user_memory_sync_identity_from_config(Some(" mswarm-key "), None);
        assert_eq!(
            identity.source,
            USER_MEMORY_SYNC_IDENTITY_SOURCE_MSWARM_API_KEY
        );
        assert!(identity.configured);
        assert_eq!(
            identity.principal_resolution,
            USER_MEMORY_SYNC_PRINCIPAL_RESOLUTION_MSWARM_INTROSPECTION
        );
        assert!(!identity.raw_credential_returned);
        assert!(identity
            .credential_fingerprint
            .as_deref()
            .is_some_and(|value| value.starts_with("sha256:")));
        assert_ne!(
            identity.credential_fingerprint.as_deref(),
            Some("mswarm-key")
        );
    }

    #[test]
    fn stable_event_ids_change_with_content_hash() {
        let first = test_event(
            "pref-1",
            Some("100"),
            json!({"agent_id":"codex","category":"workflow","content":"first"}),
        );
        let same = test_event(
            "pref-1",
            Some("100"),
            json!({"agent_id":"codex","category":"workflow","content":"first"}),
        );
        let changed = test_event(
            "pref-1",
            Some("101"),
            json!({"agent_id":"codex","category":"workflow","content":"second"}),
        );
        assert_eq!(first.event_id, same.event_id);
        assert_eq!(first.content_hash, same.content_hash);
        assert_ne!(first.event_id, changed.event_id);
        assert_ne!(first.content_hash, changed.content_hash);
    }

    #[test]
    fn payload_envelope_validation_rejects_cleartext_and_accepts_encrypted() {
        assert!(validate_user_memory_sync_payload_envelope(None).is_ok());
        assert!(validate_user_memory_sync_payload_envelope(Some(
            &UserMemorySyncPayloadEnvelope::summary_only()
        ))
        .is_ok());
        assert!(
            validate_user_memory_sync_payload_envelope(Some(&test_encrypted_envelope())).is_ok()
        );

        let cleartext = UserMemorySyncPayloadEnvelope {
            mode: USER_MEMORY_SYNC_PAYLOAD_MODE_CLEARTEXT.to_string(),
            algorithm: None,
            key_id: None,
            nonce_b64: None,
            ciphertext_b64: Some("not encrypted".to_string()),
            aad_b64: None,
            payload_hash: None,
        };
        let cleartext_error =
            validate_user_memory_sync_payload_envelope(Some(&cleartext)).unwrap_err();
        assert!(cleartext_error.to_string().contains("cleartext"));

        let malformed = UserMemorySyncPayloadEnvelope {
            ciphertext_b64: None,
            ..test_encrypted_envelope()
        };
        let malformed_error =
            validate_user_memory_sync_payload_envelope(Some(&malformed)).unwrap_err();
        assert!(malformed_error.to_string().contains("ciphertext_b64"));
    }

    #[test]
    fn payload_envelope_encryption_emits_opaque_aes_gcm_fields() {
        let key = UserMemorySyncPayloadEncryptionKey {
            key_id: "sha256:test-key".to_string(),
            key_bytes: [7; USER_MEMORY_SYNC_PAYLOAD_KEY_LEN],
        };
        let payload = json!({
            "schema_version": USER_MEMORY_SYNC_SCHEMA_VERSION,
            "kind": "profile_preference",
            "content": "sensitive local preference",
        });
        let envelope = encrypt_user_memory_sync_payload_envelope(
            &key,
            UserMemorySyncLane::ProfileMemory,
            UserMemorySyncOperation::Upsert,
            "pref-1",
            Some("100"),
            "profile_preference",
            &payload,
        )
        .unwrap();

        assert_eq!(envelope.mode, USER_MEMORY_SYNC_PAYLOAD_MODE_ENCRYPTED);
        assert_eq!(
            envelope.algorithm.as_deref(),
            Some(USER_MEMORY_SYNC_PAYLOAD_ENCRYPTION_ALGORITHM)
        );
        assert_eq!(envelope.key_id.as_deref(), Some("sha256:test-key"));
        assert_eq!(
            envelope.payload_hash,
            Some(stable_content_hash(&payload).unwrap())
        );
        assert_eq!(
            Base64Engine
                .decode(envelope.nonce_b64.as_deref().unwrap())
                .unwrap()
                .len(),
            12
        );
        assert!(!envelope
            .ciphertext_b64
            .as_deref()
            .unwrap()
            .contains("sensitive local preference"));
        assert!(envelope
            .aad_b64
            .as_deref()
            .is_some_and(|value| !value.is_empty()));
        validate_user_memory_sync_payload_envelope(Some(&envelope)).unwrap();
    }

    #[test]
    fn payload_envelope_decrypts_only_with_matching_event_identity() {
        let key = UserMemorySyncPayloadEncryptionKey {
            key_id: "sha256:test-key".to_string(),
            key_bytes: [9; USER_MEMORY_SYNC_PAYLOAD_KEY_LEN],
        };
        let payload = json!({
            "schema_version": USER_MEMORY_SYNC_SCHEMA_VERSION,
            "kind": "profile_preference",
            "content": "portable local preference",
        });
        let envelope = encrypt_user_memory_sync_payload_envelope(
            &key,
            UserMemorySyncLane::ProfileMemory,
            UserMemorySyncOperation::Upsert,
            "pref-1",
            Some("100"),
            "profile_preference",
            &payload,
        )
        .unwrap();
        let decrypted: Value = decrypt_user_memory_sync_payload_envelope(
            &key,
            UserMemorySyncLane::ProfileMemory,
            UserMemorySyncOperation::Upsert,
            "pref-1",
            Some("100"),
            "profile_preference",
            &envelope,
        )
        .unwrap();
        assert_eq!(decrypted, payload);

        let wrong_identity = decrypt_user_memory_sync_payload_envelope::<Value>(
            &key,
            UserMemorySyncLane::ProfileMemory,
            UserMemorySyncOperation::Upsert,
            "pref-2",
            Some("100"),
            "profile_preference",
            &envelope,
        )
        .unwrap_err();
        assert!(wrong_identity.to_string().contains("aad"));
    }

    #[test]
    fn bundle_id_is_stable_for_same_ordered_events() {
        let events = vec![
            test_event("pref-1", Some("100"), json!({"content":"first"})),
            test_event("pref-2", Some("101"), json!({"content":"second"})),
        ];
        let first = UserMemorySyncBundle::new(
            "test-device".to_string(),
            Some("cursor-1".to_string()),
            123,
            vec![UserMemorySyncLane::ProfileMemory],
            events.clone(),
        );
        let same = UserMemorySyncBundle::new(
            "test-device".to_string(),
            Some("cursor-1".to_string()),
            456,
            vec![UserMemorySyncLane::ProfileMemory],
            events.clone(),
        );
        let different = UserMemorySyncBundle::new(
            "test-device".to_string(),
            Some("cursor-2".to_string()),
            456,
            vec![UserMemorySyncLane::ProfileMemory],
            events,
        );
        assert_eq!(first.bundle_id, same.bundle_id);
        assert_ne!(first.created_at_ms, same.created_at_ms);
        assert_ne!(first.bundle_id, different.bundle_id);
    }

    #[test]
    fn ledger_records_uploaded_and_acked_events() {
        let temp = tempfile::tempdir().unwrap();
        let path = UserMemorySyncLedger::path_for_state_dir(temp.path());
        let event = test_event("pref-1", Some("100"), json!({"content":"first"}));
        let missing = UserMemorySyncLedger::snapshot_for_events_read_only(&path, &[event.clone()])
            .expect("missing ledger snapshot");
        assert!(!missing.exists);
        assert_eq!(missing.known_events, 0);
        assert_eq!(missing.unknown_events, 1);

        let ledger = UserMemorySyncLedger::open_or_create(&path).unwrap();
        assert_eq!(ledger.path(), path.as_path());
        assert_eq!(ledger.record_uploaded(&[event.clone()], 1000).unwrap(), 1);

        let uploaded = UserMemorySyncLedger::snapshot_for_events_read_only(&path, &[event.clone()])
            .expect("uploaded ledger snapshot");
        assert!(uploaded.exists);
        assert_eq!(uploaded.known_events, 1);
        assert_eq!(uploaded.uploaded_events, 1);
        assert_eq!(uploaded.acked_events, 0);

        assert_eq!(
            ledger
                .record_acked(&[event.event_id.clone()], 2000)
                .unwrap(),
            1
        );
        let acked = UserMemorySyncLedger::snapshot_for_events_read_only(&path, &[event]).unwrap();
        assert_eq!(acked.known_events, 1);
        assert_eq!(acked.uploaded_events, 1);
        assert_eq!(acked.acked_events, 1);
    }

    #[test]
    fn ledger_records_applied_and_skipped_feed_events() {
        let temp = tempfile::tempdir().unwrap();
        let path = UserMemorySyncLedger::path_for_state_dir(temp.path());
        let ledger = UserMemorySyncLedger::open_or_create(&path).unwrap();
        let applied = test_event("pref-1", Some("100"), json!({"content":"first"}));
        let skipped = test_event("pref-2", Some("100"), json!({"content":"second"}));
        let applied_stored = UserMemorySyncServerStoredEvent {
            cursor: "cursor_1".to_string(),
            bundle_id: "bundle-a".to_string(),
            device_id: "remote-device".to_string(),
            received_at_ms: 1000,
            event: applied.clone(),
        };
        let skipped_stored = UserMemorySyncServerStoredEvent {
            cursor: "cursor_2".to_string(),
            bundle_id: "bundle-a".to_string(),
            device_id: "remote-device".to_string(),
            received_at_ms: 1000,
            event: skipped.clone(),
        };
        assert_eq!(ledger.record_applied(&[applied_stored], 2000).unwrap(), 1);
        assert_eq!(ledger.record_skipped(&[skipped_stored], 2100).unwrap(), 1);

        let snapshot =
            UserMemorySyncLedger::snapshot_for_events_read_only(&path, &[applied, skipped])
                .unwrap();
        assert_eq!(snapshot.known_events, 2);
        assert_eq!(snapshot.applied_events, 1);
        assert_eq!(snapshot.skipped_events, 1);
        assert_eq!(snapshot.uploaded_events, 0);
        assert_eq!(snapshot.acked_events, 0);
    }

    #[test]
    fn server_store_registers_pushes_feeds_and_acks_events() {
        let temp = tempfile::tempdir().unwrap();
        let path = UserMemorySyncServerStore::path_for_state_dir(temp.path());
        let store = UserMemorySyncServerStore::open_or_create(&path).unwrap();
        let device = store
            .register_device(
                "sha256:user-a",
                "test-device",
                Some("Test Device".to_string()),
                vec![UserMemorySyncLane::ProfileMemory],
                1000,
            )
            .unwrap();
        assert_eq!(device.device_id, "test-device");
        assert_eq!(
            device.enabled_lanes,
            vec![UserMemorySyncLane::ProfileMemory]
        );

        let mut event = test_event("pref-1", Some("100"), json!({"content":"first"}));
        event.payload_envelope = Some(test_encrypted_envelope());
        let bundle = UserMemorySyncBundle::new(
            "test-device".to_string(),
            None,
            1100,
            vec![UserMemorySyncLane::ProfileMemory],
            vec![event.clone()],
        );
        let pushed = store.push_bundle("sha256:user-a", &bundle, 1200).unwrap();
        assert_eq!(pushed.accepted_event_ids, vec![event.event_id.clone()]);
        assert!(pushed.duplicate_event_ids.is_empty());
        assert_eq!(pushed.next_cursor.as_deref(), Some("cursor_1"));

        let duplicate = store.push_bundle("sha256:user-a", &bundle, 1300).unwrap();
        assert!(duplicate.accepted_event_ids.is_empty());
        assert_eq!(duplicate.duplicate_event_ids, vec![event.event_id.clone()]);

        let feed = store
            .feed(
                "sha256:user-a",
                None,
                &[UserMemorySyncLane::ProfileMemory],
                10,
                None,
            )
            .unwrap();
        assert_eq!(feed.events.len(), 1);
        assert_eq!(feed.next_cursor.as_deref(), Some("cursor_1"));
        assert_eq!(feed.events[0].event.event_id, event.event_id);
        let fed_envelope = feed.events[0].event.payload_envelope.as_ref().unwrap();
        assert_eq!(fed_envelope.mode, USER_MEMORY_SYNC_PAYLOAD_MODE_ENCRYPTED);
        assert_eq!(
            fed_envelope.ciphertext_b64.as_deref(),
            Some("Y2lwaGVydGV4dA==")
        );

        let excluded = store
            .feed(
                "sha256:user-a",
                None,
                &[UserMemorySyncLane::ProfileMemory],
                10,
                Some("test-device"),
            )
            .unwrap();
        assert!(excluded.events.is_empty());

        let ack = store
            .ack(
                "sha256:user-a",
                "second-device",
                &[event.event_id.clone(), "missing".to_string()],
                feed.next_cursor,
                1400,
            )
            .unwrap();
        assert_eq!(ack.acked_event_ids, vec![event.event_id]);
        assert_eq!(ack.unknown_event_ids, vec!["missing".to_string()]);
    }

    #[test]
    fn server_store_rejects_cleartext_payload_envelopes() {
        let temp = tempfile::tempdir().unwrap();
        let path = UserMemorySyncServerStore::path_for_state_dir(temp.path());
        let store = UserMemorySyncServerStore::open_or_create(&path).unwrap();
        let mut event = test_event("pref-1", Some("100"), json!({"content":"first"}));
        event.payload_envelope = Some(UserMemorySyncPayloadEnvelope {
            mode: USER_MEMORY_SYNC_PAYLOAD_MODE_CLEARTEXT.to_string(),
            algorithm: None,
            key_id: None,
            nonce_b64: None,
            ciphertext_b64: Some("raw json would go here".to_string()),
            aad_b64: None,
            payload_hash: None,
        });
        let bundle = UserMemorySyncBundle::new(
            "test-device".to_string(),
            None,
            1100,
            vec![UserMemorySyncLane::ProfileMemory],
            vec![event.clone()],
        );
        let pushed = store.push_bundle("sha256:user-a", &bundle, 1200).unwrap();
        assert!(pushed.accepted_event_ids.is_empty());
        assert_eq!(pushed.rejected_events.len(), 1);
        assert_eq!(pushed.rejected_events[0].event_id, event.event_id);
        assert!(pushed.rejected_events[0].reason.contains("cleartext"));

        let feed = store.feed("sha256:user-a", None, &[], 10, None).unwrap();
        assert!(feed.events.is_empty());
    }

    #[test]
    fn server_store_isolates_principals() {
        let temp = tempfile::tempdir().unwrap();
        let path = UserMemorySyncServerStore::path_for_state_dir(temp.path());
        let store = UserMemorySyncServerStore::open_or_create(&path).unwrap();
        let event = test_event("pref-1", Some("100"), json!({"content":"first"}));
        let bundle = UserMemorySyncBundle::new(
            "test-device".to_string(),
            None,
            1100,
            vec![UserMemorySyncLane::ProfileMemory],
            vec![event],
        );
        store.push_bundle("sha256:user-a", &bundle, 1200).unwrap();

        let visible = store.feed("sha256:user-a", None, &[], 10, None).unwrap();
        let isolated = store.feed("sha256:user-b", None, &[], 10, None).unwrap();
        assert_eq!(visible.events.len(), 1);
        assert!(isolated.events.is_empty());

        let snapshot_a =
            UserMemorySyncServerStore::snapshot_read_only(&path, "sha256:user-a").unwrap();
        let snapshot_b =
            UserMemorySyncServerStore::snapshot_read_only(&path, "sha256:user-b").unwrap();
        assert_eq!(snapshot_a.events, 1);
        assert_eq!(snapshot_b.events, 0);
    }
}
