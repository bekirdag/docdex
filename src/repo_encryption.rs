use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const DEFAULT_REPO_ENCRYPTION_MAX_RESULTS_PER_QUERY: usize = 10;
pub const DEFAULT_REPO_ENCRYPTION_MAX_SNIPPET_CHARS: usize = 320;
pub const DEFAULT_REPO_ENCRYPTION_KEY_ENV: &str = "DOCDEX_REPO_ENCRYPTION_KEY";
pub const REPO_ENCRYPTION_PREFIX: &str = "docdex-repo-enc:v1:";
const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoEncryptionMode {
    Disabled,
    ApplicationManagedEncryption,
}

impl Default for RepoEncryptionMode {
    fn default() -> Self {
        Self::Disabled
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoEncryptionConfig {
    #[serde(default)]
    pub encryption_mode: RepoEncryptionMode,
    #[serde(default)]
    pub key_env: Option<String>,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub shared_bearer_token_sufficient: bool,
    #[serde(default)]
    pub semantic_search_enabled: bool,
    #[serde(default)]
    pub web_discovery_enabled: bool,
    #[serde(default)]
    pub full_file_open_enabled: bool,
    #[serde(default = "default_repo_encryption_plaintext_term_index_enabled")]
    pub plaintext_term_index_enabled: bool,
    #[serde(default = "default_repo_encryption_max_results_per_query")]
    pub max_results_per_query: usize,
    #[serde(default = "default_repo_encryption_max_snippet_chars")]
    pub max_snippet_chars: usize,
}

impl Default for RepoEncryptionConfig {
    fn default() -> Self {
        Self {
            encryption_mode: RepoEncryptionMode::Disabled,
            key_env: None,
            key_id: None,
            shared_bearer_token_sufficient: false,
            semantic_search_enabled: false,
            web_discovery_enabled: false,
            full_file_open_enabled: false,
            plaintext_term_index_enabled: default_repo_encryption_plaintext_term_index_enabled(),
            max_results_per_query: default_repo_encryption_max_results_per_query(),
            max_snippet_chars: default_repo_encryption_max_snippet_chars(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoEncryptionCapabilities {
    pub supported: bool,
    pub enabled: bool,
    pub encryption_mode: RepoEncryptionMode,
    pub effective_encryption_mode: RepoEncryptionMode,
    pub key_status: RepoEncryptionKeyStatus,
    pub key_id: Option<String>,
    pub index_protection_status: RepoEncryptionIndexProtectionStatus,
    pub source_storage_status: RepoEncryptionSourceStorageStatus,
    pub residual_leakage: Vec<String>,
    pub operations: RepoEncryptionOperationCapabilities,
    pub access_checks_required: bool,
    pub shared_bearer_token_sufficient: bool,
    pub audit_required: bool,
    pub repository_isolation_required: bool,
    pub supported_encryption_modes: Vec<RepoEncryptionMode>,
    pub semantic_search_enabled: bool,
    pub web_discovery_enabled: bool,
    pub full_file_open_enabled: bool,
    pub plaintext_term_index_enabled: bool,
    pub max_results_per_query: usize,
    pub max_snippet_chars: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoEncryptionKeyStatus {
    NotRequired,
    Available,
    MissingKeyMaterial,
    InvalidKeyMaterial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoEncryptionIndexProtectionStatus {
    NotApplicable,
    PlaintextStoredFields,
    EncryptedStoredFieldsPlaintextTerms,
    SearchDisabled,
    MissingKeyMaterial,
    InvalidKeyMaterial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoEncryptionSourceStorageStatus {
    NotApplicable,
    CallerManaged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RepoEncryptionOperationStatus {
    Available,
    Disabled,
    BlockedMissingKey,
    BlockedInvalidKey,
    Unsupported,
}

#[derive(Debug, Clone, Serialize)]
pub struct RepoEncryptionOperationCapabilities {
    pub index: RepoEncryptionOperationStatus,
    pub search: RepoEncryptionOperationStatus,
    pub snippet: RepoEncryptionOperationStatus,
    pub open: RepoEncryptionOperationStatus,
    pub semantic_search: RepoEncryptionOperationStatus,
    pub web_discovery: RepoEncryptionOperationStatus,
    pub symbols: RepoEncryptionOperationStatus,
    pub ast: RepoEncryptionOperationStatus,
    pub impact_graph: RepoEncryptionOperationStatus,
    pub key_rotation: RepoEncryptionOperationStatus,
    pub backup_restore: RepoEncryptionOperationStatus,
}

#[derive(Debug, Clone)]
pub struct ResolvedRepoEncryptionKey {
    pub key_id: String,
    key_bytes: [u8; KEY_LEN],
}

impl RepoEncryptionCapabilities {
    pub fn from_config(config: &RepoEncryptionConfig) -> Self {
        let enabled = config.is_enabled();
        let key_resolution = config.resolve_key();
        let (key_status, key_id) = match &key_resolution {
            Ok(Some(key)) => (RepoEncryptionKeyStatus::Available, Some(key.key_id.clone())),
            Ok(None) => (RepoEncryptionKeyStatus::NotRequired, None),
            Err(RepoEncryptionKeyError::MissingKeyMaterial) => {
                (RepoEncryptionKeyStatus::MissingKeyMaterial, None)
            }
            Err(RepoEncryptionKeyError::InvalidKeyMaterial) => {
                (RepoEncryptionKeyStatus::InvalidKeyMaterial, None)
            }
        };
        let operation_status = encryption_operation_status(enabled, key_status);
        let index_protection_status = if !enabled {
            RepoEncryptionIndexProtectionStatus::NotApplicable
        } else {
            match key_status {
                RepoEncryptionKeyStatus::Available if config.plaintext_term_index_enabled => {
                    RepoEncryptionIndexProtectionStatus::EncryptedStoredFieldsPlaintextTerms
                }
                RepoEncryptionKeyStatus::Available => {
                    RepoEncryptionIndexProtectionStatus::SearchDisabled
                }
                RepoEncryptionKeyStatus::MissingKeyMaterial => {
                    RepoEncryptionIndexProtectionStatus::MissingKeyMaterial
                }
                RepoEncryptionKeyStatus::InvalidKeyMaterial => {
                    RepoEncryptionIndexProtectionStatus::InvalidKeyMaterial
                }
                RepoEncryptionKeyStatus::NotRequired => {
                    RepoEncryptionIndexProtectionStatus::PlaintextStoredFields
                }
            }
        };
        let residual_leakage = if enabled && config.plaintext_term_index_enabled {
            vec![
                "lexical index terms can reveal term presence".to_string(),
                "document paths and token counts remain stored for retrieval".to_string(),
            ]
        } else {
            Vec::new()
        };
        Self {
            supported: true,
            enabled,
            encryption_mode: config.encryption_mode,
            effective_encryption_mode: config.encryption_mode,
            key_status,
            key_id,
            index_protection_status,
            source_storage_status: if enabled {
                RepoEncryptionSourceStorageStatus::CallerManaged
            } else {
                RepoEncryptionSourceStorageStatus::NotApplicable
            },
            residual_leakage,
            operations: RepoEncryptionOperationCapabilities {
                index: operation_status,
                search: if enabled && !config.plaintext_term_index_enabled {
                    RepoEncryptionOperationStatus::Disabled
                } else {
                    operation_status
                },
                snippet: operation_status,
                open: if enabled && config.full_file_open_enabled {
                    operation_status
                } else if enabled {
                    RepoEncryptionOperationStatus::Disabled
                } else {
                    operation_status
                },
                semantic_search: if enabled && config.semantic_search_enabled {
                    operation_status
                } else {
                    RepoEncryptionOperationStatus::Disabled
                },
                web_discovery: if enabled && config.web_discovery_enabled {
                    operation_status
                } else {
                    RepoEncryptionOperationStatus::Disabled
                },
                symbols: if enabled {
                    RepoEncryptionOperationStatus::Disabled
                } else {
                    RepoEncryptionOperationStatus::Available
                },
                ast: if enabled {
                    RepoEncryptionOperationStatus::Disabled
                } else {
                    RepoEncryptionOperationStatus::Available
                },
                impact_graph: if enabled {
                    RepoEncryptionOperationStatus::Disabled
                } else {
                    RepoEncryptionOperationStatus::Available
                },
                key_rotation: RepoEncryptionOperationStatus::Unsupported,
                backup_restore: RepoEncryptionOperationStatus::Unsupported,
            },
            access_checks_required: enabled,
            shared_bearer_token_sufficient: config.shared_bearer_token_sufficient && !enabled,
            audit_required: enabled,
            repository_isolation_required: enabled,
            supported_encryption_modes: supported_encryption_modes(),
            semantic_search_enabled: config.semantic_search_enabled,
            web_discovery_enabled: config.web_discovery_enabled,
            full_file_open_enabled: config.full_file_open_enabled,
            plaintext_term_index_enabled: config.plaintext_term_index_enabled,
            max_results_per_query: config.max_results_per_query,
            max_snippet_chars: config.max_snippet_chars,
        }
    }
}

pub fn supported_encryption_modes() -> Vec<RepoEncryptionMode> {
    vec![
        RepoEncryptionMode::Disabled,
        RepoEncryptionMode::ApplicationManagedEncryption,
    ]
}

pub fn default_repo_encryption_max_results_per_query() -> usize {
    DEFAULT_REPO_ENCRYPTION_MAX_RESULTS_PER_QUERY
}

pub fn default_repo_encryption_max_snippet_chars() -> usize {
    DEFAULT_REPO_ENCRYPTION_MAX_SNIPPET_CHARS
}

pub fn default_repo_encryption_plaintext_term_index_enabled() -> bool {
    true
}

impl RepoEncryptionConfig {
    pub fn is_enabled(&self) -> bool {
        self.encryption_mode != RepoEncryptionMode::Disabled
    }

    pub fn apply_defaults(&mut self) {
        self.key_env = self
            .key_env
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        self.key_id = self
            .key_id
            .take()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        if self.max_results_per_query == 0 {
            self.max_results_per_query = default_repo_encryption_max_results_per_query();
        }
        if self.max_snippet_chars == 0 {
            self.max_snippet_chars = default_repo_encryption_max_snippet_chars();
        }
        if self.is_enabled() {
            self.shared_bearer_token_sufficient = false;
        }
    }

    pub fn key_env_name(&self) -> Option<&str> {
        if !self.is_enabled() {
            return None;
        }
        Some(
            self.key_env
                .as_deref()
                .unwrap_or(DEFAULT_REPO_ENCRYPTION_KEY_ENV),
        )
    }

    pub fn resolve_key(
        &self,
    ) -> std::result::Result<Option<ResolvedRepoEncryptionKey>, RepoEncryptionKeyError> {
        let Some(env_name) = self.key_env_name() else {
            return Ok(None);
        };
        let raw = std::env::var(env_name)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or(RepoEncryptionKeyError::MissingKeyMaterial)?;
        let key_bytes =
            decode_key_material(&raw).map_err(|_| RepoEncryptionKeyError::InvalidKeyMaterial)?;
        let key_id = self
            .key_id
            .clone()
            .unwrap_or_else(|| derived_key_id(&key_bytes));
        Ok(Some(ResolvedRepoEncryptionKey { key_id, key_bytes }))
    }

    pub fn require_key(&self) -> Result<ResolvedRepoEncryptionKey> {
        match self.resolve_key() {
            Ok(Some(key)) => Ok(key),
            Ok(None) => Err(anyhow!("repository encryption key is not required")),
            Err(RepoEncryptionKeyError::MissingKeyMaterial) => Err(crate::error::AppError::new(
                crate::error::ERR_REPO_ENCRYPTION_KEY_UNAVAILABLE,
                "repository encryption key material is required but unavailable",
            )
            .into()),
            Err(RepoEncryptionKeyError::InvalidKeyMaterial) => Err(crate::error::AppError::new(
                crate::error::ERR_REPO_ENCRYPTION_KEY_INVALID,
                "repository encryption key material is invalid",
            )
            .into()),
        }
    }

    pub fn protect_text(
        &self,
        key: &ResolvedRepoEncryptionKey,
        domain_id: &str,
        rel_path: &str,
        purpose: &str,
        text: &str,
    ) -> Result<String> {
        encrypt_repo_text(key, domain_id, rel_path, purpose, text)
    }

    pub fn unprotect_text(
        &self,
        key: &ResolvedRepoEncryptionKey,
        domain_id: &str,
        rel_path: &str,
        purpose: &str,
        text: &str,
    ) -> Result<String> {
        decrypt_repo_text(key, domain_id, rel_path, purpose, text)
    }
}

pub fn parse_repo_encryption_mode(raw: &str) -> Option<RepoEncryptionMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "disabled" | "off" | "none" => Some(RepoEncryptionMode::Disabled),
        "application_managed_encryption" | "application-managed-encryption" => {
            Some(RepoEncryptionMode::ApplicationManagedEncryption)
        }
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoEncryptionKeyError {
    MissingKeyMaterial,
    InvalidKeyMaterial,
}

fn encryption_operation_status(
    enabled: bool,
    key_status: RepoEncryptionKeyStatus,
) -> RepoEncryptionOperationStatus {
    if !enabled {
        return RepoEncryptionOperationStatus::Available;
    }
    match key_status {
        RepoEncryptionKeyStatus::Available => RepoEncryptionOperationStatus::Available,
        RepoEncryptionKeyStatus::MissingKeyMaterial => {
            RepoEncryptionOperationStatus::BlockedMissingKey
        }
        RepoEncryptionKeyStatus::InvalidKeyMaterial => {
            RepoEncryptionOperationStatus::BlockedInvalidKey
        }
        RepoEncryptionKeyStatus::NotRequired => RepoEncryptionOperationStatus::Unsupported,
    }
}

fn decode_key_material(raw: &str) -> Result<[u8; KEY_LEN]> {
    let value = raw.trim();
    let decoded = if let Some(rest) = value.strip_prefix("base64:") {
        Base64Engine
            .decode(rest.trim())
            .context("decode base64 repository key")?
    } else if let Some(rest) = value.strip_prefix("hex:") {
        hex::decode(rest.trim()).context("decode hex repository key")?
    } else if value.len() == KEY_LEN * 2 && value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        hex::decode(value).context("decode hex repository key")?
    } else if value.as_bytes().len() == KEY_LEN {
        value.as_bytes().to_vec()
    } else {
        Base64Engine
            .decode(value)
            .context("decode base64 repository key")?
    };
    decoded.try_into().map_err(|bytes: Vec<u8>| {
        anyhow!(
            "repository encryption key must be {KEY_LEN} bytes, got {}",
            bytes.len()
        )
    })
}

fn derived_key_id(key_bytes: &[u8; KEY_LEN]) -> String {
    let digest = Sha256::digest(key_bytes);
    hex::encode(&digest[..8])
}

pub fn repo_encryption_domain_id(repo_root: &std::path::Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(repo_root.to_string_lossy().as_bytes());
    hex::encode(hasher.finalize())
}

fn encryption_aad(domain_id: &str, rel_path: &str, purpose: &str, key_id: &str) -> String {
    format!("docdex-repo-encryption:v1:{domain_id}:{rel_path}:{purpose}:{key_id}")
}

fn encrypt_repo_text(
    key: &ResolvedRepoEncryptionKey,
    domain_id: &str,
    rel_path: &str,
    purpose: &str,
    text: &str,
) -> Result<String> {
    let aes = Aes256Gcm::new_from_slice(&key.key_bytes).context("initialize repository cipher")?;
    let nonce_seed = Uuid::new_v4().into_bytes();
    let nonce = Nonce::from_slice(&nonce_seed[..12]);
    let aad = encryption_aad(domain_id, rel_path, purpose, &key.key_id);
    let ciphertext = aes
        .encrypt(
            nonce,
            Payload {
                msg: text.as_bytes(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|err| anyhow!("encrypt repository text: {err}"))?;
    Ok(format!(
        "{REPO_ENCRYPTION_PREFIX}{}:{}:{}",
        key.key_id,
        Base64Engine.encode(&nonce_seed[..12]),
        Base64Engine.encode(ciphertext)
    ))
}

fn decrypt_repo_text(
    key: &ResolvedRepoEncryptionKey,
    domain_id: &str,
    rel_path: &str,
    purpose: &str,
    text: &str,
) -> Result<String> {
    let payload = text
        .strip_prefix(REPO_ENCRYPTION_PREFIX)
        .ok_or_else(|| anyhow!("missing repository encrypted prefix"))?;
    let mut parts = payload.splitn(3, ':');
    let key_id = parts.next().unwrap_or_default();
    let nonce_b64 = parts.next().unwrap_or_default();
    let ciphertext_b64 = parts.next().unwrap_or_default();
    if key_id != key.key_id {
        return Err(crate::error::AppError::new(
            crate::error::ERR_REPO_ENCRYPTION_KEY_INVALID,
            "repository encryption key material cannot decrypt this artifact",
        )
        .into());
    }
    let nonce_bytes = Base64Engine
        .decode(nonce_b64)
        .context("decode repository content nonce")?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!("invalid repository content nonce length"));
    }
    let ciphertext = Base64Engine
        .decode(ciphertext_b64)
        .context("decode repository encrypted content")?;
    let aes = Aes256Gcm::new_from_slice(&key.key_bytes).context("initialize repository cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let aad = encryption_aad(domain_id, rel_path, purpose, &key.key_id);
    let plaintext = aes
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext.as_ref(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| {
            crate::error::AppError::new(
                crate::error::ERR_REPO_ENCRYPTION_KEY_INVALID,
                "repository encryption key material cannot decrypt this artifact",
            )
        })?;
    String::from_utf8(plaintext).context("decode repository plaintext")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;

    const TEST_KEY: &str = "01234567890123456789012345678901";
    const OTHER_TEST_KEY: &str = "abcdefghijklmnopqrstuvwxyz123456";

    #[test]
    fn repository_encryption_is_disabled_by_default() {
        let config = RepoEncryptionConfig::default();
        let caps = RepoEncryptionCapabilities::from_config(&config);

        assert!(!config.is_enabled());
        assert_eq!(caps.encryption_mode, RepoEncryptionMode::Disabled);
        assert!(!caps.enabled);
        assert!(!caps.access_checks_required);
        assert!(!caps.audit_required);
        assert!(!caps.repository_isolation_required);
        assert!(!caps.semantic_search_enabled);
        assert!(!caps.web_discovery_enabled);
        assert!(!caps.full_file_open_enabled);
        assert_eq!(caps.key_status, RepoEncryptionKeyStatus::NotRequired);
        assert_eq!(
            caps.index_protection_status,
            RepoEncryptionIndexProtectionStatus::NotApplicable
        );
        assert_eq!(
            caps.max_results_per_query,
            DEFAULT_REPO_ENCRYPTION_MAX_RESULTS_PER_QUERY
        );
    }

    #[test]
    fn enabled_repository_encryption_never_accepts_shared_bearer_as_sufficient() {
        let _guard = ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let mut config = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            shared_bearer_token_sufficient: true,
            ..RepoEncryptionConfig::default()
        };
        config.apply_defaults();

        let caps = RepoEncryptionCapabilities::from_config(&config);
        assert!(caps.enabled);
        assert_eq!(
            caps.encryption_mode,
            RepoEncryptionMode::ApplicationManagedEncryption
        );
        assert!(caps.access_checks_required);
        assert!(caps.audit_required);
        assert!(caps.repository_isolation_required);
        assert!(!caps.shared_bearer_token_sufficient);
        assert_eq!(caps.key_status, RepoEncryptionKeyStatus::Available);
        assert_eq!(
            caps.index_protection_status,
            RepoEncryptionIndexProtectionStatus::EncryptedStoredFieldsPlaintextTerms
        );
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
    }

    #[test]
    fn supported_encryption_modes_are_explicit() {
        assert_eq!(
            supported_encryption_modes(),
            vec![
                RepoEncryptionMode::Disabled,
                RepoEncryptionMode::ApplicationManagedEncryption,
            ]
        );
    }

    #[test]
    fn enabled_repository_encryption_reports_missing_key_material() {
        let _guard = ENV_LOCK.lock();
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        let mut config = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            ..RepoEncryptionConfig::default()
        };
        config.apply_defaults();

        let caps = RepoEncryptionCapabilities::from_config(&config);
        assert_eq!(caps.key_status, RepoEncryptionKeyStatus::MissingKeyMaterial);
        assert_eq!(
            caps.operations.search,
            RepoEncryptionOperationStatus::BlockedMissingKey
        );
        assert_eq!(
            caps.index_protection_status,
            RepoEncryptionIndexProtectionStatus::MissingKeyMaterial
        );
    }

    #[test]
    fn repository_encryption_round_trips_protected_text() {
        let _guard = ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let mut config = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            ..RepoEncryptionConfig::default()
        };
        config.apply_defaults();
        let key = config.require_key().expect("key");
        let protected = config
            .protect_text(&key, "domain", "src/lib.rs", "body", "secret body")
            .expect("encrypt");

        assert!(protected.starts_with(REPO_ENCRYPTION_PREFIX));
        assert!(!protected.contains("secret body"));
        assert_eq!(
            config
                .unprotect_text(&key, "domain", "src/lib.rs", "body", &protected)
                .expect("decrypt"),
            "secret body"
        );
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
    }

    #[test]
    fn wrong_repository_encryption_key_fails_closed() {
        let _guard = ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let mut config = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            key_id: Some("stable-test-key".to_string()),
            ..RepoEncryptionConfig::default()
        };
        config.apply_defaults();
        let key = config.require_key().expect("key");
        let protected = config
            .protect_text(&key, "domain", "src/lib.rs", "body", "secret body")
            .expect("encrypt");

        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, OTHER_TEST_KEY);
        let wrong_key = config.require_key().expect("wrong key with same key id");
        let err = config
            .unprotect_text(&wrong_key, "domain", "src/lib.rs", "body", &protected)
            .expect_err("wrong key must fail closed");

        assert!(err.to_string().contains("cannot decrypt"));
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
    }

    #[test]
    fn repository_encryption_aad_mismatch_fails_closed() {
        let _guard = ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let mut config = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            ..RepoEncryptionConfig::default()
        };
        config.apply_defaults();
        let key = config.require_key().expect("key");
        let protected = config
            .protect_text(&key, "domain-a", "src/lib.rs", "body", "secret body")
            .expect("encrypt");
        let err = config
            .unprotect_text(&key, "domain-b", "src/lib.rs", "body", &protected)
            .expect_err("domain mismatch must fail closed");

        assert!(err.to_string().contains("cannot decrypt"));
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
    }
}
