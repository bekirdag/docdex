use anyhow::{Context, Result};
use std::path::Path;
use uuid::Uuid;

use crate::config::{self, AppConfig};
use crate::mswarm;
use toml;

const LEGACY_MSWARM_BASE_URL: &str = "http://127.0.0.1:8080";

pub fn set_default_model(model: &str) -> Result<bool> {
    if model.trim().is_empty() {
        return Ok(false);
    }
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&path)?;
    if config_data.llm.default_model == model {
        return Ok(false);
    }
    config_data.llm.default_model = model.to_string();
    config::write_config(&path, &config_data).context("write config")?;
    Ok(true)
}

pub fn set_embedding_model(model: &str) -> Result<bool> {
    if model.trim().is_empty() {
        return Ok(false);
    }
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&path)?;
    if config_data.llm.embedding_model == model {
        return Ok(false);
    }
    config_data.llm.embedding_model = model.to_string();
    config::write_config(&path, &config_data).context("write config")?;
    Ok(true)
}

pub fn set_browser_path(path: &Path, kind: &str) -> Result<bool> {
    if path.as_os_str().is_empty() {
        return Ok(false);
    }
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let config_path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&config_path)?;
    let mut changed = false;
    let path_buf = path.to_path_buf();
    if config_data.web.scraper.chrome_binary_path.as_ref() != Some(&path_buf) {
        config_data.web.scraper.chrome_binary_path = Some(path_buf);
        changed = true;
    }
    let kind_trimmed = kind.trim();
    if !kind_trimmed.is_empty()
        && config_data.web.scraper.browser_kind.as_deref() != Some(kind_trimmed)
    {
        config_data.web.scraper.browser_kind = Some(kind_trimmed.to_string());
        changed = true;
    }
    if changed {
        config::write_config(&config_path, &config_data).context("write config")?;
    }
    Ok(changed)
}

pub struct WebProviderKeysUpdate {
    pub brave_api_key: Option<String>,
    pub google_cse_api_key: Option<String>,
    pub google_cse_cx: Option<String>,
    pub bing_api_key: Option<String>,
}

pub struct MswarmConfigUpdate {
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub use_for_web_search: Option<bool>,
}

#[cfg_attr(not(test), allow(dead_code))]
pub struct MswarmTelemetryUpdate {
    pub required: Option<bool>,
    pub consent_accepted: Option<bool>,
    pub consent_policy_version: Option<String>,
    pub consent_token: Option<String>,
    pub client_id: Option<String>,
    pub client_type: Option<String>,
    pub registered_at_ms: Option<u64>,
    pub last_upload_at_ms: Option<u64>,
    pub upload_signing_secret: Option<String>,
}

pub struct MswarmTelemetryConsentStatus {
    pub client_id: String,
    pub client_type: String,
    pub policy_version: String,
    pub consent_token_set: bool,
}

pub fn set_web_provider_keys(update: WebProviderKeysUpdate) -> Result<bool> {
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let config_path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&config_path)?;
    let mut changed = false;

    if let Some(value) = update.brave_api_key {
        let normalized = normalize_key(value);
        if config_data.web.providers.brave_api_key != normalized {
            config_data.web.providers.brave_api_key = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.google_cse_api_key {
        let normalized = normalize_key(value);
        if config_data.web.providers.google_cse_api_key != normalized {
            config_data.web.providers.google_cse_api_key = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.google_cse_cx {
        let normalized = normalize_key(value);
        if config_data.web.providers.google_cse_cx != normalized {
            config_data.web.providers.google_cse_cx = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.bing_api_key {
        let normalized = normalize_key(value);
        if config_data.web.providers.bing_api_key != normalized {
            config_data.web.providers.bing_api_key = normalized;
            changed = true;
        }
    }

    if changed {
        config::write_config(&config_path, &config_data).context("write config")?;
    }
    Ok(changed)
}

pub fn set_mswarm_config(update: MswarmConfigUpdate) -> Result<bool> {
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let config_path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&config_path)?;
    let mut changed = false;
    let default_base_url = config::default_mswarm_base_url();
    let touched_non_base_url = update.api_key.is_some() || update.use_for_web_search.is_some();

    if let Some(value) = update.api_key {
        let normalized = normalize_key(value);
        if config_data.integrations.mswarm.api_key != normalized {
            config_data.integrations.mswarm.api_key = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.base_url {
        let normalized = normalize_key(value);
        let next_base_url = normalized.unwrap_or_else(|| default_base_url.clone());
        if config_data.integrations.mswarm.base_url != next_base_url {
            config_data.integrations.mswarm.base_url = next_base_url;
            changed = true;
        }
    } else if touched_non_base_url
        && is_legacy_or_empty_mswarm_base_url(&config_data.integrations.mswarm.base_url)
        && config_data.integrations.mswarm.base_url != default_base_url
    {
        config_data.integrations.mswarm.base_url = default_base_url.clone();
        changed = true;
    }
    if let Some(use_for_web_search) = update.use_for_web_search {
        let target_provider = if use_for_web_search {
            "mswarm".to_string()
        } else {
            config::default_discovery_provider()
        };
        if config_data.web.discovery_provider != target_provider {
            config_data.web.discovery_provider = target_provider;
            changed = true;
        }
    }

    if changed {
        config::write_config(&config_path, &config_data).context("write config")?;
    }
    Ok(changed)
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn set_mswarm_telemetry_config(update: MswarmTelemetryUpdate) -> Result<bool> {
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let config_path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&config_path)?;
    let mut changed = false;

    if let Some(value) = update.required {
        if config_data.integrations.mswarm.telemetry.required != value {
            config_data.integrations.mswarm.telemetry.required = value;
            changed = true;
        }
    }
    if let Some(value) = update.consent_accepted {
        if config_data.integrations.mswarm.telemetry.consent_accepted != value {
            config_data.integrations.mswarm.telemetry.consent_accepted = value;
            changed = true;
        }
    }
    if let Some(value) = update.consent_policy_version {
        let normalized =
            normalize_key(value).unwrap_or_else(|| mswarm::effective_policy_version(None));
        if config_data
            .integrations
            .mswarm
            .telemetry
            .consent_policy_version
            != normalized
        {
            config_data
                .integrations
                .mswarm
                .telemetry
                .consent_policy_version = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.consent_token {
        let normalized = normalize_key(value);
        if config_data.integrations.mswarm.telemetry.consent_token != normalized {
            config_data.integrations.mswarm.telemetry.consent_token = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.client_id {
        let normalized = normalize_key(value).unwrap_or_default();
        if config_data.integrations.mswarm.telemetry.client_id != normalized {
            config_data.integrations.mswarm.telemetry.client_id = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.client_type {
        let normalized = normalize_key(value)
            .unwrap_or_else(|| crate::mswarm::DOCDEX_FREE_CLIENT_TYPE.to_string());
        if config_data.integrations.mswarm.telemetry.client_type != normalized {
            config_data.integrations.mswarm.telemetry.client_type = normalized;
            changed = true;
        }
    }
    if let Some(value) = update.registered_at_ms {
        if config_data.integrations.mswarm.telemetry.registered_at_ms != value {
            config_data.integrations.mswarm.telemetry.registered_at_ms = value;
            changed = true;
        }
    }
    if let Some(value) = update.last_upload_at_ms {
        if config_data.integrations.mswarm.telemetry.last_upload_at_ms != value {
            config_data.integrations.mswarm.telemetry.last_upload_at_ms = value;
            changed = true;
        }
    }
    if let Some(value) = update.upload_signing_secret {
        let normalized = normalize_key(value);
        if config_data
            .integrations
            .mswarm
            .telemetry
            .upload_signing_secret
            != normalized
        {
            config_data
                .integrations
                .mswarm
                .telemetry
                .upload_signing_secret = normalized;
            changed = true;
        }
    }

    if changed {
        config::write_config(&config_path, &config_data).context("write config")?;
    }
    Ok(changed)
}

pub fn ensure_mswarm_telemetry_consent(
    accepted_at_ms: u128,
) -> Result<MswarmTelemetryConsentStatus> {
    std::env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let config_path = config::default_config_path()?;
    let mut config_data = load_config_no_browser(&config_path)?;
    let policy_version = mswarm::effective_policy_version(Some(
        &config_data
            .integrations
            .mswarm
            .telemetry
            .consent_policy_version,
    ));
    let registered_at_ms = accepted_at_ms.min(u64::MAX as u128) as u64;
    let base_url = config_data.integrations.mswarm.base_url.clone();
    let api_key = config_data.integrations.mswarm.api_key.clone();
    let existing_client_id =
        normalize_key(config_data.integrations.mswarm.telemetry.client_id.clone());

    let (client_id, client_type, consent_token, upload_signing_secret) = if let Some(api_key) =
        api_key
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    {
        let response =
            mswarm::issue_paid_docdex_consent(&base_url, api_key, &policy_version, accepted_at_ms)?;
        let client_id = existing_client_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        (
            client_id,
            response
                .client_type
                .unwrap_or_else(|| mswarm::DOCDEX_PAID_CLIENT_TYPE.to_string()),
            response.consent_token,
            None,
        )
    } else {
        let response = mswarm::register_free_docdex_client(
            &base_url,
            existing_client_id.as_deref(),
            &policy_version,
            accepted_at_ms,
        )?;
        (
            response.client_id.unwrap_or_else(|| {
                existing_client_id.unwrap_or_else(|| Uuid::new_v4().to_string())
            }),
            response
                .client_type
                .unwrap_or_else(|| mswarm::DOCDEX_FREE_CLIENT_TYPE.to_string()),
            response.consent_token,
            response.upload_signing_secret,
        )
    };

    config_data.integrations.mswarm.telemetry.required = true;
    config_data.integrations.mswarm.telemetry.consent_accepted = true;
    config_data
        .integrations
        .mswarm
        .telemetry
        .consent_policy_version = policy_version.clone();
    config_data.integrations.mswarm.telemetry.consent_token = Some(consent_token.clone());
    config_data.integrations.mswarm.telemetry.client_id = client_id.clone();
    config_data.integrations.mswarm.telemetry.client_type = client_type.clone();
    config_data.integrations.mswarm.telemetry.registered_at_ms = registered_at_ms;
    if let Some(secret) = upload_signing_secret {
        config_data
            .integrations
            .mswarm
            .telemetry
            .upload_signing_secret = Some(secret);
    }

    config::write_config(&config_path, &config_data).context("write config")?;

    Ok(MswarmTelemetryConsentStatus {
        client_id,
        client_type,
        policy_version,
        consent_token_set: !consent_token.trim().is_empty(),
    })
}

fn normalize_key(value: String) -> Option<String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn is_legacy_or_empty_mswarm_base_url(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty()
        || trimmed.trim_end_matches('/') == LEGACY_MSWARM_BASE_URL.trim_end_matches('/')
}

fn load_config_no_browser(path: &std::path::Path) -> Result<AppConfig> {
    if !path.exists() {
        let mut config = AppConfig::default();
        config.apply_defaults()?;
        config::apply_browser_defaults(&mut config);
        return Ok(config);
    }
    let text = std::fs::read_to_string(path).context("read config")?;
    if text.trim().is_empty() {
        let mut config = AppConfig::default();
        config.apply_defaults()?;
        config::apply_browser_defaults(&mut config);
        return Ok(config);
    }
    let mut config: AppConfig = toml::from_str(&text).context("parse config")?;
    config.apply_defaults()?;
    config::apply_browser_defaults(&mut config);
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    struct MockMswarmServer {
        addr: SocketAddr,
        shutdown: Option<mpsc::Sender<()>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl MockMswarmServer {
        fn spawn(body: String) -> Result<Self> {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            let addr = listener.local_addr()?;
            listener.set_nonblocking(true)?;
            let (tx, rx) = mpsc::channel::<()>();
            let join = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if rx.try_recv().is_ok() {
                        break;
                    }
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                            let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                            let mut buffer = Vec::new();
                            let mut chunk = [0u8; 1024];
                            loop {
                                match stream.read(&mut chunk) {
                                    Ok(0) => break,
                                    Ok(read) => {
                                        buffer.extend_from_slice(&chunk[..read]);
                                        if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                                            break;
                                        }
                                    }
                                    Err(err)
                                        if err.kind() == std::io::ErrorKind::WouldBlock
                                            || err.kind() == std::io::ErrorKind::TimedOut =>
                                    {
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }

                            let response = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                body.len(),
                                body
                            );
                            let _ = stream.write_all(response.as_bytes());
                            let _ = stream.flush();
                            break;
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            if Instant::now() > deadline {
                                break;
                            }
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(Self {
                addr,
                shutdown: Some(tx),
                join: Some(join),
            })
        }

        fn base_url(&self) -> String {
            format!("http://{}", self.addr)
        }
    }

    impl Drop for MockMswarmServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    #[test]
    fn set_default_model_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);
        let changed = set_default_model("llama3.1:8b")?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("llama3.1:8b"));
        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_embedding_model_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);
        let changed = set_embedding_model("nomic-embed-text-v1.5")?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("nomic-embed-text-v1.5"));
        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_browser_path_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let browser_path = dir.path().join("chromium-bin");
        std::fs::write(&browser_path, b"bin")?;
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);
        let changed = set_browser_path(&browser_path, "chromium")?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("chrome_binary_path"));
        assert!(contents.contains("chromium"));
        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_web_provider_keys_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);

        let changed = set_web_provider_keys(WebProviderKeysUpdate {
            brave_api_key: Some("brave-key".to_string()),
            google_cse_api_key: Some("google-key".to_string()),
            google_cse_cx: Some("cx-id".to_string()),
            bing_api_key: Some("bing-key".to_string()),
        })?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("brave-key"));
        assert!(contents.contains("google-key"));
        assert!(contents.contains("cx-id"));
        assert!(contents.contains("bing-key"));

        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_mswarm_config_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);

        let changed = set_mswarm_config(MswarmConfigUpdate {
            api_key: Some("mswarm-key".to_string()),
            base_url: Some("https://api.mswarm.org/".to_string()),
            use_for_web_search: Some(true),
        })?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("mswarm-key"));
        assert!(contents.contains("https://api.mswarm.org/"));
        assert!(contents.contains("discovery_provider = \"mswarm\""));

        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_mswarm_config_migrates_legacy_default_base_url_when_omitted() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);
        std::fs::write(
            &path,
            r#"[integrations.mswarm]
base_url = "http://127.0.0.1:8080"
"#,
        )?;

        let changed = set_mswarm_config(MswarmConfigUpdate {
            api_key: Some("mswarm-key".to_string()),
            base_url: None,
            use_for_web_search: Some(true),
        })?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("base_url = \"https://api.mswarm.org/\""));
        assert!(contents.contains("mswarm-key"));
        assert!(contents.contains("discovery_provider = \"mswarm\""));

        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_mswarm_config_preserves_custom_base_url_when_omitted() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);
        std::fs::write(
            &path,
            r#"[integrations.mswarm]
base_url = "https://custom.mswarm.example/"
"#,
        )?;

        let changed = set_mswarm_config(MswarmConfigUpdate {
            api_key: Some("mswarm-key".to_string()),
            base_url: None,
            use_for_web_search: Some(true),
        })?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("base_url = \"https://custom.mswarm.example/\""));
        assert!(contents.contains("mswarm-key"));

        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn set_mswarm_telemetry_config_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);

        let changed = set_mswarm_telemetry_config(MswarmTelemetryUpdate {
            required: Some(true),
            consent_accepted: Some(true),
            consent_policy_version: Some("2026-03-18".to_string()),
            consent_token: Some("token-123".to_string()),
            client_id: Some("client-123".to_string()),
            client_type: Some("free_docdex_client".to_string()),
            registered_at_ms: Some(42),
            last_upload_at_ms: Some(99),
            upload_signing_secret: Some("secret-123".to_string()),
        })?;
        assert!(changed);
        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("consent_accepted = true"));
        assert!(contents.contains("consent_policy_version = \"2026-03-18\""));
        assert!(contents.contains("consent_token = \"token-123\""));
        assert!(contents.contains("client_id = \"client-123\""));
        assert!(contents.contains("registered_at_ms = 42"));
        assert!(contents.contains("last_upload_at_ms = 99"));
        assert!(contents.contains("upload_signing_secret = \"secret-123\""));

        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }

    #[test]
    fn ensure_mswarm_telemetry_consent_registers_free_client() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let response = serde_json::json!({
            "client_id": "free-client-123",
            "client_type": "free_docdex_client",
            "tenant_id": "free-client-123",
            "consent_token": "token-abc",
            "expires_in_seconds": 2592000,
            "consent_types": ["anonymous", "non_anonymous"],
            "issued_at_ms": 123_u64,
            "upload_signing_secret": "upload-secret-123"
        })
        .to_string();
        let server = MockMswarmServer::spawn(response)?;
        std::env::set_var("DOCDEX_CONFIG_PATH", &path);
        std::fs::write(
            &path,
            format!(
                "[integrations.mswarm]\nbase_url = \"{}/\"\n",
                server.base_url()
            ),
        )?;

        let status = ensure_mswarm_telemetry_consent(123)?;
        assert_eq!(status.client_id, "free-client-123");
        assert_eq!(status.client_type, "free_docdex_client");
        assert_eq!(status.policy_version, "2026-03-18");
        assert!(status.consent_token_set);

        let contents = std::fs::read_to_string(&path)?;
        assert!(contents.contains("consent_accepted = true"));
        assert!(contents.contains("consent_token = \"token-abc\""));
        assert!(contents.contains("client_id = \"free-client-123\""));
        assert!(contents.contains("client_type = \"free_docdex_client\""));
        assert!(contents.contains("registered_at_ms = 123"));
        assert!(contents.contains("upload_signing_secret = \"upload-secret-123\""));

        std::env::remove_var("DOCDEX_CONFIG_PATH");
        Ok(())
    }
}
