use anyhow::{Context, Result};
use std::path::Path;

use crate::config::{self, AppConfig};
use toml;

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

fn load_config_no_browser(path: &std::path::Path) -> Result<AppConfig> {
    if !path.exists() {
        let mut config = AppConfig::default();
        config.apply_defaults()?;
        return Ok(config);
    }
    let text = std::fs::read_to_string(path).context("read config")?;
    if text.trim().is_empty() {
        let mut config = AppConfig::default();
        config.apply_defaults()?;
        return Ok(config);
    }
    let mut config: AppConfig = toml::from_str(&text).context("parse config")?;
    config.apply_defaults()?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use tempfile::TempDir;

    #[test]
    fn set_default_model_updates_config() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
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
        let _guard = ENV_LOCK.lock().unwrap();
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
        let _guard = ENV_LOCK.lock().unwrap();
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
}
