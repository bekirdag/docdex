use anyhow::{Context, Result};

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
    use tempfile::TempDir;

    #[test]
    fn set_default_model_updates_config() -> Result<()> {
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
}
