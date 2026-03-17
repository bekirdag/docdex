use anyhow::Result;
use serde::Serialize;

use crate::config;
use crate::setup::config as setup_config;

pub(crate) async fn run(command: crate::cli::MswarmCommand) -> Result<()> {
    match command {
        crate::cli::MswarmCommand::Configure {
            api_key,
            base_url,
            enable_web_search,
            disable_web_search,
            json,
        } => {
            let use_for_web_search = if enable_web_search {
                Some(true)
            } else if disable_web_search {
                Some(false)
            } else {
                None
            };
            let updated = if api_key.is_some() || base_url.is_some() || use_for_web_search.is_some()
            {
                setup_config::set_mswarm_config(setup_config::MswarmConfigUpdate {
                    api_key,
                    base_url,
                    use_for_web_search,
                })?
            } else {
                false
            };
            let config = config::AppConfig::load_default()?;
            let response = MswarmConfigureResponse {
                updated,
                configured: config.integrations.mswarm.api_key.is_some(),
                base_url: config.integrations.mswarm.base_url,
                api_key_set: config.integrations.mswarm.api_key.is_some(),
                discovery_provider: config.web.discovery_provider.clone(),
                web_search_enabled: config.web.discovery_provider.eq_ignore_ascii_case("mswarm"),
                config_path: config::default_config_path()?.to_string_lossy().to_string(),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!(
                    "mswarm configured={} web_search_enabled={} discovery_provider={} base_url={} config_path={}",
                    response.configured,
                    response.web_search_enabled,
                    response.discovery_provider,
                    response.base_url,
                    response.config_path
                );
            }
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct MswarmConfigureResponse {
    updated: bool,
    configured: bool,
    base_url: String,
    api_key_set: bool,
    discovery_provider: String,
    web_search_enabled: bool,
    config_path: String,
}
