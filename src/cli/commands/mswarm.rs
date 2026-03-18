use anyhow::Result;
use serde::Serialize;

use crate::config;
use crate::mswarm;
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
            let response = MswarmStatusResponse {
                updated,
                base_url: config.integrations.mswarm.base_url,
                api_key_set: config.integrations.mswarm.api_key.is_some(),
                discovery_provider: config.web.discovery_provider.clone(),
                web_search_enabled: config.web.discovery_provider.eq_ignore_ascii_case("mswarm"),
                consent_required: config.integrations.mswarm.telemetry.required,
                consent_accepted: config.integrations.mswarm.telemetry.consent_accepted,
                consent_policy_version: config
                    .integrations
                    .mswarm
                    .telemetry
                    .consent_policy_version
                    .clone(),
                consent_token_set: config.integrations.mswarm.telemetry.consent_token.is_some(),
                client_id: blank_to_none(&config.integrations.mswarm.telemetry.client_id),
                client_type: blank_to_none(&config.integrations.mswarm.telemetry.client_type),
                upload_signing_secret_set: config
                    .integrations
                    .mswarm
                    .telemetry
                    .upload_signing_secret
                    .is_some(),
                config_path: config::default_config_path()?.to_string_lossy().to_string(),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                println!(
                    "mswarm configured={} web_search_enabled={} discovery_provider={} base_url={} consent_accepted={} config_path={}",
                    response.api_key_set,
                    response.web_search_enabled,
                    response.discovery_provider,
                    response.base_url,
                    response.consent_accepted,
                    response.config_path
                );
            }
            Ok(())
        }
        crate::cli::MswarmCommand::Status { json } => {
            let response = current_status(false)?;
            print_status(&response, json)?;
            Ok(())
        }
        crate::cli::MswarmCommand::Revoke { reason, json } => {
            let config = config::AppConfig::load_default()?;
            let consent_token = config
                .integrations
                .mswarm
                .telemetry
                .consent_token
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No persisted mswarm consent token is available. Run `docdexd setup` or `docdexd mswarm configure` first."
                    )
                })?;
            let response = mswarm::revoke_docdex_consent(
                &config.integrations.mswarm.base_url,
                consent_token,
                reason.as_deref(),
            )?;
            let _ =
                setup_config::set_mswarm_telemetry_config(setup_config::MswarmTelemetryUpdate {
                    required: None,
                    consent_accepted: Some(false),
                    consent_policy_version: None,
                    consent_token: Some(String::new()),
                    client_id: None,
                    client_type: None,
                    registered_at_ms: None,
                    last_upload_at_ms: None,
                    upload_signing_secret: Some(String::new()),
                })?;
            let status = current_status(false)?;
            let payload = MswarmRevokeResponse {
                revoked: response.revoked,
                revoked_at_ms: response.revoked_at_ms,
                status,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!(
                    "mswarm revoked={} revoked_at_ms={:?} consent_accepted={} config_path={}",
                    payload.revoked,
                    payload.revoked_at_ms,
                    payload.status.consent_accepted,
                    payload.status.config_path
                );
            }
            Ok(())
        }
        crate::cli::MswarmCommand::RequestDeletion { reason, json } => {
            let config = config::AppConfig::load_default()?;
            let consent_token = config
                .integrations
                .mswarm
                .telemetry
                .consent_token
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "No persisted mswarm consent token is available. Run `docdexd setup` first."
                    )
                })?;
            let api_key = config.integrations.mswarm.api_key.as_deref();
            let client_id = blank_to_none(&config.integrations.mswarm.telemetry.client_id);
            let client_type = blank_to_none(&config.integrations.mswarm.telemetry.client_type);
            let response = mswarm::request_docdex_data_deletion(
                &config.integrations.mswarm.base_url,
                api_key,
                consent_token,
                if api_key.is_some() {
                    None
                } else {
                    client_id.as_deref()
                },
                if api_key.is_some() {
                    None
                } else {
                    client_type.as_deref()
                },
                reason.as_deref(),
            )?;
            let payload = MswarmDeletionResponse {
                accepted: response.accepted,
                request_id: response.request_id,
                product: response.product,
                client_id: response.client_id,
                client_type: response.client_type,
                tenant_id: response.tenant_id,
                status: response.status,
                requested_at: response.requested_at,
                config_path: config::default_config_path()?.to_string_lossy().to_string(),
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&payload)?);
            } else {
                println!(
                    "mswarm deletion_requested={} request_id={} product={} status={} config_path={}",
                    payload.accepted,
                    payload.request_id,
                    payload.product,
                    payload.status,
                    payload.config_path
                );
            }
            Ok(())
        }
    }
}

#[derive(Serialize)]
struct MswarmStatusResponse {
    updated: bool,
    base_url: String,
    api_key_set: bool,
    discovery_provider: String,
    web_search_enabled: bool,
    consent_required: bool,
    consent_accepted: bool,
    consent_policy_version: String,
    consent_token_set: bool,
    client_id: Option<String>,
    client_type: Option<String>,
    upload_signing_secret_set: bool,
    config_path: String,
}

#[derive(Serialize)]
struct MswarmRevokeResponse {
    revoked: bool,
    revoked_at_ms: Option<u128>,
    status: MswarmStatusResponse,
}

#[derive(Serialize)]
struct MswarmDeletionResponse {
    accepted: bool,
    request_id: u64,
    product: String,
    client_id: Option<String>,
    client_type: Option<String>,
    tenant_id: Option<String>,
    status: String,
    requested_at: Option<String>,
    config_path: String,
}

fn current_status(updated: bool) -> Result<MswarmStatusResponse> {
    let config = config::AppConfig::load_default()?;
    Ok(MswarmStatusResponse {
        updated,
        base_url: config.integrations.mswarm.base_url,
        api_key_set: config.integrations.mswarm.api_key.is_some(),
        discovery_provider: config.web.discovery_provider.clone(),
        web_search_enabled: config.web.discovery_provider.eq_ignore_ascii_case("mswarm"),
        consent_required: config.integrations.mswarm.telemetry.required,
        consent_accepted: config.integrations.mswarm.telemetry.consent_accepted,
        consent_policy_version: config
            .integrations
            .mswarm
            .telemetry
            .consent_policy_version
            .clone(),
        consent_token_set: config.integrations.mswarm.telemetry.consent_token.is_some(),
        client_id: blank_to_none(&config.integrations.mswarm.telemetry.client_id),
        client_type: blank_to_none(&config.integrations.mswarm.telemetry.client_type),
        upload_signing_secret_set: config
            .integrations
            .mswarm
            .telemetry
            .upload_signing_secret
            .is_some(),
        config_path: config::default_config_path()?.to_string_lossy().to_string(),
    })
}

fn print_status(response: &MswarmStatusResponse, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
    } else {
        println!(
            "mswarm api_key_set={} base_url={} discovery_provider={} web_search_enabled={} consent_accepted={} consent_token_set={} client_id={} client_type={} config_path={}",
            response.api_key_set,
            response.base_url,
            response.discovery_provider,
            response.web_search_enabled,
            response.consent_accepted,
            response.consent_token_set,
            response.client_id.as_deref().unwrap_or("-"),
            response.client_type.as_deref().unwrap_or("-"),
            response.config_path
        );
    }
    Ok(())
}

fn blank_to_none(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
