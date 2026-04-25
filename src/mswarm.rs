use anyhow::{Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::future::Future;
use std::time::Duration;

pub const DOCDEX_CONSENT_POLICY_VERSION: &str = "2026-03-18";
pub const DOCDEX_FREE_CLIENT_TYPE: &str = "free_docdex_client";
pub const DOCDEX_PAID_CLIENT_TYPE: &str = "paid_docdex_client";
const PAID_CONSENT_PATH: &str = "/v1/swarm/consent/issue";
const FREE_CLIENT_REGISTER_PATH: &str = "/v1/swarm/docdex/free-client/register";
const CONSENT_REVOKE_PATH: &str = "/v1/swarm/consent/revoke";
const DATA_DELETION_REQUEST_PATH: &str = "/v1/swarm/data/deletion-request";
const DOCDEX_CONSENT_TYPES: [&str; 2] = ["anonymous", "non_anonymous"];

#[derive(Debug)]
struct MswarmApiError {
    context_label: String,
    status: StatusCode,
    body: String,
}

impl MswarmApiError {
    fn new(context_label: &str, status: StatusCode, body: String) -> Self {
        Self {
            context_label: context_label.to_string(),
            status,
            body,
        }
    }
}

impl fmt::Display for MswarmApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.body.trim().is_empty() {
            write!(
                f,
                "mswarm {} failed with status {}",
                self.context_label, self.status
            )
        } else {
            write!(
                f,
                "mswarm {} failed with status {}: {}",
                self.context_label,
                self.status,
                self.body.trim()
            )
        }
    }
}

impl std::error::Error for MswarmApiError {}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsentIssueResponse {
    pub consent_token: String,
    pub expires_in_seconds: u64,
    #[serde(default)]
    pub consent_types: Vec<String>,
    pub issued_at_ms: u128,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_type: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub upload_signing_secret: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsentRevokeResponse {
    pub revoked: bool,
    #[serde(default)]
    pub revoked_at_ms: Option<u128>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DataDeletionRequestResponse {
    pub accepted: bool,
    pub request_id: u64,
    pub product: String,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_type: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub status: String,
    #[serde(default)]
    pub requested_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConsentProof<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    value: &'a str,
}

#[derive(Debug, Serialize)]
struct PaidConsentIssueRequest<'a> {
    consent_types: [&'a str; 2],
    policy_version: &'a str,
    timestamp_ms: u128,
    proof: ConsentProof<'a>,
}

#[derive(Debug, Serialize)]
struct FreeClientRegisterRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    product: &'a str,
    product_version: &'a str,
    policy_version: &'a str,
    timestamp_ms: u128,
    consent_types: [&'a str; 2],
}

#[derive(Debug, Serialize)]
struct ConsentRevokeRequest<'a> {
    consent_token: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct DataDeletionRequest<'a> {
    consent_token: &'a str,
    product: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'a str>,
}

pub fn effective_policy_version(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(DOCDEX_CONSENT_POLICY_VERSION)
        .to_string()
}

pub(crate) fn block_on_http_future<F, T>(future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(future)),
        Err(_) => tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build mswarm helper runtime")?
            .block_on(future),
    }
}

pub fn issue_paid_docdex_consent(
    base_url: &str,
    api_key: &str,
    policy_version: &str,
    timestamp_ms: u128,
) -> Result<ConsentIssueResponse> {
    block_on_http_future(issue_paid_docdex_consent_async(
        base_url,
        api_key,
        policy_version,
        timestamp_ms,
    ))
}

pub async fn issue_paid_docdex_consent_async(
    base_url: &str,
    api_key: &str,
    policy_version: &str,
    timestamp_ms: u128,
) -> Result<ConsentIssueResponse> {
    let client = build_client()?;
    let url = endpoint_url(base_url, PAID_CONSENT_PATH);
    let payload = PaidConsentIssueRequest {
        consent_types: DOCDEX_CONSENT_TYPES,
        policy_version,
        timestamp_ms,
        proof: ConsentProof {
            kind: "api_key",
            value: api_key,
        },
    };
    let response = client
        .post(url)
        .header("x-api-key", api_key)
        .json(&payload)
        .send()
        .await
        .context("call mswarm paid consent endpoint")?;
    parse_response(response, "paid consent").await
}

pub fn register_free_docdex_client(
    base_url: &str,
    client_id: Option<&str>,
    policy_version: &str,
    timestamp_ms: u128,
) -> Result<ConsentIssueResponse> {
    block_on_http_future(register_free_docdex_client_async(
        base_url,
        client_id,
        policy_version,
        timestamp_ms,
    ))
}

pub async fn register_free_docdex_client_async(
    base_url: &str,
    client_id: Option<&str>,
    policy_version: &str,
    timestamp_ms: u128,
) -> Result<ConsentIssueResponse> {
    let client = build_client()?;
    let url = endpoint_url(base_url, FREE_CLIENT_REGISTER_PATH);
    let payload = FreeClientRegisterRequest {
        client_id,
        product: "docdex",
        product_version: env!("CARGO_PKG_VERSION"),
        policy_version,
        timestamp_ms,
        consent_types: DOCDEX_CONSENT_TYPES,
    };
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .context("call mswarm free client register endpoint")?;
    parse_response(response, "free client registration").await
}

pub fn revoke_docdex_consent(
    base_url: &str,
    consent_token: &str,
    reason: Option<&str>,
) -> Result<ConsentRevokeResponse> {
    block_on_http_future(revoke_docdex_consent_async(base_url, consent_token, reason))
}

pub async fn revoke_docdex_consent_async(
    base_url: &str,
    consent_token: &str,
    reason: Option<&str>,
) -> Result<ConsentRevokeResponse> {
    let client = build_client()?;
    let url = endpoint_url(base_url, CONSENT_REVOKE_PATH);
    let payload = ConsentRevokeRequest {
        consent_token,
        reason,
    };
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .context("call mswarm consent revoke endpoint")?;
    parse_response(response, "consent revoke").await
}

pub fn request_docdex_data_deletion(
    base_url: &str,
    api_key: Option<&str>,
    consent_token: &str,
    client_id: Option<&str>,
    client_type: Option<&str>,
    reason: Option<&str>,
) -> Result<DataDeletionRequestResponse> {
    block_on_http_future(request_docdex_data_deletion_async(
        base_url,
        api_key,
        consent_token,
        client_id,
        client_type,
        reason,
    ))
}

pub async fn request_docdex_data_deletion_async(
    base_url: &str,
    api_key: Option<&str>,
    consent_token: &str,
    client_id: Option<&str>,
    client_type: Option<&str>,
    reason: Option<&str>,
) -> Result<DataDeletionRequestResponse> {
    let client = build_client()?;
    let url = endpoint_url(base_url, DATA_DELETION_REQUEST_PATH);
    let payload = DataDeletionRequest {
        consent_token,
        product: "docdex",
        client_id,
        client_type,
        reason,
    };
    let mut request = client.post(url).json(&payload);
    if let Some(api_key) = api_key.map(str::trim).filter(|value| !value.is_empty()) {
        request = request.header("x-api-key", api_key);
    }
    let response = request
        .send()
        .await
        .context("call mswarm data deletion endpoint")?;
    parse_response(response, "data deletion request").await
}

pub fn is_paid_consent_auth_failure(err: &anyhow::Error) -> bool {
    if let Some(api_err) = err.downcast_ref::<MswarmApiError>() {
        return api_err.context_label == "paid consent"
            && matches!(
                api_err.status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
            );
    }

    let message = err.to_string();
    (message.contains("mswarm paid consent failed with status 401")
        || message.contains("mswarm paid consent failed with status 403"))
        || (message.contains("mswarm paid consent failed")
            && message.contains("Missing or invalid API key"))
}

fn build_client() -> Result<Client> {
    Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("build mswarm http client")
}

fn endpoint_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

async fn parse_response<T>(response: Response, context_label: &str) -> Result<T>
where
    T: DeserializeOwned,
{
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow::Error::new(MswarmApiError::new(
            context_label,
            status,
            body,
        )));
    }
    response
        .json::<T>()
        .await
        .with_context(|| format!("decode mswarm {} response", context_label))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_paid_consent_auth_failure_from_typed_error() {
        let err = anyhow::Error::new(MswarmApiError::new(
            "paid consent",
            StatusCode::UNAUTHORIZED,
            r#"{"code":"unauthorized"}"#.to_string(),
        ));
        assert!(is_paid_consent_auth_failure(&err));
    }

    #[test]
    fn ignores_non_auth_or_non_paid_consent_failures() {
        let forbidden_other = anyhow::Error::new(MswarmApiError::new(
            "data deletion request",
            StatusCode::UNAUTHORIZED,
            r#"{"code":"unauthorized"}"#.to_string(),
        ));
        let generic = anyhow::anyhow!(
            "mswarm free client registration failed with status 500 Internal Server Error"
        );
        assert!(!is_paid_consent_auth_failure(&forbidden_other));
        assert!(!is_paid_consent_auth_failure(&generic));
    }
}
