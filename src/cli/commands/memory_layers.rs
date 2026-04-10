use super::emit_json_or_error;
use crate::cli::http_client::CliHttpClient;
use crate::cli::ConversationScopeArgs;
use anyhow::Result;
use reqwest::Method;

pub(crate) async fn run(scope: ConversationScopeArgs) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let mut req = client.request(Method::GET, "/v1/memory/layers");
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "memory layers").await
}
