use super::emit_json_or_error;
use crate::cli::http_client::CliHttpClient;
use crate::cli::ConversationScopeArgs;
use anyhow::Result;
use reqwest::Method;
use serde_json::json;

pub(crate) async fn run(
    scope: ConversationScopeArgs,
    intent: Option<String>,
    query: String,
) -> Result<()> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(&scope).await?;
    let mut req = client.request(Method::POST, "/v1/memory/route");
    req = client.with_conversation_scope(req, &scope)?;
    let resp = req
        .json(&json!({
            "query": query,
            "intent": intent,
        }))
        .send()
        .await?;
    emit_json_or_error(resp, "memory route").await
}
