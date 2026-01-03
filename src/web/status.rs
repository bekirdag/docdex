use std::time::Duration;

use reqwest::StatusCode;
use url::Url;

pub async fn fetch_status(url: &Url, user_agent: &str, timeout: Duration) -> Option<u16> {
    let client = reqwest::Client::builder()
        .user_agent(user_agent.to_string())
        .timeout(timeout)
        .build()
        .ok()?;
    let resp = client.head(url.clone()).send().await.ok()?;
    let status = resp.status();
    if status == StatusCode::METHOD_NOT_ALLOWED || status == StatusCode::NOT_IMPLEMENTED {
        let resp = client.get(url.clone()).send().await.ok()?;
        return Some(resp.status().as_u16());
    }
    Some(status.as_u16())
}
