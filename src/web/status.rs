use std::time::Duration;

use reqwest::StatusCode;
use url::Url;

use crate::web::policy::{public_dns_resolver, send_with_outbound_policy};

pub async fn fetch_status(url: &Url, user_agent: &str, timeout: Duration) -> Option<u16> {
    let client = reqwest::Client::builder()
        .dns_resolver(public_dns_resolver())
        .no_proxy()
        .user_agent(user_agent.to_string())
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .ok()?;
    let resp = send_with_outbound_policy(
        &client,
        reqwest::Method::HEAD,
        url.clone(),
        |client, method, url| client.request(method, url),
    )
    .await
    .ok()?;
    let status = resp.status();
    if status == StatusCode::METHOD_NOT_ALLOWED || status == StatusCode::NOT_IMPLEMENTED {
        let resp = send_with_outbound_policy(
            &client,
            reqwest::Method::GET,
            url.clone(),
            |client, method, url| client.request(method, url),
        )
        .await
        .ok()?;
        return Some(resp.status().as_u16());
    }
    Some(status.as_u16())
}
