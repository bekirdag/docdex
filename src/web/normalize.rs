use std::collections::HashSet;

use url::{form_urlencoded, Url};

const TRACKING_PARAMS: [&str; 9] = [
    "fbclid",
    "gclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "msclkid",
    "utm_campaign",
    "utm_medium",
    "utm_source",
];

pub fn normalize_url(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let mut raw = unwrap_ddg_redirect(raw).unwrap_or_else(|| raw.to_string());
    if raw.starts_with("//") {
        raw = format!("https:{raw}");
    }

    let mut url = Url::parse(&raw).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let scheme = url.scheme().to_ascii_lowercase();
    if scheme != url.scheme() {
        url.set_scheme(&scheme).ok()?;
    }
    if let Some(host) = url.host_str() {
        let lower = host.to_ascii_lowercase();
        if lower != host {
            url.set_host(Some(&lower)).ok()?;
        }
    }
    match (url.scheme(), url.port()) {
        ("http", Some(80)) | ("https", Some(443)) => {
            let _ = url.set_port(None);
        }
        _ => {}
    }
    url.set_fragment(None);

    let mut kept: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| !is_tracking_param(key))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    if kept.is_empty() {
        url.set_query(None);
    } else {
        kept.sort();
        let mut serializer = form_urlencoded::Serializer::new(String::new());
        for (key, value) in kept {
            serializer.append_pair(&key, &value);
        }
        let encoded = serializer.finish();
        url.set_query(Some(&encoded));
    }

    Some(url.into_string())
}

pub fn dedupe_urls(urls: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for url in urls {
        if let Some(normalized) = normalize_url(&url) {
            if seen.insert(normalized.clone()) {
                out.push(normalized);
            }
        }
    }
    out
}

pub fn unwrap_ddg_redirect(raw: &str) -> Option<String> {
    let parsed = Url::parse(raw).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();
    if !host.ends_with("duckduckgo.com") {
        return None;
    }
    if !parsed.path().starts_with("/l/") {
        return None;
    }
    for (key, value) in parsed.query_pairs() {
        if key == "uddg" {
            let decoded = value.into_owned();
            if !decoded.is_empty() {
                return Some(decoded);
            }
        }
    }
    None
}

fn is_tracking_param(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    if key.starts_with("utm_") {
        return true;
    }
    TRACKING_PARAMS.iter().any(|param| param == &key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_strips_tracking_and_lowercases_host() {
        let url = "HTTPS://Example.COM/Path?utm_source=foo&b=1";
        let normalized = normalize_url(url).expect("normalized url");
        assert_eq!(normalized, "https://example.com/Path?b=1");
    }

    #[test]
    fn unwrap_ddg_redirect_extracts_target() {
        let url = "https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fdoc%3Futm_source%3Dfoo";
        let normalized = normalize_url(url).expect("normalized");
        assert_eq!(normalized, "https://example.com/doc");
    }

    #[test]
    fn dedupe_urls_keeps_order_and_unique() {
        let urls = vec![
            "https://example.com/?utm_source=a".to_string(),
            "https://example.com/".to_string(),
            "https://example.com/other".to_string(),
        ];
        let deduped = dedupe_urls(urls);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped[0], "https://example.com/");
        assert_eq!(deduped[1], "https://example.com/other");
    }
}
