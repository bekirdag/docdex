pub use crate::orchestrator::web_policy::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

use once_cell::sync::Lazy;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use thiserror::Error;
use tokio::sync::Semaphore;
use url::{Host, Url};

const OUTBOUND_DNS_TIMEOUT: Duration = Duration::from_secs(3);
const OUTBOUND_DNS_MAX_CONCURRENCY: usize = 16;
static OUTBOUND_DNS_SEMAPHORE: Lazy<Arc<Semaphore>> =
    Lazy::new(|| Arc::new(Semaphore::new(OUTBOUND_DNS_MAX_CONCURRENCY)));
pub const MAX_OUTBOUND_REDIRECTS: usize = 5;

#[derive(Clone, Debug, Default)]
pub struct PublicDnsResolver;

impl Resolve for PublicDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().trim_end_matches('.').to_string();
        Box::pin(async move {
            if is_local_or_reserved_hostname(&host) {
                return Err(Box::new(OutboundUrlError::LocalHostname)
                    as Box<dyn std::error::Error + Send + Sync>);
            }
            let addresses = resolve_socket_addresses_bounded(host, 0)
                .await
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            let ips = addresses
                .iter()
                .map(std::net::SocketAddr::ip)
                .collect::<Vec<_>>();
            validate_resolved_addresses(&ips)
                .map_err(|err| Box::new(err) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}

pub fn public_dns_resolver() -> Arc<PublicDnsResolver> {
    Arc::new(PublicDnsResolver)
}

/// A stable, fail-closed error for outbound URL policy decisions.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum OutboundUrlError {
    #[error("outbound URL is invalid")]
    InvalidUrl,
    #[error("outbound URL must use http or https")]
    UnsupportedScheme,
    #[error("outbound URL must not contain credentials")]
    CredentialsNotAllowed,
    #[error("outbound URL must include a host")]
    MissingHost,
    #[error("outbound URL uses a local or reserved hostname")]
    LocalHostname,
    #[error("outbound URL resolves to a non-public address")]
    NonPublicAddress,
    #[error("outbound URL host could not be resolved")]
    DnsResolutionFailed,
    #[error("outbound URL host resolution timed out")]
    DnsResolutionTimedOut,
    #[error("cross-host browser request is not allowed for a DNS-pinned session")]
    CrossHostBrowserRequest,
    #[error("browser scraping only permits read-only GET and HEAD requests")]
    UnsafeBrowserMethod,
}

#[derive(Debug, Error)]
pub enum OutboundRequestError {
    #[error(transparent)]
    UrlPolicy(#[from] OutboundUrlError),
    #[error("outbound request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("outbound redirect location is invalid")]
    InvalidRedirect,
    #[error("outbound request exceeded the redirect limit")]
    TooManyRedirects,
}

/// Parse and fully validate an outbound URL, including its current DNS answers.
pub async fn parse_and_validate_outbound_url(raw: &str) -> Result<Url, OutboundUrlError> {
    let url = parse_outbound_url(raw)?;
    validate_outbound_url(&url).await?;
    Ok(url)
}

pub fn parse_outbound_url(raw: &str) -> Result<Url, OutboundUrlError> {
    if raw_authority_contains_credentials(raw) {
        return Err(OutboundUrlError::CredentialsNotAllowed);
    }
    let url = Url::parse(raw).map_err(|_| OutboundUrlError::InvalidUrl)?;
    validate_outbound_url_structure(&url)?;
    Ok(url)
}

/// Validate an outbound URL before a network or browser request is started.
///
/// DNS is deliberately checked before the request and every returned address must
/// be public. Callers must repeat this check for redirect destinations. The check
/// does not pin the resolver result to a later connection, so it cannot by itself
/// eliminate DNS-rebinding races.
pub async fn validate_outbound_url(url: &Url) -> Result<(), OutboundUrlError> {
    resolve_public_addresses(url).await.map(|_| ())
}

/// Resolve a structurally valid outbound URL and return only public addresses.
/// Callers that control a connector should pin it to one of these addresses.
pub async fn resolve_public_addresses(url: &Url) -> Result<Vec<IpAddr>, OutboundUrlError> {
    validate_outbound_url_structure(url)?;

    match url.host() {
        Some(Host::Ipv4(address)) => return Ok(vec![IpAddr::V4(address)]),
        Some(Host::Ipv6(address)) => return Ok(vec![IpAddr::V6(address)]),
        Some(Host::Domain(_)) => {}
        None => return Err(OutboundUrlError::MissingHost),
    }

    let host = url
        .host_str()
        .ok_or(OutboundUrlError::MissingHost)?
        .trim_end_matches('.')
        .to_string();
    let port = url
        .port_or_known_default()
        .ok_or(OutboundUrlError::UnsupportedScheme)?;
    let addresses = resolve_socket_addresses_bounded(host, port)
        .await?
        .into_iter()
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    validate_resolved_addresses(&addresses)?;
    Ok(addresses)
}

async fn resolve_socket_addresses_bounded(
    host: String,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, OutboundUrlError> {
    let deadline = Instant::now() + OUTBOUND_DNS_TIMEOUT;
    let permit = tokio::time::timeout(
        remaining_dns_budget(deadline),
        Arc::clone(&OUTBOUND_DNS_SEMAPHORE).acquire_owned(),
    )
    .await
    .map_err(|_| OutboundUrlError::DnsResolutionTimedOut)?
    .map_err(|_| OutboundUrlError::DnsResolutionFailed)?;
    let lookup = tokio::task::spawn_blocking(move || {
        // Keep the permit inside the blocking job. Timing out the awaiting task
        // cannot cancel a platform resolver call, so this prevents abandoned
        // lookups from exceeding the global blocking-DNS concurrency bound.
        let _permit = permit;
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|addresses| addresses.collect::<Vec<_>>())
    });
    tokio::time::timeout(remaining_dns_budget(deadline), lookup)
        .await
        .map_err(|_| OutboundUrlError::DnsResolutionTimedOut)?
        .map_err(|_| OutboundUrlError::DnsResolutionFailed)?
        .map_err(|_| OutboundUrlError::DnsResolutionFailed)
}

fn remaining_dns_budget(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or(Duration::ZERO)
}

/// Send a GET/HEAD-style request while validating every redirect before it is
/// contacted. The supplied client must use `reqwest::redirect::Policy::none()`.
pub async fn send_with_outbound_policy<F>(
    client: &reqwest::Client,
    mut method: reqwest::Method,
    mut url: Url,
    build_request: F,
) -> Result<reqwest::Response, OutboundRequestError>
where
    F: Fn(&reqwest::Client, reqwest::Method, Url) -> reqwest::RequestBuilder,
{
    for redirect_count in 0..=MAX_OUTBOUND_REDIRECTS {
        validate_outbound_url(&url).await?;
        let response = build_request(client, method.clone(), url.clone())
            .send()
            .await?;
        validate_outbound_url(response.url()).await?;
        if !response.status().is_redirection() {
            return Ok(response);
        }
        let Some(location) = response.headers().get(reqwest::header::LOCATION) else {
            return Ok(response);
        };
        if redirect_count == MAX_OUTBOUND_REDIRECTS {
            return Err(OutboundRequestError::TooManyRedirects);
        }
        let location = location
            .to_str()
            .map_err(|_| OutboundRequestError::InvalidRedirect)?;
        let next = url
            .join(location)
            .map_err(|_| OutboundRequestError::InvalidRedirect)?;
        validate_outbound_url(&next).await?;
        if response.status() == reqwest::StatusCode::SEE_OTHER && method != reqwest::Method::HEAD {
            method = reqwest::Method::GET;
        }
        url = next;
    }
    Err(OutboundRequestError::TooManyRedirects)
}

/// Validate URL syntax and literal destinations without performing DNS.
pub fn validate_outbound_url_structure(url: &Url) -> Result<(), OutboundUrlError> {
    if !matches!(url.scheme(), "http" | "https") {
        return Err(OutboundUrlError::UnsupportedScheme);
    }
    if has_url_credentials(url) {
        return Err(OutboundUrlError::CredentialsNotAllowed);
    }

    match url.host() {
        Some(Host::Ipv4(address)) => {
            if !is_public_ipv4(address) {
                return Err(OutboundUrlError::NonPublicAddress);
            }
        }
        Some(Host::Ipv6(address)) => {
            if !is_public_ipv6(address) {
                return Err(OutboundUrlError::NonPublicAddress);
            }
        }
        Some(Host::Domain(host)) => {
            if is_local_or_reserved_hostname(host) {
                return Err(OutboundUrlError::LocalHostname);
            }
        }
        None => return Err(OutboundUrlError::MissingHost),
    }
    Ok(())
}

fn has_url_credentials(url: &Url) -> bool {
    if !url.username().is_empty() || url.password().is_some() {
        return true;
    }
    let Some((_, after_scheme)) = url.as_str().split_once("://") else {
        return false;
    };
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

fn raw_authority_contains_credentials(raw: &str) -> bool {
    let Some((_, after_scheme)) = raw.split_once("://") else {
        return false;
    };
    after_scheme
        .split(['/', '?', '#'])
        .next()
        .is_some_and(|authority| authority.contains('@'))
}

pub fn host_matches_blocklist(url: &Url, blocklist: &[String]) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    blocklist.iter().any(|entry| {
        let entry = entry
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        !entry.is_empty() && (host == entry || host.ends_with(&format!(".{entry}")))
    })
}

fn is_local_or_reserved_hostname(raw: &str) -> bool {
    let host = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() || !host.contains('.') {
        return true;
    }
    const RESERVED_SUFFIXES: &[&str] = &[
        "localhost",
        "local",
        "localdomain",
        "internal",
        "intranet",
        "lan",
        "home",
        "home.arpa",
        "corp",
        "test",
        "example",
        "invalid",
    ];
    RESERVED_SUFFIXES
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn validate_resolved_addresses(addresses: &[IpAddr]) -> Result<(), OutboundUrlError> {
    if addresses.is_empty() {
        return Err(OutboundUrlError::DnsResolutionFailed);
    }
    if addresses.iter().any(|address| !is_public_ip(*address)) {
        return Err(OutboundUrlError::NonPublicAddress);
    }
    Ok(())
}

fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    if a == 0 || a == 10 || a == 127 {
        return false;
    }
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    if a == 169 && b == 254 {
        return false;
    }
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    if a == 192 && ((b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99) || b == 168) {
        return false;
    }
    if a == 198 && ((b == 18 || b == 19) || (b == 51 && c == 100)) {
        return false;
    }
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    // 224/4 is multicast and 240/4 is reserved (including limited broadcast).
    a < 224
}

fn is_public_ipv6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }

    let segments = address.segments();
    // The well-known NAT64 prefix embeds an IPv4 destination. Validate that
    // embedded address instead of allowing private IPv4 through a translator.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0
    {
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return is_public_ipv4(embedded);
    }

    // Current ordinary global unicast space is 2000::/3. This also rejects
    // unspecified, loopback, local, link-local, multicast and unallocated space.
    if !(0x2000..=0x3fff).contains(&segments[0]) {
        return false;
    }
    // IETF protocol assignments, 6to4, and current documentation prefixes.
    if (segments[0] == 0x2001 && segments[1] < 0x0200)
        || segments[0] == 0x2002
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0)
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn structure(raw: &str) -> Result<(), OutboundUrlError> {
        let url = Url::parse(raw).map_err(|_| OutboundUrlError::InvalidUrl)?;
        validate_outbound_url_structure(&url)
    }

    #[test]
    fn structure_requires_http_without_credentials() {
        assert_eq!(
            structure("file:///etc/passwd"),
            Err(OutboundUrlError::UnsupportedScheme)
        );
        assert_eq!(
            structure("https://user:secret@example.com/"),
            Err(OutboundUrlError::CredentialsNotAllowed)
        );
        assert_eq!(
            parse_outbound_url("https://@example.com/"),
            Err(OutboundUrlError::CredentialsNotAllowed)
        );
        assert!(structure("https://example.com/path").is_ok());
    }

    #[tokio::test]
    async fn connection_time_resolver_rejects_local_hosts() {
        let name = Name::from_str("localhost").expect("valid DNS name");
        let error = match PublicDnsResolver.resolve(name).await {
            Ok(_) => panic!("local host must be rejected by connector resolver"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("local or reserved hostname"));
    }

    #[test]
    fn structure_rejects_local_and_reserved_hostnames() {
        for raw in [
            "http://localhost/",
            "http://api.localhost./",
            "https://printer.local/",
            "https://metadata.google.internal/",
            "https://service.home.arpa/",
            "https://single-label/",
            "https://example.test/",
        ] {
            assert_eq!(
                structure(raw),
                Err(OutboundUrlError::LocalHostname),
                "{raw}"
            );
        }
    }

    #[test]
    fn structure_rejects_non_public_ipv4_literals_and_numeric_aliases() {
        for raw in [
            "http://0.0.0.0/",
            "http://10.0.0.1/",
            "http://100.64.0.1/",
            "http://127.0.0.1/",
            "http://169.254.169.254/latest/meta-data/",
            "http://172.31.255.255/",
            "http://192.0.2.1/",
            "http://192.168.1.1/",
            "http://198.18.0.1/",
            "http://198.51.100.1/",
            "http://203.0.113.1/",
            "http://224.0.0.1/",
            "http://240.0.0.1/",
            "http://2130706433/",
            "http://0x7f000001/",
        ] {
            assert_eq!(
                structure(raw),
                Err(OutboundUrlError::NonPublicAddress),
                "{raw}"
            );
        }
        assert!(structure("https://93.184.216.34/").is_ok());
    }

    #[test]
    fn structure_rejects_non_public_ipv6_literals() {
        for raw in [
            "http://[::]/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[64:ff9b::a00:1]/",
            "http://[100::1]/",
            "http://[2001:db8::1]/",
            "http://[2002::1]/",
            "http://[3fff::1]/",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
            "http://[ff02::1]/",
        ] {
            assert_eq!(
                structure(raw),
                Err(OutboundUrlError::NonPublicAddress),
                "{raw}"
            );
        }
        assert!(structure("https://[2606:4700:4700::1111]/").is_ok());
    }

    #[tokio::test]
    async fn full_validation_rejects_localhost_before_request() {
        let error = parse_and_validate_outbound_url("http://localhost:8080/")
            .await
            .expect_err("localhost must be blocked");
        assert_eq!(error, OutboundUrlError::LocalHostname);
    }

    #[test]
    fn dns_validation_rejects_mixed_public_and_private_answers() {
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            validate_resolved_addresses(&[public, private]),
            Err(OutboundUrlError::NonPublicAddress)
        );
        assert!(validate_resolved_addresses(&[public]).is_ok());
        assert_eq!(
            validate_resolved_addresses(&[]),
            Err(OutboundUrlError::DnsResolutionFailed)
        );
    }
}
