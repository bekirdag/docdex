use crate::audit::AuditLogger;
use crate::error::StartupError;
use crate::index::{IndexConfig, Indexer};
use crate::libs;
use crate::memory::MemoryStore;
use crate::metrics;
use crate::ollama::OllamaEmbedder;
use crate::search::{self, AppState, SecurityConfig};
use crate::util;
use crate::watcher;
use anyhow::{anyhow, Context, Result};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use rustls_pemfile;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::{io, sync::Arc};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::{self, pki_types::CertificateDer, pki_types::PrivateKeyDer},
    TlsAcceptor,
};
use tower::Service;
use tracing::{error, info, warn};

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl TlsConfig {
    pub fn from_options(
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
        certbot_domain: Option<String>,
        certbot_live_dir: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        if certbot_domain.is_some() || certbot_live_dir.is_some() {
            if cert.is_some() || key.is_some() {
                return Err(anyhow!(
                    "--certbot-domain/--certbot-live-dir cannot be combined with --tls-cert/--tls-key"
                ));
            }
            let live_dir = match (certbot_live_dir, certbot_domain) {
                (Some(dir), None) => dir,
                (None, Some(domain)) => PathBuf::from("/etc/letsencrypt/live").join(domain),
                (Some(dir), Some(domain)) => dir.join(domain),
                (None, None) => unreachable!("handled by outer check"),
            };
            let cert_path = live_dir.join("fullchain.pem");
            let key_path = live_dir.join("privkey.pem");
            if !cert_path.exists() {
                return Err(anyhow!(
                    "certbot certificate not found at {}",
                    cert_path.display()
                ));
            }
            if !key_path.exists() {
                return Err(anyhow!(
                    "certbot private key not found at {}",
                    key_path.display()
                ));
            }
            return Ok(Some(Self {
                cert_path,
                key_path,
            }));
        }

        match (cert, key) {
            (Some(cert_path), Some(key_path)) => Ok(Some(Self {
                cert_path,
                key_path,
            })),
            (None, None) => Ok(None),
            _ => Err(anyhow!(
                "both --tls-cert and --tls-key must be provided together"
            )),
        }
    }

    fn to_rustls(&self) -> Result<rustls::ServerConfig> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_private_key(&self.key_path)?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .with_context(|| {
                format!(
                    "build TLS config from cert={} key={}",
                    self.cert_path.display(),
                    self.key_path.display()
                )
            })?;
        Ok(config)
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = io::BufReader::new(
        std::fs::File::open(path)
            .with_context(|| format!("open TLS certificate {}", path.display()))?,
    );
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader) {
        certs
            .push(cert.map_err(|err| anyhow!("read certificates from {}: {err}", path.display()))?);
    }
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = io::BufReader::new(
        std::fs::File::open(path)
            .with_context(|| format!("open TLS private key {}", path.display()))?,
    );
    match rustls_pemfile::private_key(&mut reader)
        .map_err(|err| anyhow!("read private key from {}: {err}", path.display()))?
    {
        Some(key) => Ok(key),
        None => Err(anyhow!("no private key found in {}", path.display())),
    }
}

pub fn enter_chroot(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let target = dir
            .canonicalize()
            .with_context(|| format!("resolve chroot dir {}", dir.display()))?;
        if !target.exists() {
            return Err(anyhow!("chroot target {} does not exist", target.display()));
        }
        nix::unistd::chroot(&target)
            .with_context(|| format!("chroot into {}", target.display()))?;
        env::set_current_dir("/").context("chdir to / after chroot")?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(anyhow!("chroot is only supported on Unix platforms"))
    }
}

pub fn apply_privilege_drop(
    run_as_uid: Option<u32>,
    run_as_gid: Option<u32>,
    unshare_net: bool,
) -> Result<()> {
    #[cfg(all(unix, target_os = "linux"))]
    {
        use nix::sched::{unshare, CloneFlags};
        use nix::unistd::{setgid, setuid, Gid, Uid};

        if unshare_net {
            unshare(CloneFlags::CLONE_NEWNET).context("unshare network namespace")?;
        }
        if let Some(gid) = run_as_gid {
            let gid = Gid::from_raw(gid);
            setgid(gid).context("drop to target gid")?;
        }
        if let Some(uid) = run_as_uid {
            let uid = Uid::from_raw(uid);
            setuid(uid).context("drop to target uid")?;
        }
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use nix::unistd::{setgid, setuid, Gid, Uid};
        if unshare_net {
            warn!(
                target: "docdexd",
                "network namespace unshare is only supported on Linux; ignoring --unshare-net"
            );
        }
        if let Some(gid) = run_as_gid {
            let gid = Gid::from_raw(gid);
            setgid(gid).context("drop to target gid")?;
        }
        if let Some(uid) = run_as_uid {
            let uid = Uid::from_raw(uid);
            setuid(uid).context("drop to target uid")?;
        }
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        if run_as_uid.is_some() || run_as_gid.is_some() || unshare_net {
            return Err(anyhow!(
                "privilege dropping is only supported on Unix platforms"
            ));
        }
        Ok(())
    }
}

pub async fn serve(
    repo: PathBuf,
    host: String,
    port: u16,
    log_level: String,
    config: IndexConfig,
    security: SecurityConfig,
    tls: Option<TlsConfig>,
    allow_insecure: bool,
    require_tls: bool,
    access_log: bool,
    audit: Option<AuditLogger>,
    run_as_uid: Option<u32>,
    run_as_gid: Option<u32>,
    unshare_net: bool,
    enable_memory: bool,
    ollama_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
) -> Result<()> {
    #[cfg(unix)]
    {
        if nix::unistd::Uid::effective().is_root() && run_as_uid.is_none() && run_as_gid.is_none() {
            return Err(StartupError::new(
                "startup_refuse_root",
                "refusing to run as root without --run-as-uid/--run-as-gid; provide explicit drop targets",
            )
            .with_hint("Provide `--run-as-uid <uid>` and/or `--run-as-gid <gid>` to drop privileges after startup preparation.")
            .into());
        }
    }
    let repo_display = repo.display().to_string();

    let tls_config = match tls {
        Some(tls) => Some(Arc::new(tls.to_rustls().map_err(|err| {
            StartupError::new("startup_config_invalid", format!("invalid TLS configuration: {err}"))
                .with_hint("Check certificate/key paths and PEM contents (or disable TLS options).")
        })?)),
        None => None,
    };

    apply_privilege_drop(run_as_uid, run_as_gid, unshare_net).map_err(|err| {
        StartupError::new(
            "startup_state_invalid",
            format!("failed to apply privilege drop settings: {err}"),
        )
        .with_hint("On non-Unix platforms, remove --run-as-uid/--run-as-gid/--unshare-net.")
    })?;

    let indexer = Arc::new(Indexer::with_config(repo, config).map_err(|err| {
        if err.downcast_ref::<crate::error::AppError>().is_some() {
            return err;
        }
        StartupError::new(
            "startup_state_invalid",
            format!("failed to initialize state directory/index: {err}"),
        )
        .with_hint("Verify repo/state-dir paths and permissions; consider `--state-dir <path>`.")
        .into()
    })?);
    let libs_indexer = {
        let libs_dir =
            libs::libs_state_dir_from_index_state_dir(indexer.repo_root(), indexer.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir)
            .ok()
            .flatten()
            .map(Arc::new)
    };
    let memory = if enable_memory {
        let model = embedding_model.trim().to_string();
        if model.is_empty() {
            return Err(StartupError::new(
                "startup_config_invalid",
                "--embedding-model must not be empty when memory is enabled",
            )
            .with_hint("Set --embedding-model (or DOCDEX_EMBEDDING_MODEL) to an Ollama embedding model identifier.")
            .into());
        }
        let timeout = Duration::from_millis(embedding_timeout_ms.max(1));
        let embedder = OllamaEmbedder::new(ollama_base_url, model.clone(), timeout).map_err(|err| {
            StartupError::new(
                "startup_config_invalid",
                format!("invalid embedding base URL: {err}"),
            )
            .with_hint("Expected a URL like http://127.0.0.1:11434")
        })?;
        Some(search::MemoryState {
            store: MemoryStore::new(indexer.state_dir()),
            embedder,
        })
    } else {
        None
    };
    let metrics = Arc::new(metrics::Metrics::default());
    metrics::set_global(metrics.clone());
    let state = AppState {
        indexer: indexer.clone(),
        libs_indexer,
        security,
        access_log,
        audit,
        metrics: metrics.clone(),
        memory,
    };
    watcher::spawn(indexer.clone()).map_err(|err| {
        StartupError::new(
            "startup_state_invalid",
            format!("failed to start file watcher: {err}"),
        )
        .with_hint("Verify the repo path is accessible and not on an unsupported filesystem.")
    })?;

    let ip = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<IpAddr>().map_err(|_| {
            StartupError::new(
                "startup_config_invalid",
                format!("invalid --host value `{host}`: expected an IP address"),
            )
            .with_hint("Use `127.0.0.1` (default) or a specific interface IP like `0.0.0.0`.")
        })?
    };
    let is_loopback = ip.is_loopback();
    if require_tls && !is_loopback && tls_config.is_none() && !allow_insecure {
        return Err(StartupError::new(
            "startup_tls_required",
            "refusing to bind on non-loopback without TLS; provide --tls-cert/--tls-key or --insecure to allow plain HTTP",
        )
        .with_hint("Provide `--tls-cert/--tls-key`, use `--certbot-domain/--certbot-live-dir`, or (unsafe) pass `--insecure` behind a trusted proxy.")
        .into());
    }
    let addr = SocketAddr::new(ip, port);

    let listener = TcpListener::bind(&addr).await.map_err(|err| {
        StartupError::new("startup_bind_failed", format!("failed to bind {addr}: {err}")).with_hint(
            "If the port is in use, choose another with `--port`; if permission is denied, use an unprivileged port (>=1024).",
        )
    })?;

    // Logging is intentionally initialised only after startup validation + bind succeed so
    // startup failures emit a single structured error without interleaved log lines.
    util::init_logging(&log_level)?;

    if !is_loopback {
        warn!(
            target: "docdexd",
            host = %host,
            port,
            tls = %tls_config.as_ref().map(|_| "enabled").unwrap_or("disabled"),
            insecure = allow_insecure,
            require_tls,
            "binding on non-loopback interface; ensure network access is restricted"
        );
        if !require_tls && tls_config.is_none() {
            warn!(
                target: "docdexd",
                host = %host,
                port,
                "TLS enforcement disabled on non-loopback bind; run behind a trusted proxy"
            );
        }
    }
    let router = search::router(state);
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    info!(
        target: "docdexd",
        repo = %repo_display,
        host = %host,
        port,
        "listening on {addr}"
    );
    if let Some(tls_config) = tls_config.clone() {
        let tls_acceptor = TlsAcceptor::from(tls_config);
        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let acceptor = tls_acceptor.clone();
            let svc = make_service.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        let mut make = svc;
                        match make.call(remote_addr).await {
                            Ok(service) => {
                                let hyper_service = TowerToHyperService::new(service);
                                if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                    TokioExecutor::new(),
                                )
                                .serve_connection(io, hyper_service)
                                .await
                                {
                                    warn!(target: "docdexd", error = ?err, client = %remote_addr, "tls connection failed");
                                }
                            }
                            Err(err) => {
                                warn!(target: "docdexd", error = ?err, client = %remote_addr, "failed to build service");
                            }
                        }
                    }
                    Err(err) => {
                        warn!(target: "docdexd", error = ?err, client = %remote_addr, "tls accept failed");
                    }
                }
            });
        }
    }
    let result = axum::serve(listener, make_service).await;
    match result {
        Ok(()) => {
            info!(
                target: "docdexd",
                repo = %repo_display,
                host = %host,
                port,
                "docdex daemon shut down gracefully"
            );
            Ok(())
        }
        Err(err) => {
            error!(
                target: "docdexd",
                repo = %repo_display,
                host = %host,
                port,
                error = ?err,
                "docdex daemon terminated with error"
            );
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const RSA_PKCS1_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANUee5GgCjqHEzWL
tMMq4ER76GyKDNMfY7F0VqkorzNpFBrG9muvKfZD/TvknitNkpbSnSJKQNYl97zS
OrvOMkak26EkWoWjjCrhwxm4oV1WrXt699r279A2tFQ2HyrbGcLoHI/iMVKmGU4J
zpYxKgQp5p4SbZiWLwRQVQqf3iBXAgMBAAECgYBfdmQLexCZ3t9v4MB7m70RcB9Q
XxYXi7vwRRh8dUjlUnA6/lxrJ+837ISGS4W+B+VdwcG5FmGsix1JazH75gUGZmNh
hI3ejlYaDlCaCQAqTLNL0y9a3N6O/2rb6dR6QuOMo3+yDb52DCC1kXGqmPEgzcAn
FvLyoq/Q9BIgy9oP4QJBAPQ5m3I/WA5zIRQdrKAgk/lQ1RI1WTmH9psb3uV7d1Tl
lDueYDToW+Ma1+bUqVkWns7BFGtT+Ik/k4XllhkhuAsCQQDfZPHHUeGJnaghM1vH
u1MtLP8XxUeN9By9GeB3h5XhQ+sUnPk/ipQ7YhHvtMnVouuyadRgy3mzaAgBfMXI
0AxlAkEAu3lNPlIpwk3WYp602OapMIVASo3xRBx+zWqDnB0+6UiilXFp4LNNdfQx
L9ynct/OYGAO0KTQ8GqBUBOBOSGNKQJBAKIzqD3iHRGP0IDyyoQ2ZolZr4qx6meO
xMMlI8+GOfRLHUhlRbC2TTTk20MiEJ624c40e0kg1KfING/oCa/qJ+UCQCiS+Isg
cUYCAn9PPJZDQP9LU4l6qeuEAoATKyuWprc/TceQyn6gmk1ObjxchTsMq+/z1FQk
HPNvqmQsrqx0Rc0=
-----END PRIVATE KEY-----"#;

    #[test]
    fn from_options_requires_both_manual_paths() {
        let err =
            TlsConfig::from_options(Some(PathBuf::from("cert.pem")), None, None, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("both --tls-cert and --tls-key must be provided together"));
    }

    #[test]
    fn certbot_live_dir_paths_are_used() {
        let temp = TempDir::new().unwrap();
        let live = temp.path().join("live");
        fs::create_dir_all(&live).unwrap();
        let cert_path = live.join("fullchain.pem");
        let key_path = live.join("privkey.pem");
        fs::write(&cert_path, "dummy cert").unwrap();
        fs::write(&key_path, RSA_PKCS1_KEY).unwrap();

        let tls = TlsConfig::from_options(None, None, None, Some(live.clone()))
            .expect("certbot live dir should configure tls")
            .expect("tls should be present");
        assert_eq!(tls.cert_path, cert_path);
        assert_eq!(tls.key_path, key_path);
    }

    #[test]
    fn pkcs1_keys_are_supported() {
        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("rsa.pem");
        fs::write(&key_path, RSA_PKCS1_KEY).unwrap();
        load_private_key(&key_path).expect("pkcs1 key should parse");
    }
}
