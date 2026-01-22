use crate::config;
use anyhow::Result;
use std::env;
use std::path::PathBuf;

#[cfg(unix)]
use anyhow::anyhow;
#[cfg(unix)]
use std::fs;

#[cfg(unix)]
mod unix_listener {
    use super::*;
    use axum::Router;
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        service::TowerToHyperService,
    };
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::UnixListener;
    use tower::Service;
    use tracing::{info, warn};

    pub async fn spawn(socket_path: PathBuf, router: Router) -> Result<()> {
        if socket_path.exists() {
            fs::remove_file(&socket_path).map_err(|err| {
                anyhow!(
                    "failed to remove existing mcp ipc socket {}: {err}",
                    socket_path.display()
                )
            })?;
        }
        let listener = UnixListener::bind(&socket_path).map_err(|err| {
            anyhow!(
                "failed to bind mcp ipc socket {}: {err}",
                socket_path.display()
            )
        })?;
        if let Err(err) = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)) {
            warn!(
                target: "docdexd",
                error = ?err,
                socket = %socket_path.display(),
                "failed to set mcp ipc socket permissions"
            );
        }
        let make_service = router.into_make_service();
        info!(
            target: "docdexd",
            socket = %socket_path.display(),
            "mcp ipc unix socket listening"
        );
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let mut make = make_service.clone();
                        tokio::spawn(async move {
                            match make.call(()).await {
                                Ok(service) => {
                                    let io = TokioIo::new(stream);
                                    let hyper_service = TowerToHyperService::new(service);
                                    if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                        TokioExecutor::new(),
                                    )
                                    .serve_connection(io, hyper_service)
                                    .await
                                    {
                                        warn!(
                                            target: "docdexd",
                                            error = ?err,
                                            "mcp ipc unix socket connection failed"
                                        );
                                    }
                                }
                                Err(err) => {
                                    warn!(
                                        target: "docdexd",
                                        error = ?err,
                                        "mcp ipc unix socket service build failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "docdexd",
                            error = ?err,
                            "mcp ipc unix socket accept failed"
                        );
                        break;
                    }
                }
            }
        });
        Ok(())
    }
}

#[cfg(windows)]
mod windows_listener {
    use super::*;
    use axum::Router;
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        service::TowerToHyperService,
    };
    use tokio::net::windows::named_pipe::ServerOptions;
    use tower::Service;
    use tracing::{info, warn};

    pub async fn spawn(pipe_name: String, router: Router) -> Result<()> {
        let make_service = router.into_make_service();
        info!(
            target: "docdexd",
            pipe = %pipe_name,
            "mcp ipc named pipe listening"
        );
        tokio::spawn(async move {
            loop {
                let server = match ServerOptions::new().create(&pipe_name) {
                    Ok(server) => server,
                    Err(err) => {
                        warn!(
                            target: "docdexd",
                            error = ?err,
                            "mcp ipc named pipe bind failed"
                        );
                        break;
                    }
                };
                if let Err(err) = server.connect().await {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        "mcp ipc named pipe accept failed"
                    );
                    continue;
                }
                let mut make = make_service.clone();
                tokio::spawn(async move {
                    match make.call(()).await {
                        Ok(service) => {
                            let io = TokioIo::new(server);
                            let hyper_service = TowerToHyperService::new(service);
                            if let Err(err) =
                                hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                                    .serve_connection(io, hyper_service)
                                    .await
                            {
                                warn!(
                                    target: "docdexd",
                                    error = ?err,
                                    "mcp ipc named pipe connection failed"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                "mcp ipc named pipe service build failed"
                            );
                        }
                    }
                });
            }
        });
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpIpcMode {
    Auto,
    Off,
}

impl McpIpcMode {
    pub fn is_enabled(self) -> bool {
        matches!(self, McpIpcMode::Auto)
    }

    pub fn from_str(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "auto" => Some(McpIpcMode::Auto),
            "off" => Some(McpIpcMode::Off),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpIpcEndpoint {
    UnixSocket(PathBuf),
    WindowsPipe(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpIpcSource {
    Cli,
    Env,
    Config,
    Default,
}

impl McpIpcSource {
    pub fn as_str(self) -> &'static str {
        match self {
            McpIpcSource::Cli => "cli",
            McpIpcSource::Env => "env",
            McpIpcSource::Config => "config",
            McpIpcSource::Default => "default",
        }
    }
}

#[derive(Debug, Clone)]
pub struct McpIpcConfig {
    pub mode: McpIpcMode,
    pub endpoint: Option<McpIpcEndpoint>,
    pub source: McpIpcSource,
    pub explicit: bool,
}

impl McpIpcConfig {
    pub fn is_enabled(&self) -> bool {
        self.mode.is_enabled()
    }

    pub fn requires_bind_success(&self) -> bool {
        self.is_enabled() && self.explicit
    }
}

pub fn resolve_mcp_ipc_config(
    server: &config::ServerConfig,
    cli_mode: Option<McpIpcMode>,
    cli_socket_path: Option<PathBuf>,
    cli_pipe_name: Option<String>,
    create_dirs: bool,
) -> Result<McpIpcConfig> {
    let env_mode = env_mcp_ipc_mode();
    let explicit = cli_mode.is_some()
        || cli_socket_path.is_some()
        || cli_pipe_name.is_some()
        || env_mode.is_some();
    let (mode, source) = if let Some(mode) = cli_mode {
        (mode, McpIpcSource::Cli)
    } else if let Some(mode) = env_mode {
        (mode, McpIpcSource::Env)
    } else if let Some(mode) = McpIpcMode::from_str(&server.mcp_ipc_mode) {
        (mode, McpIpcSource::Config)
    } else {
        (McpIpcMode::Auto, McpIpcSource::Default)
    };

    if mode == McpIpcMode::Off {
        return Ok(McpIpcConfig {
            mode,
            endpoint: None,
            source,
            explicit,
        });
    }

    #[cfg(not(unix))]
    let _ = create_dirs;

    #[cfg(unix)]
    {
        let _ = cli_pipe_name;
        let path = resolve_unix_socket_path(cli_socket_path, &server.mcp_socket_path, create_dirs)?;
        return Ok(McpIpcConfig {
            mode,
            endpoint: Some(McpIpcEndpoint::UnixSocket(path)),
            source,
            explicit,
        });
    }

    #[cfg(windows)]
    {
        let _ = cli_socket_path;
        let pipe = resolve_windows_pipe_name(cli_pipe_name, &server.mcp_pipe_name);
        return Ok(McpIpcConfig {
            mode,
            endpoint: Some(McpIpcEndpoint::WindowsPipe(pipe)),
            source,
            explicit,
        });
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = cli_socket_path;
        let _ = cli_pipe_name;
        Ok(McpIpcConfig {
            mode: McpIpcMode::Off,
            endpoint: None,
            source: McpIpcSource::Default,
            explicit,
        })
    }
}

#[cfg(unix)]
fn resolve_unix_socket_path(
    cli_socket_path: Option<PathBuf>,
    config_socket_path: &str,
    create_dirs: bool,
) -> Result<PathBuf> {
    let path = if let Some(path) = cli_socket_path {
        path
    } else {
        let trimmed = config_socket_path.trim();
        if !trimmed.is_empty() {
            PathBuf::from(trimmed)
        } else {
            default_unix_socket_path()?
        }
    };
    if create_dirs {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                anyhow!(
                    "failed to create mcp socket dir {}: {err}",
                    parent.display()
                )
            })?;
        }
    }
    Ok(path)
}

#[cfg(unix)]
fn default_unix_socket_path() -> Result<PathBuf> {
    if let Some(runtime) = env::var_os("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(runtime).join("docdex").join("mcp.sock"));
    }
    let home = home_dir().ok_or_else(|| anyhow!("unable to resolve home directory"))?;
    Ok(home.join(".docdex").join("run").join("mcp.sock"))
}

#[cfg(windows)]
fn resolve_windows_pipe_name(cli_pipe_name: Option<String>, config_pipe_name: &str) -> String {
    let raw = if let Some(value) = cli_pipe_name {
        value
    } else {
        let trimmed = config_pipe_name.trim();
        if trimmed.is_empty() {
            "docdex-mcp".to_string()
        } else {
            trimmed.to_string()
        }
    };
    normalize_pipe_name(&raw)
}

#[cfg(windows)]
fn normalize_pipe_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with("\\\\.\\pipe\\") {
        trimmed.to_string()
    } else {
        format!("\\\\.\\pipe\\{}", trimmed)
    }
}

#[cfg(unix)]
fn home_dir() -> Option<PathBuf> {
    if let Some(home) = env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    if let Some(home) = env::var_os("USERPROFILE") {
        return Some(PathBuf::from(home));
    }
    let drive = env::var_os("HOMEDRIVE")?;
    let path = env::var_os("HOMEPATH")?;
    Some(PathBuf::from(drive).join(path))
}

fn env_mcp_ipc_mode() -> Option<McpIpcMode> {
    let raw = env::var("DOCDEX_MCP_IPC").ok()?;
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" | "auto" => Some(McpIpcMode::Auto),
        "0" | "false" | "no" | "off" => Some(McpIpcMode::Off),
        _ => None,
    }
}

#[cfg(unix)]
pub async fn spawn_mcp_ipc_listener(router: axum::Router, config: &McpIpcConfig) -> Result<()> {
    if !config.is_enabled() {
        return Ok(());
    }
    let Some(endpoint) = config.endpoint.clone() else {
        return Ok(());
    };
    match endpoint {
        McpIpcEndpoint::UnixSocket(path) => unix_listener::spawn(path, router).await,
        McpIpcEndpoint::WindowsPipe(_) => Ok(()),
    }
}

#[cfg(windows)]
pub async fn spawn_mcp_ipc_listener(router: axum::Router, config: &McpIpcConfig) -> Result<()> {
    if !config.is_enabled() {
        return Ok(());
    }
    let Some(endpoint) = config.endpoint.clone() else {
        return Ok(());
    };
    match endpoint {
        McpIpcEndpoint::WindowsPipe(pipe) => windows_listener::spawn(pipe, router).await,
        McpIpcEndpoint::UnixSocket(_) => Ok(()),
    }
}

#[cfg(not(any(unix, windows)))]
pub async fn spawn_mcp_ipc_listener(_router: axum::Router, _config: &McpIpcConfig) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use parking_lot::ReentrantMutexGuard;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
        _lock: ReentrantMutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let lock = ENV_LOCK.lock();
            let prev = env::var(key).ok();
            env::set_var(key, value);
            Self {
                key,
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(ref value) = self.prev {
                env::set_var(self.key, value);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn default_unix_socket_uses_xdg_runtime_dir() -> Result<()> {
        let temp = TempDir::new()?;
        let _runtime = EnvGuard::set("XDG_RUNTIME_DIR", temp.path().to_string_lossy().as_ref());
        let path = default_unix_socket_path()?;
        assert!(path.ends_with("docdex/mcp.sock"));
        assert!(path.starts_with(temp.path()));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn resolve_unix_socket_path_honors_cli_override() -> Result<()> {
        let temp = TempDir::new()?;
        let socket = temp.path().join("mcp.sock");
        let path = resolve_unix_socket_path(Some(socket.clone()), "", true)?;
        assert_eq!(path, socket);
        assert!(socket.parent().unwrap().exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn resolve_unix_socket_path_skips_dir_creation() -> Result<()> {
        let temp = TempDir::new()?;
        let nested = temp.path().join("subdir").join("mcp.sock");
        let path = resolve_unix_socket_path(Some(nested.clone()), "", false)?;
        assert_eq!(path, nested);
        assert!(!nested.parent().unwrap().exists());
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn normalize_pipe_name_adds_prefix() {
        let name = normalize_pipe_name("docdex-mcp");
        assert_eq!(name, "\\\\.\\pipe\\docdex-mcp");
        let name = normalize_pipe_name("\\\\.\\pipe\\docdex-mcp");
        assert_eq!(name, "\\\\.\\pipe\\docdex-mcp");
    }
}
