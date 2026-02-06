use crate::cli::McpAddTransport;
use crate::config;
use crate::ipc::mcp_ipc;
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use toml::map::Map as TomlMap;
use toml::Value as TomlValue;

const DEFAULT_MCP_BASE_URL: &str = "http://127.0.0.1:28491";

fn home_dir() -> Result<PathBuf> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let value = std::env::var(key).with_context(|| format!("{key} not set"))?;
    Ok(PathBuf::from(value))
}

fn app_data_dir() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

#[derive(Debug, Clone)]
pub(crate) struct McpEndpointInfo {
    pub(crate) base_url: String,
    pub(crate) running: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct McpEndpointUrls {
    pub(crate) sse_url: String,
    pub(crate) http_url: String,
}

pub(crate) fn resolve_mcp_endpoint_info() -> McpEndpointInfo {
    if let Ok(Some(metadata)) = crate::daemon::lock::read_running_metadata() {
        return McpEndpointInfo {
            base_url: format!("http://127.0.0.1:{}", metadata.port),
            running: true,
        };
    }
    let base_url = crate::cli::http_client::resolve_base_url()
        .unwrap_or_else(|_| DEFAULT_MCP_BASE_URL.to_string());
    McpEndpointInfo {
        base_url,
        running: false,
    }
}

pub(crate) fn mcp_endpoint_urls(base_url: &str) -> McpEndpointUrls {
    let base = base_url.trim_end_matches('/');
    McpEndpointUrls {
        sse_url: format!("{base}/v1/mcp/sse"),
        http_url: format!("{base}/v1/mcp"),
    }
}

fn mcp_add_banner_lines(info: &McpEndpointInfo) -> Vec<String> {
    let urls = mcp_endpoint_urls(&info.base_url);
    let mut lines = Vec::new();
    lines.push(format!(
        "[docdexd mcp-add] Shared MCP endpoint (HTTP/SSE): {}",
        urls.sse_url
    ));
    lines.push(format!(
        "[docdexd mcp-add] MCP JSON-RPC endpoint: {}",
        urls.http_url
    ));
    if !info.running {
        lines.push(format!(
            "[docdexd mcp-add] Daemon not running. Start it with: docdexd daemon"
        ));
        lines.push(format!(
            "[docdexd mcp-add] Default MCP base URL: {}",
            info.base_url
        ));
    }
    lines
}

fn print_mcp_add_banner(info: &McpEndpointInfo) {
    for line in mcp_add_banner_lines(info) {
        println!("{line}");
    }
}

pub(crate) fn run(
    agent: String,
    transport: McpAddTransport,
    repo: Option<PathBuf>,
    remove: bool,
    all: bool,
) -> Result<()> {
    let repo_root = repo
        .unwrap_or(std::env::current_dir().context("determine current directory")?)
        .canonicalize()
        .context("resolve repo root")?;
    let endpoint_info = resolve_mcp_endpoint_info();
    let urls = mcp_endpoint_urls(&endpoint_info.base_url);
    let mut ipc_config = None;
    if transport == McpAddTransport::Ipc {
        let config = config::AppConfig::load_default().unwrap_or_default();
        ipc_config = Some(
            mcp_ipc::resolve_mcp_ipc_config(
                &config.server,
                Some(mcp_ipc::McpIpcMode::Auto),
                None,
                None,
                false,
            )
            .context("resolve mcp ipc config")?,
        );
    }
    if !remove {
        print_mcp_add_banner(&endpoint_info);
    }
    let targets: Vec<&str> = if all {
        vec![
            "codex",
            "continue",
            "cline",
            "cursor-cli",
            "cursor",
            "claude-cli",
            "claude",
            "droid",
            "factory",
            "gemini",
            "windsurf",
            "roo",
            "pearai",
            "void",
            "zed",
            "vscode",
            "amp",
            "forge",
            "copilot",
            "warp",
            "grok",
        ]
    } else {
        vec![agent.as_str()]
    };
    for target in targets {
        let installed = agent_available(target, &repo_root);
        println!(
            "[docdexd mcp-add] {} {}",
            if remove { "removing from" } else { "adding to" },
            target
        );
        handle_mcp_add(
            target,
            &repo_root,
            &urls,
            transport,
            ipc_config.as_ref(),
            remove,
            installed,
        )?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        codex_entry_http, codex_entry_ipc, mcp_add_banner_lines, upsert_codex_config,
        McpEndpointInfo,
    };
    use std::fs;
    use tempfile::TempDir;
    use toml::Value as TomlValue;

    #[test]
    fn mcp_add_banner_includes_http_endpoints() {
        let info = McpEndpointInfo {
            base_url: "http://127.0.0.1:4000".to_string(),
            running: true,
        };
        let lines = mcp_add_banner_lines(&info);
        assert!(lines
            .iter()
            .any(|line| line.contains("http://127.0.0.1:4000/v1/mcp/sse")));
        assert!(lines
            .iter()
            .any(|line| line.contains("http://127.0.0.1:4000/v1/mcp")));
        assert!(!lines.iter().any(|line| line.contains("Start it with")));
    }

    #[test]
    fn mcp_add_banner_includes_start_hint_when_not_running() {
        let info = McpEndpointInfo {
            base_url: "http://127.0.0.1:28491".to_string(),
            running: false,
        };
        let lines = mcp_add_banner_lines(&info);
        assert!(lines
            .iter()
            .any(|line| line.contains("Default MCP base URL")));
        assert!(lines
            .iter()
            .any(|line| { line.contains("Start it with") && line.contains("docdexd daemon") }));
    }

    #[test]
    fn codex_config_writes_http_entry() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        upsert_codex_config(&path, codex_entry_http("http://127.0.0.1:28491/v1/mcp"))?;
        let data = fs::read_to_string(&path)?;
        let root: TomlValue = toml::from_str(&data)?;
        let mcp_servers = root
            .get("mcp_servers")
            .and_then(|v| v.as_table())
            .ok_or("missing mcp_servers")?;
        let docdex = mcp_servers
            .get("docdex")
            .and_then(|v| v.as_table())
            .ok_or("missing docdex entry")?;
        assert_eq!(
            docdex.get("url").and_then(|v| v.as_str()),
            Some("http://127.0.0.1:28491/v1/mcp")
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn codex_config_writes_ipc_socket_entry() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let entry = codex_entry_ipc(&crate::ipc::mcp_ipc::McpIpcEndpoint::UnixSocket(
            "/tmp/docdex-mcp.sock".into(),
        ));
        upsert_codex_config(&path, entry)?;
        let data = fs::read_to_string(&path)?;
        let root: TomlValue = toml::from_str(&data)?;
        let mcp_servers = root
            .get("mcp_servers")
            .and_then(|v| v.as_table())
            .ok_or("missing mcp_servers")?;
        let docdex = mcp_servers
            .get("docdex")
            .and_then(|v| v.as_table())
            .ok_or("missing docdex entry")?;
        assert_eq!(
            docdex.get("transport").and_then(|v| v.as_str()),
            Some("ipc")
        );
        assert_eq!(
            docdex.get("socket_path").and_then(|v| v.as_str()),
            Some("/tmp/docdex-mcp.sock")
        );
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn codex_config_writes_ipc_pipe_entry() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let path = dir.path().join("config.toml");
        let entry = codex_entry_ipc(&crate::ipc::mcp_ipc::McpIpcEndpoint::WindowsPipe(
            "\\\\.\\pipe\\docdex-mcp".to_string(),
        ));
        upsert_codex_config(&path, entry)?;
        let data = fs::read_to_string(&path)?;
        let root: TomlValue = toml::from_str(&data)?;
        let mcp_servers = root
            .get("mcp_servers")
            .and_then(|v| v.as_table())
            .ok_or("missing mcp_servers")?;
        let docdex = mcp_servers
            .get("docdex")
            .and_then(|v| v.as_table())
            .ok_or("missing docdex entry")?;
        assert_eq!(
            docdex.get("transport").and_then(|v| v.as_str()),
            Some("ipc")
        );
        assert_eq!(
            docdex.get("pipe_name").and_then(|v| v.as_str()),
            Some("\\\\.\\pipe\\docdex-mcp")
        );
        Ok(())
    }
}

fn continue_config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = Path::new(&home).join(".continue").join("config.json");
    Ok(path)
}

fn codex_config_path() -> Result<PathBuf> {
    let home = home_dir()?;
    Ok(home.join(".codex").join("config.toml"))
}

fn config_paths_for_agent(agent: &str) -> Result<Vec<PathBuf>> {
    let home = home_dir()?;
    let app_data = app_data_dir();
    let mut paths = Vec::new();
    if cfg!(windows) {
        let app_data = app_data.context("APPDATA not set")?;
        match agent {
            "cursor" => {
                paths.push(home.join(".cursor").join("mcp.json"));
            }
            "windsurf" => {
                paths.push(
                    home.join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
                );
            }
            "vscode" => {
                paths.push(app_data.join("Code").join("User").join("mcp.json"));
            }
            "roo" => {
                paths.push(
                    app_data
                        .join("Code")
                        .join("User")
                        .join("globalStorage")
                        .join("rooveterinaryinc.roo-cline")
                        .join("settings")
                        .join("mcp_settings.json"),
                );
            }
            "pearai" => {
                paths.push(home.join(".kiro").join("settings").join("mcp.json"));
                paths.push(home.join(".pearai").join("mcp.json"));
            }
            "void" => {
                paths.push(app_data.join("Void").join("mcp.json"));
            }
            "zed" => {
                paths.push(app_data.join("Zed").join("settings.json"));
            }
            _ => {}
        }
    } else if cfg!(target_os = "macos") {
        match agent {
            "cursor" => {
                paths.push(home.join(".cursor").join("mcp.json"));
            }
            "windsurf" => {
                paths.push(
                    home.join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
                );
            }
            "vscode" => {
                paths.push(
                    home.join("Library")
                        .join("Application Support")
                        .join("Code")
                        .join("User")
                        .join("mcp.json"),
                );
            }
            "roo" => {
                paths.push(
                    home.join("Library")
                        .join("Application Support")
                        .join("Code")
                        .join("User")
                        .join("globalStorage")
                        .join("rooveterinaryinc.roo-cline")
                        .join("settings")
                        .join("mcp_settings.json"),
                );
            }
            "pearai" => {
                paths.push(home.join(".kiro").join("settings").join("mcp.json"));
                paths.push(home.join(".config").join("pearai").join("mcp.json"));
            }
            "void" => {
                paths.push(
                    home.join("Library")
                        .join("Application Support")
                        .join("Void")
                        .join("mcp.json"),
                );
            }
            "zed" => {
                paths.push(home.join(".config").join("zed").join("settings.json"));
            }
            _ => {}
        }
    } else {
        match agent {
            "cursor" => {
                paths.push(home.join(".cursor").join("mcp.json"));
            }
            "windsurf" => {
                paths.push(
                    home.join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
                );
            }
            "vscode" => {
                paths.push(
                    home.join(".config")
                        .join("Code")
                        .join("User")
                        .join("mcp.json"),
                );
            }
            "roo" => {
                paths.push(
                    home.join(".config")
                        .join("Code")
                        .join("User")
                        .join("globalStorage")
                        .join("rooveterinaryinc.roo-cline")
                        .join("settings")
                        .join("mcp_settings.json"),
                );
            }
            "pearai" => {
                paths.push(home.join(".kiro").join("settings").join("mcp.json"));
                paths.push(home.join(".config").join("pearai").join("mcp.json"));
            }
            "void" => {
                paths.push(home.join(".config").join("Void").join("mcp.json"));
            }
            "zed" => {
                paths.push(home.join(".config").join("zed").join("settings.json"));
            }
            _ => {}
        }
    }
    Ok(paths)
}

fn upsert_mcp_url_entry(path: &Path, url: &str) -> Result<()> {
    let mut contents = json!({});
    if path.exists() {
        let data = fs::read_to_string(path)?;
        contents = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
    }
    let obj = contents
        .as_object_mut()
        .ok_or_else(|| anyhow!("config root is not an object"))?;
    if let Some(mcp_servers) = obj.get_mut("mcpServers").and_then(|v| v.as_array_mut()) {
        let idx = mcp_servers.iter().position(|entry| {
            entry
                .get("name")
                .and_then(|value| value.as_str())
                .map(|name| name == "docdex")
                .unwrap_or(false)
        });
        let entry = json!({
            "name": "docdex",
            "url": url
        });
        if let Some(idx) = idx {
            mcp_servers[idx] = entry;
        } else {
            mcp_servers.push(entry);
        }
    } else {
        let key = if obj.get("mcpServers").and_then(|v| v.as_object()).is_some() {
            "mcpServers"
        } else if obj.get("mcp_servers").and_then(|v| v.as_object()).is_some() {
            "mcp_servers"
        } else {
            "mcpServers"
        };
        let mcp_servers = obj
            .entry(key)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| anyhow!("{key} is not an object"))?;
        mcp_servers.insert(
            "docdex".to_string(),
            json!({
                "url": url
            }),
        );
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let pretty = serde_json::to_string_pretty(&contents)?;
    fs::write(path, pretty)?;
    Ok(())
}

fn remove_mcp_entry(path: &Path, warn_only: bool) -> Result<()> {
    if !path.exists() {
        if warn_only {
            return Ok(());
        }
        return Err(anyhow!("config file not found: {}", path.display()));
    }
    let data = fs::read_to_string(path)?;
    let mut contents: serde_json::Value = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
    if let Some(obj) = contents.as_object_mut() {
        if let Some(mcp_servers) = obj.get_mut("mcpServers").and_then(|v| v.as_array_mut()) {
            mcp_servers.retain(|entry| {
                entry
                    .get("name")
                    .and_then(|value| value.as_str())
                    .map(|name| name != "docdex")
                    .unwrap_or(true)
            });
            let pretty = serde_json::to_string_pretty(&contents)?;
            fs::write(path, pretty)?;
            return Ok(());
        }
        for key in ["mcpServers", "mcp_servers"] {
            if let Some(mcp_servers) = obj.get_mut(key).and_then(|v| v.as_object_mut()) {
                mcp_servers.remove("docdex");
                let pretty = serde_json::to_string_pretty(&contents)?;
                fs::write(path, pretty)?;
                return Ok(());
            }
        }
    }
    if warn_only {
        Ok(())
    } else {
        Err(anyhow!("mcpServers.docdex not found in {}", path.display()))
    }
}

fn upsert_zed_entry(path: &Path, url: &str) -> Result<()> {
    let mut contents = json!({});
    if path.exists() {
        let data = fs::read_to_string(path)?;
        contents = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
    }
    let obj = contents
        .as_object_mut()
        .ok_or_else(|| anyhow!("config root is not an object"))?;
    let mcp_servers = obj
        .entry("experimental_mcp_servers")
        .or_insert_with(|| json!({}))
        .as_object_mut()
        .ok_or_else(|| anyhow!("experimental_mcp_servers is not an object"))?;
    mcp_servers.insert(
        "docdex".to_string(),
        json!({
            "url": url
        }),
    );
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let pretty = serde_json::to_string_pretty(&contents)?;
    fs::write(path, pretty)?;
    Ok(())
}

fn remove_zed_entry(path: &Path, warn_only: bool) -> Result<()> {
    if !path.exists() {
        if warn_only {
            return Ok(());
        }
        return Err(anyhow!("config file not found: {}", path.display()));
    }
    let data = fs::read_to_string(path)?;
    let mut contents: serde_json::Value = serde_json::from_str(&data).unwrap_or_else(|_| json!({}));
    if let Some(obj) = contents.as_object_mut() {
        if let Some(mcp_servers) = obj
            .get_mut("experimental_mcp_servers")
            .and_then(|v| v.as_object_mut())
        {
            mcp_servers.remove("docdex");
            let pretty = serde_json::to_string_pretty(&contents)?;
            fs::write(path, pretty)?;
            return Ok(());
        }
    }
    if warn_only {
        Ok(())
    } else {
        Err(anyhow!(
            "experimental_mcp_servers.docdex not found in {}",
            path.display()
        ))
    }
}

fn codex_entry_http(url: &str) -> TomlMap<String, TomlValue> {
    let mut entry = TomlMap::new();
    entry.insert("url".to_string(), TomlValue::String(url.to_string()));
    entry
}

fn codex_entry_ipc(endpoint: &mcp_ipc::McpIpcEndpoint) -> TomlMap<String, TomlValue> {
    let mut entry = TomlMap::new();
    entry.insert(
        "transport".to_string(),
        TomlValue::String("ipc".to_string()),
    );
    match endpoint {
        mcp_ipc::McpIpcEndpoint::UnixSocket(path) => {
            entry.insert(
                "socket_path".to_string(),
                TomlValue::String(path.to_string_lossy().to_string()),
            );
        }
        mcp_ipc::McpIpcEndpoint::WindowsPipe(pipe) => {
            entry.insert("pipe_name".to_string(), TomlValue::String(pipe.to_string()));
        }
    }
    entry
}

fn upsert_codex_config(path: &Path, docdex_entry: TomlMap<String, TomlValue>) -> Result<()> {
    let mut root: TomlValue = if path.exists() {
        let data = fs::read_to_string(path)?;
        toml::from_str(&data).unwrap_or_else(|_| TomlValue::Table(TomlMap::new()))
    } else {
        TomlValue::Table(TomlMap::new())
    };
    let table = root
        .as_table_mut()
        .ok_or_else(|| anyhow!("codex config root is not a table"))?;
    let mut mcp_table = TomlMap::new();
    if let Some(existing) = table.remove("mcp_servers") {
        match existing {
            TomlValue::Table(existing) => {
                mcp_table = existing;
            }
            TomlValue::Array(entries) => {
                for entry in entries {
                    let Some(entry_table) = entry.as_table() else {
                        continue;
                    };
                    let Some(name) = entry_table.get("name").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let mut cleaned = entry_table.clone();
                    cleaned.remove("name");
                    mcp_table.insert(name.to_string(), TomlValue::Table(cleaned));
                }
            }
            _ => {}
        }
    }
    mcp_table.insert("docdex".to_string(), TomlValue::Table(docdex_entry));
    table.insert("mcp_servers".to_string(), TomlValue::Table(mcp_table));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let payload = toml::to_string_pretty(&root)?;
    fs::write(path, payload)?;
    Ok(())
}

fn remove_codex_config(path: &Path, warn_only: bool) -> Result<()> {
    if !path.exists() {
        if warn_only {
            return Ok(());
        }
        return Err(anyhow!("config file not found: {}", path.display()));
    }
    let data = fs::read_to_string(path)?;
    let mut root: TomlValue =
        toml::from_str(&data).unwrap_or_else(|_| TomlValue::Table(TomlMap::new()));
    let table = root
        .as_table_mut()
        .ok_or_else(|| anyhow!("codex config root is not a table"))?;
    let mut removed = false;
    let mut remove_section = false;
    if let Some(existing) = table.get_mut("mcp_servers") {
        match existing {
            TomlValue::Table(mcp_table) => {
                removed = mcp_table.remove("docdex").is_some();
                remove_section = mcp_table.is_empty();
            }
            TomlValue::Array(entries) => {
                let before = entries.len();
                entries.retain(|entry| {
                    entry
                        .get("name")
                        .and_then(|value| value.as_str())
                        .map(|name| name != "docdex")
                        .unwrap_or(true)
                });
                removed = before != entries.len();
                remove_section = entries.is_empty();
            }
            _ => {}
        }
    }
    if remove_section {
        table.remove("mcp_servers");
    }
    if !removed {
        if warn_only {
            return Ok(());
        }
        return Err(anyhow!(
            "mcp_servers.docdex not found in {}",
            path.display()
        ));
    }
    let payload = toml::to_string_pretty(&root)?;
    fs::write(path, payload)?;
    Ok(())
}

fn is_cmd_available(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

fn agent_available(agent: &str, repo_root: &Path) -> bool {
    match agent {
        "codex" => codex_config_path().map(|p| p.exists()).unwrap_or(false),
        "cursor" => config_paths_for_agent(agent)
            .map(|paths| paths.iter().any(|path| path.exists()))
            .unwrap_or(false),
        "cursor-cli" => is_cmd_available("cursor"),
        "claude" | "claude-cli" => is_cmd_available("claude"),
        "continue" => continue_config_path().map(|p| p.exists()).unwrap_or(false),
        "cline" => repo_root.join(".vscode").exists(),
        "windsurf" | "roo" | "pearai" | "void" | "zed" => config_paths_for_agent(agent)
            .map(|paths| paths.iter().any(|path| path.exists()))
            .unwrap_or(false),
        "droid" | "factory" => is_cmd_available("droid"),
        "gemini" => is_cmd_available("gemini"),
        "vscode" => config_paths_for_agent(agent)
            .map(|paths| paths.iter().any(|path| path.exists()))
            .unwrap_or(false),
        "amp" => is_cmd_available("amp"),
        "forge" => is_cmd_available("forge"),
        "copilot" => is_cmd_available("copilot"),
        "warp" => is_cmd_available("warp"),
        "grok" => false,
        _ => false,
    }
}

fn handle_mcp_add(
    agent: &str,
    repo_root: &Path,
    urls: &McpEndpointUrls,
    transport: McpAddTransport,
    ipc_config: Option<&mcp_ipc::McpIpcConfig>,
    remove: bool,
    installed: bool,
) -> Result<()> {
    match agent {
        "codex" => {
            if remove {
                let path = codex_config_path()?;
                remove_codex_config(&path, true)?;
                println!(
                    "Removed docdex from Codex config at {} (if it existed)",
                    path.display()
                );
            } else {
                let path = codex_config_path()?;
                let docdex_entry = if transport == McpAddTransport::Ipc {
                    if let Some(config) = ipc_config {
                        if let Some(endpoint) = config.endpoint.as_ref() {
                            codex_entry_ipc(endpoint)
                        } else {
                            println!(
                                "[docdexd mcp-add] IPC transport not supported on this platform; falling back to HTTP for Codex."
                            );
                            codex_entry_http(&urls.http_url)
                        }
                    } else {
                        println!(
                            "[docdexd mcp-add] IPC transport unavailable; falling back to HTTP for Codex."
                        );
                        codex_entry_http(&urls.http_url)
                    }
                } else {
                    codex_entry_http(&urls.http_url)
                };
                upsert_codex_config(&path, docdex_entry)?;
                println!("Added docdex to Codex config at {}", path.display());
            }
        }
        "continue" => {
            let path = continue_config_path()?;
            if remove {
                remove_mcp_entry(&path, false)?;
                println!("Removed docdex from Continue config at {}", path.display());
            } else {
                upsert_mcp_url_entry(&path, &urls.sse_url)?;
                println!("Added docdex to Continue config at {}", path.display());
            }
        }
        "cline" => {
            let path = repo_root.join(".vscode").join("settings.json");
            if remove {
                remove_mcp_entry(&path, true)?;
                println!(
                    "Removed docdex from Cline settings at {} (if it existed)",
                    path.display()
                );
            } else {
                upsert_mcp_url_entry(&path, &urls.sse_url)?;
                println!("Added docdex to Cline settings at {}", path.display());
            }
        }
        "windsurf" | "roo" | "pearai" | "void" => {
            let paths = config_paths_for_agent(agent)?;
            if !installed {
                if paths.is_empty() {
                    println!("{agent}: no config path could be resolved.");
                } else {
                    for path in &paths {
                        println!(
                            "{agent}: create or edit {} and set mcpServers.docdex.url to {}",
                            path.display(),
                            urls.sse_url
                        );
                    }
                }
                return Ok(());
            }
            for path in &paths {
                if remove {
                    remove_mcp_entry(path, true)?;
                    println!(
                        "Removed docdex from {agent} config at {} (if it existed)",
                        path.display()
                    );
                } else {
                    upsert_mcp_url_entry(path, &urls.sse_url)?;
                    println!("Added docdex to {agent} config at {}", path.display());
                }
            }
        }
        "zed" => {
            let paths = config_paths_for_agent(agent)?;
            if !installed {
                if paths.is_empty() {
                    println!("{agent}: no config path could be resolved.");
                } else {
                    for path in &paths {
                        println!(
                            "{agent}: edit {} and set experimental_mcp_servers.docdex.url to {}",
                            path.display(),
                            urls.sse_url
                        );
                    }
                }
                return Ok(());
            }
            for path in &paths {
                if remove {
                    remove_zed_entry(path, true)?;
                    println!(
                        "Removed docdex from {agent} config at {} (if it existed)",
                        path.display()
                    );
                } else {
                    upsert_zed_entry(path, &urls.sse_url)?;
                    println!("Added docdex to {agent} config at {}", path.display());
                }
            }
        }
        "cursor" => {
            let paths = config_paths_for_agent(agent)?;
            if !installed {
                if paths.is_empty() {
                    println!("{agent}: no config path could be resolved.");
                } else {
                    for path in &paths {
                        println!(
                            "{agent}: create or edit {} and set mcpServers.docdex.url to {}",
                            path.display(),
                            urls.sse_url
                        );
                    }
                }
                return Ok(());
            }
            for path in &paths {
                if remove {
                    remove_mcp_entry(path, true)?;
                    println!(
                        "Removed docdex from {agent} config at {} (if it existed)",
                        path.display()
                    );
                } else {
                    upsert_mcp_url_entry(path, &urls.sse_url)?;
                    println!("Added docdex to {agent} config at {}", path.display());
                }
            }
        }
        "cursor-cli" => {
            if installed {
                let mut cmd = std::process::Command::new("cursor");
                if remove {
                    cmd.args(["mcp", "remove", "docdex"]);
                } else {
                    cmd.args(["mcp", "add", "docdex", &urls.sse_url]);
                }
                let status = cmd.status().context("run cursor mcp command")?;
                if status.success() {
                    println!(
                        "Cursor CLI MCP {} complete for repo {}",
                        if remove { "remove" } else { "add" },
                        repo_root.display()
                    );
                } else {
                    println!(
                        "Cursor CLI MCP {} failed with status {}; run manually: cursor mcp {} docdex {}",
                        if remove { "remove" } else { "add" },
                        status,
                        if remove { "remove" } else { "add" },
                        urls.sse_url
                    );
                }
            } else {
                println!(
                    "Cursor CLI not detected; run manually: cursor mcp {} docdex {}",
                    if remove { "remove" } else { "add" },
                    urls.sse_url
                );
            }
        }
        "claude" => {
            if remove {
                println!("Claude Desktop: remove the docdex entry from Developer -> MCP Servers.");
            } else {
                println!(
                    "Claude Desktop: Developer -> MCP Servers -> Add, URL: {}",
                    urls.sse_url
                );
            }
        }
        "claude-cli" => {
            if installed {
                let mut cmd = std::process::Command::new("claude");
                if remove {
                    cmd.args(["mcp", "remove", "docdex"]);
                } else {
                    cmd.args([
                        "mcp",
                        "add",
                        "--transport",
                        "http",
                        "docdex",
                        &urls.http_url,
                    ]);
                }
                let status = cmd.status().context("run claude mcp command")?;
                if status.success() {
                    println!(
                        "Claude CLI MCP {} complete for repo {}",
                        if remove { "remove" } else { "add" },
                        repo_root.display()
                    );
                } else {
                    println!(
                        "Claude CLI MCP {} failed with status {}; run manually: claude mcp {} --transport http docdex {}",
                        if remove { "remove" } else { "add" },
                        status,
                        if remove { "remove" } else { "add" },
                        urls.http_url
                    );
                }
            } else {
                println!(
                    "Claude CLI not detected; run manually: claude mcp {} --transport http docdex {}",
                    if remove { "remove" } else { "add" },
                    urls.http_url
                );
            }
        }
        "droid" | "factory" => {
            if installed && !remove {
                let mut cmd = std::process::Command::new("droid");
                cmd.args(["mcp", "add", "docdex", &urls.sse_url]);
                let status = cmd.status().context("run droid mcp command")?;
                if status.success() {
                    println!("Factory/Kiro MCP add complete for {}", urls.sse_url);
                } else {
                    println!(
                        "Factory/Kiro MCP add failed with status {}; run manually: droid mcp add docdex {}",
                        status, urls.sse_url
                    );
                }
            } else {
                println!(
                    "Factory/Kiro CLI: run manually {} docdex with `droid mcp add docdex {}`",
                    if remove { "remove" } else { "add" },
                    urls.sse_url
                );
            }
        }
        "gemini" => {
            if installed && !remove {
                let mut cmd = std::process::Command::new("gemini");
                cmd.args(["mcp", "add", "docdex", &urls.sse_url]);
                let status = cmd.status().context("run gemini mcp command")?;
                if status.success() {
                    println!("Gemini MCP add complete for {}", urls.sse_url);
                } else {
                    println!(
                        "Gemini MCP add failed with status {}; run manually: gemini mcp add docdex {}",
                        status, urls.sse_url
                    );
                }
            } else {
                println!(
                    "Gemini CLI {} manually: gemini mcp {} docdex {}",
                    if remove { "remove" } else { "add" },
                    if remove { "remove" } else { "add" },
                    urls.sse_url
                );
            }
        }
        "vscode" => {
            let paths = config_paths_for_agent(agent)?;
            if !installed {
                if paths.is_empty() {
                    println!("{agent}: no config path could be resolved.");
                } else {
                    for path in &paths {
                        println!(
                            "{agent}: create or edit {} and set mcpServers.docdex.url to {}",
                            path.display(),
                            urls.sse_url
                        );
                    }
                }
                return Ok(());
            }
            for path in &paths {
                if remove {
                    remove_mcp_entry(path, true)?;
                    println!(
                        "Removed docdex from {agent} config at {} (if it existed)",
                        path.display()
                    );
                } else {
                    upsert_mcp_url_entry(path, &urls.sse_url)?;
                    println!("Added docdex to {agent} config at {}", path.display());
                }
            }
        }
        "amp" => {
            println!(
                "Sourcegraph amp expects HTTP/SSE; register your endpoint: amp mcp add docdex {}",
                urls.sse_url
            );
        }
        "forge" => {
            println!(
                "Forge Code CLI: register docdex with the HTTP/SSE endpoint {}",
                urls.sse_url
            );
        }
        "copilot" => {
            println!(
                "GitHub Copilot CLI: add docdex with HTTP/SSE endpoint {}",
                urls.sse_url
            );
        }
        "warp" => {
            println!("Warp: add docdex in settings pointing to {}", urls.sse_url);
        }
        "grok" => {
            println!(
                "Grok MCP client: register docdex with HTTP/SSE endpoint {}",
                urls.sse_url
            );
        }
        _ => println!("Unsupported agent: {agent}"),
    }
    Ok(())
}
