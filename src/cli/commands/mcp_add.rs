use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use serde_json::json;
use std::fs;
use std::path::Path;
use std::path::PathBuf;

fn home_dir() -> Result<PathBuf> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    let value = std::env::var(key).with_context(|| format!("{key} not set"))?;
    Ok(PathBuf::from(value))
}

fn app_data_dir() -> Option<PathBuf> {
    std::env::var("APPDATA").ok().map(PathBuf::from)
}

pub fn run(
    agent: String,
    repo: Option<PathBuf>,
    max_results: usize,
    log: String,
    remove: bool,
    all: bool,
) -> Result<()> {
    let repo_root = repo
        .unwrap_or(std::env::current_dir().context("determine current directory")?)
        .canonicalize()
        .context("resolve repo root")?;
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
        handle_mcp_add(target, &repo_root, &log, max_results, remove, installed)?;
    }
    Ok(())
}

fn continue_config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let path = Path::new(&home).join(".continue").join("config.json");
    Ok(path)
}

fn config_paths_for_agent(agent: &str) -> Result<Vec<PathBuf>> {
    let home = home_dir()?;
    let app_data = app_data_dir();
    let mut paths = Vec::new();
    if cfg!(windows) {
        let app_data = app_data.context("APPDATA not set")?;
        match agent {
            "windsurf" => {
                paths.push(
                    home.join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
                );
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
            "windsurf" => {
                paths.push(
                    home.join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
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
            "windsurf" => {
                paths.push(
                    home.join(".codeium")
                        .join("windsurf")
                        .join("mcp_config.json"),
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

fn upsert_mcp_entry(path: &Path, command: &str, args: Vec<String>) -> Result<()> {
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
            "command": command,
            "args": args
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
                "command": command,
                "args": args
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

fn upsert_zed_entry(path: &Path, command: &str, args: Vec<String>) -> Result<()> {
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
            "command": command,
            "args": args
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

fn is_cmd_available(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

fn agent_available(agent: &str, repo_root: &Path) -> bool {
    match agent {
        "codex" => is_cmd_available("codex"),
        "cursor" | "cursor-cli" => is_cmd_available("cursor"),
        "claude" | "claude-cli" => is_cmd_available("claude"),
        "continue" => continue_config_path().map(|p| p.exists()).unwrap_or(false),
        "cline" => repo_root.join(".vscode").exists(),
        "windsurf" | "roo" | "pearai" | "void" | "zed" => config_paths_for_agent(agent)
            .map(|paths| paths.iter().any(|path| path.exists()))
            .unwrap_or(false),
        "droid" | "factory" => is_cmd_available("droid"),
        "gemini" => is_cmd_available("gemini"),
        "vscode" => is_cmd_available("code"),
        "amp" => is_cmd_available("amp"),
        "forge" => is_cmd_available("forge"),
        "copilot" => is_cmd_available("copilot"),
        "warp" => is_cmd_available("warp"),
        "grok" => false,
        _ => false,
    }
}

fn stdio_args(repo_root: &Path, log: &str, max_results: usize) -> Vec<String> {
    vec![
        "mcp".to_string(),
        "--repo".to_string(),
        repo_root.display().to_string(),
        "--log".to_string(),
        log.to_string(),
        "--max-results".to_string(),
        max_results.to_string(),
    ]
}

fn handle_mcp_add(
    agent: &str,
    repo_root: &Path,
    log: &str,
    max_results: usize,
    remove: bool,
    installed: bool,
) -> Result<()> {
    match agent {
        "codex" => {
            if !installed {
                println!(
                    "Codex not detected; run manually: codex mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
                return Ok(());
            }
            let mut cmd = std::process::Command::new("codex");
            if remove {
                cmd.args(["mcp", "remove", "docdex"]);
            } else {
                cmd.args([
                    "mcp",
                    "add",
                    "docdex",
                    "--",
                    "docdexd",
                    "mcp",
                    "--repo",
                    &repo_root.display().to_string(),
                    "--log",
                    log,
                    "--max-results",
                    &max_results.to_string(),
                ]);
            }
            let status = cmd.status().context("run codex mcp command")?;
            if status.success() {
                println!(
                    "Codex MCP {} complete for repo {}",
                    if remove { "remove" } else { "add" },
                    repo_root.display()
                );
            } else {
                println!(
                    "Codex MCP {} failed with status {}; run manually: codex mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    status,
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "continue" => {
            let path = continue_config_path()?;
            if remove {
                remove_mcp_entry(&path, false)?;
                println!("Removed docdex from Continue config at {}", path.display());
            } else {
                let args = stdio_args(repo_root, log, max_results);
                upsert_mcp_entry(&path, "docdexd", args)?;
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
                let args = stdio_args(repo_root, log, max_results);
                upsert_mcp_entry(&path, "docdexd", args)?;
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
                            "{agent}: create or edit {} and set mcpServers.docdex to command: docdexd mcp --repo {} --log {} --max-results {}",
                            path.display(),
                            repo_root.display(),
                            log,
                            max_results
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
                    let args = stdio_args(repo_root, log, max_results);
                    upsert_mcp_entry(path, "docdexd", args)?;
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
                            "{agent}: edit {} and set experimental_mcp_servers.docdex to command: docdexd mcp --repo {} --log {} --max-results {}",
                            path.display(),
                            repo_root.display(),
                            log,
                            max_results
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
                    let args = stdio_args(repo_root, log, max_results);
                    upsert_zed_entry(path, "docdexd", args)?;
                    println!("Added docdex to {agent} config at {}", path.display());
                }
            }
        }
        "cursor" => {
            if remove {
                println!(
                    "Cursor UI: remove the MCP server named docdex from Settings -> MCP Servers."
                );
            } else {
                println!(
                    "Cursor UI: add docdex with command: docdexd mcp --repo {} --log {} --max-results {}",
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "cursor-cli" => {
            if installed {
                let mut cmd = std::process::Command::new("cursor");
                if remove {
                    cmd.args(["mcp", "remove", "docdex"]);
                } else {
                    cmd.args([
                        "mcp",
                        "add",
                        "docdex",
                        "--",
                        "docdexd",
                        "mcp",
                        "--repo",
                        &repo_root.display().to_string(),
                        "--log",
                        log,
                        "--max-results",
                        &max_results.to_string(),
                    ]);
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
                        "Cursor CLI MCP {} failed with status {}; run manually: cursor mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                        if remove { "remove" } else { "add" },
                        status,
                        if remove { "remove" } else { "add" },
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Cursor CLI not detected; run manually: cursor mcp {} docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "claude" => {
            if remove {
                println!("Claude Desktop: remove the docdex entry from Developer -> MCP Servers.");
            } else {
                println!(
                    "Claude Desktop: Developer -> MCP Servers -> Add, command: docdexd mcp --repo {} --log {} --max-results {}",
                    repo_root.display(),
                    log,
                    max_results
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
                        "stdio",
                        "docdex",
                        "--",
                        "docdexd",
                        "mcp",
                        "--repo",
                        &repo_root.display().to_string(),
                        "--log",
                        log,
                        "--max-results",
                        &max_results.to_string(),
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
                        "Claude CLI MCP {} failed with status {}; run manually: claude mcp add --transport stdio docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                        if remove { "remove" } else { "add" },
                        status,
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Claude CLI not detected; run manually: claude mcp add --transport stdio docdex -- docdexd mcp --repo {} --log {} --max-results {}",
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "droid" | "factory" => {
            if installed && !remove {
                let mut cmd = std::process::Command::new("droid");
                cmd.args([
                    "mcp",
                    "add",
                    "docdex",
                    &format!(
                        "docdexd mcp --repo {} --log {} --max-results {}",
                        repo_root.display(),
                        log,
                        max_results
                    ),
                ]);
                let status = cmd.status().context("run droid mcp command")?;
                if status.success() {
                    println!(
                        "Factory/Kiro MCP add complete for repo {}",
                        repo_root.display()
                    );
                } else {
                    println!(
                        "Factory/Kiro MCP add failed with status {}; run manually: droid mcp add docdex \"docdexd mcp --repo {} --log {} --max-results {}\"",
                        status,
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Factory/Kiro CLI: run manually {} docdex with `droid mcp add docdex \"docdexd mcp --repo {} --log {} --max-results {}\"`",
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "gemini" => {
            if installed && !remove {
                let mut cmd = std::process::Command::new("gemini");
                cmd.args([
                    "mcp",
                    "add",
                    "docdex",
                    "docdexd",
                    "mcp",
                    "--repo",
                    &repo_root.display().to_string(),
                    "--log",
                    log,
                    "--max-results",
                    &max_results.to_string(),
                ]);
                let status = cmd.status().context("run gemini mcp command")?;
                if status.success() {
                    println!("Gemini MCP add complete for repo {}", repo_root.display());
                } else {
                    println!(
                        "Gemini MCP add failed with status {}; run manually: gemini mcp add docdex docdexd mcp --repo {} --log {} --max-results {}",
                        status,
                        repo_root.display(),
                        log,
                        max_results
                    );
                }
            } else {
                println!(
                    "Gemini CLI {} manually: gemini mcp {} docdex docdexd mcp --repo {} --log {} --max-results {}",
                    if remove { "remove" } else { "add" },
                    if remove { "remove" } else { "add" },
                    repo_root.display(),
                    log,
                    max_results
                );
            }
        }
        "vscode" => {
            let payload = format!(
                "{{\"name\":\"docdex\",\"command\":\"docdexd\",\"args\":[\"mcp\",\"--repo\",\"{}\",\"--log\",\"{}\",\"--max-results\",\"{}\"]}}",
                repo_root.display(),
                log,
                max_results
            );
            if installed && !remove {
                let status = std::process::Command::new("code")
                    .args(["--add-mcp", &payload])
                    .status()
                    .context("run code --add-mcp")?;
                if status.success() {
                    println!("VS Code MCP add complete via CLI.");
                } else {
                    println!(
                        "VS Code CLI add failed with status {}; add manually with `code --add-mcp '{payload}'`",
                        status
                    );
                }
            } else {
                println!(
                    "VS Code CLI {} manually with: code --add-mcp '{}'",
                    if remove { "remove" } else { "add" },
                    payload
                );
            }
        }
        "amp" => {
            println!("Sourcegraph amp expects HTTP/SSE; register your HTTP endpoint, e.g., `amp mcp add docdex http://localhost:5273/.mcp/v1`.");
        }
        "forge" => {
            println!(
                "Forge Code CLI: forge mcp import '[{{\"name\":\"docdex\",\"type\":\"stdio\",\"command\":\"docdexd\",\"args\":[\"mcp\",\"--repo\",\"{}\",\"--log\",\"{}\",\"--max-results\",\"{}\"]}}]'",
                repo_root.display(),
                log,
                max_results
            );
        }
        "copilot" => {
            println!("GitHub Copilot CLI: start a session and run `/mcp add docdex`, command: docdexd mcp --repo {} --log {} --max-results {}", repo_root.display(), log, max_results);
        }
        "warp" => {
            println!("Warp: add docdex in settings pointing to `docdexd mcp --repo {} --log {} --max-results {}`", repo_root.display(), log, max_results);
        }
        "grok" => {
            println!(
                "Grok MCP client: register docdex with command: docdexd mcp --repo {} --log {} --max-results {}",
                repo_root.display(),
                log,
                max_results
            );
        }
        _ => println!("Unsupported agent: {agent}"),
    }
    Ok(())
}
