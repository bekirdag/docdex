use super::{repo_hint_for_command, should_ensure_daemon, Cli, CliMcpIpcMode, Command, ServeArgs};
use crate::config::RepoArgs;
use clap::Parser;
use std::path::PathBuf;
use tempfile::TempDir;

fn repo_args(path: PathBuf) -> RepoArgs {
    RepoArgs {
        repo: path,
        state_dir: None,
        exclude_prefix: Vec::new(),
        exclude_dir: Vec::new(),
        enable_symbol_extraction: true,
    }
}

fn serve_args(repo: RepoArgs) -> ServeArgs {
    ServeArgs {
        repo,
        repo_explicit: false,
        host: None,
        port: None,
        expose: false,
        log: "warn".to_string(),
        tls_cert: None,
        tls_key: None,
        certbot_domain: None,
        certbot_live_dir: None,
        insecure: false,
        require_tls: true,
        auth_token: None,
        preflight_check: false,
        max_limit: 8,
        max_query_bytes: 4096,
        max_request_bytes: 16384,
        rate_limit_per_min: 0,
        rate_limit_burst: 0,
        strip_snippet_html: false,
        secure_mode: true,
        disable_snippet_text: false,
        enable_memory: false,
        agent_id: None,
        enable_mcp: false,
        disable_mcp: false,
        mcp_ipc: None,
        mcp_socket_path: None,
        mcp_pipe_name: None,
        embedding_base_url: None,
        ollama_base_url: "http://127.0.0.1:11434".to_string(),
        embedding_model: "nomic-embed-text".to_string(),
        embedding_timeout_ms: 0,
        access_log: true,
        audit_log_path: None,
        audit_max_bytes: 5_000_000,
        audit_max_files: 5,
        audit_disable: false,
        run_as_uid: None,
        run_as_gid: None,
        chroot_dir: None,
        unshare_net: false,
        allow_ip: Vec::new(),
    }
}

#[test]
fn ensure_daemon_skips_help_only() {
    assert!(!should_ensure_daemon(&Command::HelpAll));
    assert!(should_ensure_daemon(&Command::Check));
}

#[test]
fn ensure_daemon_skips_setup() {
    let cmd = Command::Setup {
        args: super::SetupArgs {
            non_interactive: true,
            json: false,
            force: false,
            auto: false,
            ollama_path: None,
        },
    };
    assert!(!should_ensure_daemon(&cmd));
}

#[test]
fn ensure_daemon_for_index_and_hint() {
    let temp = TempDir::new().expect("temp dir");
    let repo = repo_args(temp.path().to_path_buf());
    let cmd = Command::Index {
        repo: repo.clone(),
        libs_sources: None,
    };
    assert!(should_ensure_daemon(&cmd));
    let hint = repo_hint_for_command(&cmd).expect("repo hint");
    assert_eq!(hint, repo.repo_root());
}

#[test]
fn ensure_daemon_skips_serve() {
    let temp = TempDir::new().expect("temp dir");
    let repo = repo_args(temp.path().to_path_buf());
    let cmd = Command::Serve {
        args: serve_args(repo.clone()),
    };
    assert!(!should_ensure_daemon(&cmd));
    assert!(repo_hint_for_command(&cmd).is_none());
}

#[test]
fn ensure_daemon_for_delegation_savings() {
    let cmd = Command::Delegation {
        command: super::DelegationCommand::Savings { json: true },
    };
    assert!(should_ensure_daemon(&cmd));
    assert!(repo_hint_for_command(&cmd).is_none());
}

#[test]
fn ensure_daemon_skips_delegation_agents() {
    let cmd = Command::Delegation {
        command: super::DelegationCommand::Agents { json: true },
    };
    assert!(!should_ensure_daemon(&cmd));
    assert!(repo_hint_for_command(&cmd).is_none());
}

#[test]
fn parse_mcp_ipc_flag() {
    let cli = Cli::try_parse_from(["docdexd", "serve", "--repo", ".", "--mcp-ipc", "off"])
        .expect("parse");
    match cli.command {
        Command::Serve { args } => {
            assert_eq!(args.mcp_ipc, Some(CliMcpIpcMode::Off));
        }
        _ => panic!("expected serve command"),
    }
}

#[test]
fn parse_dag_export_alias() {
    let cli = Cli::try_parse_from(["docdexd", "dag", "export", "--repo", ".", "session-123"])
        .expect("parse");
    match cli.command {
        Command::Dag { command } => match command {
            super::DagCommand::Export { session_id, .. } => {
                assert_eq!(session_id, "session-123");
            }
            _ => panic!("expected dag export"),
        },
        _ => panic!("expected dag command"),
    }
}

#[test]
fn parse_delegation_savings_command() {
    let cli = Cli::try_parse_from(["docdexd", "delegation", "savings", "--json", "true"])
        .expect("parse");
    match cli.command {
        Command::Delegation { command } => match command {
            super::DelegationCommand::Savings { json } => assert!(json),
            _ => panic!("expected delegation savings command"),
        },
        _ => panic!("expected delegation command"),
    }
}

#[test]
fn parse_delegation_agents_command() {
    let cli = Cli::try_parse_from(["docdexd", "delegation", "agents", "--json"]).expect("parse");
    match cli.command {
        Command::Delegation { command } => match command {
            super::DelegationCommand::Agents { json } => assert!(json),
            _ => panic!("expected delegation agents command"),
        },
        _ => panic!("expected delegation command"),
    }
}
