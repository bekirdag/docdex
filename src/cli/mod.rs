pub mod commands;
pub(crate) mod http_client;

use crate::config;
use crate::config::RepoArgs;
use crate::error::StartupError;
use anyhow::Result;
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use clap::error::ErrorKind;
use serde_json::json;
use std::path::PathBuf;
use std::env;

#[derive(Parser, Debug)]
#[command(
    name = "docdexd",
    version,
    about = "Local documentation index/search daemon",
    long_about = "Docdex indexes plain-text/markdown documentation under a workspace and serves top-k search/snippet results over HTTP or CLI. Defaults store data under ~/.docdex/state (scoped as repos/<repo_id>/index) and avoid common tool caches; override paths and exclusions with --state-dir/--exclude-* or matching env vars. Optional MCP server (`docdexd mcp`) exposes docdex_search/index/files/open/stats tools over stdio for MCP-aware clients; register it in your MCP client as server \"docdex\" with command: docdexd mcp --repo <repo> --log warn."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(ValueEnum, Clone, Copy, Debug)]
#[value(rename_all = "kebab-case")]
pub(crate) enum CliDiffMode {
    #[value(alias = "working_tree")]
    WorkingTree,
    Staged,
    Range,
}

pub(crate) fn cli_local_mode() -> bool {
    match env::var("DOCDEX_CLI_LOCAL").ok().map(|v| v.trim().to_ascii_lowercase()) {
        Some(value)
            if matches!(
                value.as_str(),
                "1" | "true" | "t" | "yes" | "y" | "on"
            ) =>
        {
            true
        }
        _ => false,
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
    /// Validate config, state, and local dependencies for readiness.
    Check,
    /// Serve HTTP API for search/snippets.
    Serve {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Bind host (defaults to server.http_bind_addr in config)"
        )]
        host: Option<String>,
        #[arg(long, help = "Bind port (defaults to server.http_bind_addr in config)")]
        port: Option<u16>,
        #[arg(
            long,
            env = "DOCDEX_EXPOSE",
            default_value_t = false,
            action = ArgAction::SetTrue,
            help = "Allow binding to non-loopback interfaces (requires --auth-token)"
        )]
        expose: bool,
        #[arg(long, default_value = "info")]
        log: String,
        #[arg(
            long,
            env = "DOCDEX_TLS_CERT",
            requires = "tls_key",
            help = "TLS certificate PEM file for HTTPS (requires --tls-key)"
        )]
        tls_cert: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_TLS_KEY",
            requires = "tls_cert",
            help = "TLS private key PEM file for HTTPS (requires --tls-cert)"
        )]
        tls_key: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_CERTBOT_DOMAIN",
            conflicts_with_all = ["tls_cert", "tls_key", "certbot_live_dir"],
            help = "Use certbot live dir at /etc/letsencrypt/live/<domain> for TLS (implies HTTPS)"
        )]
        certbot_domain: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_CERTBOT_LIVE_DIR",
            value_name = "PATH",
            conflicts_with_all = ["tls_cert", "tls_key", "certbot_domain"],
            help = "Use explicit certbot live dir containing fullchain.pem and privkey.pem (implies HTTPS)"
        )]
        certbot_live_dir: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_INSECURE_HTTP",
            default_value_t = false,
            help = "Allow plain HTTP on non-loopback binds (use only behind a trusted proxy)"
        )]
        insecure: bool,
        #[arg(
            long,
            env = "DOCDEX_REQUIRE_TLS",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Require TLS for non-loopback binds (set to false when TLS is already terminated by a trusted proxy)"
        )]
        require_tls: bool,
        #[arg(
            long,
            env = "DOCDEX_AUTH_TOKEN",
            help = "Optional bearer token required on HTTP requests (Authorization: Bearer ...)"
        )]
        auth_token: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_PREFLIGHT_CHECK",
            default_value_t = false,
            action = ArgAction::Set,
            help = "Run `docdexd check` before serving; fail fast on missing dependencies"
        )]
        preflight_check: bool,
        #[arg(
            long,
            env = "DOCDEX_MAX_LIMIT",
            default_value_t = 8,
            help = "Maximum allowed `limit` on search/snippet requests"
        )]
        max_limit: usize,
        #[arg(
            long,
            env = "DOCDEX_MAX_QUERY_BYTES",
            default_value_t = 4096,
            help = "Maximum allowed query string size in bytes"
        )]
        max_query_bytes: usize,
        #[arg(
            long,
            env = "DOCDEX_MAX_REQUEST_BYTES",
            default_value_t = 16384,
            help = "Maximum allowed request size (Content-Length or body hint) in bytes"
        )]
        max_request_bytes: usize,
        #[arg(
            long,
            env = "DOCDEX_RATE_LIMIT_PER_MIN",
            default_value_t = 0u32,
            help = "Optional per-IP request rate limit per minute (0 disables rate limiting; defaults on in secure mode)"
        )]
        rate_limit_per_min: u32,
        #[arg(
            long,
            env = "DOCDEX_RATE_LIMIT_BURST",
            default_value_t = 0u32,
            help = "Optional burst size for rate limiting (defaults to per-minute limit when unset/0; defaults on in secure mode)"
        )]
        rate_limit_burst: u32,
        #[arg(
            long,
            env = "DOCDEX_STRIP_SNIPPET_HTML",
            default_value_t = false,
            action = ArgAction::SetTrue,
            help = "Omit snippet HTML in responses (serves text-only snippets)"
        )]
        strip_snippet_html: bool,
        #[arg(
            long,
            env = "DOCDEX_SECURE_MODE",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Secure defaults: enable default rate limits (loopback-only access is enforced unless --expose)"
        )]
        secure_mode: bool,
        #[arg(
            long,
            env = "DOCDEX_DISABLE_SNIPPET_TEXT",
            default_value_t = false,
            help = "Omit snippet text/html from responses (only doc metadata is returned)"
        )]
        disable_snippet_text: bool,
        #[arg(
            long,
            env = "DOCDEX_ENABLE_MEMORY",
            default_value_t = false,
            value_parser = clap::builder::BoolishValueParser::new(),
            action = ArgAction::Set,
            help = "Enable repo-scoped memory endpoints (/v1/memory/store, /v1/memory/recall)"
        )]
        enable_memory: bool,
        #[arg(
            long,
            env = "DOCDEX_DEFAULT_AGENT_ID",
            value_parser = config::non_empty_string,
            help = "Default profile agent id when requests omit agent_id"
        )]
        agent_id: Option<String>,
        #[arg(
            long,
            action = ArgAction::SetTrue,
            conflicts_with = "disable_mcp",
            help = "Enable MCP auto-start when serving (overrides config)"
        )]
        enable_mcp: bool,
        #[arg(
            long,
            action = ArgAction::SetTrue,
            conflicts_with = "enable_mcp",
            help = "Disable MCP auto-start when serving (overrides config)"
        )]
        disable_mcp: bool,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_BASE_URL",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (memory); takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (memory) (legacy; prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Ollama embedding model identifier"
        )]
        embedding_model: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
            default_value_t = 0u64,
            help = "Embedding request timeout in milliseconds (0 disables)"
        )]
        embedding_timeout_ms: u64,
        #[arg(
            long,
            env = "DOCDEX_ACCESS_LOG",
            default_value_t = true,
            action = ArgAction::Set,
            help = "Emit structured access logs (redacts query values; disable with --access-log=false)"
        )]
        access_log: bool,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_LOG_PATH",
            help = "Optional path to write audit log entries (defaults to <state-dir>/audit.log)"
        )]
        audit_log_path: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_MAX_BYTES",
            default_value_t = 5_000_000,
            help = "Max size of an audit log file before rotation"
        )]
        audit_max_bytes: u64,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_MAX_FILES",
            default_value_t = 5,
            help = "Number of audit log files to retain"
        )]
        audit_max_files: u32,
        #[arg(
            long,
            env = "DOCDEX_AUDIT_DISABLE",
            default_value_t = false,
            help = "Disable audit logging"
        )]
        audit_disable: bool,
        #[arg(
            long,
            env = "DOCDEX_RUN_AS_UID",
            help = "(Unix only) Drop privileges to this numeric UID after startup preparation"
        )]
        run_as_uid: Option<u32>,
        #[arg(
            long,
            env = "DOCDEX_RUN_AS_GID",
            help = "(Unix only) Drop privileges to this numeric GID after startup preparation"
        )]
        run_as_gid: Option<u32>,
        #[arg(
            long,
            env = "DOCDEX_CHROOT",
            value_name = "PATH",
            help = "(Unix only) chroot to PATH before serving; repo/state paths must be reachable inside the jail"
        )]
        chroot_dir: Option<PathBuf>,
        #[arg(
            long,
            env = "DOCDEX_UNSHARE_NET",
            default_value_t = false,
            help = "(Linux only) unshare network namespace before serving (requires CAP_SYS_ADMIN/root; no-op elsewhere)"
        )]
        unshare_net: bool,
        #[arg(
            long,
            env = "DOCDEX_ALLOW_IPS",
            value_delimiter = ',',
            value_parser = config::non_empty_string,
            help = "Optional comma-separated IPs/CIDRs allowed to access the HTTP API (default: loopback-only unless --expose; allow all when list is empty in exposed mode)"
        )]
        allow_ip: Vec<String>,
    },
    /// Print help for all commands and flags.
    HelpAll,
    /// Scan the index for sensitive terms before enabling access.
    SelfCheck {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_delimiter = ',',
            value_parser = config::non_empty_string,
            help = "Comma-separated sensitive terms to scan for"
        )]
        terms: Vec<String>,
        #[arg(
            long,
            default_value_t = 5,
            help = "Max hits to return per term; reports if more exist"
        )]
        limit: usize,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            help = "Include built-in sensitive patterns (tokens/keys/passwords) in the scan"
        )]
        include_default_patterns: bool,
    },
    /// Show hardware-aware LLM recommendations.
    LlmList,
    /// Install Ollama if missing, pull required models, and update LLM defaults.
    LlmSetup {
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_PATH",
            value_name = "PATH",
            help = "Explicit path to the Ollama binary (falls back to PATH)"
        )]
        ollama_path: Option<PathBuf>,
    },
    /// Build or rebuild the entire index for a repo.
    Index {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Optional JSON file of libs sources to ingest during indexing"
        )]
        libs_sources: Option<PathBuf>,
    },
    /// Ingest a single document file (incremental update).
    Ingest {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long)]
        file: PathBuf,
    },
    /// Run an ad-hoc chat query via CLI (JSON output).
    #[command(visible_alias = "query")]
    Chat {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            short,
            long,
            help = "Chat query (omit to start an interactive REPL)"
        )]
        query: Option<String>,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Override the Ollama model for this chat query"
        )]
        model: Option<String>,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Use a mcoda agent slug or id for LLM calls"
        )]
        agent: Option<String>,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Profile agent id to load behavioral preferences"
        )]
        agent_id: Option<String>,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(
            long,
            value_name = "N",
            help = "Max web results to fetch per query (Tier 2)"
        )]
        max_web_results: Option<usize>,
        #[arg(
            long,
            default_value_t = false,
            help = "Only search the repo index (ignore any repo-scoped libs index, if present)"
        )]
        repo_only: bool,
        #[arg(
            long,
            alias = "skip-local-search",
            default_value_t = false,
            help = "Skip local index search and only use web results"
        )]
        web_only: bool,
        #[arg(
            long,
            alias = "no-web-cache",
            default_value_t = false,
            help = "Disable web cache reads/writes for this query"
        )]
        no_cache: bool,
        #[arg(
            long,
            default_value_t = false,
            help = "Use the LLM to filter local search results before scoring"
        )]
        llm_filter_local_results: bool,
        #[arg(
            long,
            default_value_t = false,
            help = "Emit a minimal JSON response with only scores and web summary"
        )]
        compress_results: bool,
        #[arg(
            long,
            default_value_t = false,
            help = "Stream a text summary to stdout instead of printing JSON"
        )]
        stream: bool,
        #[arg(
            long,
            value_enum,
            help = "Enable diff-aware context (working-tree, staged, or range)"
        )]
        diff_mode: Option<CliDiffMode>,
        #[arg(
            long,
            value_name = "REV",
            help = "Diff range base ref (required when diff-mode=range)"
        )]
        diff_base: Option<String>,
        #[arg(
            long,
            value_name = "REV",
            help = "Diff range head ref (required when diff-mode=range)"
        )]
        diff_head: Option<String>,
        #[arg(
            long,
            value_name = "PATH",
            action = ArgAction::Append,
            help = "Limit diff to specific paths (repeatable)"
        )]
        diff_path: Vec<PathBuf>,
    },
    /// Agent-related workflows.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    /// Clear all cached web discovery/fetch entries.
    WebCacheFlush,
    /// Ingest library documentation sources into the repo-scoped libs index.
    LibsIngest {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Path to a JSON file containing `{ \"sources\": [...] }` entries"
        )]
        sources: PathBuf,
    },
    /// Discover eligible library documentation sources for a repo (dependency manifests + optional configured sources).
    LibsDiscover {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Optional JSON file containing `{ \"sources\": [...] }` entries to merge as explicit configured sources"
        )]
        sources: Option<PathBuf>,
    },
    /// Manage library docs ingestion and discovery.
    Libs {
        #[command(subcommand)]
        command: LibsCommand,
    },
    /// Run a web discovery query (DuckDuckGo HTML).
    WebSearch {
        #[arg(short, long, value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, default_value_t = 8)]
        limit: usize,
    },
    /// Fetch a single URL for web context.
    WebFetch {
        #[arg(long, value_parser = config::non_empty_string)]
        url: String,
    },
    /// Run a web-assisted query (forces Tier 2 gate behavior).
    WebRag {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(short, long, value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(
            long,
            default_value_t = false,
            help = "Only search the repo index (ignore any repo-scoped libs index, if present)"
        )]
        repo_only: bool,
        #[arg(
            long,
            default_value_t = false,
            help = "Stream a text summary to stdout instead of printing JSON"
        )]
        stream: bool,
    },
    /// View DAG traces.
    Dag {
        #[command(subcommand)]
        command: DagCommand,
    },
    /// Run targeted tests for a repo.
    RunTests {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_name = "PATH", help = "Optional file or directory to scope tests")]
        target: Option<PathBuf>,
    },
    /// Launch the local TUI client.
    Tui {
        #[arg(long, value_name = "PATH", help = "Optional repo root to open")]
        repo: Option<PathBuf>,
    },
    /// Store a memory item (requires Ollama embeddings).
    MemoryStore {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string, help = "Text to store in memory")]
        text: String,
        #[arg(long, help = "Optional JSON object metadata (stringified)")]
        metadata: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_BASE_URL",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls; takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (legacy; prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Ollama embedding model identifier"
        )]
        embedding_model: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
            default_value_t = 0u64,
            help = "Embedding request timeout in milliseconds (0 disables)"
        )]
        embedding_timeout_ms: u64,
    },
    /// Recall memory items by semantic similarity (requires Ollama embeddings).
    MemoryRecall {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string, help = "Query text to embed")]
        query: String,
        #[arg(long, default_value_t = 5, help = "Max results to return (1..=50)")]
        top_k: usize,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_BASE_URL",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls; takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Ollama base URL for embedding calls (legacy; prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Ollama embedding model identifier"
        )]
        embedding_model: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
            default_value_t = 0u64,
            help = "Embedding request timeout in milliseconds (0 disables)"
        )]
        embedding_timeout_ms: u64,
    },
    /// Manage global agent profiles and preference memory.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Run semantic gatekeeper hooks against staged changes (HTTP or Unix socket).
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Report Tree-sitter parser version status for symbols indexing.
    SymbolsStatus {
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// List unresolved dynamic import diagnostics from the impact graph.
    ImpactDiagnostics {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Repo-relative file path to filter diagnostics"
        )]
        file: Option<String>,
        #[arg(long, help = "Max diagnostics to return (default 200, max 1000)")]
        limit: Option<usize>,
        #[arg(long, help = "Offset into diagnostics list")]
        offset: Option<usize>,
    },
    /// Manage explicit repo identity mappings for shared state dirs.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
    },
    /// Run an MCP (Model Context Protocol) server over stdio.
    #[command(
        long_about = "Run an MCP server over stdio. This command launches the companion `docdex-mcp-server` binary; if it is missing, build it with `cargo build -p docdex-mcp-server` or set DOCDEX_MCP_SERVER_BIN to the binary path."
    )]
    Mcp {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, default_value = "warn")]
        log: String,
        #[arg(
            long,
            visible_alias = "mcp-max-results",
            default_value_t = 8,
            help = "Maximum results to return from docdex_search tool"
        )]
        max_results: usize,
        #[arg(
            long,
            env = "DOCDEX_MCP_RATE_LIMIT_PER_MIN",
            default_value_t = 0u32,
            help = "Optional global tool-call rate limit per minute for MCP (0 disables)"
        )]
        rate_limit_per_min: u32,
        #[arg(
            long,
            env = "DOCDEX_MCP_RATE_LIMIT_BURST",
            default_value_t = 0u32,
            help = "Optional burst size for MCP rate limiting (defaults to per-minute limit when 0)"
        )]
        rate_limit_burst: u32,
        #[arg(
            long,
            env = "DOCDEX_AUTH_TOKEN",
            help = "Optional bearer token required by MCP initialize"
        )]
        auth_token: Option<String>,
    },
    /// Helper to register or remove Docdex MCP in supported agent CLIs.
    McpAdd {
        /// Agent to configure (currently automates Codex; others print commands to run).
        #[arg(
            long,
            value_parser = [
                "codex",
                "cursor",
                "cursor-cli",
                "continue",
                "cline",
                "claude",
                "claude-cli",
                "grok",
                "droid",
                "factory",
                "gemini",
                "vscode",
                "amp",
                "forge",
                "copilot",
                "warp"
            ],
            default_value = "codex"
        )]
        agent: String,
        /// Repo/workspace root for the MCP server; defaults to current directory.
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Max results clamp for docdex_search.
        #[arg(long, default_value_t = 8)]
        max_results: usize,
        /// Log level for the MCP server.
        #[arg(long, default_value = "warn")]
        log: String,
        /// Remove the MCP entry instead of adding it (where supported).
        #[arg(long, default_value_t = false)]
        remove: bool,
        /// Add to all known agents that are detected on this system.
        #[arg(long, default_value_t = false)]
        all: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum RepoCommand {
    /// Explicitly re-associate a moved/renamed repo path to existing state under a shared `--state-dir`.
    Reassociate {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            required_unless_present = "old_path",
            help = "Target repo fingerprint (SHA-256 hex) to associate with --repo"
        )]
        fingerprint: Option<String>,
        #[arg(
            long,
            value_name = "PATH",
            required_unless_present = "fingerprint",
            help = "Previous canonical repo path (may no longer exist); used to find the existing mapping"
        )]
        old_path: Option<PathBuf>,
    },
    /// Inspect how Docdex resolves repo identity and any shared-state mapping.
    Inspect {
        #[command(flatten)]
        repo: RepoArgs,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum AgentCommand {
    /// Evaluate all mcoda agents with a fixed query set (writes results to ./tmp).
    Eval {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, default_value_t = 8)]
        limit: usize,
        #[arg(
            long,
            value_name = "N",
            help = "Max web results to fetch per query (Tier 2)"
        )]
        max_web_results: Option<usize>,
        #[arg(
            long,
            default_value_t = false,
            help = "Only search the repo index (ignore any repo-scoped libs index, if present)"
        )]
        repo_only: bool,
        #[arg(
            long,
            alias = "skip-local-search",
            default_value_t = false,
            help = "Skip local index search and only use web results"
        )]
        web_only: bool,
        #[arg(
            long,
            alias = "no-web-cache",
            default_value_t = false,
            help = "Disable web cache reads/writes for these queries"
        )]
        no_cache: bool,
        #[arg(
            long,
            default_value_t = false,
            help = "Use the LLM to filter local search results before scoring"
        )]
        llm_filter_local_results: bool,
        #[arg(
            long,
            value_name = "N",
            help = "Limit the number of eval queries to run"
        )]
        max_queries: Option<usize>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum ProfileCommand {
    /// List profile agents and preferences.
    List {
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
    },
    /// Add a new preference (bypasses evolution).
    Add {
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: String,
        #[arg(long, value_parser = config::non_empty_string)]
        category: String,
        #[arg(long, value_parser = config::non_empty_string)]
        content: String,
        #[arg(long, value_parser = config::non_empty_string)]
        role: Option<String>,
    },
    /// Search preferences by semantic similarity.
    Search {
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: String,
        #[arg(long, value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, default_value_t = 8)]
        top_k: usize,
    },
    /// Export preferences to a sync manifest.
    Export {
        #[arg(long, value_name = "PATH", default_value = "profile_sync.json")]
        out: PathBuf,
    },
    /// Import preferences from a sync manifest.
    Import {
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum HookCommand {
    /// Validate staged files via the running daemon (fails open if unavailable).
    PreCommit {
        #[command(flatten)]
        repo: RepoArgs,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum LibsCommand {
    /// Fetch and ingest library docs from a sources file.
    Fetch {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Path to a JSON file containing `{ \"sources\": [...] }` entries"
        )]
        sources: Option<PathBuf>,
    },
    /// Discover eligible library documentation sources for a repo.
    Discover {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_name = "PATH",
            help = "Optional JSON file containing `{ \"sources\": [...] }` entries to merge as explicit configured sources"
        )]
        sources: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum DagCommand {
    /// Render a session DAG trace.
    View {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(value_name = "SESSION_ID", value_parser = config::non_empty_string)]
        session_id: String,
        #[arg(long, default_value = "text", value_parser = ["text", "dot", "json"])]
        format: String,
        #[arg(long, value_name = "N")]
        max_nodes: Option<usize>,
    },
}

pub async fn run() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if matches!(err.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                err.print().map_err(anyhow::Error::from)?;
                return Ok(());
            }
            return Err(
                StartupError::new("startup_config_invalid", err.to_string())
                    .with_hint("Run `docdexd help-all` for full usage.")
                    .into(),
            );
        }
    };
    if !matches!(cli.command, Command::Check | Command::HelpAll) {
        config::AppConfig::load_default().map_err(|err| {
            StartupError::new("startup_config_invalid", format!("failed to load config: {err}"))
                .with_hint("Ensure ~/.docdex is writable and HOME is set correctly.")
        })?;
    }
    commands::dispatch(cli.command).await
}

pub fn render_error_and_exit(err: anyhow::Error) -> ! {
    if let Some(startup) = err.downcast_ref::<StartupError>() {
        let mut body = serde_json::Map::new();
        body.insert("code".to_string(), json!(startup.code));
        body.insert("message".to_string(), json!(startup.message.as_str()));
        if let Some(hint) = startup.hint.as_ref() {
            body.insert("hint".to_string(), json!(hint));
        }
        if let Some(steps) = startup.remediation.as_ref() {
            body.insert("remediation".to_string(), json!(steps));
        }
        let payload = serde_json::Value::Object({
            let mut root = serde_json::Map::new();
            root.insert("error".to_string(), serde_json::Value::Object(body));
            root
        });
        match serde_json::to_string(&payload) {
            Ok(line) => eprintln!("{line}"),
            Err(_) => eprintln!("{}", startup.message),
        }
        std::process::exit(1);
    }
    if let Some(app) = err.downcast_ref::<crate::error::AppError>() {
        let mut body = serde_json::Map::new();
        body.insert("code".to_string(), json!(app.code));
        body.insert("message".to_string(), json!(app.message.as_str()));
        if let Some(details) = app.details.as_ref() {
            body.insert("details".to_string(), details.clone());
        }
        let payload = serde_json::Value::Object({
            let mut root = serde_json::Map::new();
            root.insert("error".to_string(), serde_json::Value::Object(body));
            root
        });
        match serde_json::to_string(&payload) {
            Ok(line) => eprintln!("{line}"),
            Err(_) => eprintln!("{}", app.message),
        }
        std::process::exit(1);
    }

    eprintln!("{err}");
    std::process::exit(1);
}
