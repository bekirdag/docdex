pub mod commands;
pub(crate) mod daemon_spawn;
pub(crate) mod http_client;

use crate::config;
use crate::config::RepoArgs;
use crate::error::StartupError;
use anyhow::Result;
use clap::error::ErrorKind;
use clap::{
    parser::ValueSource, ArgAction, Args, CommandFactory, FromArgMatches, Parser, Subcommand,
    ValueEnum,
};
use serde_json::json;
use std::env;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "docdexd",
    version,
    about = "Local documentation index/search daemon",
    long_about = "Docdex indexes plain-text/markdown documentation under a workspace and serves top-k search/snippet results over HTTP or CLI. Defaults store data under ~/.docdex/state (scoped as repos/<repo_id>/index) and avoid common tool caches; override paths and exclusions with --state-dir/--exclude-* or matching env vars. The daemon exposes a shared MCP HTTP/SSE endpoint (e.g., /v1/mcp/sse); agents should connect to the HTTP/SSE endpoint directly."
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

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub(crate) enum CliMcpIpcMode {
    Auto,
    Off,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[value(rename_all = "kebab-case")]
pub(crate) enum McpAddTransport {
    Http,
    Ipc,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ServeArgs {
    #[command(flatten)]
    pub repo: RepoArgs,
    #[arg(skip)]
    pub repo_explicit: bool,
    #[arg(
        long,
        value_parser = config::non_empty_string,
        help = "Bind host (defaults to server.http_bind_addr in config)"
    )]
    pub host: Option<String>,
    #[arg(long, help = "Bind port (defaults to server.http_bind_addr in config)")]
    pub port: Option<u16>,
    #[arg(
        long,
        env = "DOCDEX_EXPOSE",
        default_value_t = false,
        action = ArgAction::SetTrue,
        help = "Allow binding to non-loopback interfaces (requires --auth-token)"
    )]
    pub expose: bool,
    #[arg(long, default_value = "info")]
    pub log: String,
    #[arg(
        long,
        env = "DOCDEX_TLS_CERT",
        requires = "tls_key",
        help = "TLS certificate PEM file for HTTPS (requires --tls-key)"
    )]
    pub tls_cert: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_TLS_KEY",
        requires = "tls_cert",
        help = "TLS private key PEM file for HTTPS (requires --tls-cert)"
    )]
    pub tls_key: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_CERTBOT_DOMAIN",
        conflicts_with_all = ["tls_cert", "tls_key", "certbot_live_dir"],
        help = "Use certbot live dir at /etc/letsencrypt/live/<domain> for TLS (implies HTTPS)"
    )]
    pub certbot_domain: Option<String>,
    #[arg(
        long,
        env = "DOCDEX_CERTBOT_LIVE_DIR",
        value_name = "PATH",
        conflicts_with_all = ["tls_cert", "tls_key", "certbot_domain"],
        help = "Use explicit certbot live dir containing fullchain.pem and privkey.pem (implies HTTPS)"
    )]
    pub certbot_live_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_INSECURE_HTTP",
        default_value_t = false,
        help = "Allow plain HTTP on non-loopback binds (use only behind a trusted proxy)"
    )]
    pub insecure: bool,
    #[arg(
        long,
        env = "DOCDEX_REQUIRE_TLS",
        default_value_t = true,
        action = ArgAction::Set,
        help = "Require TLS for non-loopback binds (set to false when TLS is already terminated by a trusted proxy)"
    )]
    pub require_tls: bool,
    #[arg(
        long,
        env = "DOCDEX_AUTH_TOKEN",
        help = "Optional bearer token required on HTTP requests (Authorization: Bearer ...)"
    )]
    pub auth_token: Option<String>,
    #[arg(
        long,
        env = "DOCDEX_PREFLIGHT_CHECK",
        default_value_t = false,
        action = ArgAction::Set,
        help = "Run `docdexd check` before serving; fail fast on missing dependencies"
    )]
    pub preflight_check: bool,
    #[arg(
        long,
        env = "DOCDEX_MAX_LIMIT",
        default_value_t = 8,
        help = "Maximum allowed `limit` on search/snippet requests"
    )]
    pub max_limit: usize,
    #[arg(
        long,
        env = "DOCDEX_MAX_QUERY_BYTES",
        default_value_t = 4096,
        help = "Maximum allowed query string size in bytes"
    )]
    pub max_query_bytes: usize,
    #[arg(
        long,
        env = "DOCDEX_MAX_REQUEST_BYTES",
        default_value_t = 16384,
        help = "Maximum allowed request size (Content-Length or body hint) in bytes"
    )]
    pub max_request_bytes: usize,
    #[arg(
        long,
        env = "DOCDEX_RATE_LIMIT_PER_MIN",
        default_value_t = 0u32,
        help = "Optional per-IP request rate limit per minute (0 disables rate limiting; defaults on in secure mode)"
    )]
    pub rate_limit_per_min: u32,
    #[arg(
        long,
        env = "DOCDEX_RATE_LIMIT_BURST",
        default_value_t = 0u32,
        help = "Optional burst size for rate limiting (defaults to per-minute limit when unset/0; defaults on in secure mode)"
    )]
    pub rate_limit_burst: u32,
    #[arg(
        long,
        env = "DOCDEX_STRIP_SNIPPET_HTML",
        default_value_t = false,
        action = ArgAction::SetTrue,
        help = "Omit snippet HTML in responses (serves text-only snippets)"
    )]
    pub strip_snippet_html: bool,
    #[arg(
        long,
        env = "DOCDEX_SECURE_MODE",
        default_value_t = true,
        action = ArgAction::Set,
        help = "Secure defaults: enable default rate limits (loopback-only access is enforced unless --expose)"
    )]
    pub secure_mode: bool,
    #[arg(
        long,
        env = "DOCDEX_DISABLE_SNIPPET_TEXT",
        default_value_t = false,
        help = "Omit snippet text/html from responses (only doc metadata is returned)"
    )]
    pub disable_snippet_text: bool,
    #[arg(
        long,
        env = "DOCDEX_ENABLE_MEMORY",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
        action = ArgAction::Set,
        help = "Enable repo-scoped memory endpoints (/v1/memory/store, /v1/memory/recall)"
    )]
    pub enable_memory: bool,
    #[arg(skip)]
    pub enable_memory_explicit: bool,
    #[arg(
        long,
        env = "DOCDEX_AGENT_ID",
        value_name = "AGENT_ID",
        help = "Default agent id for profile memory (used when requests omit agent_id)"
    )]
    pub agent_id: Option<String>,
    #[arg(
        long,
        env = "DOCDEX_ENABLE_MCP",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        help = "Enable MCP proxy auto-start (HTTP/SSE endpoint on the daemon)"
    )]
    pub enable_mcp: bool,
    #[arg(
        long,
        env = "DOCDEX_DISABLE_MCP",
        default_value_t = false,
        value_parser = clap::builder::BoolishValueParser::new(),
        action = ArgAction::Set,
        num_args = 0..=1,
        default_missing_value = "true",
        help = "Disable MCP proxy auto-start"
    )]
    pub disable_mcp: bool,
    #[arg(
        long,
        value_enum,
        help = "MCP IPC transport mode (auto or off). Defaults to server.mcp_ipc_mode"
    )]
    pub mcp_ipc: Option<CliMcpIpcMode>,
    #[arg(
        long,
        env = "DOCDEX_MCP_SOCKET_PATH",
        value_name = "PATH",
        help = "Unix socket path for MCP IPC (overrides server.mcp_socket_path)"
    )]
    pub mcp_socket_path: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_MCP_PIPE_NAME",
        value_name = "NAME",
        help = "Windows named pipe for MCP IPC (overrides server.mcp_pipe_name)"
    )]
    pub mcp_pipe_name: Option<String>,
    #[arg(
        long,
        env = "DOCDEX_EMBEDDING_BASE_URL",
        help = "Embedding base URL (preferred over --ollama-base-url)"
    )]
    pub embedding_base_url: Option<String>,
    #[arg(
        long,
        env = "DOCDEX_OLLAMA_BASE_URL",
        default_value = "http://127.0.0.1:11434",
        help = "Legacy embedding base URL (deprecated; use --embedding-base-url)"
    )]
    pub ollama_base_url: String,
    #[arg(
        long,
        env = "DOCDEX_EMBEDDING_MODEL",
        default_value = "nomic-embed-text",
        help = "Embedding model identifier"
    )]
    pub embedding_model: String,
    #[arg(
        long,
        env = "DOCDEX_EMBEDDING_TIMEOUT_MS",
        default_value_t = 0u64,
        help = "Embedding timeout in milliseconds (0 disables)"
    )]
    pub embedding_timeout_ms: u64,
    #[arg(
        long,
        env = "DOCDEX_ACCESS_LOG",
        default_value_t = true,
        action = ArgAction::Set,
        help = "Enable structured access logs"
    )]
    pub access_log: bool,
    #[arg(
        long,
        env = "DOCDEX_AUDIT_LOG_PATH",
        value_name = "PATH",
        help = "Audit log path (defaults to <state-dir>/audit.log)"
    )]
    pub audit_log_path: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_AUDIT_MAX_BYTES",
        default_value_t = 5_000_000,
        help = "Audit log max size before rotation"
    )]
    pub audit_max_bytes: u64,
    #[arg(
        long,
        env = "DOCDEX_AUDIT_MAX_FILES",
        default_value_t = 5,
        help = "Audit log max rotated files"
    )]
    pub audit_max_files: u32,
    #[arg(
        long,
        env = "DOCDEX_AUDIT_DISABLE",
        default_value_t = false,
        action = ArgAction::SetTrue,
        help = "Disable audit logging"
    )]
    pub audit_disable: bool,
    #[arg(long, env = "DOCDEX_RUN_AS_UID")]
    pub run_as_uid: Option<u32>,
    #[arg(long, env = "DOCDEX_RUN_AS_GID")]
    pub run_as_gid: Option<u32>,
    #[arg(long, env = "DOCDEX_CHROOT_DIR")]
    pub chroot_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_UNSHARE_NET",
        default_value_t = false,
        action = ArgAction::SetTrue,
        help = "Unshare network namespace (Linux-only)"
    )]
    pub unshare_net: bool,
    #[arg(
        long,
        env = "DOCDEX_ALLOW_IPS",
        value_delimiter = ',',
        help = "Comma-separated IPs/CIDRs allowed to access the API"
    )]
    pub allow_ip: Vec<String>,
}

pub(crate) fn cli_local_mode() -> bool {
    match env::var("DOCDEX_CLI_LOCAL")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
    {
        Some(value) if matches!(value.as_str(), "1" | "true" | "t" | "yes" | "y" | "on") => true,
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
        args: ServeArgs,
    },
    /// Run singleton daemon service (multi-repo).
    #[command(visible_alias = "start")]
    Daemon {
        #[command(flatten)]
        args: ServeArgs,
    },
    /// Print help for all commands and flags.
    HelpAll,
    /// Manage browser discovery and setup.
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
    /// Manage mswarm integration settings.
    Mswarm {
        #[command(subcommand)]
        command: MswarmCommand,
    },
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
    /// Inspect local LLM services and model detection.
    Llm {
        #[command(subcommand)]
        command: LlmCommand,
    },
    /// Delegation telemetry and savings.
    Delegation {
        #[command(subcommand)]
        command: DelegationCommand,
    },
    /// Run the interactive setup wizard for Ollama and models.
    #[command(visible_alias = "llm-setup")]
    Setup {
        #[command(flatten)]
        args: SetupArgs,
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
    /// Search repo docs/code (HTTP /search equivalent).
    Search {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string, help = "Search query")]
        query: String,
        #[arg(long, default_value_t = crate::max_size::DEFAULT_SEARCH_LIMIT)]
        limit: usize,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            help = "Include libs index in search results"
        )]
        include_libs: bool,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            help = "Include snippets in results"
        )]
        snippets: bool,
        #[arg(long, help = "Drop hits whose token_estimate exceeds this value")]
        max_tokens: Option<u64>,
        #[arg(long, default_value_t = false, help = "Force web discovery")]
        force_web: bool,
        #[arg(long, default_value_t = false, help = "Skip local search")]
        skip_local_search: bool,
        #[arg(long, default_value_t = false, help = "Disable web cache")]
        no_cache: bool,
        #[arg(long, help = "Max web results to fetch (Tier 2)")]
        max_web_results: Option<usize>,
        #[arg(
            long,
            default_value_t = false,
            help = "Use the LLM to filter local results before scoring"
        )]
        llm_filter_local_results: bool,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            help = "Run web discovery asynchronously when enabled"
        )]
        async_web: bool,
    },
    /// Run an ad-hoc chat query via CLI (JSON output).
    #[command(visible_alias = "query")]
    Chat {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(short, long, help = "Chat query (omit to start an interactive REPL)")]
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
    /// Render a repo folder tree with standard excludes.
    Tree {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            value_name = "PATH",
            help = "Repo-relative path to render (defaults to repo root)"
        )]
        path: Option<PathBuf>,
        #[arg(
            short = 'd',
            long,
            value_name = "N",
            help = "Max depth (default: unlimited)"
        )]
        max_depth: Option<usize>,
        #[arg(short = 'D', long, default_value_t = false, help = "Directories only")]
        dirs_only: bool,
        #[arg(
            short = 'a',
            long,
            default_value_t = false,
            help = "Include hidden entries"
        )]
        include_hidden: bool,
        #[arg(
            short = 'e',
            long,
            value_delimiter = ',',
            help = "Extra excludes (comma-separated)"
        )]
        extra_excludes: Vec<String>,
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
        #[arg(
            long,
            value_name = "PATH",
            help = "Optional file or directory to scope tests"
        )]
        target: Option<PathBuf>,
    },
    /// Launch the local TUI client.
    Tui {
        #[arg(long, value_name = "PATH", help = "Optional repo root to open")]
        repo: Option<PathBuf>,
    },
    /// Store a memory item (requires local embeddings).
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
            help = "Embedding base URL; takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Legacy Ollama embedding base URL (prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Embedding model identifier"
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
    /// Recall memory items by semantic similarity (requires local embeddings).
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
            help = "Embedding base URL; takes precedence over --ollama-base-url when both are set"
        )]
        embedding_base_url: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_OLLAMA_BASE_URL",
            default_value = "http://127.0.0.1:11434",
            value_parser = config::non_empty_string,
            help = "Legacy Ollama embedding base URL (prefer --embedding-base-url / DOCDEX_EMBEDDING_BASE_URL)"
        )]
        ollama_base_url: String,
        #[arg(
            long,
            env = "DOCDEX_EMBEDDING_MODEL",
            default_value = "nomic-embed-text",
            help = "Embedding model identifier"
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
    /// Compact repo memory by removing superseded entries.
    MemoryCompact {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            default_value_t = false,
            help = "Apply deletions (default: dry-run)"
        )]
        apply: bool,
    },
    /// Show the current six memory layers, their storage, and recommended agent usage.
    MemoryLayers {
        #[command(flatten)]
        scope: ConversationScopeArgs,
    },
    /// Recommend which Docdex memory lanes to consult or write for a specific task.
    MemoryRoute {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(
            long,
            value_parser = ["read", "write", "auto"],
            help = "Force read/write routing; defaults to auto inference."
        )]
        intent: Option<String>,
        #[arg(value_name = "QUERY", value_parser = config::non_empty_string)]
        query: String,
    },
    /// Manage repo-scoped conversation memory sessions.
    Conversations {
        #[command(subcommand)]
        command: ConversationCommand,
    },
    /// Manage repo-scoped agent diary entries.
    Diary {
        #[command(subcommand)]
        command: DiaryCommand,
    },
    /// Manage global agent profiles and preference memory.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Manage global personal-preferences memory captures and derived records.
    PersonalPreferences {
        #[command(subcommand)]
        command: PersonalPreferencesCommand,
    },
    /// Manage AI-terminal capture and generated skill synchronization.
    AiTerminals {
        #[command(subcommand)]
        command: AiTerminalsCommand,
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
    /// Read impact graph edges for a repo-relative file.
    ImpactGraph {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Repo-relative file path to analyze"
        )]
        file: String,
        #[arg(long, help = "Max edges to return (default 1000, max 20000)")]
        max_edges: Option<i64>,
        #[arg(long, help = "Max traversal depth (default 10, max 50)")]
        max_depth: Option<i64>,
        #[arg(
            long,
            value_parser = config::non_empty_string,
            help = "Comma-separated edge type filter (e.g. import,require)"
        )]
        edge_types: Option<String>,
    },
    /// Read a file slice from the repo (similar to docdex_open).
    Open {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string, help = "Repo-relative file path")]
        file: String,
        #[arg(long, help = "1-based start line")]
        start: Option<usize>,
        #[arg(long, help = "1-based end line")]
        end: Option<usize>,
        #[arg(long, help = "Return the first N lines (implies --clamp)")]
        head: Option<usize>,
        #[arg(long, default_value_t = false, help = "Clamp range to file bounds")]
        clamp: bool,
    },
    /// File helpers for agent workflows.
    File {
        #[command(subcommand)]
        command: FileCommand,
    },
    /// Test helpers for agent workflows.
    Test {
        #[command(subcommand)]
        command: TestCommand,
    },
    /// Manage explicit repo identity mappings for shared state dirs.
    Repo {
        #[command(subcommand)]
        command: RepoCommand,
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
                "windsurf",
                "roo",
                "pearai",
                "void",
                "zed",
                "vscode",
                "amp",
                "forge",
                "copilot",
                "warp"
            ],
            default_value = "codex"
        )]
        agent: String,
        /// Transport to configure for Codex (http or ipc).
        #[arg(long, value_enum, default_value = "http")]
        transport: McpAddTransport,
        /// Repo/workspace root for MCP configuration; defaults to current directory.
        #[arg(long)]
        repo: Option<PathBuf>,
        /// Remove the MCP entry instead of adding it (where supported).
        #[arg(long, default_value_t = false)]
        remove: bool,
        /// Add to all known agents that are detected on this system.
        #[arg(long, default_value_t = false)]
        all: bool,
    },
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SetupArgs {
    #[arg(long, help = "Do not prompt; print manual setup instructions instead")]
    pub non_interactive: bool,
    #[arg(long, help = "Emit JSON summary to stdout")]
    pub json: bool,
    #[arg(long, help = "Always run setup even if already completed")]
    pub force: bool,
    #[arg(long, hide = true)]
    pub auto: bool,
    #[arg(
        long,
        env = "DOCDEX_OLLAMA_PATH",
        value_name = "PATH",
        help = "Explicit path to the Ollama binary (falls back to PATH)"
    )]
    pub ollama_path: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub(crate) enum LlmCommand {
    /// Show hardware-aware LLM recommendations.
    List,
    /// Detect installed local LLM services without starting or installing anything.
    Detect {
        #[arg(long, help = "Emit provider probe results as JSON")]
        json: bool,
    },
    /// Show local LLM library defaults and selection diagnostics.
    Diagnostics {
        #[arg(long, help = "Emit local LLM diagnostics as JSON")]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum RepoCommand {
    /// Initialize a repo in the running daemon and print the repo_id payload.
    Init {
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// Print the repo fingerprint for the current path.
    Id {
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// Report git status for the repo.
    Status {
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// Print `clean` or `dirty` based on git status.
    Dirty {
        #[command(flatten)]
        repo: RepoArgs,
        /// Exit with code 1 if dirty.
        #[arg(long, default_value_t = false)]
        exit_code: bool,
    },
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
pub(crate) enum DelegationCommand {
    /// Show delegation savings telemetry.
    Savings {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(
            long,
            default_value_t = false,
            action = ArgAction::SetTrue,
            help = "Show aggregated delegation savings across all repos mounted in the daemon"
        )]
        all: bool,
        #[arg(
            long,
            default_value_t = false,
            action = ArgAction::SetTrue,
            help = "Print JSON output"
        )]
        json: bool,
    },
    /// List available local delegation agents and models.
    Agents {
        #[arg(
            long,
            default_value_t = false,
            action = ArgAction::SetTrue,
            help = "Print JSON output"
        )]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum FileCommand {
    /// Ensure the file ends with a newline.
    EnsureNewline {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string)]
        file: String,
    },
    /// Write file content (overwrites existing file).
    Write {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string)]
        file: String,
        /// Content to write (mutually exclusive with --stdin).
        #[arg(long)]
        content: Option<String>,
        /// Read content from stdin.
        #[arg(long, default_value_t = false)]
        stdin: bool,
        /// Allow creating a new file if it doesn't exist.
        #[arg(long, default_value_t = false)]
        create: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum TestCommand {
    /// Run `node <file>` in the repo root.
    RunNode {
        #[command(flatten)]
        repo: RepoArgs,
        #[arg(long, value_parser = config::non_empty_string)]
        file: String,
        /// Additional args to pass to node (repeatable or space-separated).
        #[arg(long, value_parser = config::non_empty_string)]
        args: Vec<String>,
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
pub(crate) enum PersonalPreferencesCommand {
    /// Show personal-preferences storage and queue status.
    Status,
    /// List configured personal-preferences categories and context policy.
    Categories,
    /// List personal-preferences retention policies.
    RetentionPolicies,
    /// List captured sessions.
    List {
        #[arg(long, value_parser = config::non_empty_string)]
        status: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one captured session with ordered messages.
    Read {
        #[arg(value_parser = config::non_empty_string)]
        capture_id: String,
    },
    /// Search derived personal-preference records.
    Search {
        #[arg(value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, default_value_t = 10)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
    },
    /// List records by review status.
    Reviews {
        #[arg(long, value_parser = config::non_empty_string)]
        status: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Approve, reject, or re-queue one derived record.
    Review {
        #[arg(value_parser = config::non_empty_string)]
        record_id: String,
        #[arg(long, value_parser = config::non_empty_string)]
        verdict: String,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Manually process queued captures with a local mcoda agent.
    Process {
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, default_value_t = false)]
        retry_failed: bool,
        #[arg(long)]
        retry_stale_processing_ms: Option<i64>,
    },
    /// Scan supported local AI-client transcript roots and queue new captures.
    Scan {
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Apply or preview retention pruning.
    Prune {
        #[arg(long)]
        raw_retention_days: Option<u32>,
        #[arg(long)]
        derived_retention_days: Option<u32>,
        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Export one capture or the whole store to a JSON bundle.
    Export {
        #[arg(long, value_parser = config::non_empty_string)]
        capture_id: Option<String>,
    },
    /// Redact raw transcript content for one capture.
    Redact {
        #[arg(value_parser = config::non_empty_string)]
        capture_id: String,
    },
    /// Delete one capture and its derived records.
    Delete {
        #[arg(value_parser = config::non_empty_string)]
        capture_id: String,
    },
    /// Purge all captures and derived records.
    Purge {
        #[arg(long, default_value_t = false)]
        include_exports: bool,
    },
    /// Manage extracted personal-preference claims.
    Claims {
        #[command(subcommand)]
        command: PersonalPreferencesClaimsCommand,
    },
    /// Add explicit feedback events that influence future mind-clone context.
    Feedback {
        #[command(subcommand)]
        command: PersonalPreferencesFeedbackCommand,
    },
    /// Capture and inspect first-class operator events.
    OperatorEvents {
        #[command(subcommand)]
        command: PersonalPreferencesOperatorEventsCommand,
    },
    /// Inspect temporal identity snapshots.
    Snapshots {
        #[command(subcommand)]
        command: PersonalPreferencesSnapshotsCommand,
    },
    /// Inspect synthesized operator routines.
    Routines {
        #[command(subcommand)]
        command: PersonalPreferencesRoutinesCommand,
    },
    /// Compile a queryable operator mind map from claims and routines.
    MindMap {
        #[arg(value_parser = config::non_empty_string)]
        query: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
    },
    /// Compile SKILL.md-compatible operator playbooks from stable routines.
    Playbooks {
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f32,
        #[arg(long, default_value_t = 2)]
        min_support_count: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
    },
    /// List, read, and sync generated skills derived from the mind clone.
    Skills {
        #[command(subcommand)]
        command: PersonalPreferencesSkillsCommand,
    },
    /// Compile or evaluate a bounded mind-clone context pack.
    Clone {
        #[command(subcommand)]
        command: PersonalPreferencesCloneCommand,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum AiTerminalsCommand {
    /// Detect supported AI-terminal targets without persisting integration records.
    Detect {
        #[arg(long, default_value_t = false)]
        all: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// List configured AI-terminal integrations.
    List,
    /// Show AI-terminal capture and generated-skill sync status.
    Status,
    /// List normalized AI-terminal capture events.
    Events {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Bootstrap Docdex-owned generated skill roots for supported terminals.
    Integrate {
        #[arg(long, default_value_t = false)]
        all: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// Record a normalized AI-terminal session summary into personal preferences.
    Capture {
        #[arg(long, default_value = "codex", value_parser = config::non_empty_string)]
        terminal: String,
        #[arg(long, value_parser = config::non_empty_string)]
        integration_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        source_session_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        event_kind: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        repo_scope: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        summary: String,
        #[arg(long)]
        transcript_text: Option<String>,
        #[arg(long = "metadata-json")]
        metadata_json: Option<String>,
    },
    /// Sync generated skills to enabled terminal integrations.
    SyncSkills {
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f32,
        #[arg(long, default_value_t = 2)]
        min_support_count: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
        #[arg(long, default_value_t = false)]
        no_install: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesSkillsCommand {
    /// List generated skills and their current versions/installations.
    List,
    /// List generated-skill registry events.
    Events {
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one generated skill by id, slug, or skill name.
    Read {
        #[arg(value_parser = config::non_empty_string)]
        skill_id: String,
    },
    /// Preview generated skill candidates without installing them.
    Preview {
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f32,
        #[arg(long, default_value_t = 2)]
        min_support_count: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// Render generated skill candidates without installing them.
    Render {
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f32,
        #[arg(long, default_value_t = 2)]
        min_support_count: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// Validate one generated skill's current version.
    Validate {
        #[arg(value_parser = config::non_empty_string)]
        skill_id: String,
    },
    /// Install one generated skill to enabled terminal integrations.
    Install {
        #[arg(value_parser = config::non_empty_string)]
        skill_id: String,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// Disable one generated skill in the registry.
    Disable {
        #[arg(value_parser = config::non_empty_string)]
        skill_id: String,
        #[arg(long, value_parser = config::non_empty_string)]
        reason: Option<String>,
    },
    /// Roll back one generated skill to the previous rendered version.
    Rollback {
        #[arg(value_parser = config::non_empty_string)]
        skill_id: String,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// Promote stable playbooks into generated skills and optionally install them.
    Sync {
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f32,
        #[arg(long, default_value_t = 2)]
        min_support_count: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
        #[arg(long, default_value_t = false)]
        no_install: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
    /// Run the generated-skills autopilot once.
    Autopilot {
        #[arg(long, default_value_t = false)]
        once: bool,
        #[arg(long, default_value_t = 0.7)]
        min_confidence: f32,
        #[arg(long, default_value_t = 2)]
        min_support_count: usize,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
        #[arg(long, default_value_t = false)]
        no_install: bool,
        #[arg(long = "terminal", value_parser = config::non_empty_string)]
        terminals: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesClaimsCommand {
    /// List extracted claims.
    List {
        #[arg(long, value_parser = config::non_empty_string)]
        query: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        truth_status: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        claim_origin: Option<String>,
        #[arg(long, default_value_t = false)]
        include_sensitive: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one claim.
    Read {
        #[arg(value_parser = config::non_empty_string)]
        claim_id: String,
    },
    /// Review one claim.
    Review {
        #[arg(value_parser = config::non_empty_string)]
        claim_id: String,
        #[arg(long, value_parser = config::non_empty_string)]
        verdict: String,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Override one claim with a corrected value.
    Override {
        #[arg(value_parser = config::non_empty_string)]
        claim_id: String,
        #[arg(long, value_parser = config::non_empty_string)]
        value: String,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Forget one claim and redact its usable value.
    Forget {
        #[arg(value_parser = config::non_empty_string)]
        claim_id: String,
        #[arg(long)]
        notes: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesFeedbackCommand {
    /// Add a feedback event.
    Add {
        #[arg(long, value_parser = config::non_empty_string)]
        event_type: String,
        #[arg(long, value_parser = config::non_empty_string)]
        claim_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        capture_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        category: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        attribute: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        value: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long = "metadata-json")]
        metadata_json: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesOperatorEventsCommand {
    /// List captured operator events.
    List {
        #[arg(long, value_parser = config::non_empty_string)]
        event_kind: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        action: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        repo_root: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Record one manual operator event.
    Record {
        #[arg(long, value_parser = config::non_empty_string)]
        event_kind: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        action: String,
        #[arg(long)]
        summary: Option<String>,
        #[arg(long)]
        command_text: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        source_session_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        repo_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        repo_root: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        capture_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        artifact_path: Option<String>,
        #[arg(long)]
        occurred_at_ms: Option<i64>,
        #[arg(long = "metadata-json")]
        metadata_json: Option<String>,
    },
    /// Scan repo planning/progress/SDS artifacts into operator events.
    ScanArtifacts {
        #[arg(long)]
        repo_root: Option<PathBuf>,
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesSnapshotsCommand {
    /// List identity snapshots.
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one snapshot.
    Read {
        #[arg(value_parser = config::non_empty_string)]
        snapshot_id: String,
    },
    /// Rebuild the latest snapshot set from current claims.
    Rebuild,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesRoutinesCommand {
    /// List synthesized operator routines.
    List {
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one routine by id or routine key.
    Read {
        #[arg(value_parser = config::non_empty_string)]
        routine_id: String,
    },
    /// Explain one routine with source claims per step.
    Explain {
        #[arg(value_parser = config::non_empty_string)]
        routine_id: String,
    },
    /// Rebuild synthesized routines from current claims.
    Rebuild,
}

#[derive(Subcommand, Debug)]
pub(crate) enum PersonalPreferencesCloneCommand {
    /// Build a bounded clone context pack.
    Context {
        #[arg(value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        mode: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
        #[arg(long)]
        max_records: Option<usize>,
        #[arg(long)]
        budget_tokens: Option<usize>,
    },
    /// Compile an operator-clone directive checklist for an agent task.
    Directive {
        #[arg(value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        mode: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
        #[arg(long)]
        max_records: Option<usize>,
        #[arg(long)]
        budget_tokens: Option<usize>,
        #[arg(long, value_parser = config::non_empty_string)]
        task_type: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        risk_level: Option<String>,
        #[arg(long = "current-file", value_parser = config::non_empty_string)]
        current_files: Vec<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        current_plan_path: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        enforcement_level: Option<String>,
    },
    /// Explain why a clone context pack was selected.
    Explain {
        #[arg(value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        mode: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
        #[arg(long)]
        max_records: Option<usize>,
        #[arg(long)]
        budget_tokens: Option<usize>,
    },
    /// Evaluate clone-pack fidelity heuristics for a query.
    Evaluate {
        #[arg(value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        mode: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
        #[arg(long)]
        max_records: Option<usize>,
        #[arg(long)]
        budget_tokens: Option<usize>,
    },
    /// Replay-score whether the clone pack predicts expected next-step categories.
    ReplayEvaluate {
        #[arg(value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        mode: Option<String>,
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
        #[arg(long)]
        max_records: Option<usize>,
        #[arg(long)]
        budget_tokens: Option<usize>,
        #[arg(long = "expected-category", value_parser = config::non_empty_string)]
        expected_categories: Vec<String>,
    },
    /// Generate replay cases from executable operator routines.
    ReplayDataset {
        #[arg(long, default_value_t = false)]
        ci_subset: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
    },
    /// Run the replay suite and report aggregate clone-prediction metrics.
    ReplaySuite {
        #[arg(long, default_value_t = false)]
        ci_subset: bool,
        #[arg(long)]
        limit: Option<usize>,
        #[arg(long)]
        threshold: Option<f32>,
        #[arg(long, default_value_t = false)]
        allow_sensitive: bool,
        #[arg(long, value_parser = config::non_empty_string)]
        current_repo_root: Option<String>,
        #[arg(long)]
        max_records: Option<usize>,
        #[arg(long)]
        budget_tokens: Option<usize>,
    },
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ConversationScopeArgs {
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with = "conversation_namespace",
        help = "Repository/workspace root for repo-scoped conversation memory. Defaults to the current directory unless --conversation-namespace is provided."
    )]
    pub repo: Option<PathBuf>,
    #[arg(
        long = "conversation-namespace",
        alias = "namespace",
        value_parser = config::non_empty_string,
        conflicts_with = "repo",
        help = "Explicit global conversation namespace for repo-less conversation memory."
    )]
    pub conversation_namespace: Option<String>,
}

impl ConversationScopeArgs {
    pub(crate) fn repo_root(&self) -> Option<PathBuf> {
        if self.conversation_namespace().is_some() {
            return None;
        }
        let candidate = self.repo.clone().unwrap_or_else(|| PathBuf::from("."));
        Some(candidate.canonicalize().unwrap_or(candidate))
    }

    pub(crate) fn conversation_namespace(&self) -> Option<&str> {
        self.conversation_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }
}

#[derive(Subcommand, Debug)]
pub(crate) enum ConversationCommand {
    /// Import a conversation transcript or native export file into conversation memory.
    Import {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "PATH")]
        path: PathBuf,
        #[arg(
            long,
            default_value = "auto",
            value_parser = ["auto", "plain_text", "generic_json", "codex_jsonl", "claude_jsonl", "chatgpt_export"]
        )]
        format: String,
        #[arg(long, value_parser = config::non_empty_string)]
        source: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        source_session_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        title: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        transport: Option<String>,
    },
    /// Search imported conversation sessions and matching message snippets in the current scope.
    Search {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "QUERY", value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// List imported conversation sessions for the current scope.
    List {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read one conversation session with ordered messages.
    Read {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "SESSION_ID", value_parser = config::non_empty_string)]
        session_id: String,
    },
    /// Export one conversation session with linked diary entries.
    Export {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "SESSION_ID", value_parser = config::non_empty_string)]
        session_id: String,
    },
    /// Redact one conversation session and remove its derived wake-up artifacts.
    Redact {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "SESSION_ID", value_parser = config::non_empty_string)]
        session_id: String,
    },
    /// Preview or apply conversation retention cleanup.
    Prune {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(long, default_value_t = false)]
        apply: bool,
        #[arg(long)]
        manual_retention_days: Option<u32>,
        #[arg(long)]
        auto_capture_retention_days: Option<u32>,
        #[arg(long)]
        diary_retention_days: Option<u32>,
        #[arg(long)]
        hook_event_retention_days: Option<u32>,
        #[arg(long)]
        working_memory_retention_days: Option<u32>,
        #[arg(long)]
        episodic_rollup_retention_days: Option<u32>,
    },
    /// Delete one conversation session and its derived artifacts.
    Delete {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "SESSION_ID", value_parser = config::non_empty_string)]
        session_id: String,
    },
    /// Query temporal knowledge facts extracted from conversations in the current scope.
    KgQuery {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "QUERY", value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        relation: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Read the timeline for one entity or decision topic.
    KgTimeline {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "ENTITY", value_parser = config::non_empty_string)]
        entity: String,
        #[arg(long, value_parser = config::non_empty_string)]
        relation: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Search canonical graph entities extracted from conversations in the current scope.
    KgSearchNodes {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "QUERY", value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        entity_type: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Search graph edges extracted from conversations in the current scope.
    KgSearchEdges {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "QUERY", value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        relation: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Search provenance episodes extracted from conversations in the current scope.
    KgSearchEpisodes {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "QUERY", value_parser = config::non_empty_string)]
        query: String,
        #[arg(long, value_parser = config::non_empty_string)]
        source_type: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
    /// Inspect graph edges adjacent to one entity or topic.
    KgNeighborhood {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "ENTITY", value_parser = config::non_empty_string)]
        entity: String,
        #[arg(long, value_parser = config::non_empty_string)]
        relation: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Fetch code-facing links recorded for one graph entity.
    KgEntityLinks {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "ENTITY", value_parser = config::non_empty_string)]
        entity: String,
        #[arg(long, value_parser = config::non_empty_string)]
        link_type: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Fetch one provenance episode with its graph edges and evidence.
    KgEpisode {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "EPISODE_ID", value_parser = config::non_empty_string)]
        episode_id: String,
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },
    /// Delete one graph edge and its fact projection.
    KgDeleteEdge {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "EDGE_ID", value_parser = config::non_empty_string)]
        edge_id: String,
    },
    /// Delete one provenance episode and its graph edges/facts.
    KgDeleteEpisode {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(value_name = "EPISODE_ID", value_parser = config::non_empty_string)]
        episode_id: String,
    },
    /// Rebuild graph-side link projections and SQLite indexes.
    KgRebuild {
        #[command(flatten)]
        scope: ConversationScopeArgs,
    },
    /// Delete all knowledge graph data for the current scope.
    KgClear {
        #[command(flatten)]
        scope: ConversationScopeArgs,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum DiaryCommand {
    /// Write one diary entry for the repo and agent.
    Write {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, default_value = "note", value_parser = config::non_empty_string)]
        entry_type: String,
        #[arg(long, value_parser = config::non_empty_string)]
        source_session_id: Option<String>,
        #[arg(value_name = "CONTENT", value_parser = config::non_empty_string)]
        content: String,
    },
    /// Read diary entries for the repo and optional agent.
    Read {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        #[arg(long, default_value_t = 0)]
        offset: usize,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum BrowserCommand {
    /// List browser candidates and the selected binary.
    List,
    /// Run browser discovery (and Linux auto-install) then persist config.
    Setup,
    /// Install headless Chromium on Linux and update config.
    Install,
}

#[derive(Subcommand, Debug)]
pub(crate) enum MswarmCommand {
    /// Set or update the mswarm API key, base URL, and web-search preference.
    Configure {
        #[arg(
            long,
            env = "DOCDEX_MSWARM_API_KEY",
            value_name = "KEY",
            help = "mswarm runtime API key (sent as x-api-key)"
        )]
        api_key: Option<String>,
        #[arg(
            long,
            env = "DOCDEX_MSWARM_BASE_URL",
            value_name = "URL",
            help = "mswarm gateway base URL override (default: https://api.mswarm.org/)"
        )]
        base_url: Option<String>,
        #[arg(
            long,
            default_value_t = false,
            action = ArgAction::SetTrue,
            conflicts_with = "disable_web_search",
            help = "Use mswarm as the primary Docdex web discovery provider"
        )]
        enable_web_search: bool,
        #[arg(
            long,
            default_value_t = false,
            action = ArgAction::SetTrue,
            conflicts_with = "enable_web_search",
            help = "Stop using mswarm as the primary Docdex web discovery provider"
        )]
        disable_web_search: bool,
        #[arg(long, default_value_t = false, help = "Emit JSON summary")]
        json: bool,
    },
    /// Show the current mswarm integration and telemetry consent state.
    Status {
        #[arg(long, default_value_t = false, help = "Emit JSON summary")]
        json: bool,
    },
    /// Revoke the currently stored mswarm consent token.
    Revoke {
        #[arg(long, value_name = "TEXT", help = "Optional revoke reason")]
        reason: Option<String>,
        #[arg(long, default_value_t = false, help = "Emit JSON summary")]
        json: bool,
    },
    /// Submit a data deletion request to mswarm for the current Docdex identity.
    RequestDeletion {
        #[arg(long, value_name = "TEXT", help = "Optional deletion reason")]
        reason: Option<String>,
        #[arg(long, default_value_t = false, help = "Emit JSON summary")]
        json: bool,
    },
}

#[derive(Subcommand, Debug)]
pub(crate) enum HookCommand {
    /// Validate staged files via the running daemon (fails open if unavailable).
    PreCommit {
        #[command(flatten)]
        repo: RepoArgs,
    },
    /// Enqueue or synchronously process a conversation-memory hook action.
    Conversation {
        #[command(flatten)]
        scope: ConversationScopeArgs,
        #[arg(
            long,
            value_parser = [
                "periodic_memory_save",
                "pre_compaction_summarization",
                "session_close_summarization"
            ]
        )]
        action: String,
        #[arg(long, value_parser = config::non_empty_string)]
        source: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        source_session_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        title: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        agent_id: Option<String>,
        #[arg(long, value_parser = config::non_empty_string)]
        transport: Option<String>,
        #[arg(
            long,
            default_value = "auto",
            value_parser = ["auto", "plain_text", "generic_json", "codex_jsonl", "claude_jsonl", "chatgpt_export"]
        )]
        format: String,
        #[arg(long, value_name = "PATH")]
        transcript: Option<PathBuf>,
        #[arg(long, value_parser = config::non_empty_string)]
        summary_text: Option<String>,
        #[arg(long, default_value_t = false)]
        wait_for_processing: bool,
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
    /// Alias for `dag view`.
    Export {
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
    let matches = match Cli::command().try_get_matches() {
        Ok(matches) => matches,
        Err(err) => {
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                err.print().map_err(anyhow::Error::from)?;
                return Ok(());
            }
            return Err(StartupError::new("startup_config_invalid", err.to_string())
                .with_hint("Run `docdexd help-all` for full usage.")
                .into());
        }
    };
    let mut cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => {
            if matches!(
                err.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                err.print().map_err(anyhow::Error::from)?;
                return Ok(());
            }
            return Err(StartupError::new("startup_config_invalid", err.to_string())
                .with_hint("Run `docdexd help-all` for full usage.")
                .into());
        }
    };
    if let Some(daemon_matches) = matches.subcommand_matches("daemon") {
        let repo_explicit = repo_flag_provided()
            || matches!(
                daemon_matches.value_source("repo"),
                Some(ValueSource::EnvVariable)
            );
        let enable_memory_explicit = matches!(
            daemon_matches.value_source("enable_memory"),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        );
        if let Command::Daemon { args } = &mut cli.command {
            args.repo_explicit = repo_explicit;
            args.enable_memory_explicit = enable_memory_explicit;
        }
    }
    if let Some(serve_matches) = matches.subcommand_matches("serve") {
        let repo_explicit = repo_flag_provided()
            || matches!(
                serve_matches.value_source("repo"),
                Some(ValueSource::EnvVariable)
            );
        let enable_memory_explicit = matches!(
            serve_matches.value_source("enable_memory"),
            Some(ValueSource::CommandLine | ValueSource::EnvVariable)
        );
        if let Command::Serve { args } = &mut cli.command {
            args.repo_explicit = repo_explicit;
            args.enable_memory_explicit = enable_memory_explicit;
        }
    }
    let config = if !matches!(cli.command, Command::HelpAll) {
        Some(config::AppConfig::load_default().map_err(|err| {
            StartupError::new(
                "startup_config_invalid",
                format!("failed to load config: {err}"),
            )
            .with_hint("Ensure ~/.docdex is writable and HOME is set correctly.")
        })?)
    } else {
        None
    };
    if should_ensure_daemon(&cli.command)
        && !cli_local_mode()
        && std::env::var_os("DOCDEX_HTTP_BASE_URL").is_none()
    {
        if let Some(config) = config.as_ref() {
            let repo_hint = repo_hint_for_command(&cli.command);
            daemon_spawn::ensure_daemon_running(config, repo_hint)?;
        }
    }
    commands::dispatch(cli.command).await
}

fn should_ensure_daemon(command: &Command) -> bool {
    if matches!(
        command,
        Command::Delegation {
            command: DelegationCommand::Agents { .. }
        }
    ) {
        return false;
    }
    !matches!(
        command,
        Command::Serve { .. }
            | Command::Daemon { .. }
            | Command::HelpAll
            | Command::Llm { .. }
            | Command::Setup { .. }
            | Command::Mswarm { .. }
            | Command::Tree { .. }
            | Command::Open { .. }
            | Command::File { .. }
            | Command::Test { .. }
    )
}

fn repo_flag_provided() -> bool {
    env::args_os().any(|arg| {
        if arg == "--repo" {
            return true;
        }
        let value = arg.to_string_lossy();
        value.starts_with("--repo=")
    })
}

fn repo_hint_for_command(command: &Command) -> Option<PathBuf> {
    match command {
        Command::SelfCheck { repo, .. } => Some(repo.repo_root()),
        Command::Index { repo, .. } => Some(repo.repo_root()),
        Command::Ingest { repo, .. } => Some(repo.repo_root()),
        Command::Search { repo, .. } => Some(repo.repo_root()),
        Command::Chat { repo, .. } => Some(repo.repo_root()),
        Command::LibsIngest { repo, .. } => Some(repo.repo_root()),
        Command::LibsDiscover { repo, .. } => Some(repo.repo_root()),
        Command::Libs { command } => match command {
            LibsCommand::Discover { repo, .. } => Some(repo.repo_root()),
            LibsCommand::Fetch { repo, .. } => Some(repo.repo_root()),
        },
        Command::Dag { command } => match command {
            DagCommand::View { repo, .. } => Some(repo.repo_root()),
            DagCommand::Export { repo, .. } => Some(repo.repo_root()),
        },
        Command::Delegation { command } => match command {
            DelegationCommand::Savings { repo, all, .. } => {
                if *all {
                    None
                } else {
                    Some(repo.repo_root())
                }
            }
            DelegationCommand::Agents { .. } => None,
        },
        Command::SymbolsStatus { repo } => Some(repo.repo_root()),
        Command::ImpactDiagnostics { repo, .. } => Some(repo.repo_root()),
        Command::ImpactGraph { repo, .. } => Some(repo.repo_root()),
        Command::Open { repo, .. } => Some(repo.repo_root()),
        Command::File { command } => match command {
            FileCommand::EnsureNewline { repo, .. } => Some(repo.repo_root()),
            FileCommand::Write { repo, .. } => Some(repo.repo_root()),
        },
        Command::Test { command } => match command {
            TestCommand::RunNode { repo, .. } => Some(repo.repo_root()),
        },
        Command::RunTests { repo, .. } => Some(repo.repo_root()),
        Command::Tui { repo } => repo
            .as_ref()
            .map(|root| root.canonicalize().unwrap_or_else(|_| root.to_path_buf())),
        Command::MemoryStore { repo, .. } => Some(repo.repo_root()),
        Command::MemoryRecall { repo, .. } => Some(repo.repo_root()),
        Command::Mswarm { .. } => None,
        Command::MemoryCompact { repo, .. } => Some(repo.repo_root()),
        Command::MemoryLayers { scope } => scope.repo_root(),
        Command::MemoryRoute { scope, .. } => scope.repo_root(),
        Command::Conversations { command } => match command {
            ConversationCommand::Import { scope, .. } => scope.repo_root(),
            ConversationCommand::Search { scope, .. } => scope.repo_root(),
            ConversationCommand::List { scope, .. } => scope.repo_root(),
            ConversationCommand::Read { scope, .. } => scope.repo_root(),
            ConversationCommand::Export { scope, .. } => scope.repo_root(),
            ConversationCommand::Redact { scope, .. } => scope.repo_root(),
            ConversationCommand::Prune { scope, .. } => scope.repo_root(),
            ConversationCommand::Delete { scope, .. } => scope.repo_root(),
            ConversationCommand::KgQuery { scope, .. } => scope.repo_root(),
            ConversationCommand::KgTimeline { scope, .. } => scope.repo_root(),
            ConversationCommand::KgSearchNodes { scope, .. } => scope.repo_root(),
            ConversationCommand::KgSearchEdges { scope, .. } => scope.repo_root(),
            ConversationCommand::KgSearchEpisodes { scope, .. } => scope.repo_root(),
            ConversationCommand::KgNeighborhood { scope, .. } => scope.repo_root(),
            ConversationCommand::KgEntityLinks { scope, .. } => scope.repo_root(),
            ConversationCommand::KgEpisode { scope, .. } => scope.repo_root(),
            ConversationCommand::KgDeleteEdge { scope, .. } => scope.repo_root(),
            ConversationCommand::KgDeleteEpisode { scope, .. } => scope.repo_root(),
            ConversationCommand::KgRebuild { scope, .. } => scope.repo_root(),
            ConversationCommand::KgClear { scope, .. } => scope.repo_root(),
        },
        Command::Diary { command } => match command {
            DiaryCommand::Write { scope, .. } => scope.repo_root(),
            DiaryCommand::Read { scope, .. } => scope.repo_root(),
        },
        Command::Hook { command } => match command {
            HookCommand::PreCommit { repo } => Some(repo.repo_root()),
            HookCommand::Conversation { scope, .. } => scope.repo_root(),
        },
        Command::WebRag { repo, .. } => Some(repo.repo_root()),
        Command::Repo { command } => match command {
            RepoCommand::Init { repo, .. } => Some(repo.repo_root()),
            RepoCommand::Id { repo, .. } => Some(repo.repo_root()),
            RepoCommand::Status { repo, .. } => Some(repo.repo_root()),
            RepoCommand::Dirty { repo, .. } => Some(repo.repo_root()),
            RepoCommand::Inspect { repo, .. } => Some(repo.repo_root()),
            RepoCommand::Reassociate { repo, .. } => Some(repo.repo_root()),
        },
        _ => None,
    }
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

#[cfg(test)]
mod tests;
