use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::NamedTempFile;
use tracing::warn;
use url::Url;
use uuid::Uuid;

const MCODA_DIR: &str = ".mcoda";
const MCODA_DB: &str = "mcoda.db";
const MCODA_KEY: &str = "mcoda.key";
const MCODA_AGENT_LIST_JSON_REFRESH_ARGS: [&str; 4] =
    ["agent", "list", "--json", "--refresh-health"];
const MCODA_AGENT_LIST_JSON_ARGS: [&str; 3] = ["agent", "list", "--json"];
const DOCDEX_MCODA_CLI_TIMEOUT_MS: &str = "DOCDEX_MCODA_CLI_TIMEOUT_MS";
const DEFAULT_MCODA_CLI_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_MCODA_CLI_BACKOFF_MS: u64 = 60_000;
const MCODA_CLI_POLL_INTERVAL_MS: u64 = 50;
const AUTH_IV_LEN: usize = 12;
const AUTH_TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

#[derive(Debug, Clone)]
pub struct McodaRegistry {
    pub db_path: PathBuf,
    pub agents: Vec<McodaAgent>,
}

#[derive(Debug, Clone)]
pub struct McodaAgent {
    pub id: String,
    pub slug: String,
    pub adapter: String,
    pub default_model: Option<String>,
    pub config: Option<Value>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
    pub rating: Option<f64>,
    pub cost_per_million: Option<f64>,
    pub max_complexity: Option<i64>,
    pub best_usage: Option<String>,
    pub reasoning_rating: Option<f64>,
    pub health_status: Option<String>,
    pub cli_binary: Option<String>,
    pub capabilities: Vec<String>,
    pub models: Vec<McodaAgentModel>,
    pub auth: Option<McodaAgentAuth>,
    pub usage_limits: Vec<McodaAgentUsageLimit>,
}

#[derive(Debug, Clone)]
pub struct McodaAgentModel {
    pub model_name: String,
    pub is_default: bool,
    pub config: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct McodaAgentAuth {
    pub encrypted_secret: String,
    pub decrypted_secret: Option<String>,
    pub last_verified_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct McodaAgentUsageLimit {
    pub agent_id: String,
    pub limit_scope: String,
    pub limit_key: String,
    pub window_type: String,
    pub status: String,
    pub reset_at: Option<String>,
    pub observed_at: Option<String>,
    pub source: Option<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McodaCloudAgent {
    pub slug: String,
    pub provider: String,
    pub default_model: String,
    #[serde(default)]
    pub cost_per_million: Option<f64>,
    #[serde(default)]
    pub rating: Option<f64>,
    #[serde(default)]
    pub reasoning_rating: Option<f64>,
    #[serde(default)]
    pub max_complexity: Option<i64>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub health_status: Option<String>,
    #[serde(default)]
    pub context_window: Option<u64>,
    #[serde(default)]
    pub max_output_tokens: Option<u32>,
    #[serde(default)]
    pub supports_tools: bool,
    #[serde(default)]
    pub best_usage: Option<String>,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub supports_reasoning: Option<bool>,
    #[serde(default)]
    pub pricing_snapshot_id: Option<String>,
    #[serde(default)]
    pub pricing_version: Option<String>,
    #[serde(default)]
    pub sync: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct McodaCloudListOptions {
    pub provider: Option<String>,
    pub limit: Option<usize>,
    pub max_cost_per_million: Option<f64>,
    pub min_context_window: Option<usize>,
    pub min_reasoning_rating: Option<f64>,
    pub sort_by_catalog_rating: bool,
    pub base_url: Option<String>,
    pub api_key: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McodaCliAgentRecord {
    id: Option<String>,
    slug: Option<String>,
    adapter: Option<String>,
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default)]
    config: Option<Value>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    updated_at: Option<String>,
    #[serde(default)]
    rating: Option<f64>,
    #[serde(default)]
    cost_per_million: Option<f64>,
    #[serde(default)]
    max_complexity: Option<i64>,
    #[serde(default)]
    best_usage: Option<String>,
    #[serde(default)]
    reasoning_rating: Option<f64>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    models: Vec<McodaCliModelRecord>,
    #[serde(default)]
    health: Option<McodaCliHealthRecord>,
    #[serde(default)]
    health_status: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McodaCliModelRecord {
    #[serde(default)]
    model_name: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    default: Option<bool>,
    #[serde(default)]
    is_default: Option<bool>,
    #[serde(default)]
    config: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct McodaCliHealthRecord {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    details: Option<Value>,
}

struct McodaCliOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum McodaCliAttemptKind {
    Refresh,
    Plain,
}

#[derive(Default)]
struct McodaCliBackoffState {
    refresh_until: Option<Instant>,
    plain_until: Option<Instant>,
}

impl McodaRegistry {
    pub fn load_default() -> Result<Option<Self>> {
        if let Some(registry) = Self::load_from_cli()? {
            return Ok(Some(registry));
        }
        Self::load_default_db_only()
    }

    pub fn load_default_db_only() -> Result<Option<Self>> {
        let db_path = default_db_path()?;
        if !db_path.exists() {
            return Ok(None);
        }
        let key_path = default_key_path()?;
        Ok(Some(Self::load_from_paths(&db_path, &key_path)?))
    }

    pub fn load_from_cli() -> Result<Option<Self>> {
        let Some(stdout) = run_mcoda_agent_list_json()? else {
            return Ok(None);
        };
        let mut agents =
            parse_mcoda_cli_agents(&stdout).context("parse mcoda agent list --json")?;
        let db_path = default_db_path()?;
        let key_path = default_key_path()?;
        hydrate_cli_agents_from_db(&mut agents, &db_path, &key_path);
        Ok(Some(Self { db_path, agents }))
    }

    pub fn load_from_paths(db_path: &Path, key_path: &Path) -> Result<Self> {
        let conn = open_readonly_immutable(db_path)
            .with_context(|| format!("open mcoda registry {}", db_path.display()))?;

        let mut agents = load_agents(&conn)?;
        let mut capabilities = load_capabilities(&conn)?;
        let mut models = load_models(&conn)?;
        let mut auth = load_auth(&conn, key_path)?;
        let mut health = load_health(&conn)?;
        let mut usage_limits = load_usage_limits(&conn)?;

        for agent in &mut agents {
            if let Some(values) = capabilities.remove(&agent.id) {
                agent.capabilities = values;
            }
            if let Some(values) = models.remove(&agent.id) {
                agent.models = values;
            }
            if let Some(value) = auth.remove(&agent.id) {
                agent.auth = Some(value);
            }
            if let Some(value) = health.remove(&agent.id) {
                agent.health_status = Some(value);
            }
            if let Some(values) = usage_limits.remove(&agent.id) {
                agent.usage_limits = values;
            }
        }

        Ok(Self {
            db_path: db_path.to_path_buf(),
            agents,
        })
    }

    pub fn agent_by_id(&self, id: &str) -> Option<&McodaAgent> {
        self.agents.iter().find(|agent| agent.id == id)
    }

    pub fn agent_by_slug(&self, slug: &str) -> Option<&McodaAgent> {
        self.agents.iter().find(|agent| agent.slug == slug)
    }
}

pub(crate) fn default_db_path() -> Result<PathBuf> {
    Ok(default_mcoda_dir()?.join(MCODA_DB))
}

fn default_key_path() -> Result<PathBuf> {
    Ok(default_mcoda_dir()?.join(MCODA_KEY))
}

fn default_mcoda_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            Some(PathBuf::from(drive).join(path))
        })
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(home.join(MCODA_DIR))
}

fn trim_non_empty(input: Option<String>) -> Option<String> {
    let value = input?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn trim_non_empty_str(input: Option<&str>) -> Option<String> {
    let value = input?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn cli_binary_from_health_details(details: Option<&Value>) -> Option<String> {
    let details = details?.as_object()?;
    trim_non_empty_str(details.get("binary").and_then(Value::as_str))
}

fn cli_binary_from_config(config: Option<&Value>) -> Option<String> {
    let config = config?.as_object()?;
    for key in ["binary", "cliBinary", "cli_path", "cliPath"] {
        let Some(value) = config.get(key) else {
            continue;
        };
        if let Some(binary) = trim_non_empty_str(value.as_str()) {
            return Some(binary);
        }
    }
    None
}

fn run_mcoda_agent_list_json() -> Result<Option<String>> {
    let cli_disabled = std::env::var("DOCDEX_DISABLE_MCODA_CLI")
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        })
        .unwrap_or(false);
    if cli_disabled {
        return Ok(None);
    }

    let timeout = mcoda_cli_timeout();
    let attempts: [&[&str]; 2] = [
        &MCODA_AGENT_LIST_JSON_REFRESH_ARGS,
        &MCODA_AGENT_LIST_JSON_ARGS,
    ];
    for args in attempts {
        if should_skip_mcoda_cli_attempt(args) {
            continue;
        }
        let output = match run_mcoda_command(args, timeout) {
            Ok(Some(output)) => output,
            Ok(None) => continue,
            Err(err) => return Err(err),
        };
        if !output.status.success() {
            note_mcoda_cli_failure(args);
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!(
                target: "docdexd",
                args = ?args,
                status = ?output.status.code(),
                stderr = %stderr.trim(),
                "mcoda agent list failed"
            );
            continue;
        }
        let stdout = String::from_utf8(output.stdout).context("decode mcoda agent list --json")?;
        if stdout.trim().is_empty() {
            note_mcoda_cli_failure(args);
            continue;
        }
        clear_mcoda_cli_failure(args);
        return Ok(Some(stdout));
    }
    Ok(None)
}

fn build_mcoda_cloud_list_args(options: &McodaCloudListOptions) -> Vec<String> {
    let mut args = vec![
        "cloud".to_string(),
        "agent".to_string(),
        "list".to_string(),
        "--json".to_string(),
    ];
    if let Some(provider) = trim_non_empty(options.provider.clone()) {
        args.push("--provider".to_string());
        args.push(provider);
    }
    if let Some(limit) = options.limit.filter(|value| *value > 0) {
        args.push("--limit".to_string());
        args.push(limit.to_string());
    }
    if let Some(max_cost) = options
        .max_cost_per_million
        .filter(|value| value.is_finite() && *value >= 0.0)
    {
        args.push("--max-cost-per-1m-token".to_string());
        args.push(max_cost.to_string());
    }
    if let Some(min_context) = options.min_context_window.filter(|value| *value > 0) {
        args.push("--min-context".to_string());
        args.push(min_context.to_string());
    }
    if let Some(min_reasoning) = options
        .min_reasoning_rating
        .filter(|value| value.is_finite() && *value >= 0.0)
    {
        args.push("--min-reasoning".to_string());
        args.push(min_reasoning.to_string());
    }
    if options.sort_by_catalog_rating {
        args.push("--sorted-by-catalog-rating".to_string());
    }
    args
}

fn cloud_command_envs(options: &McodaCloudListOptions) -> Vec<(&'static str, &str)> {
    let mut envs = Vec::new();
    if let Some(base_url) = options
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        envs.push(("MCODA_MSWARM_BASE_URL", base_url));
    }
    if let Some(api_key) = options
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        envs.push(("MCODA_MSWARM_API_KEY", api_key));
    }
    envs
}

fn parse_mcoda_cloud_agents(raw: &str) -> Result<Vec<McodaCloudAgent>> {
    serde_json::from_str(raw).context("decode mcoda cloud agent payload")
}

pub fn list_cloud_agents(options: &McodaCloudListOptions) -> Result<Vec<McodaCloudAgent>> {
    let args = build_mcoda_cloud_list_args(options);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let envs = cloud_command_envs(options);
    let output = match run_mcoda_command_with_env(&arg_refs, mcoda_cli_timeout(), &envs) {
        Ok(Some(output)) => output,
        Ok(None) => return Ok(Vec::new()),
        Err(err) => return Err(err).context("run mcoda cloud agent list"),
    };
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "mcoda cloud agent list failed (status {:?}): {}",
            output.status.code(),
            stderr.trim()
        ));
    }
    let stdout =
        String::from_utf8(output.stdout).context("decode mcoda cloud agent list --json")?;
    if stdout.trim().is_empty() {
        return Ok(Vec::new());
    }
    parse_mcoda_cloud_agents(&stdout)
}

fn mcoda_cli_timeout() -> Duration {
    std::env::var(DOCDEX_MCODA_CLI_TIMEOUT_MS)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_MCODA_CLI_TIMEOUT_MS))
}

fn mcoda_cli_backoff() -> Duration {
    Duration::from_millis(DEFAULT_MCODA_CLI_BACKOFF_MS)
}

fn mcoda_cli_backoff_state() -> &'static Mutex<McodaCliBackoffState> {
    static STATE: OnceLock<Mutex<McodaCliBackoffState>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(McodaCliBackoffState::default()))
}

fn mcoda_cli_attempt_kind(args: &[&str]) -> McodaCliAttemptKind {
    if args.len() == MCODA_AGENT_LIST_JSON_REFRESH_ARGS.len()
        && args
            .iter()
            .copied()
            .eq(MCODA_AGENT_LIST_JSON_REFRESH_ARGS.iter().copied())
    {
        McodaCliAttemptKind::Refresh
    } else {
        McodaCliAttemptKind::Plain
    }
}

fn should_skip_mcoda_cli_attempt(args: &[&str]) -> bool {
    let kind = mcoda_cli_attempt_kind(args);
    let now = Instant::now();
    let Ok(state) = mcoda_cli_backoff_state().lock() else {
        return false;
    };
    let until = match kind {
        McodaCliAttemptKind::Refresh => state.refresh_until,
        McodaCliAttemptKind::Plain => state.plain_until,
    };
    until.is_some_and(|deadline| deadline > now)
}

fn note_mcoda_cli_failure(args: &[&str]) {
    let kind = mcoda_cli_attempt_kind(args);
    let deadline = Instant::now() + mcoda_cli_backoff();
    if let Ok(mut state) = mcoda_cli_backoff_state().lock() {
        match kind {
            McodaCliAttemptKind::Refresh => state.refresh_until = Some(deadline),
            McodaCliAttemptKind::Plain => state.plain_until = Some(deadline),
        }
    }
}

fn clear_mcoda_cli_failure(args: &[&str]) {
    let kind = mcoda_cli_attempt_kind(args);
    if let Ok(mut state) = mcoda_cli_backoff_state().lock() {
        match kind {
            McodaCliAttemptKind::Refresh => state.refresh_until = None,
            McodaCliAttemptKind::Plain => state.plain_until = None,
        }
    }
}

#[cfg(test)]
fn reset_mcoda_cli_backoff() {
    if let Ok(mut state) = mcoda_cli_backoff_state().lock() {
        *state = McodaCliBackoffState::default();
    }
}

fn run_mcoda_command(args: &[&str], timeout: Duration) -> Result<Option<McodaCliOutput>> {
    run_mcoda_command_with_env(args, timeout, &[])
}

fn run_mcoda_command_with_env(
    args: &[&str],
    timeout: Duration,
    envs: &[(&str, &str)],
) -> Result<Option<McodaCliOutput>> {
    let stdout_file = NamedTempFile::new().context("create mcoda stdout temp file")?;
    let stderr_file = NamedTempFile::new().context("create mcoda stderr temp file")?;
    let stdout_writer = stdout_file
        .reopen()
        .context("open mcoda stdout temp file")?;
    let stderr_writer = stderr_file
        .reopen()
        .context("open mcoda stderr temp file")?;

    let mut command = Command::new("mcoda");
    command
        .args(args)
        .stdout(Stdio::from(stdout_writer))
        .stderr(Stdio::from(stderr_writer));
    for (key, value) in envs {
        command.env(key, value);
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).context("spawn mcoda command"),
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().context("poll mcoda command")? {
            Some(status) => {
                let stdout = fs::read(stdout_file.path()).context("read mcoda stdout temp file")?;
                let stderr = fs::read(stderr_file.path()).context("read mcoda stderr temp file")?;
                return Ok(Some(McodaCliOutput {
                    status,
                    stdout,
                    stderr,
                }));
            }
            None if Instant::now() >= deadline => {
                note_mcoda_cli_failure(args);
                if let Err(err) = child.kill() {
                    warn!(
                        target: "docdexd",
                        args = ?args,
                        error = ?err,
                        "failed to kill timed out mcoda process"
                    );
                }
                let _ = child.wait();
                warn!(
                    target: "docdexd",
                    args = ?args,
                    timeout_ms = timeout.as_millis(),
                    "mcoda command timed out"
                );
                return Ok(None);
            }
            None => thread::sleep(Duration::from_millis(MCODA_CLI_POLL_INTERVAL_MS)),
        }
    }
}

fn parse_mcoda_cli_agents(raw: &str) -> Result<Vec<McodaAgent>> {
    let records: Vec<McodaCliAgentRecord> =
        serde_json::from_str(raw).context("decode mcoda CLI payload")?;
    let mut agents = Vec::new();
    for record in records {
        let Some(id) = trim_non_empty(record.id) else {
            continue;
        };
        let Some(slug) = trim_non_empty(record.slug) else {
            continue;
        };
        let Some(adapter) = trim_non_empty(record.adapter) else {
            continue;
        };

        let mut models = Vec::new();
        for model in record.models {
            let model_name =
                trim_non_empty(model.model_name).or_else(|| trim_non_empty(model.name));
            let Some(model_name) = model_name else {
                continue;
            };
            models.push(McodaAgentModel {
                model_name,
                is_default: model.default.unwrap_or(false) || model.is_default.unwrap_or(false),
                config: model.config,
            });
        }
        let default_model = trim_non_empty(record.default_model).or_else(|| {
            models
                .iter()
                .find(|model| model.is_default)
                .map(|model| model.model_name.clone())
        });
        let config = record.config;
        let health = record.health;
        let cli_binary = health
            .as_ref()
            .and_then(|health| cli_binary_from_health_details(health.details.as_ref()))
            .or_else(|| cli_binary_from_config(config.as_ref()));
        let health_status = trim_non_empty(record.health_status)
            .or_else(|| health.and_then(|health| trim_non_empty(health.status)));

        agents.push(McodaAgent {
            id,
            slug,
            adapter,
            default_model,
            config,
            created_at: trim_non_empty(record.created_at),
            updated_at: trim_non_empty(record.updated_at),
            rating: record.rating,
            cost_per_million: record.cost_per_million,
            max_complexity: record.max_complexity,
            best_usage: trim_non_empty(record.best_usage),
            reasoning_rating: record.reasoning_rating,
            health_status,
            cli_binary,
            capabilities: record.capabilities,
            models,
            auth: None,
            usage_limits: Vec::new(),
        });
    }
    Ok(agents)
}

fn hydrate_cli_agents_from_db(agents: &mut [McodaAgent], db_path: &Path, key_path: &Path) {
    if agents.is_empty() || !db_path.exists() {
        return;
    }
    let conn = match open_readonly_immutable(db_path) {
        Ok(conn) => conn,
        Err(err) => {
            warn!(
                "failed to open mcoda db {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            return;
        }
    };

    let mut auth_by_id = match load_auth(&conn, key_path) {
        Ok(auth) => auth,
        Err(err) => {
            warn!(
                "failed to load mcoda auth from {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            HashMap::new()
        }
    };
    let mut usage_limits_by_id = match load_usage_limits(&conn) {
        Ok(usage_limits) => usage_limits,
        Err(err) => {
            warn!(
                "failed to load mcoda usage limits from {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            HashMap::new()
        }
    };
    let db_agents = match load_agents(&conn) {
        Ok(agents) => agents,
        Err(err) => {
            warn!(
                "failed to load mcoda agents from {} while hydrating CLI agents: {err}",
                db_path.display()
            );
            Vec::new()
        }
    };
    if auth_by_id.is_empty() && db_agents.is_empty() {
        return;
    }

    let mut db_agents_by_id: HashMap<String, McodaAgent> = HashMap::new();
    let mut db_id_by_slug: HashMap<String, String> = HashMap::new();
    for agent in db_agents {
        db_id_by_slug.insert(agent.slug.clone(), agent.id.clone());
        db_agents_by_id.insert(agent.id.clone(), agent);
    }

    for agent in agents.iter_mut() {
        let db_agent = db_agents_by_id.get(&agent.id).or_else(|| {
            db_id_by_slug
                .get(&agent.slug)
                .and_then(|db_id| db_agents_by_id.get(db_id))
        });
        if let Some(db_agent) = db_agent {
            if agent.config.is_none() {
                agent.config = db_agent.config.clone();
            }
            if agent.default_model.is_none() {
                agent.default_model = db_agent.default_model.clone();
            }
            if agent.cli_binary.is_none() {
                agent.cli_binary = db_agent.cli_binary.clone();
            }
            if agent.adapter.trim().is_empty() {
                agent.adapter = db_agent.adapter.clone();
            }
        }

        if agent.auth.is_none() {
            if let Some(auth) = auth_by_id.remove(&agent.id) {
                agent.auth = Some(auth);
            } else if let Some(db_id) = db_id_by_slug.get(&agent.slug) {
                if let Some(auth) = auth_by_id.remove(db_id) {
                    agent.auth = Some(auth);
                }
            }
        }
        if agent.usage_limits.is_empty() {
            if let Some(usage_limits) = usage_limits_by_id.remove(&agent.id) {
                agent.usage_limits = usage_limits;
            } else if let Some(db_id) = db_id_by_slug.get(&agent.slug) {
                if let Some(usage_limits) = usage_limits_by_id.remove(db_id) {
                    agent.usage_limits = usage_limits;
                }
            }
        }
    }
}

fn open_readonly_immutable(path: &Path) -> Result<Connection> {
    let url = Url::from_file_path(path)
        .map_err(|_| anyhow!("invalid mcoda db path: {}", path.display()))?;
    let mut uri = url.to_string();
    let separator = if uri.contains('?') { "&" } else { "?" };
    uri.push_str(separator);
    uri.push_str("immutable=1&mode=ro");
    Connection::open_with_flags(
        uri.as_str(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI,
    )
    .context("open sqlite connection")
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    if !table_exists(conn, table)? {
        return Ok(HashSet::new());
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = HashSet::new();
    for row in rows {
        columns.insert(row?);
    }
    Ok(columns)
}

fn load_agents(conn: &Connection) -> Result<Vec<McodaAgent>> {
    if !table_exists(conn, "agents")? {
        return Ok(Vec::new());
    }
    let columns = table_columns(conn, "agents")?;
    let rating_sql = if columns.contains("rating") {
        "rating"
    } else {
        "NULL"
    };
    let cost_sql = if columns.contains("cost_per_million") {
        "cost_per_million"
    } else {
        "NULL"
    };
    let complexity_sql = if columns.contains("max_complexity") {
        "max_complexity"
    } else {
        "NULL"
    };
    let usage_sql = if columns.contains("best_usage") {
        "best_usage"
    } else {
        "NULL"
    };
    let reasoning_sql = if columns.contains("reasoning_rating") {
        "reasoning_rating"
    } else {
        "NULL"
    };
    let mut stmt = conn.prepare(
        &format!(
            "SELECT id, slug, adapter, default_model, config_json, created_at, updated_at,
                    {rating_sql} as rating, {cost_sql} as cost_per_million, {complexity_sql} as max_complexity,
                    {usage_sql} as best_usage, {reasoning_sql} as reasoning_rating
             FROM agents
             ORDER BY slug ASC"
        ),
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<f64>>(7)?,
            row.get::<_, Option<f64>>(8)?,
            row.get::<_, Option<i64>>(9)?,
            row.get::<_, Option<String>>(10)?,
            row.get::<_, Option<f64>>(11)?,
        ))
    })?;

    let mut agents = Vec::new();
    for row in rows {
        let (
            id,
            slug,
            adapter,
            default_model,
            config_raw,
            created_at,
            updated_at,
            rating,
            cost_per_million,
            max_complexity,
            best_usage,
            reasoning_rating,
        ) = row?;
        let config = match config_raw {
            Some(raw) => Some(serde_json::from_str(&raw).context("parse agents.config_json")?),
            None => None,
        };
        let cli_binary = cli_binary_from_config(config.as_ref());
        agents.push(McodaAgent {
            id,
            slug,
            adapter,
            default_model,
            config,
            created_at,
            updated_at,
            rating,
            cost_per_million,
            max_complexity,
            best_usage,
            reasoning_rating,
            capabilities: Vec::new(),
            models: Vec::new(),
            auth: None,
            usage_limits: Vec::new(),
            health_status: None,
            cli_binary,
        });
    }
    Ok(agents)
}

fn load_capabilities(conn: &Connection) -> Result<HashMap<String, Vec<String>>> {
    if !table_exists(conn, "agent_capabilities")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, capability
         FROM agent_capabilities
         ORDER BY capability ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for row in rows {
        let (agent_id, capability) = row?;
        map.entry(agent_id).or_default().push(capability);
    }
    Ok(map)
}

fn load_models(conn: &Connection) -> Result<HashMap<String, Vec<McodaAgentModel>>> {
    if !table_exists(conn, "agent_models")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, model_name, is_default, config_json
         FROM agent_models
         ORDER BY model_name ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut map: HashMap<String, Vec<McodaAgentModel>> = HashMap::new();
    for row in rows {
        let (agent_id, model_name, is_default, config_raw) = row?;
        let config = match config_raw {
            Some(raw) => {
                Some(serde_json::from_str(&raw).context("parse agent_models.config_json")?)
            }
            None => None,
        };
        let model = McodaAgentModel {
            model_name,
            is_default: is_default != 0,
            config,
        };
        map.entry(agent_id).or_default().push(model);
    }
    Ok(map)
}

fn load_auth(conn: &Connection, key_path: &Path) -> Result<HashMap<String, McodaAgentAuth>> {
    if !table_exists(conn, "agent_auth")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, encrypted_secret, last_verified_at, updated_at
         FROM agent_auth",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;

    let mut raw = Vec::new();
    for row in rows {
        raw.push(row?);
    }

    let needs_key = raw
        .iter()
        .any(|(_, secret, _, _)| !secret.trim().is_empty());
    let key = if needs_key {
        match load_mcoda_key(key_path) {
            Ok(key) => Some(key),
            Err(err) => {
                warn!("failed to load mcoda key {}: {err}", key_path.display());
                None
            }
        }
    } else {
        None
    };

    let mut map: HashMap<String, McodaAgentAuth> = HashMap::new();
    for (agent_id, encrypted_secret, last_verified_at, updated_at) in raw {
        let decrypted_secret = if encrypted_secret.trim().is_empty() {
            None
        } else if let Some(key) = key.as_ref() {
            match decrypt_secret(&encrypted_secret, key) {
                Ok(secret) => {
                    let trimmed = secret.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                }
                Err(err) => {
                    warn!(
                        "failed to decrypt mcoda agent_auth secret for agent {}: {err}",
                        agent_id
                    );
                    None
                }
            }
        } else {
            warn!(
                "mcoda key missing; cannot decrypt agent_auth secret for agent {}",
                agent_id
            );
            None
        };
        map.insert(
            agent_id,
            McodaAgentAuth {
                encrypted_secret,
                decrypted_secret,
                last_verified_at,
                updated_at,
            },
        );
    }
    Ok(map)
}

fn load_health(conn: &Connection) -> Result<HashMap<String, String>> {
    if !table_exists(conn, "agent_health")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, status
         FROM agent_health
         ORDER BY agent_id ASC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut map: HashMap<String, String> = HashMap::new();
    for row in rows {
        let (agent_id, status) = row?;
        let trimmed = status.trim();
        if !trimmed.is_empty() {
            map.insert(agent_id, trimmed.to_string());
        }
    }
    Ok(map)
}

fn load_usage_limits(conn: &Connection) -> Result<HashMap<String, Vec<McodaAgentUsageLimit>>> {
    if !table_exists(conn, "agent_usage_limits")? {
        return Ok(HashMap::new());
    }
    let mut stmt = conn.prepare(
        "SELECT agent_id, limit_scope, limit_key, window_type, status, reset_at, observed_at, source, details_json
         FROM agent_usage_limits
         ORDER BY datetime(observed_at) DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, Option<String>>(7)?,
            row.get::<_, Option<String>>(8)?,
        ))
    })?;
    let mut map: HashMap<String, Vec<McodaAgentUsageLimit>> = HashMap::new();
    for row in rows {
        let (
            agent_id,
            limit_scope,
            limit_key,
            window_type,
            status,
            reset_at,
            observed_at,
            source,
            details_raw,
        ) = row?;
        let details = match details_raw {
            Some(raw) => {
                Some(serde_json::from_str(&raw).context("parse agent_usage_limits.details_json")?)
            }
            None => None,
        };
        map.entry(agent_id.clone())
            .or_default()
            .push(McodaAgentUsageLimit {
                agent_id,
                limit_scope,
                limit_key,
                window_type,
                status,
                reset_at,
                observed_at,
                source,
                details,
            });
    }
    Ok(map)
}

fn load_mcoda_key(path: &Path) -> Result<Vec<u8>> {
    let key = fs::read(path).with_context(|| format!("read mcoda key {}", path.display()))?;
    if key.len() != KEY_LEN {
        return Err(anyhow!(
            "mcoda key must be {KEY_LEN} bytes, got {}",
            key.len()
        ));
    }
    Ok(key)
}

fn decrypt_secret(payload: &str, key: &[u8]) -> Result<String> {
    let decoded = Base64Engine
        .decode(payload.trim())
        .context("base64 decode agent_auth secret")?;
    if decoded.len() < AUTH_IV_LEN + AUTH_TAG_LEN {
        return Err(anyhow!(
            "agent_auth secret is too short ({} bytes)",
            decoded.len()
        ));
    }
    let (iv, rest) = decoded.split_at(AUTH_IV_LEN);
    let (tag, ciphertext) = rest.split_at(AUTH_TAG_LEN);
    let cipher = Aes256Gcm::new_from_slice(key).context("init AES-256-GCM")?;
    let nonce = Nonce::from_slice(iv);
    let mut combined = Vec::with_capacity(ciphertext.len() + tag.len());
    combined.extend_from_slice(ciphertext);
    combined.extend_from_slice(tag);
    let plaintext = cipher
        .decrypt(nonce, combined.as_ref())
        .map_err(|_| anyhow!("decrypt agent_auth secret"))?;
    let decoded = String::from_utf8(plaintext).context("decode agent_auth secret utf8")?;
    Ok(decoded)
}

fn ensure_mcoda_key(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        return load_mcoda_key(path);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create mcoda key dir {}", parent.display()))?;
    }
    let mut key = Vec::with_capacity(KEY_LEN);
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    key.extend_from_slice(Uuid::new_v4().as_bytes());
    fs::write(path, &key).with_context(|| format!("write mcoda key {}", path.display()))?;
    Ok(key)
}

fn encrypt_secret(secret: &str, key: &[u8]) -> Result<String> {
    if key.len() != KEY_LEN {
        return Err(anyhow!(
            "mcoda key must be {KEY_LEN} bytes, got {}",
            key.len()
        ));
    }
    let cipher = Aes256Gcm::new_from_slice(key).context("init AES-256-GCM")?;
    let nonce_bytes = &Uuid::new_v4().into_bytes()[..AUTH_IV_LEN];
    let nonce = Nonce::from_slice(nonce_bytes);
    let encrypted = cipher
        .encrypt(nonce, secret.as_bytes())
        .map_err(|_| anyhow!("encrypt agent_auth secret"))?;
    let split_at = encrypted
        .len()
        .checked_sub(AUTH_TAG_LEN)
        .ok_or_else(|| anyhow!("encrypt agent_auth secret: ciphertext too short"))?;
    let (ciphertext, tag) = encrypted.split_at(split_at);
    let mut payload = Vec::with_capacity(AUTH_IV_LEN + AUTH_TAG_LEN + ciphertext.len());
    payload.extend_from_slice(nonce_bytes);
    payload.extend_from_slice(tag);
    payload.extend_from_slice(ciphertext);
    Ok(Base64Engine.encode(payload))
}

fn managed_cloud_agent_slug(remote_slug: &str) -> String {
    let normalized = remote_slug
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .to_string();
    format!(
        "mswarm-cloud-{}",
        if normalized.is_empty() {
            "agent"
        } else {
            &normalized
        }
    )
}

fn infer_cloud_best_usage(agent: &McodaCloudAgent) -> String {
    let fragments = [
        agent.slug.as_str(),
        agent.default_model.as_str(),
        agent.display_name.as_deref().unwrap_or_default(),
        agent.description.as_deref().unwrap_or_default(),
    ]
    .join(" ")
    .to_ascii_lowercase();
    if fragments.contains("review") {
        return "code_reviewer".to_string();
    }
    if fragments.contains("coder") || fragments.contains("codestral") || fragments.contains("code")
    {
        return "code_writer".to_string();
    }
    if fragments.contains("thinking") || fragments.contains("reason") {
        return "general_chat".to_string();
    }
    "general_chat".to_string()
}

fn cloud_capabilities(agent: &McodaCloudAgent, usage: &str) -> Vec<String> {
    let mut capabilities: Vec<String> = Vec::new();
    match usage {
        "code_writer" => {
            capabilities.push("code_write".to_string());
            capabilities.push("code_review".to_string());
            capabilities.push("chat".to_string());
        }
        "code_reviewer" => {
            capabilities.push("code_review".to_string());
            capabilities.push("chat".to_string());
        }
        _ => {
            capabilities.push("chat".to_string());
        }
    }
    if agent.supports_tools {
        capabilities.push("tools".to_string());
    }
    for capability in &agent.capabilities {
        if let Some(value) = trim_non_empty_str(Some(capability)) {
            capabilities.push(value.to_ascii_lowercase());
        }
    }
    capabilities.sort();
    capabilities.dedup();
    capabilities
}

fn managed_cloud_config(base_url: &str, openai_base_url: &str, agent: &McodaCloudAgent) -> Value {
    serde_json::json!({
        "baseUrl": openai_base_url,
        "apiBaseUrl": openai_base_url,
        "mswarmCloud": {
            "managed": true,
            "remoteSlug": agent.slug,
            "provider": agent.provider,
            "modelId": agent.model_id,
            "displayName": agent.display_name,
            "description": agent.description,
            "supportsReasoning": agent.supports_reasoning,
            "pricingSnapshotId": agent.pricing_snapshot_id,
            "pricingVersion": agent.pricing_version,
            "catalogBaseUrl": base_url,
            "openAiBaseUrl": openai_base_url,
            "sync": agent.sync,
            "syncedAt": chrono::Utc::now().to_rfc3339(),
        }
    })
}

fn normalized_cloud_health_status(agent: &McodaCloudAgent) -> Option<String> {
    let status = agent.health_status.as_deref()?.trim().to_ascii_lowercase();
    if status.is_empty() {
        None
    } else {
        Some(status)
    }
}

fn ensure_mcoda_agent_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL,
            adapter TEXT NOT NULL,
            default_model TEXT,
            openai_compatible INTEGER,
            context_window INTEGER,
            max_output_tokens INTEGER,
            supports_tools INTEGER,
            rating REAL,
            reasoning_rating REAL,
            best_usage TEXT,
            cost_per_million REAL,
            max_complexity INTEGER,
            rating_samples INTEGER,
            rating_last_score REAL,
            rating_updated_at TEXT,
            complexity_samples INTEGER,
            complexity_updated_at TEXT,
            config_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_capabilities (
            agent_id TEXT NOT NULL,
            capability TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS agent_models (
            agent_id TEXT NOT NULL,
            model_name TEXT NOT NULL,
            is_default INTEGER NOT NULL,
            config_json TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_auth (
            agent_id TEXT PRIMARY KEY,
            encrypted_secret TEXT NOT NULL,
            last_verified_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS agent_health (
            agent_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            last_checked_at TEXT,
            details_json TEXT
        );",
    )
    .context("ensure mcoda agent tables")?;
    Ok(())
}

pub fn materialize_cloud_agents(
    base_url: &str,
    api_key: &str,
    agents: &[McodaCloudAgent],
) -> Result<Vec<String>> {
    if agents.is_empty() {
        return Ok(Vec::new());
    }
    let db_path = default_db_path()?;
    let key_path = default_key_path()?;
    if let Some(parent) = db_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create mcoda db dir {}", parent.display()))?;
    }
    let conn = Connection::open(&db_path)
        .with_context(|| format!("open mcoda registry {}", db_path.display()))?;
    ensure_mcoda_agent_tables(&conn)?;
    let key = ensure_mcoda_key(&key_path)?;
    let encrypted_api_key = encrypt_secret(api_key, &key)?;
    let now = chrono::Utc::now().to_rfc3339();
    let openai_base_url = Url::parse(base_url)
        .and_then(|url| url.join("/v1/swarm/openai/"))
        .context("derive mswarm openai base url")?
        .to_string();
    let existing_agents = load_agents(&conn).unwrap_or_default();
    let existing_by_slug: HashMap<String, McodaAgent> = existing_agents
        .into_iter()
        .map(|agent| (agent.slug.clone(), agent))
        .collect();
    let agent_columns = table_columns(&conn, "agents")?;
    let mut local_slugs = Vec::new();

    for agent in agents {
        let local_slug = managed_cloud_agent_slug(&agent.slug);
        let existing = existing_by_slug.get(&local_slug);
        if let Some(existing) = existing {
            let managed_slug = existing
                .config
                .as_ref()
                .and_then(|config| config.pointer("/mswarmCloud/remoteSlug"))
                .and_then(Value::as_str);
            if managed_slug != Some(agent.slug.as_str()) {
                return Err(anyhow!(
                    "refusing to overwrite non-mswarm agent {local_slug}"
                ));
            }
        }

        let agent_id = existing
            .map(|record| record.id.clone())
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let usage = agent
            .best_usage
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| infer_cloud_best_usage(agent));
        let capabilities = cloud_capabilities(agent, &usage);
        let config = managed_cloud_config(base_url, &openai_base_url, agent);
        let config_raw =
            serde_json::to_string(&config).context("serialize managed cloud config")?;
        let rating = existing.and_then(|record| record.rating).or(agent.rating);
        let reasoning_rating = existing
            .and_then(|record| record.reasoning_rating)
            .or(agent.reasoning_rating)
            .or(rating);
        let max_complexity = existing
            .and_then(|record| record.max_complexity)
            .or(agent.max_complexity)
            .unwrap_or(5);
        let cost_per_million = existing
            .and_then(|record| record.cost_per_million)
            .or(agent.cost_per_million)
            .unwrap_or(0.0);
        let created_at = existing
            .and_then(|record| record.created_at.clone())
            .unwrap_or_else(|| now.clone());

        let mut fields = vec![
            ("id", rusqlite::types::Value::from(agent_id.clone())),
            ("slug", rusqlite::types::Value::from(local_slug.clone())),
            (
                "adapter",
                rusqlite::types::Value::from("openai-api".to_string()),
            ),
            (
                "default_model",
                rusqlite::types::Value::from(agent.default_model.clone()),
            ),
            ("config_json", rusqlite::types::Value::from(config_raw)),
            ("created_at", rusqlite::types::Value::from(created_at)),
            ("updated_at", rusqlite::types::Value::from(now.clone())),
        ];
        if agent_columns.contains("openai_compatible") {
            fields.push(("openai_compatible", rusqlite::types::Value::from(1_i64)));
        }
        if agent_columns.contains("context_window") {
            fields.push((
                "context_window",
                agent
                    .context_window
                    .map(|value| rusqlite::types::Value::from(value as i64))
                    .unwrap_or(rusqlite::types::Value::Null),
            ));
        }
        if agent_columns.contains("max_output_tokens") {
            fields.push((
                "max_output_tokens",
                agent
                    .max_output_tokens
                    .map(|value| rusqlite::types::Value::from(value as i64))
                    .unwrap_or(rusqlite::types::Value::Null),
            ));
        }
        if agent_columns.contains("supports_tools") {
            fields.push((
                "supports_tools",
                rusqlite::types::Value::from(if agent.supports_tools { 1_i64 } else { 0_i64 }),
            ));
        }
        if agent_columns.contains("rating") {
            fields.push((
                "rating",
                rating
                    .map(rusqlite::types::Value::from)
                    .unwrap_or(rusqlite::types::Value::Null),
            ));
        }
        if agent_columns.contains("reasoning_rating") {
            fields.push((
                "reasoning_rating",
                reasoning_rating
                    .map(rusqlite::types::Value::from)
                    .unwrap_or(rusqlite::types::Value::Null),
            ));
        }
        if agent_columns.contains("best_usage") {
            fields.push(("best_usage", rusqlite::types::Value::from(usage.clone())));
        }
        if agent_columns.contains("cost_per_million") {
            fields.push((
                "cost_per_million",
                rusqlite::types::Value::from(cost_per_million),
            ));
        }
        if agent_columns.contains("max_complexity") {
            fields.push((
                "max_complexity",
                rusqlite::types::Value::from(max_complexity),
            ));
        }

        let field_names = fields.iter().map(|(name, _)| *name).collect::<Vec<_>>();
        let placeholders = (0..field_names.len())
            .map(|_| "?".to_string())
            .collect::<Vec<_>>();
        let update_assignments = field_names
            .iter()
            .filter(|name| **name != "id" && **name != "created_at")
            .map(|name| format!("{name} = excluded.{name}"))
            .collect::<Vec<_>>();
        let sql = format!(
            "INSERT INTO agents ({}) VALUES ({}) \
             ON CONFLICT(id) DO UPDATE SET {}",
            field_names.join(", "),
            placeholders.join(", "),
            update_assignments.join(", ")
        );
        let values = rusqlite::params_from_iter(fields.iter().map(|(_, value)| value));
        conn.execute(&sql, values)
            .context("upsert managed cloud agent")?;

        if table_exists(&conn, "agent_capabilities")? {
            conn.execute(
                "DELETE FROM agent_capabilities WHERE agent_id = ?1",
                params![agent_id],
            )?;
            for capability in &capabilities {
                conn.execute(
                    "INSERT INTO agent_capabilities (agent_id, capability) VALUES (?1, ?2)",
                    params![agent_id, capability],
                )?;
            }
        }
        if table_exists(&conn, "agent_models")? {
            conn.execute(
                "DELETE FROM agent_models WHERE agent_id = ?1",
                params![agent_id],
            )?;
            let model_config = serde_json::json!({
                "provider": agent.provider,
                "remoteSlug": agent.slug,
                "modelId": agent.model_id,
                "pricingVersion": agent.pricing_version,
            });
            conn.execute(
                "INSERT INTO agent_models (agent_id, model_name, is_default, config_json) VALUES (?1, ?2, 1, ?3)",
                params![agent_id, agent.default_model, serde_json::to_string(&model_config)?],
            )?;
        }
        if table_exists(&conn, "agent_auth")? {
            conn.execute(
                "INSERT INTO agent_auth (agent_id, encrypted_secret, last_verified_at, updated_at)
                 VALUES (?1, ?2, NULL, ?3)
                 ON CONFLICT(agent_id) DO UPDATE SET encrypted_secret = excluded.encrypted_secret, updated_at = excluded.updated_at",
                params![agent_id, encrypted_api_key, now],
            )?;
        }
        if table_exists(&conn, "agent_health")? {
            if let Some(status) = normalized_cloud_health_status(agent) {
                conn.execute(
                    "INSERT INTO agent_health (agent_id, status, last_checked_at, details_json)
                     VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(agent_id) DO UPDATE SET status = excluded.status, last_checked_at = excluded.last_checked_at, details_json = excluded.details_json",
                    params![
                        agent_id,
                        status,
                        now,
                        serde_json::to_string(&serde_json::json!({
                            "source": "docdex.mswarm",
                            "remoteSlug": agent.slug,
                            "remoteHealthStatus": agent.health_status,
                        }))?
                    ],
                )?;
            }
        }
        local_slugs.push(local_slug);
    }
    Ok(local_slugs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use std::ffi::OsString;
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.take() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn parse_mcoda_cli_agents_maps_health_and_models() -> Result<()> {
        let raw = r#"
[
  {
    "id":"agent-1",
    "slug":"devstral-local",
    "adapter":"ollama-remote",
    "defaultModel":"devstral-small-2",
    "rating":7.8,
    "costPerMillion":0,
    "maxComplexity":5,
    "bestUsage":"code_write",
    "reasoningRating":8.1,
    "capabilities":["code_write","code_review"],
    "health":{"status":"healthy","details":{"binary":"/Users/test/.local/bin/claude"}},
    "models":[{"modelName":"devstral-small-2","isDefault":true}]
  },
  {
    "id":"agent-2",
    "slug":"qa-json",
    "adapter":"codex-cli",
    "defaultModel":"gpt-5.2-codex",
    "capabilities":[],
    "health":{"status":"unhealthy"},
    "models":[{"name":"gpt-5.2-codex","default":true}]
  },
  {
    "slug":"missing-id",
    "adapter":"ollama-remote"
  }
]
"#;

        let agents = parse_mcoda_cli_agents(raw)?;
        assert_eq!(agents.len(), 2);
        assert_eq!(agents[0].id, "agent-1");
        assert_eq!(agents[0].health_status.as_deref(), Some("healthy"));
        assert_eq!(
            agents[0].cli_binary.as_deref(),
            Some("/Users/test/.local/bin/claude")
        );
        assert_eq!(agents[0].models.len(), 1);
        assert_eq!(agents[0].models[0].model_name, "devstral-small-2");
        assert!(agents[0].models[0].is_default);
        assert_eq!(agents[1].id, "agent-2");
        assert_eq!(agents[1].health_status.as_deref(), Some("unhealthy"));
        assert_eq!(agents[1].default_model.as_deref(), Some("gpt-5.2-codex"));
        assert_eq!(agents[1].cli_binary, None);
        Ok(())
    }

    #[test]
    fn load_from_cli_falls_back_when_refresh_hangs() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        reset_mcoda_cli_backoff();
        let temp = TempDir::new()?;
        let script_path = temp.path().join("mcoda");
        fs::write(
            &script_path,
            r#"#!/bin/sh
if [ "$4" = "--refresh-health" ]; then
  sleep 2
  exit 0
fi
printf '%s' '[{"id":"agent-1","slug":"qwen-3.5-27b","adapter":"ollama-remote","defaultModel":"qwen3.5:27b","capabilities":["code_write"],"health":{"status":"healthy"}}]'
"#,
        )?;
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&script_path)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script_path, permissions)?;
        }

        let existing_paths = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .collect::<Vec<_>>();
        let joined_path = std::env::join_paths(
            std::iter::once(temp.path().to_path_buf()).chain(existing_paths.into_iter()),
        )?;
        let _path_guard = EnvVarGuard::set("PATH", joined_path);
        let _timeout_guard = EnvVarGuard::set(DOCDEX_MCODA_CLI_TIMEOUT_MS, "1000");
        let _disable_guard = EnvVarGuard::set("DOCDEX_DISABLE_MCODA_CLI", "0");

        let registry = McodaRegistry::load_from_cli()?.expect("registry");
        let agent = registry.agent_by_slug("qwen-3.5-27b").expect("agent");
        assert_eq!(agent.default_model.as_deref(), Some("qwen3.5:27b"));
        assert_eq!(agent.health_status.as_deref(), Some("healthy"));
        Ok(())
    }

    #[test]
    fn load_from_cli_skips_repeated_refresh_timeouts_during_backoff() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        reset_mcoda_cli_backoff();
        let temp = TempDir::new()?;
        let plain_log_path = temp.path().join("mcoda-plain.log");
        let script_path = temp.path().join("mcoda");
        fs::write(
            &script_path,
            format!(
                r#"#!/bin/sh
if [ "$4" = "--refresh-health" ]; then
  sleep 1
  exit 0
fi
LOG_FILE="{}"
printf '%s\n' "$*" >> "$LOG_FILE"
printf '%s' '[{{"id":"agent-1","slug":"claude-sonnet","adapter":"claude-cli","defaultModel":"sonnet","capabilities":["code_write"],"health":{{"status":"healthy"}}}}]'
"#,
                plain_log_path.display()
            ),
        )?;
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&script_path)?.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&script_path, permissions)?;
        }

        let existing_paths = std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .collect::<Vec<_>>();
        let joined_path = std::env::join_paths(
            std::iter::once(temp.path().to_path_buf()).chain(existing_paths.into_iter()),
        )?;
        let _path_guard = EnvVarGuard::set("PATH", joined_path);
        let _disable_guard = EnvVarGuard::set("DOCDEX_DISABLE_MCODA_CLI", "0");

        // The timeout path is covered in load_from_cli_falls_back_when_refresh_hangs.
        // Seed refresh backoff directly here so the repeated-attempt skip stays deterministic
        // under full-suite parallel load.
        note_mcoda_cli_failure(&MCODA_AGENT_LIST_JSON_REFRESH_ARGS);
        let _first = McodaRegistry::load_from_cli()?.expect("first registry");
        assert!(
            should_skip_mcoda_cli_attempt(&MCODA_AGENT_LIST_JSON_REFRESH_ARGS),
            "expected refresh attempt to remain in backoff after timeout"
        );
        assert!(
            !should_skip_mcoda_cli_attempt(&MCODA_AGENT_LIST_JSON_ARGS),
            "expected plain attempt to remain available during refresh backoff"
        );
        let _second = McodaRegistry::load_from_cli()?.expect("second registry");
        let count = fs::read_to_string(&plain_log_path)?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count() as u32;
        assert_eq!(count, 2, "expected both calls to use the plain fallback");
        Ok(())
    }

    #[test]
    fn parse_mcoda_cloud_agents_maps_catalog_payload() -> Result<()> {
        let raw = r#"
[
  {
    "slug": "openrouter-qwen-qwen3-coder",
    "provider": "openrouter",
    "default_model": "qwen/qwen3-coder",
    "cost_per_million": 0.75,
    "rating": 8.4,
    "reasoning_rating": 7.0,
    "max_complexity": 8,
    "capabilities": ["code_write", "code_review"],
    "health_status": "healthy",
    "context_window": 262144,
    "max_output_tokens": 32768,
    "supports_tools": true,
    "best_usage": "code_writer"
  }
]
"#;
        let agents = parse_mcoda_cloud_agents(raw)?;
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].slug, "openrouter-qwen-qwen3-coder");
        assert_eq!(agents[0].provider, "openrouter");
        assert_eq!(agents[0].default_model, "qwen/qwen3-coder");
        assert_eq!(agents[0].cost_per_million, Some(0.75));
        assert_eq!(agents[0].context_window, Some(262144));
        assert!(agents[0].supports_tools);
        Ok(())
    }

    #[test]
    fn materialize_cloud_agents_creates_managed_openai_registry_entries() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let temp = TempDir::new()?;
        let _home = EnvVarGuard::set("HOME", temp.path());
        let _userprofile = EnvVarGuard::set("USERPROFILE", temp.path());
        let slugs = materialize_cloud_agents(
            "https://api.mswarm.org/",
            "cloud-key",
            &[McodaCloudAgent {
                slug: "openrouter-qwen-qwen3-coder".to_string(),
                provider: "openrouter".to_string(),
                default_model: "qwen/qwen3-coder".to_string(),
                cost_per_million: Some(0.75),
                rating: Some(8.4),
                reasoning_rating: Some(7.0),
                max_complexity: Some(8),
                capabilities: vec!["code_write".to_string(), "code_review".to_string()],
                health_status: Some("healthy".to_string()),
                context_window: Some(262144),
                max_output_tokens: Some(32768),
                supports_tools: true,
                best_usage: Some("code_writer".to_string()),
                model_id: Some("openrouter/qwen/qwen3-coder".to_string()),
                display_name: Some("Qwen3 Coder".to_string()),
                description: Some("Coder model".to_string()),
                supports_reasoning: Some(true),
                pricing_snapshot_id: Some("snap-1".to_string()),
                pricing_version: Some("2026-03-18".to_string()),
                sync: None,
            }],
        )?;
        assert_eq!(
            slugs,
            vec!["mswarm-cloud-openrouter-qwen-qwen3-coder".to_string()]
        );

        let registry =
            McodaRegistry::load_default_db_only()?.expect("mcoda registry after materialization");
        let agent = registry
            .agent_by_slug("mswarm-cloud-openrouter-qwen-qwen3-coder")
            .expect("managed cloud agent");
        assert_eq!(agent.adapter, "openai-api");
        assert_eq!(agent.default_model.as_deref(), Some("qwen/qwen3-coder"));
        assert_eq!(agent.cost_per_million, Some(0.75));
        assert_eq!(agent.health_status.as_deref(), Some("healthy"));
        assert!(agent
            .config
            .as_ref()
            .and_then(|config| config.pointer("/mswarmCloud/managed"))
            .and_then(Value::as_bool)
            .unwrap_or(false));
        assert_eq!(
            agent
                .auth
                .as_ref()
                .and_then(|auth| auth.decrypted_secret.as_deref()),
            Some("cloud-key")
        );
        Ok(())
    }
}
