use crate::config::{AppConfig, DelegationConfig, LlmConfig};
use crate::mcoda::registry::{
    list_cloud_agents, materialize_cloud_agents, McodaAgent, McodaAgentUsageLimit,
    McodaCloudListOptions, McodaRegistry,
};
use crate::ollama;
use crate::setup::ollama as setup_ollama;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::future::{Future, Ready};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use url::Url;
use which::which;

const LIBRARY_DIR: &str = "llm";
const LIBRARY_FILE: &str = "local_model_library.json";
const LIBRARY_VERSION: u32 = 1;
const CAP_CODE_WRITER: &str = "code_writer";
const CAP_CODE_REVIEWER: &str = "code_reviewer";
const CAP_GENERAL_CHAT: &str = "general_chat";
const CAP_CHAT: &str = "chat";
const CAP_CODE: &str = "code";
const CAP_EMBEDDING: &str = "embedding";
const CAP_REASONING: &str = "reasoning";
const CAP_TOOL_CAPABLE: &str = "tool_capable";
const CAP_VISION: &str = "vision";
const CAP_UNSUPPORTED_FOR_DELEGATION: &str = "unsupported_for_delegation";
const DEFAULT_LIBRARY_TTL_SECS: u64 = 300;
const DEFAULT_SERVICE_PROBE_TIMEOUT_MS: u64 = 500;
const MIN_LOCAL_DELEGATION_CONTEXT_TOKENS: u32 = 4096;
const WEB_CLASSIFY_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_WEB_CLASSIFICATIONS_PER_REFRESH: usize = 3;
const DELEGATION_FAILURE_HISTORY_DIR: &str = "errors";
const DELEGATION_FAILURE_HISTORY_FILE: &str = "delegation_local_failures.jsonl";
const DEFAULT_LOCAL_TARGET_FAILURE_THRESHOLD: usize = 2;
const DEFAULT_LOCAL_TARGET_FAILURE_LOOKBACK_SECS: u64 = 6 * 60 * 60;
const DEFAULT_LOCAL_TARGET_FAILURE_COOLDOWN_SECS: u64 = 30 * 60;
const LOCAL_TARGET_FAILURE_THRESHOLD_ENV: &str = "DOCDEX_DELEGATION_FAILURE_THRESHOLD";
const LOCAL_TARGET_FAILURE_LOOKBACK_ENV: &str = "DOCDEX_DELEGATION_FAILURE_LOOKBACK_SECS";
const LOCAL_TARGET_FAILURE_COOLDOWN_ENV: &str = "DOCDEX_DELEGATION_FAILURE_COOLDOWN_SECS";
const LOCAL_AGENT_SOURCE_MCODA_LOCAL: &str = "mcoda-local";
const LOCAL_AGENT_SOURCE_MCODA_CLOUD: &str = "mcoda-cloud";
const ROLLING_5H_WINDOW_MS: u128 = 5 * 60 * 60 * 1000;
const DAILY_WINDOW_MS: u128 = 24 * 60 * 60 * 1000;
const WEEKLY_WINDOW_MS: u128 = 7 * 24 * 60 * 60 * 1000;
const OTHER_WINDOW_MS: u128 = 60 * 60 * 1000;
const FALLBACK_EMBEDDING_MODEL: &str = "nomic-embed-text";
const FALLBACK_DELEGATION_MODEL: &str = "phi3.5:3.8b";

#[derive(Debug, Clone)]
pub(crate) struct ModelClassification {
    pub capabilities: Vec<String>,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscoveredModelName {
    pub(crate) name: String,
    pub(crate) raw_name: String,
}

type NoWebFuture = Ready<Result<String>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalModelLibrary {
    #[serde(default = "default_library_version")]
    pub version: u32,
    #[serde(default)]
    pub updated_at_ms: u128,
    #[serde(default)]
    pub services: Vec<LocalServiceEntry>,
    #[serde(default)]
    pub models: Vec<LocalModelEntry>,
    #[serde(default)]
    pub agents: Vec<LocalAgentEntry>,
    #[serde(default)]
    pub defaults: LocalDefaultSelection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_local_agent_selection: Option<CachedLocalAgentSelection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalLlmProvider {
    #[serde(rename = "ollama")]
    Ollama,
    #[serde(rename = "vllm")]
    Vllm,
    #[serde(rename = "llama-cpp")]
    LlamaCpp,
    #[serde(rename = "llama-cpp-python")]
    LlamaCppPython,
    #[serde(rename = "lm-studio")]
    LmStudio,
    #[serde(rename = "localai")]
    LocalAi,
    #[serde(rename = "sglang")]
    Sglang,
    #[serde(rename = "tgi")]
    Tgi,
    #[serde(rename = "custom-openai-compatible")]
    CustomOpenAiCompatible,
}

impl Default for LocalLlmProvider {
    fn default() -> Self {
        Self::Ollama
    }
}

impl LocalLlmProvider {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::Vllm => "vllm",
            Self::LlamaCpp => "llama-cpp",
            Self::LlamaCppPython => "llama-cpp-python",
            Self::LmStudio => "lm-studio",
            Self::LocalAi => "localai",
            Self::Sglang => "sglang",
            Self::Tgi => "tgi",
            Self::CustomOpenAiCompatible => "custom-openai-compatible",
        }
    }

    pub fn mcoda_runner_kind(&self) -> &'static str {
        match self {
            Self::Ollama => "ollama",
            Self::Vllm => "vllm",
            Self::LlamaCpp => "llama-cpp",
            Self::LlamaCppPython => "llama-cpp-python",
            Self::LmStudio => "lm-studio",
            Self::LocalAi => "localai",
            Self::Sglang => "sglang",
            Self::Tgi => "tgi",
            Self::CustomOpenAiCompatible => "custom",
        }
    }

    pub fn from_mcoda_runner_kind(kind: &str) -> Option<Self> {
        let normalized = kind
            .trim()
            .to_ascii_lowercase()
            .replace('_', "-")
            .replace(' ', "-");
        match normalized.as_str() {
            "ollama" | "ollama-local" | "ollama-remote" | "ollama-cli" => Some(Self::Ollama),
            "vllm" | "vllm-local" => Some(Self::Vllm),
            "llama-cpp" | "llamacpp" | "llama-cpp-local" | "llamacpp-local" => Some(Self::LlamaCpp),
            "llama-cpp-python" | "llamacpp-python" | "llama-cpp-python-local" => {
                Some(Self::LlamaCppPython)
            }
            "lm-studio" | "lmstudio" | "lm-studio-local" => Some(Self::LmStudio),
            "localai" | "local-ai" | "localai-local" | "local-ai-local" => Some(Self::LocalAi),
            "sglang" | "sglang-local" => Some(Self::Sglang),
            "tgi" | "tgi-local" | "text-generation-inference" => Some(Self::Tgi),
            "custom" | "custom-local" | "custom-openai-compatible" | "openai-compatible-local" => {
                Some(Self::CustomOpenAiCompatible)
            }
            _ => None,
        }
    }

    pub fn is_openai_compatible(&self) -> bool {
        !matches!(self, Self::Ollama)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalLibrarySourceType {
    #[serde(rename = "local_process")]
    LocalProcess,
    #[serde(rename = "local_config")]
    LocalConfig,
    #[serde(rename = "mcoda_local_agent")]
    McodaLocalAgent,
    #[serde(rename = "mcoda_remote_agent")]
    McodaRemoteAgent,
    #[serde(rename = "mcoda_cloud_agent")]
    McodaCloudAgent,
    #[serde(rename = "installer_fallback")]
    InstallerFallback,
}

impl Default for LocalLibrarySourceType {
    fn default() -> Self {
        Self::LocalProcess
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LocalServiceHealth {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "healthy")]
    Healthy,
    #[serde(rename = "degraded")]
    Degraded,
    #[serde(rename = "unavailable")]
    Unavailable,
}

impl Default for LocalServiceHealth {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum McodaReconciliationStatus {
    #[serde(rename = "unknown")]
    Unknown,
    #[serde(rename = "matching_healthy_agent")]
    MatchingHealthyAgent,
    #[serde(rename = "matching_unhealthy_agent")]
    MatchingUnhealthyAgent,
    #[serde(rename = "no_matching_agent")]
    NoMatchingAgent,
    #[serde(rename = "not_applicable")]
    NotApplicable,
}

impl Default for McodaReconciliationStatus {
    fn default() -> Self {
        Self::Unknown
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LocalCapabilityFlags {
    #[serde(default)]
    pub embedding: bool,
    #[serde(default)]
    pub chat: bool,
    #[serde(default)]
    pub delegation: bool,
    #[serde(default)]
    pub code: bool,
    #[serde(default)]
    pub vision: bool,
    #[serde(default)]
    pub reasoning: bool,
    #[serde(default)]
    pub tool_capable: bool,
    #[serde(default)]
    pub unsupported_for_delegation: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalMcodaAgentMatch {
    pub agent_id: String,
    pub agent_slug: String,
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalServiceEndpoint {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub models_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chat_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalServiceModelEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub capability_flags: LocalCapabilityFlags,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window_tokens: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimensions: Option<u32>,
    #[serde(default)]
    pub mcoda_reconciliation: McodaReconciliationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcoda_agent_match: Option<LocalMcodaAgentMatch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcoda_setup_hint: Option<String>,
    #[serde(default)]
    pub delegation_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalServiceEntry {
    pub service_id: String,
    #[serde(default)]
    pub provider: LocalLlmProvider,
    #[serde(default)]
    pub source_type: LocalLibrarySourceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default)]
    pub endpoints: Vec<LocalServiceEndpoint>,
    #[serde(default)]
    pub health: LocalServiceHealth,
    #[serde(default)]
    pub models: Vec<LocalServiceModelEntry>,
    #[serde(default)]
    pub capability_flags: LocalCapabilityFlags,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub last_seen_at_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalServiceProbeEntry {
    #[serde(default)]
    pub provider: LocalLlmProvider,
    #[serde(default)]
    pub source_type: LocalLibrarySourceType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub binary_names: Vec<String>,
    #[serde(default)]
    pub found_binaries: Vec<String>,
    #[serde(default)]
    pub endpoints: Vec<LocalServiceEndpoint>,
    #[serde(default)]
    pub health: LocalServiceHealth,
    #[serde(default)]
    pub service_detected: bool,
    #[serde(default)]
    pub model_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub checked_at_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalServiceDetectionReport {
    #[serde(default)]
    pub updated_at_ms: u128,
    #[serde(default)]
    pub probes: Vec<LocalServiceProbeEntry>,
    #[serde(default)]
    pub library: LocalModelLibrary,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalLibraryDiagnostics {
    #[serde(default)]
    pub updated_at_ms: u128,
    #[serde(default)]
    pub ttl_ms: u128,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub services_detected: usize,
    #[serde(default)]
    pub models_detected: usize,
    #[serde(default)]
    pub agents_detected: usize,
    #[serde(default)]
    pub defaults: LocalDefaultSelection,
    #[serde(default)]
    pub status_messages: Vec<LocalLibraryStatusMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LocalLibraryStatusMessage {
    pub code: String,
    pub severity: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<LocalLlmProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LocalDefaultSelection {
    #[serde(default)]
    pub embedding: LocalDefaultChoice,
    #[serde(default)]
    pub delegation: LocalDefaultChoice,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LocalDefaultChoice {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected: Option<LocalDefaultCandidate>,
    #[serde(default)]
    pub candidates: Vec<LocalDefaultCandidate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LocalDefaultCandidateKind {
    ConfiguredEmbedding,
    ConfiguredDelegation,
    LocalServiceModel,
    McodaLocalAgent,
    McodaEmbeddingAgent,
    SelfHostedRemoteAgent,
    OllamaInstalledModel,
    OllamaSetupFallback,
}

impl Default for LocalDefaultCandidateKind {
    fn default() -> Self {
        Self::OllamaSetupFallback
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct LocalDefaultCandidate {
    #[serde(default)]
    pub kind: LocalDefaultCandidateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<LocalLlmProvider>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_type: Option<LocalLibrarySourceType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_slug: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default)]
    pub explicit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedLocalAgentSelection {
    pub policy: String,
    pub agent_id: String,
    pub agent_slug: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_kind: Option<String>,
    #[serde(default)]
    pub selected_at_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalModelEntry {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_name: Option<String>,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub capability_flags: LocalCapabilityFlags,
    #[serde(default)]
    pub delegation_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub classification_method: String,
    #[serde(default)]
    pub last_seen_at_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_classified_at_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalAgentEntry {
    pub agent_id: String,
    pub agent_slug: String,
    #[serde(default = "default_local_agent_source")]
    pub source: String,
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runner_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_complexity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_per_million: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_rating: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_status: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub delegation_ready: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_readiness_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub classification_method: String,
    #[serde(default)]
    pub last_seen_at_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_classified_at_ms: Option<u128>,
}

fn default_library_version() -> u32 {
    LIBRARY_VERSION
}

impl Default for LocalModelLibrary {
    fn default() -> Self {
        Self {
            version: LIBRARY_VERSION,
            updated_at_ms: 0,
            services: Vec::new(),
            models: Vec::new(),
            agents: Vec::new(),
            defaults: LocalDefaultSelection::default(),
            cached_local_agent_selection: None,
        }
    }
}

fn default_local_agent_source() -> String {
    LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string()
}

pub(crate) fn resolve_local_ollama_base_url(llm_config: &LlmConfig) -> Option<String> {
    let provider = llm_config.provider.trim();
    if provider.eq_ignore_ascii_case("ollama") {
        let base_url = llm_config.base_url.trim();
        if !base_url.is_empty() && is_local_ollama_base_url(base_url) {
            return Some(base_url.to_string());
        }
    }
    if let Some(value) = env_trimmed("DOCDEX_OLLAMA_BASE_URL") {
        if is_local_ollama_base_url(&value) {
            return Some(value);
        }
    }
    if let Some(value) = env_trimmed("DOCDEX_EMBEDDING_BASE_URL") {
        if is_local_ollama_base_url(&value) {
            return Some(value);
        }
    }
    let default_url = "http://127.0.0.1:11434";
    if is_local_ollama_base_url(default_url) {
        return Some(default_url.to_string());
    }
    None
}

fn local_llm_provider_from_config(provider: &str) -> Option<LocalLlmProvider> {
    LocalLlmProvider::from_mcoda_runner_kind(provider)
}

pub(crate) fn is_local_ollama_base_url(base_url: &str) -> bool {
    is_local_http_base_url(base_url)
}

pub(crate) fn is_local_http_base_url(base_url: &str) -> bool {
    let trimmed = base_url.trim();
    if trimmed.to_ascii_lowercase().starts_with("http://[::1]") {
        return true;
    }
    if let Ok(url) = Url::parse(base_url) {
        if url.scheme() != "http" {
            return false;
        }
        if let Some(host) = url.host_str() {
            return is_loopback_host(host);
        }
    }
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return false;
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    is_loopback_host(host)
}

fn dedupe_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value = trimmed.trim_end_matches('/').to_string();
        if seen.insert(value.to_ascii_lowercase()) {
            deduped.push(value);
        }
    }
    deduped
}

fn supported_probe_providers() -> Vec<LocalLlmProvider> {
    vec![
        LocalLlmProvider::Ollama,
        LocalLlmProvider::Vllm,
        LocalLlmProvider::LlamaCpp,
        LocalLlmProvider::LlamaCppPython,
        LocalLlmProvider::LmStudio,
        LocalLlmProvider::LocalAi,
        LocalLlmProvider::Sglang,
        LocalLlmProvider::Tgi,
        LocalLlmProvider::CustomOpenAiCompatible,
    ]
}

fn provider_display_name(provider: &LocalLlmProvider) -> &'static str {
    match provider {
        LocalLlmProvider::Ollama => "Ollama",
        LocalLlmProvider::Vllm => "vLLM",
        LocalLlmProvider::LlamaCpp => "llama.cpp",
        LocalLlmProvider::LlamaCppPython => "llama-cpp-python",
        LocalLlmProvider::LmStudio => "LM Studio",
        LocalLlmProvider::LocalAi => "LocalAI",
        LocalLlmProvider::Sglang => "SGLang",
        LocalLlmProvider::Tgi => "Text Generation Inference",
        LocalLlmProvider::CustomOpenAiCompatible => "Custom OpenAI-compatible",
    }
}

fn provider_binary_names(provider: &LocalLlmProvider) -> &'static [&'static str] {
    match provider {
        LocalLlmProvider::Ollama => &["ollama"],
        LocalLlmProvider::Vllm => &["vllm"],
        LocalLlmProvider::LlamaCpp => &["llama-server", "llama-cli"],
        LocalLlmProvider::LlamaCppPython => &[],
        LocalLlmProvider::LmStudio => &["lms"],
        LocalLlmProvider::LocalAi => &["local-ai", "localai"],
        LocalLlmProvider::Sglang => &["sglang"],
        LocalLlmProvider::Tgi => &["text-generation-launcher"],
        LocalLlmProvider::CustomOpenAiCompatible => &[],
    }
}

fn provider_env_keys(provider: &LocalLlmProvider) -> &'static [&'static str] {
    match provider {
        LocalLlmProvider::Ollama => &["DOCDEX_OLLAMA_BASE_URL", "DOCDEX_EMBEDDING_BASE_URL"],
        LocalLlmProvider::Vllm => &["DOCDEX_VLLM_BASE_URL"],
        LocalLlmProvider::LlamaCpp => &["DOCDEX_LLAMA_CPP_BASE_URL"],
        LocalLlmProvider::LlamaCppPython => &["DOCDEX_LLAMA_CPP_PYTHON_BASE_URL"],
        LocalLlmProvider::LmStudio => &["DOCDEX_LM_STUDIO_BASE_URL"],
        LocalLlmProvider::LocalAi => &["DOCDEX_LOCALAI_BASE_URL"],
        LocalLlmProvider::Sglang => &["DOCDEX_SGLANG_BASE_URL"],
        LocalLlmProvider::Tgi => &["DOCDEX_TGI_BASE_URL"],
        LocalLlmProvider::CustomOpenAiCompatible => {
            &["DOCDEX_OPENAI_COMPATIBLE_BASE_URL", "DOCDEX_LLM_BASE_URL"]
        }
    }
}

fn provider_default_base_urls(provider: &LocalLlmProvider) -> &'static [&'static str] {
    match provider {
        LocalLlmProvider::Ollama => &["http://127.0.0.1:11434"],
        LocalLlmProvider::Vllm => &["http://127.0.0.1:8000"],
        LocalLlmProvider::LlamaCpp => &["http://127.0.0.1:8080"],
        LocalLlmProvider::LlamaCppPython => &["http://127.0.0.1:8000"],
        LocalLlmProvider::LmStudio => &["http://127.0.0.1:1234"],
        LocalLlmProvider::LocalAi => &["http://127.0.0.1:8080"],
        LocalLlmProvider::Sglang => &["http://127.0.0.1:30000"],
        LocalLlmProvider::Tgi => &["http://127.0.0.1:8080"],
        LocalLlmProvider::CustomOpenAiCompatible => &[],
    }
}

fn configured_base_urls_for_provider(
    provider: &LocalLlmProvider,
    llm_config: &LlmConfig,
) -> Vec<String> {
    let mut candidates = Vec::new();
    if local_llm_provider_from_config(&llm_config.provider).as_ref() == Some(provider) {
        candidates.push(llm_config.base_url.clone());
    }
    for key in provider_env_keys(provider) {
        if let Some(value) = env_trimmed(key) {
            candidates.push(value);
        }
    }
    candidates
        .into_iter()
        .filter(|url| is_local_http_base_url(url))
        .collect()
}

fn base_urls_for_provider(provider: &LocalLlmProvider, llm_config: &LlmConfig) -> Vec<String> {
    dedupe_strings(
        configured_base_urls_for_provider(provider, llm_config)
            .into_iter()
            .chain(
                provider_default_base_urls(provider)
                    .iter()
                    .map(|value| value.to_string()),
            )
            .filter(|url| is_local_http_base_url(url)),
    )
}

fn found_provider_binaries(provider: &LocalLlmProvider) -> Vec<String> {
    provider_binary_names(provider)
        .iter()
        .filter_map(|binary| {
            which(binary)
                .ok()
                .map(|path| path.to_string_lossy().to_string())
        })
        .collect()
}

pub(crate) fn normalize_model_name(name: &str) -> String {
    let trimmed = name.trim().trim_matches('"').trim();
    let stripped = trimmed
        .strip_prefix("/models/")
        .or_else(|| trimmed.strip_prefix("models/"))
        .unwrap_or(trimmed);
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn normalize_model_key(name: &str) -> String {
    normalize_model_name(name).to_ascii_lowercase()
}

fn push_discovered_model(
    models: &mut Vec<DiscoveredModelName>,
    seen: &mut HashSet<String>,
    raw_name: impl Into<String>,
) {
    let raw_name = raw_name.into().trim().trim_matches('"').trim().to_string();
    let name = normalize_model_name(&raw_name);
    if name.is_empty() {
        return;
    }
    if seen.insert(name.to_ascii_lowercase()) {
        models.push(DiscoveredModelName { name, raw_name });
    }
}

fn key_contains_any(key: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| key.contains(needle))
}

fn embedding_model_key(key: &str) -> bool {
    key_contains_any(
        key,
        &[
            "embedding",
            "embed",
            "nomic-embed",
            "bge",
            "e5-",
            "e5_",
            "e5/",
            "gte-",
            "gte_",
            "all-minilm",
            "minilm",
            "text-embedding",
            "snowflake-arctic-embed",
        ],
    )
}

fn qwen_vl_model_key(key: &str) -> bool {
    key.contains("qwen")
        && (key.contains("-vl")
            || key.contains("_vl")
            || key.contains(" vl")
            || key.contains("qwen-vl")
            || key.contains("qwen2-vl")
            || key.contains("qwen2.5-vl")
            || key.contains("qwen3-vl"))
}

pub(crate) fn classify_model_known(name: &str) -> Option<ModelClassification> {
    let key = normalize_model_key(name);
    if embedding_model_key(&key) {
        return Some(normalize_caps(vec![CAP_EMBEDDING.to_string()], "known_map"));
    }
    if qwen_vl_model_key(&key) {
        return Some(normalize_caps(
            vec![
                CAP_VISION.to_string(),
                CAP_GENERAL_CHAT.to_string(),
                CAP_REASONING.to_string(),
                CAP_TOOL_CAPABLE.to_string(),
            ],
            "known_map",
        ));
    }
    if key.contains("qwen") && key.contains("coder") {
        return Some(normalize_caps(
            vec![
                CAP_CODE_WRITER.to_string(),
                CAP_CODE_REVIEWER.to_string(),
                CAP_GENERAL_CHAT.to_string(),
                CAP_REASONING.to_string(),
                CAP_TOOL_CAPABLE.to_string(),
            ],
            "known_map",
        ));
    }
    if key.contains("qwen") {
        return Some(normalize_caps(
            vec![
                CAP_GENERAL_CHAT.to_string(),
                CAP_REASONING.to_string(),
                CAP_TOOL_CAPABLE.to_string(),
            ],
            "known_map",
        ));
    }
    if key.contains("phi") {
        return Some(normalize_caps(
            vec![CAP_CODE_WRITER.to_string(), CAP_GENERAL_CHAT.to_string()],
            "known_map",
        ));
    }
    if key.contains("codellama") || key.contains("deepseek-coder") || key.contains("codestral") {
        return Some(normalize_caps(
            vec![
                CAP_CODE_WRITER.to_string(),
                CAP_CODE_REVIEWER.to_string(),
                CAP_GENERAL_CHAT.to_string(),
                CAP_REASONING.to_string(),
            ],
            "known_map",
        ));
    }
    if key.contains("deepseek") {
        return Some(normalize_caps(
            vec![CAP_GENERAL_CHAT.to_string(), CAP_REASONING.to_string()],
            "known_map",
        ));
    }
    if key.contains("llama") {
        let mut caps = vec![CAP_GENERAL_CHAT.to_string()];
        if key.contains("tool") || key.contains("function") {
            caps.push(CAP_TOOL_CAPABLE.to_string());
        }
        return Some(normalize_caps(caps, "known_map"));
    }
    None
}

pub(crate) fn classify_model_heuristic(name: &str) -> ModelClassification {
    let key = normalize_model_key(name);
    let mut caps = Vec::new();
    if embedding_model_key(&key) {
        caps.push(CAP_EMBEDDING.to_string());
    }
    if key.contains("vision")
        || key.contains("llava")
        || key.contains("clip")
        || key.contains("-vl")
        || key.contains("_vl")
    {
        caps.push(CAP_VISION.to_string());
    }
    if key.contains("code") || key.contains("coder") {
        caps.push(CAP_CODE_WRITER.to_string());
        caps.push(CAP_CODE_REVIEWER.to_string());
    }
    if key.contains("reason") || key.contains("r1") {
        caps.push(CAP_REASONING.to_string());
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    if key.contains("tool") || key.contains("function") {
        caps.push(CAP_TOOL_CAPABLE.to_string());
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    if key.contains("instruct") || key.contains("chat") {
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    if caps.is_empty() {
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    normalize_caps(caps, "heuristic")
}

pub(crate) async fn classify_model_with_web_text<F, Fut>(
    model_name: &str,
    fetcher: F,
) -> Result<Option<ModelClassification>>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let query = format!("Ollama model {} best use cases", model_name);
    let text = fetcher(query).await?;
    Ok(classify_model_from_web_text(&text))
}

pub(crate) async fn discover_ollama_models(
    base_url: &str,
    timeout: Duration,
    allow_start: bool,
) -> Vec<DiscoveredModelName> {
    let mut models = Vec::new();
    let mut seen = HashSet::new();
    match ollama::list_models(base_url, timeout).await {
        Ok(list) => {
            for model in list {
                push_discovered_model(&mut models, &mut seen, model);
            }
        }
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                base_url = %base_url,
                "ollama model discovery failed via /api/tags"
            );
        }
    }

    if models.is_empty() {
        if let Some(bin) = setup_ollama::resolve_ollama_path(None) {
            let cli_models = if allow_start {
                setup_ollama::list_models(&bin)
            } else {
                match setup_ollama::list_models_if_running(&bin) {
                    Ok(Some(models)) => Ok(models),
                    Ok(None) => Ok(Vec::new()),
                    Err(err) => Err(err),
                }
            };
            match cli_models {
                Ok(list) => {
                    for model in list {
                        push_discovered_model(&mut models, &mut seen, model);
                    }
                }
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        "ollama model discovery failed via CLI"
                    );
                }
            }
        }
    }

    models
}

#[derive(Debug, Default)]
struct ProviderProbeOutcome {
    probe: LocalServiceProbeEntry,
    services: Vec<LocalServiceEntry>,
    models: Vec<LocalModelEntry>,
}

#[derive(Debug, Default)]
struct EndpointModelProbe {
    health: LocalServiceHealth,
    models: Vec<String>,
    note: Option<String>,
}

#[derive(Debug, Default)]
struct EndpointHealthProbe {
    health: LocalServiceHealth,
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelsResponse {
    #[serde(default)]
    data: Vec<OpenAiModelEntry>,
}

#[derive(Debug, Deserialize)]
struct OpenAiModelEntry {
    id: Option<String>,
}

fn local_model_entry_from_probe(
    provider: &LocalLlmProvider,
    name: &str,
    service_health: &LocalServiceHealth,
    now_ms: u128,
) -> LocalModelEntry {
    let raw_name = name.trim().to_string();
    let normalized = normalize_model_name(name);
    let classification =
        classify_model_known(&normalized).unwrap_or_else(|| classify_model_heuristic(&normalized));
    let capability_flags = capability_flags_from_caps(&classification.capabilities);
    let (delegation_ready, delegation_readiness_reason) =
        model_delegation_readiness(&classification.capabilities, service_health, None);
    LocalModelEntry {
        name: normalized,
        raw_name: if raw_name.is_empty() {
            None
        } else {
            Some(raw_name)
        },
        source: provider.as_str().to_string(),
        capabilities: classification.capabilities,
        capability_flags,
        delegation_ready,
        delegation_readiness_reason,
        notes: None,
        classification_method: classification.method,
        last_seen_at_ms: now_ms,
        last_classified_at_ms: None,
    }
}

fn openai_compatible_base_url(base_url: &str) -> String {
    let normalized = normalized_base_url(base_url);
    normalized
        .strip_suffix("/v1")
        .unwrap_or(&normalized)
        .to_string()
}

fn openai_compatible_health_path(provider: &LocalLlmProvider) -> &'static str {
    match provider {
        LocalLlmProvider::Vllm
        | LocalLlmProvider::LlamaCpp
        | LocalLlmProvider::LlamaCppPython
        | LocalLlmProvider::Sglang
        | LocalLlmProvider::Tgi => "/health",
        LocalLlmProvider::LocalAi => "/readyz",
        LocalLlmProvider::Ollama
        | LocalLlmProvider::LmStudio
        | LocalLlmProvider::CustomOpenAiCompatible => "/v1/models",
    }
}

fn openai_compatible_service_endpoints(
    provider: &LocalLlmProvider,
    base_url: &str,
) -> Vec<LocalServiceEndpoint> {
    let base_url = openai_compatible_base_url(base_url);
    let health_path = openai_compatible_health_path(provider);
    vec![LocalServiceEndpoint {
        base_url: Some(base_url.clone()),
        health_url: Some(format!("{base_url}{health_path}")),
        models_url: Some(format!("{base_url}/v1/models")),
        chat_url: Some(format!("{base_url}/v1/chat/completions")),
        delegation_url: Some(format!("{base_url}/v1/chat/completions")),
        embeddings_url: Some(format!("{base_url}/v1/embeddings")),
    }]
}

fn build_openai_compatible_service_entry(
    provider: LocalLlmProvider,
    base_url: &str,
    models: &[LocalModelEntry],
    health: LocalServiceHealth,
    notes: Option<String>,
    now_ms: u128,
) -> LocalServiceEntry {
    let base_url = openai_compatible_base_url(base_url);
    let service_models: Vec<LocalServiceModelEntry> = models
        .iter()
        .map(|entry| local_service_model_from_entry(entry, &health))
        .collect();
    let capability_flags = aggregate_capability_flags(&service_models);
    LocalServiceEntry {
        service_id: format!("{}:{base_url}", provider.as_str()),
        provider: provider.clone(),
        source_type: LocalLibrarySourceType::LocalProcess,
        display_name: Some(provider_display_name(&provider).to_string()),
        base_url: Some(base_url.clone()),
        endpoints: openai_compatible_service_endpoints(&provider, &base_url),
        health,
        models: service_models,
        capability_flags,
        notes,
        last_seen_at_ms: now_ms,
    }
}

async fn probe_openai_compatible_models(base_url: &str, timeout: Duration) -> EndpointModelProbe {
    let base_url = openai_compatible_base_url(base_url);
    let models_url = format!("{base_url}/v1/models");
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(err) => {
            return EndpointModelProbe {
                health: LocalServiceHealth::Unknown,
                models: Vec::new(),
                note: Some(format!("failed to build HTTP client: {err}")),
            }
        }
    };
    let response = match client.get(&models_url).send().await {
        Ok(response) => response,
        Err(err) => {
            return EndpointModelProbe {
                health: LocalServiceHealth::Unavailable,
                models: Vec::new(),
                note: Some(format!("{models_url} unreachable: {err}")),
            }
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return EndpointModelProbe {
            health: LocalServiceHealth::Degraded,
            models: Vec::new(),
            note: Some(format!("{models_url} requires authentication")),
        };
    }
    if !status.is_success() {
        return EndpointModelProbe {
            health: LocalServiceHealth::Unavailable,
            models: Vec::new(),
            note: Some(format!("{models_url} returned status {status}")),
        };
    }
    let body = match response.json::<OpenAiModelsResponse>().await {
        Ok(body) => body,
        Err(err) => {
            return EndpointModelProbe {
                health: LocalServiceHealth::Degraded,
                models: Vec::new(),
                note: Some(format!("{models_url} returned invalid model JSON: {err}")),
            }
        }
    };
    let models = dedupe_strings(body.data.into_iter().filter_map(|entry| entry.id));
    EndpointModelProbe {
        health: LocalServiceHealth::Healthy,
        models,
        note: None,
    }
}

async fn probe_openai_compatible_health(
    health_url: &str,
    timeout: Duration,
) -> EndpointHealthProbe {
    let client = match reqwest::Client::builder().timeout(timeout).build() {
        Ok(client) => client,
        Err(err) => {
            return EndpointHealthProbe {
                health: LocalServiceHealth::Unknown,
                note: Some(format!("failed to build HTTP client: {err}")),
            }
        }
    };
    let response = match client.get(health_url).send().await {
        Ok(response) => response,
        Err(err) => {
            return EndpointHealthProbe {
                health: LocalServiceHealth::Unavailable,
                note: Some(format!("{health_url} unreachable: {err}")),
            }
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return EndpointHealthProbe {
            health: LocalServiceHealth::Degraded,
            note: Some(format!("{health_url} requires authentication")),
        };
    }
    if !status.is_success() {
        return EndpointHealthProbe {
            health: LocalServiceHealth::Unavailable,
            note: Some(format!("{health_url} returned status {status}")),
        };
    }
    EndpointHealthProbe {
        health: LocalServiceHealth::Healthy,
        note: None,
    }
}

fn combined_openai_compatible_health(
    health_probe: Option<&EndpointHealthProbe>,
    model_health: &LocalServiceHealth,
) -> LocalServiceHealth {
    if model_health == &LocalServiceHealth::Healthy {
        return LocalServiceHealth::Healthy;
    }
    if health_probe
        .as_ref()
        .is_some_and(|probe| probe.health == LocalServiceHealth::Healthy)
    {
        return LocalServiceHealth::Degraded;
    }
    if model_health == &LocalServiceHealth::Degraded
        || health_probe
            .as_ref()
            .is_some_and(|probe| probe.health == LocalServiceHealth::Degraded)
    {
        return LocalServiceHealth::Degraded;
    }
    if model_health == &LocalServiceHealth::Unknown
        || health_probe
            .as_ref()
            .is_some_and(|probe| probe.health == LocalServiceHealth::Unknown)
    {
        return LocalServiceHealth::Unknown;
    }
    LocalServiceHealth::Unavailable
}

fn provider_probe_health(
    services: &[LocalServiceEntry],
    attempted_endpoint_probe: bool,
    found_binaries: &[String],
) -> LocalServiceHealth {
    if !services.is_empty() {
        if services
            .iter()
            .any(|service| service.health == LocalServiceHealth::Healthy)
        {
            LocalServiceHealth::Healthy
        } else {
            LocalServiceHealth::Degraded
        }
    } else if attempted_endpoint_probe {
        LocalServiceHealth::Unavailable
    } else if !found_binaries.is_empty() {
        LocalServiceHealth::Unknown
    } else {
        LocalServiceHealth::Unavailable
    }
}

async fn probe_provider(
    provider: LocalLlmProvider,
    llm_config: &LlmConfig,
    timeout: Duration,
    allow_start_ollama: bool,
    now_ms: u128,
) -> ProviderProbeOutcome {
    let binary_names: Vec<String> = provider_binary_names(&provider)
        .iter()
        .map(|value| value.to_string())
        .collect();
    let found_binaries = found_provider_binaries(&provider);
    let base_urls = base_urls_for_provider(&provider, llm_config);
    let mut checked_endpoints = Vec::new();
    let mut services = Vec::new();
    let mut models = Vec::new();
    let mut notes = Vec::new();

    if found_binaries.is_empty() && !binary_names.is_empty() {
        notes.push("no provider binary found on PATH".to_string());
    }
    if base_urls.is_empty() && provider == LocalLlmProvider::CustomOpenAiCompatible {
        notes.push(
            "no local OpenAI-compatible base URL configured; set DOCDEX_OPENAI_COMPATIBLE_BASE_URL or DOCDEX_LLM_BASE_URL to a loopback HTTP URL"
                .to_string(),
        );
    }

    match provider {
        LocalLlmProvider::Ollama => {
            for base_url in &base_urls {
                checked_endpoints.extend(ollama_service_endpoints(base_url));
                let discovered =
                    discover_ollama_models(base_url, timeout, allow_start_ollama).await;
                if discovered.is_empty() {
                    notes.push(format!("no Ollama models discovered at {base_url}"));
                    continue;
                }
                let start = models.len();
                for model in discovered {
                    models.push(local_model_entry_from_probe(
                        &provider,
                        &model.raw_name,
                        &LocalServiceHealth::Healthy,
                        now_ms,
                    ));
                }
                let service_models = &models[start..];
                services.push(build_ollama_service_entry(base_url, service_models, now_ms));
            }
        }
        _ => {
            for base_url in &base_urls {
                let endpoints = openai_compatible_service_endpoints(&provider, base_url);
                let endpoint = endpoints.first().cloned().unwrap_or_default();
                checked_endpoints.extend(endpoints);
                let health_url = endpoint.health_url.as_deref();
                let models_url = endpoint.models_url.as_deref();
                let health_probe = match health_url {
                    Some(url) if Some(url) != models_url => {
                        Some(probe_openai_compatible_health(url, timeout).await)
                    }
                    _ => None,
                };
                let mut service_notes = Vec::new();
                if let Some(note) = health_probe.as_ref().and_then(|probe| probe.note.as_ref()) {
                    notes.push(note.clone());
                    service_notes.push(note.clone());
                }
                let probe = probe_openai_compatible_models(base_url, timeout).await;
                if let Some(note) = probe.note.as_ref() {
                    notes.push(note.clone());
                    service_notes.push(note.clone());
                }
                let health =
                    combined_openai_compatible_health(health_probe.as_ref(), &probe.health);
                if health != LocalServiceHealth::Unavailable || !probe.models.is_empty() {
                    let start = models.len();
                    for name in probe.models {
                        models.push(local_model_entry_from_probe(
                            &provider, &name, &health, now_ms,
                        ));
                    }
                    let service_models = &models[start..];
                    services.push(build_openai_compatible_service_entry(
                        provider.clone(),
                        base_url,
                        service_models,
                        health,
                        if service_notes.is_empty() {
                            None
                        } else {
                            Some(service_notes.join("; "))
                        },
                        now_ms,
                    ));
                }
            }
        }
    }

    let service_detected = !services.is_empty();
    let health = provider_probe_health(&services, !checked_endpoints.is_empty(), &found_binaries);
    let probe = LocalServiceProbeEntry {
        provider: provider.clone(),
        source_type: LocalLibrarySourceType::LocalProcess,
        display_name: Some(provider_display_name(&provider).to_string()),
        binary_names,
        found_binaries,
        endpoints: checked_endpoints,
        health,
        service_detected,
        model_count: models.len(),
        notes: if notes.is_empty() {
            None
        } else {
            Some(notes.join("; "))
        },
        checked_at_ms: now_ms,
    };
    ProviderProbeOutcome {
        probe,
        services,
        models,
    }
}

async fn probe_local_services(
    llm_config: &LlmConfig,
    timeout: Duration,
    allow_start_ollama: bool,
    include_ollama: bool,
    now_ms: u128,
) -> (
    Vec<LocalServiceProbeEntry>,
    Vec<LocalServiceEntry>,
    Vec<LocalModelEntry>,
) {
    let mut probes = Vec::new();
    let mut services = Vec::new();
    let mut models = Vec::new();
    for provider in supported_probe_providers() {
        if !include_ollama && provider == LocalLlmProvider::Ollama {
            continue;
        }
        let outcome =
            probe_provider(provider, llm_config, timeout, allow_start_ollama, now_ms).await;
        probes.push(outcome.probe);
        services.extend(outcome.services);
        models.extend(outcome.models);
    }
    (probes, services, models)
}

pub(crate) async fn detect_local_service_report(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    timeout: Duration,
) -> Result<LocalServiceDetectionReport> {
    let now = now_ms();
    let (probes, services, models) =
        probe_local_services(llm_config, timeout, false, true, now).await;
    let agents = discover_mcoda_agents_read_only(state_dir_override, llm_config);
    let mut services = services;
    reconcile_services_with_mcoda_agents(&mut services, &agents);
    let mut library = LocalModelLibrary {
        updated_at_ms: now,
        services,
        models,
        agents,
        ..LocalModelLibrary::default()
    };
    library.defaults = resolve_local_default_selection(&library, llm_config);
    Ok(LocalServiceDetectionReport {
        updated_at_ms: now,
        probes,
        library,
    })
}

fn managed_mswarm_cloud_agent(agent: &McodaAgent) -> bool {
    agent
        .config
        .as_ref()
        .and_then(|config| config.pointer("/mswarmCloud/managed"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(crate) fn local_agent_is_cloud(entry: &LocalAgentEntry) -> bool {
    entry.source == LOCAL_AGENT_SOURCE_MCODA_CLOUD
}

fn delegation_cloud_credentials() -> Option<(String, String)> {
    let config = AppConfig::load_default().ok()?;
    let api_key = config.integrations.mswarm.api_key?.trim().to_string();
    if api_key.is_empty() {
        return None;
    }
    let base_url = config.integrations.mswarm.base_url.trim();
    if base_url.is_empty() {
        return None;
    }
    Some((base_url.to_string(), api_key))
}

fn refresh_managed_mswarm_cloud_agents(llm_config: &LlmConfig) {
    if !llm_config.delegation.cloud.enabled {
        return;
    }
    let Some((base_url, api_key)) = delegation_cloud_credentials() else {
        return;
    };
    let sync_limit = llm_config.delegation.cloud.sync_limit.max(1);
    let options = McodaCloudListOptions {
        provider: Some(llm_config.delegation.cloud.provider.clone())
            .filter(|value| !value.trim().is_empty()),
        limit: Some(llm_config.delegation.cloud.limit.max(sync_limit)),
        max_cost_per_million: Some(llm_config.delegation.cloud.max_cost_per_million),
        min_context_window: Some(llm_config.delegation.cloud.min_context.max(1)),
        min_reasoning_rating: Some(llm_config.delegation.cloud.min_reasoning),
        sort_by_catalog_rating: llm_config.delegation.cloud.sorted_by_catalog_rating,
        base_url: Some(base_url.clone()),
        api_key: Some(api_key.clone()),
    };
    let cloud_agents = match list_cloud_agents(&options) {
        Ok(agents) => agents,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "mcoda cloud agent discovery failed"
            );
            return;
        }
    };
    if cloud_agents.is_empty() {
        return;
    }
    let selected: Vec<_> = cloud_agents.into_iter().take(sync_limit).collect();
    if let Err(err) = materialize_cloud_agents(&base_url, &api_key, &selected) {
        warn!(
            target: "docdexd",
            error = ?err,
            "failed to materialize mcoda cloud agents for delegation"
        );
    }
}

pub(crate) fn discover_mcoda_agents(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
) -> Vec<LocalAgentEntry> {
    discover_mcoda_agents_inner(state_dir_override, llm_config, true)
}

fn discover_mcoda_agents_read_only(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
) -> Vec<LocalAgentEntry> {
    discover_mcoda_agents_inner(state_dir_override, llm_config, false)
}

fn discover_mcoda_agents_inner(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    refresh_cloud_agents: bool,
) -> Vec<LocalAgentEntry> {
    if refresh_cloud_agents {
        refresh_managed_mswarm_cloud_agents(llm_config);
    }
    let allow_cloud_agents =
        llm_config.delegation.cloud.enabled && delegation_cloud_credentials().is_some();
    let registry = match McodaRegistry::load_default() {
        Ok(Some(registry)) => registry,
        Ok(None) => return Vec::new(),
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "mcoda registry load failed"
            );
            return Vec::new();
        }
    };
    let now = now_ms();
    let recent_failures = load_recent_local_target_failures(state_dir_override);
    registry
        .agents
        .iter()
        .filter(|agent| allow_cloud_agents || !managed_mswarm_cloud_agent(agent))
        .map(|agent| mcoda_agent_entry(agent, llm_config, now, Some(&recent_failures)))
        .collect()
}

pub(crate) fn library_has_candidates(library: &LocalModelLibrary) -> bool {
    if library.services.iter().any(|service| {
        service.health == LocalServiceHealth::Healthy
            && service
                .models
                .iter()
                .any(service_model_has_delegation_default_capability)
    }) {
        return true;
    }
    if library.agents.iter().any(local_agent_delegation_candidate) {
        return true;
    }
    library.models.iter().any(local_model_delegation_candidate)
}

pub(crate) fn delegation_is_enabled(
    config: &DelegationConfig,
    library: Option<&LocalModelLibrary>,
) -> bool {
    if config.enabled {
        return true;
    }
    if !config.auto_enable {
        return false;
    }
    let enabled = library.map_or(false, library_has_candidates);
    if enabled {
        info!(
            target: "docdexd",
            "delegation auto-enabled via local model library"
        );
    }
    enabled
}

pub(crate) async fn refresh_local_library_if_stale(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
) -> Result<LocalModelLibrary> {
    refresh_local_library_if_stale_with_web::<fn(String) -> NoWebFuture, NoWebFuture>(
        state_dir_override,
        llm_config,
        allow_start_ollama,
        None,
    )
    .await
}

pub(crate) async fn refresh_local_library(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
) -> Result<LocalModelLibrary> {
    refresh_local_library_with_web::<fn(String) -> NoWebFuture, NoWebFuture>(
        state_dir_override,
        llm_config,
        allow_start_ollama,
        None,
    )
    .await
}

pub(crate) async fn refresh_local_library_with_web<F, Fut>(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
    web_fetcher: Option<&mut F>,
) -> Result<LocalModelLibrary>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    refresh_local_library_inner(
        state_dir_override,
        llm_config,
        allow_start_ollama,
        web_fetcher,
        true,
    )
    .await
}

pub(crate) async fn refresh_local_library_if_stale_with_web<F, Fut>(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
    web_fetcher: Option<&mut F>,
) -> Result<LocalModelLibrary>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    refresh_local_library_inner(
        state_dir_override,
        llm_config,
        allow_start_ollama,
        web_fetcher,
        false,
    )
    .await
}

async fn refresh_local_library_inner<F, Fut>(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
    mut web_fetcher: Option<&mut F>,
    force_refresh: bool,
) -> Result<LocalModelLibrary>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let mut library = load_local_library(state_dir_override)?;
    let now = now_ms();
    if !force_refresh && library.updated_at_ms > 0 {
        let elapsed_ms = now.saturating_sub(library.updated_at_ms);
        if elapsed_ms < library_ttl().as_millis() as u128 {
            library.defaults = resolve_local_default_selection(&library, llm_config);
            return Ok(library);
        }
    }

    let mut models = Vec::new();
    let mut services = Vec::new();
    let mut web_budget = MAX_WEB_CLASSIFICATIONS_PER_REFRESH;
    if let Some(base_url) = resolve_local_ollama_base_url(llm_config) {
        let service_model_start = models.len();
        let discovered =
            discover_ollama_models(&base_url, Duration::from_secs(2), allow_start_ollama).await;
        for discovered_model in discovered {
            let name = discovered_model.name;
            let existing = library.models.iter().find(|entry| entry.name == name);
            let mut classification =
                classify_model_known(&name).unwrap_or_else(|| classify_model_heuristic(&name));
            let should_web = classification.method == "heuristic"
                && web_budget > 0
                && is_web_candidate(&classification.capabilities)
                && should_web_classify(existing, now)
                && web_fetcher.is_some();
            if should_web {
                if let Some(fetcher) = web_fetcher.as_mut() {
                    if let Ok(Some(web_classification)) =
                        classify_model_with_web_text(&name, fetcher).await
                    {
                        classification = web_classification;
                        web_budget = web_budget.saturating_sub(1);
                    }
                }
            }
            let last_classified_at_ms = if classification.method == "web" {
                Some(now)
            } else {
                existing.and_then(|entry| entry.last_classified_at_ms)
            };
            let capability_flags = capability_flags_from_caps(&classification.capabilities);
            let (delegation_ready, delegation_readiness_reason) = model_delegation_readiness(
                &classification.capabilities,
                &LocalServiceHealth::Healthy,
                None,
            );
            models.push(LocalModelEntry {
                name: name.clone(),
                raw_name: Some(discovered_model.raw_name),
                source: "ollama".to_string(),
                capabilities: classification.capabilities,
                capability_flags,
                delegation_ready,
                delegation_readiness_reason,
                notes: existing.and_then(|entry| entry.notes.clone()),
                classification_method: classification.method,
                last_seen_at_ms: now,
                last_classified_at_ms,
            });
        }
        let service_models = &models[service_model_start..];
        if !service_models.is_empty() {
            services.push(build_ollama_service_entry(&base_url, service_models, now));
        }
    }

    let (_probes, mut detected_services, mut detected_models) =
        probe_local_services(llm_config, service_probe_timeout(), false, false, now).await;
    services.append(&mut detected_services);
    models.append(&mut detected_models);

    let agents = discover_mcoda_agents(state_dir_override, llm_config);
    reconcile_services_with_mcoda_agents(&mut services, &agents);

    library.updated_at_ms = now;
    library.services = services;
    library.models = models;
    library.agents = agents;
    library.defaults = resolve_local_default_selection(&library, llm_config);
    save_local_library(state_dir_override, &library)?;
    let (known_count, heuristic_count, web_count, other_count) =
        classification_method_counts(&library.models);
    info!(
        target: "docdexd",
        models = library.models.len(),
        agents = library.agents.len(),
        known = known_count,
        heuristic = heuristic_count,
        web = web_count,
        other = other_count,
        "local model library refreshed"
    );
    Ok(library)
}

pub fn library_path(state_dir_override: Option<&Path>) -> Result<PathBuf> {
    let root = resolve_state_root(state_dir_override)?;
    Ok(root.join(LIBRARY_DIR).join(LIBRARY_FILE))
}

pub fn load_local_library(state_dir_override: Option<&Path>) -> Result<LocalModelLibrary> {
    let path = library_path(state_dir_override)?;
    if !path.exists() {
        return Ok(LocalModelLibrary::default());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    match serde_json::from_str::<LocalModelLibrary>(&raw) {
        Ok(mut library) => {
            if library.version == 0 {
                library.version = LIBRARY_VERSION;
            }
            Ok(library)
        }
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                path = %path.display(),
                "local model library is corrupt; rebuilding"
            );
            backup_corrupt_library(&path);
            Ok(LocalModelLibrary::default())
        }
    }
}

pub fn save_local_library(
    state_dir_override: Option<&Path>,
    library: &LocalModelLibrary,
) -> Result<()> {
    let path = library_path(state_dir_override)?;
    ensure_library_dir(&path)?;
    let payload = serde_json::to_string_pretty(library).context("serialize local model library")?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn resolve_state_root(state_dir_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = state_dir_override {
        return Ok(path.to_path_buf());
    }
    if let Ok(value) = std::env::var("DOCDEX_STATE_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    crate::state_paths::default_state_base_dir()
}

fn ensure_library_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    crate::state_layout::ensure_state_dir_secure(parent)
}

fn env_trimmed(key: &str) -> Option<String> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn env_u64(key: &str) -> Option<u64> {
    let raw = env_trimmed(key)?;
    raw.parse::<u64>().ok()
}

fn library_ttl() -> Duration {
    env_u64("DOCDEX_LOCAL_LIBRARY_TTL_SECS")
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_LIBRARY_TTL_SECS))
}

pub(crate) fn service_probe_timeout() -> Duration {
    env_u64("DOCDEX_LOCAL_SERVICE_PROBE_TIMEOUT_MS")
        .map(Duration::from_millis)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_SERVICE_PROBE_TIMEOUT_MS))
}

pub(crate) fn local_library_diagnostics(
    library: &LocalModelLibrary,
    llm_config: &LlmConfig,
) -> LocalLibraryDiagnostics {
    let ttl_ms = library_ttl().as_millis();
    let now = now_ms();
    let stale = library.updated_at_ms == 0 || now.saturating_sub(library.updated_at_ms) >= ttl_ms;
    let defaults = resolve_local_default_selection(library, llm_config);
    LocalLibraryDiagnostics {
        updated_at_ms: library.updated_at_ms,
        ttl_ms,
        stale,
        services_detected: library.services.len(),
        models_detected: library.models.len(),
        agents_detected: library.agents.len(),
        status_messages: local_library_status_messages(library, &defaults),
        defaults,
    }
}

fn skipped_service_model_reason(model: &LocalServiceModelEntry) -> String {
    if model.capability_flags.unsupported_for_delegation {
        return "model is not suitable for local delegation".to_string();
    }
    if !model.delegation_ready {
        return model
            .delegation_readiness_reason
            .clone()
            .unwrap_or_else(|| "model is not marked delegation-ready".to_string());
    }
    "model lacks chat, code, reasoning, or tool-capable delegation signals".to_string()
}

fn local_library_status_messages(
    library: &LocalModelLibrary,
    defaults: &LocalDefaultSelection,
) -> Vec<LocalLibraryStatusMessage> {
    let mut messages = Vec::new();
    for service in &library.services {
        if service.health != LocalServiceHealth::Healthy {
            messages.push(LocalLibraryStatusMessage {
                code: "local_service_unavailable".to_string(),
                severity: "warning".to_string(),
                message: format!("local {} service is not healthy", service.provider.as_str()),
                provider: Some(service.provider.clone()),
                service_id: Some(service.service_id.clone()),
                base_url: service.base_url.clone(),
                reason: Some(local_service_health_label(&service.health).to_string()),
                ..LocalLibraryStatusMessage::default()
            });
            continue;
        }
        for model in &service.models {
            let model_name = local_service_model_execution_name(model);
            if model.capability_flags.embedding
                || service_model_has_delegation_default_capability(model)
            {
                messages.push(LocalLibraryStatusMessage {
                    code: "installed_model_found".to_string(),
                    severity: "info".to_string(),
                    message: format!(
                        "installed {} model found on {}",
                        model_name,
                        service.provider.as_str()
                    ),
                    provider: Some(service.provider.clone()),
                    service_id: Some(service.service_id.clone()),
                    base_url: service.base_url.clone(),
                    model: Some(model_name),
                    ..LocalLibraryStatusMessage::default()
                });
            } else {
                let reason = skipped_service_model_reason(model);
                messages.push(LocalLibraryStatusMessage {
                    code: "model_skipped".to_string(),
                    severity: "info".to_string(),
                    message: format!(
                        "installed {} model skipped on {}: {}",
                        model_name,
                        service.provider.as_str(),
                        reason
                    ),
                    provider: Some(service.provider.clone()),
                    service_id: Some(service.service_id.clone()),
                    base_url: service.base_url.clone(),
                    model: Some(model_name),
                    reason: Some(reason),
                    ..LocalLibraryStatusMessage::default()
                });
            }
        }
    }

    for agent in &library.agents {
        if mcoda_agent_health_is_ready(agent.health_status.as_deref()) {
            messages.push(LocalLibraryStatusMessage {
                code: "existing_mcoda_agent_found".to_string(),
                severity: "info".to_string(),
                message: format!("existing mcoda agent found: {}", agent.agent_slug.trim()),
                provider: local_agent_provider(agent),
                service_id: None,
                base_url: agent.base_url.clone(),
                model: agent
                    .default_model
                    .clone()
                    .or_else(|| agent.model_names.first().cloned()),
                agent_id: Some(agent.agent_id.clone()),
                agent_slug: Some(agent.agent_slug.clone()),
                ..LocalLibraryStatusMessage::default()
            });
        } else if !agent.agent_id.trim().is_empty() || !agent.agent_slug.trim().is_empty() {
            let agent_label = agent.agent_slug.trim().if_empty(agent.agent_id.trim());
            messages.push(LocalLibraryStatusMessage {
                code: "unhealthy_mcoda_agent".to_string(),
                severity: "warning".to_string(),
                message: format!("mcoda agent is not healthy: {agent_label}"),
                provider: local_agent_provider(agent),
                service_id: None,
                base_url: agent.base_url.clone(),
                model: agent
                    .default_model
                    .clone()
                    .or_else(|| agent.model_names.first().cloned()),
                agent_id: Some(agent.agent_id.clone()),
                agent_slug: Some(agent.agent_slug.clone()),
                reason: agent.health_status.clone(),
            });
        }
    }

    if let Some(selected) = defaults.embedding.selected.as_ref() {
        if selected.kind == LocalDefaultCandidateKind::OllamaSetupFallback {
            messages.push(fallback_setup_status(
                "embedding",
                defaults.embedding.setup_hint.as_deref(),
                selected,
            ));
        } else {
            messages.push(LocalLibraryStatusMessage {
                code: "embedding_model_selected".to_string(),
                severity: "info".to_string(),
                message: format!(
                    "embedding default selected: {}",
                    candidate_display_name(selected)
                ),
                provider: selected.provider.clone(),
                service_id: selected.service_id.clone(),
                base_url: selected.base_url.clone(),
                model: selected
                    .raw_model
                    .clone()
                    .or_else(|| selected.model.clone()),
                agent_id: selected.agent_id.clone(),
                agent_slug: selected.agent_slug.clone(),
                reason: selected.reason.clone(),
            });
        }
    }

    if let Some(selected) = defaults.delegation.selected.as_ref() {
        if selected.kind == LocalDefaultCandidateKind::OllamaSetupFallback {
            messages.push(fallback_setup_status(
                "delegation",
                defaults.delegation.setup_hint.as_deref(),
                selected,
            ));
        } else {
            messages.push(LocalLibraryStatusMessage {
                code: "delegation_model_selected".to_string(),
                severity: "info".to_string(),
                message: format!(
                    "local delegation default selected: {}",
                    candidate_display_name(selected)
                ),
                provider: selected.provider.clone(),
                service_id: selected.service_id.clone(),
                base_url: selected.base_url.clone(),
                model: selected
                    .raw_model
                    .clone()
                    .or_else(|| selected.model.clone()),
                agent_id: selected.agent_id.clone(),
                agent_slug: selected.agent_slug.clone(),
                reason: selected.reason.clone(),
            });
        }
    }

    messages
}

fn fallback_setup_status(
    lane: &str,
    setup_hint: Option<&str>,
    selected: &LocalDefaultCandidate,
) -> LocalLibraryStatusMessage {
    LocalLibraryStatusMessage {
        code: "fallback_setup_needed".to_string(),
        severity: "warning".to_string(),
        message: setup_hint
            .map(str::to_string)
            .unwrap_or_else(|| format!("{lane} needs local fallback setup")),
        provider: selected.provider.clone(),
        model: selected
            .raw_model
            .clone()
            .or_else(|| selected.model.clone()),
        reason: selected.reason.clone(),
        ..LocalLibraryStatusMessage::default()
    }
}

fn candidate_display_name(candidate: &LocalDefaultCandidate) -> String {
    if let Some(agent_slug) = candidate
        .agent_slug
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!("agent:{agent_slug}");
    }
    if let Some(agent_id) = candidate
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!("agent:{agent_id}");
    }
    if let Some(model) = candidate
        .raw_model
        .as_deref()
        .or(candidate.model.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(provider) = candidate.provider.as_ref() {
            return format!("{}:{model}", provider.as_str());
        }
        return model.to_string();
    }
    local_default_candidate_kind_label(&candidate.kind).to_string()
}

fn local_default_candidate_kind_label(kind: &LocalDefaultCandidateKind) -> &'static str {
    match kind {
        LocalDefaultCandidateKind::ConfiguredEmbedding => "configured_embedding",
        LocalDefaultCandidateKind::ConfiguredDelegation => "configured_delegation",
        LocalDefaultCandidateKind::LocalServiceModel => "local_service_model",
        LocalDefaultCandidateKind::McodaLocalAgent => "mcoda_local_agent",
        LocalDefaultCandidateKind::McodaEmbeddingAgent => "mcoda_embedding_agent",
        LocalDefaultCandidateKind::SelfHostedRemoteAgent => "self_hosted_remote_agent",
        LocalDefaultCandidateKind::OllamaInstalledModel => "ollama_installed_model",
        LocalDefaultCandidateKind::OllamaSetupFallback => "ollama_setup_fallback",
    }
}

trait EmptyStrExt {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str;
}

impl EmptyStrExt for str {
    fn if_empty<'a>(&'a self, fallback: &'a str) -> &'a str {
        if self.is_empty() {
            fallback
        } else {
            self
        }
    }
}

fn web_classify_ttl() -> Duration {
    env_u64("DOCDEX_LOCAL_LIBRARY_WEB_TTL_SECS")
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(WEB_CLASSIFY_TTL_SECS))
}

fn normalize_agent_capabilities(adapter: &str, capabilities: &[String]) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for capability in capabilities {
        let normalized = capability.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        match normalized.as_str() {
            "code" => tags.push(CAP_CODE.to_string()),
            "code_write" | "code-writer" | "code_writer" => {
                tags.push(CAP_CODE.to_string());
                tags.push(CAP_CODE_WRITER.to_string());
            }
            "code_review" | "code-reviewer" | "code_reviewer" => {
                tags.push(CAP_CODE.to_string());
                tags.push(CAP_CODE_REVIEWER.to_string());
            }
            "chat" | "general-chat" | "general_chat" => {
                tags.push(CAP_CHAT.to_string());
                tags.push(CAP_GENERAL_CHAT.to_string());
            }
            "reasoning" | "reasoner" => tags.push(CAP_REASONING.to_string()),
            "tool" | "tools" | "tool-capable" | "tool_capable" | "function_calling" => {
                tags.push(CAP_TOOL_CAPABLE.to_string());
            }
            "unsupported" | "unsupported_for_delegation" => {
                tags.push(CAP_UNSUPPORTED_FOR_DELEGATION.to_string());
            }
            _ => tags.push(normalized),
        }
    }
    let adapter_name = adapter.trim().to_ascii_lowercase();
    if adapter_name == "ollama" || adapter_name.starts_with("ollama-") {
        tags.push("local".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn classify_model_from_web_text(text: &str) -> Option<ModelClassification> {
    let lowered = text.to_ascii_lowercase();
    let mut caps = Vec::new();
    if lowered.contains("embedding") {
        caps.push(CAP_EMBEDDING.to_string());
    }
    if lowered.contains("vision")
        || lowered.contains("image")
        || lowered.contains("multimodal")
        || lowered.contains("visual")
    {
        caps.push(CAP_VISION.to_string());
    }
    if lowered.contains("code")
        || lowered.contains("coding")
        || lowered.contains("programming")
        || lowered.contains("developer")
    {
        caps.push(CAP_CODE_WRITER.to_string());
        caps.push(CAP_CODE_REVIEWER.to_string());
    }
    if lowered.contains("review") || lowered.contains("refactor") {
        caps.push(CAP_CODE_REVIEWER.to_string());
    }
    if lowered.contains("reasoning")
        || lowered.contains("reasoner")
        || lowered.contains("chain of thought")
        || lowered.contains("math")
    {
        caps.push(CAP_REASONING.to_string());
    }
    if lowered.contains("tool use")
        || lowered.contains("tool calling")
        || lowered.contains("function calling")
        || lowered.contains("function-call")
    {
        caps.push(CAP_TOOL_CAPABLE.to_string());
    }
    if lowered.contains("chat") || lowered.contains("assistant") {
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    if caps.is_empty() {
        return None;
    }
    Some(normalize_caps(caps, "web"))
}

fn push_capability(caps: &mut Vec<String>, capability: &str) {
    if !caps
        .iter()
        .any(|value| value.eq_ignore_ascii_case(capability))
    {
        caps.push(capability.to_string());
    }
}

fn normalize_caps(caps: Vec<String>, method: &str) -> ModelClassification {
    let mut caps: Vec<String> = caps
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect();
    let has_code = caps
        .iter()
        .any(|cap| cap == CAP_CODE || cap == CAP_CODE_WRITER || cap == CAP_CODE_REVIEWER);
    let has_chat = caps
        .iter()
        .any(|cap| cap == CAP_CHAT || cap == CAP_GENERAL_CHAT);
    let has_reasoning = caps.iter().any(|cap| cap == CAP_REASONING);
    let has_tool = caps.iter().any(|cap| cap == CAP_TOOL_CAPABLE);
    if has_code {
        push_capability(&mut caps, CAP_CODE);
    }
    if has_chat || has_code || has_reasoning || has_tool {
        push_capability(&mut caps, CAP_CHAT);
        push_capability(&mut caps, CAP_GENERAL_CHAT);
    }
    let has_embedding = caps.iter().any(|cap| cap == CAP_EMBEDDING);
    let has_vision = caps.iter().any(|cap| cap == CAP_VISION);
    let delegation_supported = has_code || has_chat || has_reasoning || has_tool;
    if (has_embedding || has_vision) && !delegation_supported {
        push_capability(&mut caps, CAP_UNSUPPORTED_FOR_DELEGATION);
    }
    caps.sort();
    caps.dedup();
    ModelClassification {
        capabilities: caps,
        method: method.to_string(),
    }
}

fn has_capability(capabilities: &[String], capability: &str) -> bool {
    capabilities
        .iter()
        .any(|value| value.eq_ignore_ascii_case(capability))
}

fn capability_flags_from_caps(capabilities: &[String]) -> LocalCapabilityFlags {
    let embedding = has_capability(capabilities, CAP_EMBEDDING);
    let vision = has_capability(capabilities, CAP_VISION);
    let code = has_capability(capabilities, CAP_CODE)
        || has_capability(capabilities, CAP_CODE_WRITER)
        || has_capability(capabilities, CAP_CODE_REVIEWER);
    let reasoning = has_capability(capabilities, CAP_REASONING);
    let tool_capable = has_capability(capabilities, CAP_TOOL_CAPABLE);
    let chat = has_capability(capabilities, CAP_CHAT)
        || has_capability(capabilities, CAP_GENERAL_CHAT)
        || code
        || reasoning
        || tool_capable;
    let unsupported_for_delegation = has_capability(capabilities, CAP_UNSUPPORTED_FOR_DELEGATION)
        || ((embedding || vision) && !chat);
    LocalCapabilityFlags {
        embedding,
        chat,
        delegation: is_candidate_capabilities(capabilities),
        code,
        vision,
        reasoning,
        tool_capable,
        unsupported_for_delegation,
    }
}

fn aggregate_capability_flags(models: &[LocalServiceModelEntry]) -> LocalCapabilityFlags {
    let mut flags = LocalCapabilityFlags::default();
    for model in models {
        flags.embedding |= model.capability_flags.embedding;
        flags.chat |= model.capability_flags.chat;
        flags.delegation |= model.capability_flags.delegation;
        flags.code |= model.capability_flags.code;
        flags.vision |= model.capability_flags.vision;
        flags.reasoning |= model.capability_flags.reasoning;
        flags.tool_capable |= model.capability_flags.tool_capable;
        flags.unsupported_for_delegation |= model.capability_flags.unsupported_for_delegation;
    }
    flags
}

fn normalized_base_url(base_url: &str) -> String {
    base_url.trim().trim_end_matches('/').to_string()
}

fn canonical_loopback_base_url(base_url: &str) -> String {
    let normalized = normalized_base_url(base_url);
    let Ok(mut url) = Url::parse(&normalized) else {
        return normalized;
    };
    let Some(host) = url.host_str() else {
        return normalized;
    };
    if (url.scheme() == "http" || url.scheme() == "https") && is_loopback_host(host) {
        let _ = url.set_host(Some("127.0.0.1"));
        return url.to_string().trim_end_matches('/').to_string();
    }
    normalized
}

fn canonical_match_base_url(provider: &LocalLlmProvider, base_url: &str) -> String {
    let base_url = if provider.is_openai_compatible() {
        openai_compatible_base_url(base_url)
    } else {
        normalized_base_url(base_url)
    };
    canonical_loopback_base_url(&base_url)
}

fn json_string_field(value: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        value
            .get(*key)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
    })
}

fn mcoda_config_string(config: Option<&Value>, keys: &[&str]) -> Option<String> {
    let config = config?;
    json_string_field(config, keys)
        .or_else(|| {
            config
                .get("localRunner")
                .and_then(|value| json_string_field(value, keys))
        })
        .or_else(|| {
            config
                .pointer("/agent/config")
                .and_then(|value| json_string_field(value, keys))
        })
}

fn mcoda_agent_model_names(agent: &McodaAgent) -> Vec<String> {
    dedupe_strings(
        agent
            .default_model
            .iter()
            .cloned()
            .chain(agent.models.iter().map(|model| model.model_name.clone())),
    )
}

fn mcoda_agent_provider_from_adapter(adapter: &str) -> Option<LocalLlmProvider> {
    LocalLlmProvider::from_mcoda_runner_kind(adapter)
}

fn mcoda_agent_provider(agent: &McodaAgent) -> Option<LocalLlmProvider> {
    mcoda_config_string(agent.config.as_ref(), &["runnerKind", "runner_kind"])
        .and_then(|runner_kind| LocalLlmProvider::from_mcoda_runner_kind(&runner_kind))
        .or_else(|| mcoda_agent_provider_from_adapter(&agent.adapter))
}

fn mcoda_agent_runner_kind(agent: &McodaAgent) -> Option<String> {
    mcoda_agent_provider(agent).map(|provider| provider.mcoda_runner_kind().to_string())
}

fn mcoda_agent_can_use_default_local_ollama_base_url(agent: &McodaAgent) -> bool {
    let kind = mcoda_config_string(agent.config.as_ref(), &["runnerKind", "runner_kind"])
        .unwrap_or_else(|| agent.adapter.clone());
    let normalized = kind
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .replace(' ', "-");
    matches!(
        normalized.as_str(),
        "ollama" | "ollama-local" | "ollama-cli"
    )
}

fn mcoda_agent_base_url(agent: &McodaAgent, llm_config: &LlmConfig) -> Option<String> {
    mcoda_config_string(
        agent.config.as_ref(),
        &[
            "baseUrl",
            "endpoint",
            "apiBaseUrl",
            "base_url",
            "api_base_url",
        ],
    )
    .map(|base_url| {
        mcoda_agent_provider(agent)
            .map(|provider| canonical_match_base_url(&provider, &base_url))
            .unwrap_or_else(|| normalized_base_url(&base_url))
    })
    .or_else(|| match mcoda_agent_provider(agent) {
        Some(LocalLlmProvider::Ollama)
            if mcoda_agent_can_use_default_local_ollama_base_url(agent) =>
        {
            resolve_local_ollama_base_url(llm_config)
        }
        _ => None,
    })
}

fn ollama_service_endpoints(base_url: &str) -> Vec<LocalServiceEndpoint> {
    let base_url = normalized_base_url(base_url);
    vec![LocalServiceEndpoint {
        base_url: Some(base_url.clone()),
        health_url: Some(format!("{base_url}/api/tags")),
        models_url: Some(format!("{base_url}/api/tags")),
        chat_url: Some(format!("{base_url}/api/chat")),
        delegation_url: Some(format!("{base_url}/api/generate")),
        embeddings_url: Some(format!("{base_url}/api/embeddings")),
    }]
}

fn local_service_health_label(health: &LocalServiceHealth) -> &'static str {
    match health {
        LocalServiceHealth::Unknown => "unknown",
        LocalServiceHealth::Healthy => "healthy",
        LocalServiceHealth::Degraded => "degraded",
        LocalServiceHealth::Unavailable => "unavailable",
    }
}

fn model_delegation_readiness(
    capabilities: &[String],
    service_health: &LocalServiceHealth,
    context_window_tokens: Option<u32>,
) -> (bool, Option<String>) {
    let flags = capability_flags_from_caps(capabilities);
    if flags.unsupported_for_delegation {
        return (
            false,
            Some("unsupported for delegation: embedding-only or vision-only model".to_string()),
        );
    }
    if flags.embedding && !(flags.chat || flags.code || flags.reasoning || flags.tool_capable) {
        return (
            false,
            Some("unsupported for delegation: embedding model only".to_string()),
        );
    }
    if service_health != &LocalServiceHealth::Healthy {
        return (
            false,
            Some(format!(
                "service health is {}; healthy service required",
                local_service_health_label(service_health)
            )),
        );
    }
    if let Some(context_window_tokens) = context_window_tokens {
        if context_window_tokens < MIN_LOCAL_DELEGATION_CONTEXT_TOKENS {
            return (
                false,
                Some(format!(
                    "context window {context_window_tokens} tokens is below {MIN_LOCAL_DELEGATION_CONTEXT_TOKENS}"
                )),
            );
        }
    }
    if !(flags.chat || flags.code || flags.reasoning || flags.tool_capable) {
        return (
            false,
            Some("no chat, code, reasoning, or tool capability detected".to_string()),
        );
    }
    (
        true,
        Some("healthy service with non-embedding chat/code-capable model".to_string()),
    )
}

fn local_service_model_from_entry(
    entry: &LocalModelEntry,
    service_health: &LocalServiceHealth,
) -> LocalServiceModelEntry {
    let context_window_tokens = None;
    let capability_flags = capability_flags_from_caps(&entry.capabilities);
    let (delegation_ready, delegation_readiness_reason) =
        model_delegation_readiness(&entry.capabilities, service_health, context_window_tokens);
    LocalServiceModelEntry {
        name: entry.name.clone(),
        raw_name: entry.raw_name.clone().or_else(|| Some(entry.name.clone())),
        capabilities: entry.capabilities.clone(),
        capability_flags,
        context_window_tokens,
        embedding_dimensions: None,
        mcoda_reconciliation: McodaReconciliationStatus::Unknown,
        mcoda_agent_match: None,
        mcoda_setup_hint: None,
        delegation_ready,
        delegation_readiness_reason,
        notes: entry.notes.clone(),
    }
}

fn build_ollama_service_entry(
    base_url: &str,
    models: &[LocalModelEntry],
    now_ms: u128,
) -> LocalServiceEntry {
    let base_url = normalized_base_url(base_url);
    let health = if models.is_empty() {
        LocalServiceHealth::Unknown
    } else {
        LocalServiceHealth::Healthy
    };
    let service_models: Vec<LocalServiceModelEntry> = models
        .iter()
        .map(|entry| local_service_model_from_entry(entry, &health))
        .collect();
    let capability_flags = aggregate_capability_flags(&service_models);
    LocalServiceEntry {
        service_id: format!("ollama:{base_url}"),
        provider: LocalLlmProvider::Ollama,
        source_type: LocalLibrarySourceType::LocalProcess,
        display_name: Some("Ollama".to_string()),
        base_url: Some(base_url.clone()),
        endpoints: ollama_service_endpoints(&base_url),
        health,
        models: service_models,
        capability_flags,
        notes: None,
        last_seen_at_ms: now_ms,
    }
}

pub(crate) fn resolve_local_default_selection(
    library: &LocalModelLibrary,
    llm_config: &LlmConfig,
) -> LocalDefaultSelection {
    LocalDefaultSelection {
        embedding: resolve_embedding_default(library, llm_config),
        delegation: resolve_delegation_default(library, llm_config),
    }
}

fn resolve_embedding_default(
    library: &LocalModelLibrary,
    llm_config: &LlmConfig,
) -> LocalDefaultChoice {
    let mut candidates = Vec::new();
    if let Some(candidate) = configured_embedding_default_candidate(library, llm_config) {
        push_unique_default_candidate(&mut candidates, candidate);
    }
    for candidate in healthy_service_embedding_default_candidates(library, false) {
        push_unique_default_candidate(&mut candidates, candidate);
    }
    for candidate in healthy_mcoda_embedding_default_candidates(library) {
        push_unique_default_candidate(&mut candidates, candidate);
    }
    for candidate in ollama_embedding_fallback_candidates(library) {
        push_unique_default_candidate(&mut candidates, candidate);
    }

    let mut setup_hint = None;
    if candidates.is_empty() {
        let hint = format!(
            "install or set up Ollama and pull {FALLBACK_EMBEDDING_MODEL} for local embeddings"
        );
        setup_hint = Some(hint.clone());
        candidates.push(ollama_setup_candidate(
            FALLBACK_EMBEDDING_MODEL,
            "no healthy local embedding model or mcoda embedding agent was found",
        ));
    }
    LocalDefaultChoice {
        selected: candidates.first().cloned(),
        candidates,
        setup_hint,
    }
}

fn resolve_delegation_default(
    library: &LocalModelLibrary,
    llm_config: &LlmConfig,
) -> LocalDefaultChoice {
    let mut candidates = Vec::new();
    if let Some(candidate) = configured_delegation_default_candidate(library, llm_config) {
        push_unique_default_candidate(&mut candidates, candidate);
    }
    for candidate in healthy_zero_cost_local_mcoda_default_candidates(library) {
        push_unique_default_candidate(&mut candidates, candidate);
    }
    for candidate in healthy_service_delegation_default_candidates(library, false) {
        push_unique_default_candidate(&mut candidates, candidate);
    }
    if llm_config.delegation.cloud.enabled {
        for candidate in healthy_config_allowed_self_hosted_default_candidates(library) {
            push_unique_default_candidate(&mut candidates, candidate);
        }
    }
    for candidate in ollama_delegation_fallback_candidates(library) {
        push_unique_default_candidate(&mut candidates, candidate);
    }

    let mut setup_hint = None;
    if candidates.is_empty() {
        let hint = format!(
            "install or set up Ollama and pull {FALLBACK_DELEGATION_MODEL} for local delegation"
        );
        setup_hint = Some(hint.clone());
        candidates.push(ollama_setup_candidate(
            FALLBACK_DELEGATION_MODEL,
            "no healthy zero-cost mcoda agent or code/chat-capable local model was found",
        ));
    }
    LocalDefaultChoice {
        selected: candidates.first().cloned(),
        candidates,
        setup_hint,
    }
}

fn configured_embedding_default_candidate(
    library: &LocalModelLibrary,
    llm_config: &LlmConfig,
) -> Option<LocalDefaultCandidate> {
    let configured = llm_config.embedding_model.trim();
    if configured.is_empty() {
        return None;
    }
    find_service_embedding_candidate(library, configured).or_else(|| {
        find_mcoda_embedding_candidate(library, configured).map(|mut candidate| {
            candidate.kind = LocalDefaultCandidateKind::ConfiguredEmbedding;
            candidate.explicit = true;
            candidate.reason = Some(format!(
                "configured embedding model {configured} is available from a healthy mcoda agent"
            ));
            candidate
        })
    })
}

fn configured_delegation_default_candidate(
    library: &LocalModelLibrary,
    llm_config: &LlmConfig,
) -> Option<LocalDefaultCandidate> {
    configured_delegation_values(&llm_config.delegation)
        .into_iter()
        .find_map(|value| configured_delegation_value_candidate(library, &value))
}

fn configured_delegation_values(config: &DelegationConfig) -> Vec<String> {
    let mut values = Vec::new();
    push_configured_value(&mut values, &config.code.local_agent_id);
    push_configured_value(&mut values, &config.general.local_agent_id);
    push_configured_value(&mut values, &config.local_agent_id);
    if config.cloud.enabled {
        push_configured_value(&mut values, &config.code.cloud_agent_id);
        push_configured_value(&mut values, &config.general.cloud_agent_id);
        push_configured_value(&mut values, &config.cloud_agent_id);
    }
    values
}

fn push_configured_value(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() || values.iter().any(|existing| existing == value) {
        return;
    }
    values.push(value.to_string());
}

fn configured_delegation_value_candidate(
    library: &LocalModelLibrary,
    configured: &str,
) -> Option<LocalDefaultCandidate> {
    let configured = configured.trim();
    let model_override = configured
        .strip_prefix("model:")
        .or_else(|| configured.strip_prefix("ollama:"))
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let lookup = model_override.unwrap_or(configured);
    if model_override.is_none() {
        if let Some(agent) = library.agents.iter().find(|agent| {
            agent.agent_id == configured
                || (!agent.agent_slug.is_empty() && agent.agent_slug == configured)
        }) {
            return Some(agent_default_candidate(
                LocalDefaultCandidateKind::ConfiguredDelegation,
                agent,
                "explicit delegation target from user configuration",
                true,
            ));
        }
    }
    find_service_delegation_candidate(library, lookup, true).or_else(|| {
        find_legacy_delegation_candidate(
            library,
            lookup,
            LocalDefaultCandidateKind::ConfiguredDelegation,
        )
        .map(|mut candidate| {
            candidate.explicit = true;
            candidate.reason = Some(format!(
                "configured delegation model {lookup} is available in the local library"
            ));
            candidate
        })
    })
}

fn find_service_embedding_candidate(
    library: &LocalModelLibrary,
    configured: &str,
) -> Option<LocalDefaultCandidate> {
    library.services.iter().find_map(|service| {
        if service.health != LocalServiceHealth::Healthy {
            return None;
        }
        service
            .models
            .iter()
            .find(|model| {
                model.capability_flags.embedding && service_model_name_matches(model, configured)
            })
            .map(|model| {
                service_model_default_candidate(
                    LocalDefaultCandidateKind::ConfiguredEmbedding,
                    service,
                    model,
                    format!(
                        "configured embedding model {configured} is available from a healthy local service"
                    ),
                    true,
                )
            })
    })
}

fn find_mcoda_embedding_candidate(
    library: &LocalModelLibrary,
    configured: &str,
) -> Option<LocalDefaultCandidate> {
    healthy_mcoda_embedding_default_candidates(library)
        .into_iter()
        .find(|candidate| {
            candidate
                .model
                .as_deref()
                .is_some_and(|model| model_name_matches(model, configured))
                || candidate
                    .raw_model
                    .as_deref()
                    .is_some_and(|model| model_name_matches(model, configured))
        })
}

fn find_service_delegation_candidate(
    library: &LocalModelLibrary,
    configured: &str,
    explicit: bool,
) -> Option<LocalDefaultCandidate> {
    library.services.iter().find_map(|service| {
        if service.health != LocalServiceHealth::Healthy {
            return None;
        }
        service
            .models
            .iter()
            .find(|model| {
                service_model_name_matches(model, configured)
                    && service_model_has_delegation_default_capability(model)
            })
            .map(|model| {
                service_model_default_candidate(
                    LocalDefaultCandidateKind::ConfiguredDelegation,
                    service,
                    model,
                    format!(
                        "configured delegation model {configured} is available from the local service inventory"
                    ),
                    explicit,
                )
            })
    })
}

fn find_legacy_embedding_candidate(
    library: &LocalModelLibrary,
    configured: &str,
    kind: LocalDefaultCandidateKind,
) -> Option<LocalDefaultCandidate> {
    library.models.iter().find_map(|model| {
        if local_model_supports_legacy_ollama_target(model)
            && legacy_model_name_matches(model, configured)
            && legacy_model_has_embedding_capability(model)
        {
            Some(legacy_model_default_candidate(kind.clone(), model))
        } else {
            None
        }
    })
}

fn find_legacy_delegation_candidate(
    library: &LocalModelLibrary,
    configured: &str,
    kind: LocalDefaultCandidateKind,
) -> Option<LocalDefaultCandidate> {
    library.models.iter().find_map(|model| {
        if legacy_model_name_matches(model, configured) && local_model_delegation_candidate(model) {
            Some(legacy_model_default_candidate(kind.clone(), model))
        } else {
            None
        }
    })
}

fn healthy_service_embedding_default_candidates(
    library: &LocalModelLibrary,
    include_ollama_fallback: bool,
) -> Vec<LocalDefaultCandidate> {
    let mut candidates = Vec::new();
    for service in &library.services {
        if service.health != LocalServiceHealth::Healthy {
            continue;
        }
        for model in &service.models {
            if !model.capability_flags.embedding {
                continue;
            }
            if !include_ollama_fallback
                && service.provider == LocalLlmProvider::Ollama
                && service_model_name_matches(model, FALLBACK_EMBEDDING_MODEL)
            {
                continue;
            }
            candidates.push(service_model_default_candidate(
                LocalDefaultCandidateKind::LocalServiceModel,
                service,
                model,
                "healthy local embedding model from supported service",
                false,
            ));
        }
    }
    candidates.sort_by(compare_default_candidates);
    candidates
}

fn healthy_mcoda_embedding_default_candidates(
    library: &LocalModelLibrary,
) -> Vec<LocalDefaultCandidate> {
    let mut candidates: Vec<LocalDefaultCandidate> = library
        .agents
        .iter()
        .filter(|agent| {
            local_agent_source_is_local(agent)
                && !local_agent_is_cloud(agent)
                && !agent_is_self_hosted_remote(agent)
                && mcoda_agent_health_is_ready(agent.health_status.as_deref())
                && agent_is_not_paid(agent)
                && agent_has_embedding_capability(agent)
        })
        .map(|agent| {
            agent_default_candidate(
                LocalDefaultCandidateKind::McodaEmbeddingAgent,
                agent,
                "healthy local mcoda embedding agent",
                false,
            )
        })
        .collect();
    candidates.sort_by(compare_default_candidates);
    candidates
}

fn ollama_embedding_fallback_candidates(library: &LocalModelLibrary) -> Vec<LocalDefaultCandidate> {
    let mut candidates = Vec::new();
    for service in &library.services {
        if service.provider != LocalLlmProvider::Ollama
            || service.health != LocalServiceHealth::Healthy
        {
            continue;
        }
        for model in &service.models {
            if model.capability_flags.embedding
                && service_model_name_matches(model, FALLBACK_EMBEDDING_MODEL)
            {
                candidates.push(service_model_default_candidate(
                    LocalDefaultCandidateKind::OllamaInstalledModel,
                    service,
                    model,
                    "Ollama fallback embedding model is already installed",
                    false,
                ));
            }
        }
    }
    if candidates.is_empty() {
        if let Some(candidate) = find_legacy_embedding_candidate(
            library,
            FALLBACK_EMBEDDING_MODEL,
            LocalDefaultCandidateKind::OllamaInstalledModel,
        ) {
            candidates.push(candidate);
        }
    }
    candidates.sort_by(compare_default_candidates);
    candidates
}

fn healthy_zero_cost_local_mcoda_default_candidates(
    library: &LocalModelLibrary,
) -> Vec<LocalDefaultCandidate> {
    let mut candidates: Vec<(i32, LocalDefaultCandidate)> = library
        .agents
        .iter()
        .filter(|agent| {
            local_agent_source_is_local(agent)
                && !local_agent_is_cloud(agent)
                && !agent_is_self_hosted_remote(agent)
                && local_agent_delegation_candidate(agent)
                && mcoda_agent_health_is_ready(agent.health_status.as_deref())
                && matches!(agent.cost_per_million, Some(cost) if cost <= 0.0)
                && agent_has_delegation_default_capability(agent)
        })
        .map(|agent| {
            (
                agent_delegation_default_score(agent),
                agent_default_candidate(
                    LocalDefaultCandidateKind::McodaLocalAgent,
                    agent,
                    "healthy zero-cost local mcoda agent",
                    false,
                ),
            )
        })
        .filter(|(score, _)| *score > 0)
        .collect();
    candidates.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| compare_default_candidates(left, right))
    });
    candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

fn healthy_service_delegation_default_candidates(
    library: &LocalModelLibrary,
    include_ollama: bool,
) -> Vec<LocalDefaultCandidate> {
    let mut candidates = Vec::new();
    for service in &library.services {
        if service.health != LocalServiceHealth::Healthy {
            continue;
        }
        if !include_ollama && service.provider == LocalLlmProvider::Ollama {
            continue;
        }
        for model in &service.models {
            if !service_model_has_delegation_default_capability(model) {
                continue;
            }
            candidates.push((
                service_model_delegation_default_score(model),
                service_model_default_candidate(
                    LocalDefaultCandidateKind::LocalServiceModel,
                    service,
                    model,
                    "healthy local service model with code/chat capability",
                    false,
                ),
            ));
        }
    }
    candidates.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| compare_default_candidates(left, right))
    });
    candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

fn healthy_config_allowed_self_hosted_default_candidates(
    library: &LocalModelLibrary,
) -> Vec<LocalDefaultCandidate> {
    let mut candidates: Vec<(i32, LocalDefaultCandidate)> = library
        .agents
        .iter()
        .filter(|agent| {
            local_agent_source_is_local(agent)
                && !local_agent_is_cloud(agent)
                && agent_is_self_hosted_remote(agent)
                && local_agent_delegation_candidate(agent)
                && mcoda_agent_health_is_ready(agent.health_status.as_deref())
                && agent_is_not_paid(agent)
                && agent_has_delegation_default_capability(agent)
        })
        .map(|agent| {
            (
                agent_delegation_default_score(agent),
                agent_default_candidate(
                    LocalDefaultCandidateKind::SelfHostedRemoteAgent,
                    agent,
                    "healthy self-hosted remote mcoda agent allowed by delegation.cloud.enabled",
                    false,
                ),
            )
        })
        .filter(|(score, _)| *score > 0)
        .collect();
    candidates.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| compare_default_candidates(left, right))
    });
    candidates
        .into_iter()
        .map(|(_, candidate)| candidate)
        .collect()
}

fn ollama_delegation_fallback_candidates(
    library: &LocalModelLibrary,
) -> Vec<LocalDefaultCandidate> {
    let mut preferred = Vec::new();
    let mut other = Vec::new();
    for service in &library.services {
        if service.provider != LocalLlmProvider::Ollama
            || service.health != LocalServiceHealth::Healthy
        {
            continue;
        }
        for model in &service.models {
            if !service_model_has_delegation_default_capability(model) {
                continue;
            }
            let candidate = service_model_default_candidate(
                LocalDefaultCandidateKind::OllamaInstalledModel,
                service,
                model,
                "installed Ollama chat/code model fallback",
                false,
            );
            if service_model_name_matches(model, FALLBACK_DELEGATION_MODEL) {
                preferred.push(candidate);
            } else {
                other.push((service_model_delegation_default_score(model), candidate));
            }
        }
    }
    if preferred.is_empty() && other.is_empty() {
        if let Some(candidate) = find_legacy_delegation_candidate(
            library,
            FALLBACK_DELEGATION_MODEL,
            LocalDefaultCandidateKind::OllamaInstalledModel,
        ) {
            preferred.push(candidate);
        }
    }
    preferred.sort_by(compare_default_candidates);
    other.sort_by(|(left_score, left), (right_score, right)| {
        right_score
            .cmp(left_score)
            .then_with(|| compare_default_candidates(left, right))
    });
    preferred.extend(other.into_iter().map(|(_, candidate)| candidate));
    preferred
}

fn service_model_default_candidate(
    kind: LocalDefaultCandidateKind,
    service: &LocalServiceEntry,
    model: &LocalServiceModelEntry,
    reason: impl Into<String>,
    explicit: bool,
) -> LocalDefaultCandidate {
    LocalDefaultCandidate {
        kind,
        provider: Some(service.provider.clone()),
        source_type: Some(service.source_type.clone()),
        service_id: Some(service.service_id.clone()),
        model: Some(model.name.clone()),
        raw_model: model.raw_name.clone(),
        base_url: service.base_url.clone(),
        reason: Some(reason.into()),
        explicit,
        ..LocalDefaultCandidate::default()
    }
}

fn legacy_model_default_candidate(
    kind: LocalDefaultCandidateKind,
    model: &LocalModelEntry,
) -> LocalDefaultCandidate {
    LocalDefaultCandidate {
        kind,
        provider: local_llm_provider_from_config(&model.source),
        source_type: Some(LocalLibrarySourceType::LocalProcess),
        model: Some(model.name.clone()),
        raw_model: model.raw_name.clone(),
        reason: Some("legacy local model library entry is available".to_string()),
        ..LocalDefaultCandidate::default()
    }
}

fn agent_default_candidate(
    kind: LocalDefaultCandidateKind,
    agent: &LocalAgentEntry,
    reason: impl Into<String>,
    explicit: bool,
) -> LocalDefaultCandidate {
    LocalDefaultCandidate {
        kind,
        provider: local_agent_provider(agent),
        source_type: Some(agent_source_type(agent)),
        model: agent
            .default_model
            .clone()
            .or_else(|| agent.model_names.first().cloned()),
        raw_model: agent.default_model.clone(),
        agent_id: Some(agent.agent_id.clone()),
        agent_slug: Some(agent.agent_slug.clone()),
        base_url: agent.base_url.clone(),
        runner_kind: agent.runner_kind.clone(),
        reason: Some(reason.into()),
        explicit,
        ..LocalDefaultCandidate::default()
    }
}

fn ollama_setup_candidate(model: &str, reason: impl Into<String>) -> LocalDefaultCandidate {
    LocalDefaultCandidate {
        kind: LocalDefaultCandidateKind::OllamaSetupFallback,
        provider: Some(LocalLlmProvider::Ollama),
        source_type: Some(LocalLibrarySourceType::InstallerFallback),
        model: Some(model.to_string()),
        reason: Some(reason.into()),
        ..LocalDefaultCandidate::default()
    }
}

fn agent_source_type(agent: &LocalAgentEntry) -> LocalLibrarySourceType {
    if local_agent_is_cloud(agent) {
        LocalLibrarySourceType::McodaCloudAgent
    } else if agent_is_self_hosted_remote(agent) {
        LocalLibrarySourceType::McodaRemoteAgent
    } else {
        LocalLibrarySourceType::McodaLocalAgent
    }
}

fn agent_is_self_hosted_remote(agent: &LocalAgentEntry) -> bool {
    !local_agent_is_cloud(agent)
        && agent
            .base_url
            .as_deref()
            .is_some_and(|base_url| !is_local_http_base_url(base_url))
}

fn agent_is_not_paid(agent: &LocalAgentEntry) -> bool {
    agent
        .cost_per_million
        .map(|cost| cost <= 0.0)
        .unwrap_or(true)
}

fn agent_has_embedding_capability(agent: &LocalAgentEntry) -> bool {
    capability_flags_from_caps(&agent.capabilities).embedding
}

fn agent_has_delegation_default_capability(agent: &LocalAgentEntry) -> bool {
    let flags = capability_flags_from_caps(&agent.capabilities);
    if flags.unsupported_for_delegation && !(flags.chat || flags.code || flags.reasoning) {
        return false;
    }
    flags.code
        || flags.chat
        || flags.reasoning
        || flags.tool_capable
        || mcoda_agent_usage_implies_delegation(agent.usage.as_deref())
}

pub(crate) fn local_service_model_delegation_candidate(model: &LocalServiceModelEntry) -> bool {
    service_model_has_delegation_default_capability(model)
}

fn service_model_has_delegation_default_capability(model: &LocalServiceModelEntry) -> bool {
    model.delegation_ready
        && !model.capability_flags.unsupported_for_delegation
        && (model.capability_flags.code
            || model.capability_flags.chat
            || model.capability_flags.reasoning
            || model.capability_flags.tool_capable)
}

fn service_model_delegation_default_score(model: &LocalServiceModelEntry) -> i32 {
    let mut score = 0;
    if model.capability_flags.code {
        score += 40;
    }
    if model.capability_flags.reasoning {
        score += 20;
    }
    if model.capability_flags.tool_capable {
        score += 10;
    }
    if model.capability_flags.chat {
        score += 5;
    }
    if let Some(tokens) = model.context_window_tokens {
        if tokens >= 8192 {
            score += 4;
        }
    }
    let key = normalize_model_key(model.raw_name.as_deref().unwrap_or(&model.name));
    if key.contains("qwen") {
        score += 8;
    }
    if key.contains("coder") || key.contains("code") {
        score += 8;
    }
    if key.contains("phi") {
        score += 4;
    }
    if key.contains("llama") {
        score += 2;
    }
    score
}

fn agent_delegation_default_score(agent: &LocalAgentEntry) -> i32 {
    let mut score = 0;
    let flags = capability_flags_from_caps(&agent.capabilities);
    if flags.code {
        score += 40;
    }
    if flags.reasoning {
        score += 20;
    }
    if flags.tool_capable {
        score += 10;
    }
    if flags.chat {
        score += 5;
    }
    if let Some(usage) = agent
        .usage
        .as_deref()
        .map(|value| value.to_ascii_lowercase())
    {
        if usage.contains("code") {
            score += 16;
        }
        if usage.contains("review") {
            score += 8;
        }
        if usage.contains("general") || usage.contains("chat") {
            score += 4;
        }
    }
    if let Some(max_complexity) = agent.max_complexity {
        score += max_complexity.clamp(0, 10) as i32;
    }
    if let Some(reasoning_rating) = agent.reasoning_rating.filter(|value| value.is_finite()) {
        score += reasoning_rating.round().clamp(0.0, 10.0) as i32;
    }
    if let Some(rating) = agent.rating.filter(|value| value.is_finite()) {
        score += rating.round().clamp(0.0, 10.0) as i32;
    }
    let key = agent
        .default_model
        .as_deref()
        .or_else(|| agent.model_names.first().map(String::as_str))
        .map(normalize_model_key)
        .unwrap_or_default();
    if key.contains("qwen") {
        score += 8;
    }
    if key.contains("coder") || key.contains("code") {
        score += 8;
    }
    score
}

fn provider_default_order(provider: Option<&LocalLlmProvider>) -> u8 {
    match provider {
        Some(LocalLlmProvider::Vllm) => 10,
        Some(LocalLlmProvider::LlamaCpp) => 20,
        Some(LocalLlmProvider::LlamaCppPython) => 21,
        Some(LocalLlmProvider::LmStudio) => 30,
        Some(LocalLlmProvider::LocalAi) => 40,
        Some(LocalLlmProvider::Sglang) => 50,
        Some(LocalLlmProvider::Tgi) => 60,
        Some(LocalLlmProvider::CustomOpenAiCompatible) => 70,
        Some(LocalLlmProvider::Ollama) => 90,
        None => 100,
    }
}

fn compare_default_candidates(
    left: &LocalDefaultCandidate,
    right: &LocalDefaultCandidate,
) -> std::cmp::Ordering {
    provider_default_order(left.provider.as_ref())
        .cmp(&provider_default_order(right.provider.as_ref()))
        .then_with(|| {
            left.agent_slug
                .as_deref()
                .unwrap_or_default()
                .cmp(right.agent_slug.as_deref().unwrap_or_default())
        })
        .then_with(|| {
            left.agent_id
                .as_deref()
                .unwrap_or_default()
                .cmp(right.agent_id.as_deref().unwrap_or_default())
        })
        .then_with(|| {
            left.raw_model
                .as_deref()
                .or(left.model.as_deref())
                .unwrap_or_default()
                .cmp(
                    right
                        .raw_model
                        .as_deref()
                        .or(right.model.as_deref())
                        .unwrap_or_default(),
                )
        })
        .then_with(|| {
            left.base_url
                .as_deref()
                .unwrap_or_default()
                .cmp(right.base_url.as_deref().unwrap_or_default())
        })
}

fn push_unique_default_candidate(
    candidates: &mut Vec<LocalDefaultCandidate>,
    candidate: LocalDefaultCandidate,
) {
    if candidates
        .iter()
        .any(|existing| default_candidate_same_target(existing, &candidate))
    {
        return;
    }
    candidates.push(candidate);
}

fn default_candidate_same_target(
    left: &LocalDefaultCandidate,
    right: &LocalDefaultCandidate,
) -> bool {
    if let (Some(left_agent), Some(right_agent)) = (&left.agent_id, &right.agent_id) {
        return left_agent == right_agent;
    }
    left.provider == right.provider
        && left.base_url == right.base_url
        && candidate_model_key(left) == candidate_model_key(right)
        && candidate_model_key(left).is_some()
}

fn candidate_model_key(candidate: &LocalDefaultCandidate) -> Option<String> {
    candidate
        .raw_model
        .as_deref()
        .or(candidate.model.as_deref())
        .map(normalize_model_key)
        .filter(|key| !key.is_empty())
}

fn service_model_name_matches(model: &LocalServiceModelEntry, requested: &str) -> bool {
    model_name_matches(&model.name, requested)
        || model
            .raw_name
            .as_deref()
            .is_some_and(|raw| model_name_matches(raw, requested))
}

fn legacy_model_name_matches(model: &LocalModelEntry, requested: &str) -> bool {
    model_name_matches(&model.name, requested)
        || model
            .raw_name
            .as_deref()
            .is_some_and(|raw| model_name_matches(raw, requested))
}

fn legacy_model_has_embedding_capability(model: &LocalModelEntry) -> bool {
    model.capability_flags.embedding || has_capability(&model.capabilities, CAP_EMBEDDING)
}

fn model_name_matches(candidate: &str, requested: &str) -> bool {
    let candidate = normalize_model_key(candidate);
    let requested = normalize_model_key(requested);
    if candidate.is_empty() || requested.is_empty() {
        return false;
    }
    if candidate == requested {
        return true;
    }
    candidate
        .strip_suffix(":latest")
        .is_some_and(|value| value == requested)
        || requested
            .strip_suffix(":latest")
            .is_some_and(|value| value == candidate)
}

fn local_agent_source_is_local(agent: &LocalAgentEntry) -> bool {
    agent
        .source
        .eq_ignore_ascii_case(LOCAL_AGENT_SOURCE_MCODA_LOCAL)
        || agent.source.eq_ignore_ascii_case("mcoda_local_agent")
}

fn local_agent_provider(agent: &LocalAgentEntry) -> Option<LocalLlmProvider> {
    agent
        .runner_kind
        .as_deref()
        .and_then(LocalLlmProvider::from_mcoda_runner_kind)
        .or_else(|| LocalLlmProvider::from_mcoda_runner_kind(&agent.adapter))
}

fn local_agent_model_keys(agent: &LocalAgentEntry) -> HashSet<String> {
    agent
        .default_model
        .iter()
        .cloned()
        .chain(agent.model_names.iter().cloned())
        .map(|model| normalize_model_key(&model))
        .filter(|key| !key.is_empty())
        .collect()
}

fn service_model_keys(model: &LocalServiceModelEntry) -> HashSet<String> {
    model
        .raw_name
        .iter()
        .cloned()
        .chain(std::iter::once(model.name.clone()))
        .map(|name| normalize_model_key(&name))
        .filter(|key| !key.is_empty())
        .collect()
}

fn local_agent_matches_service_model(
    service: &LocalServiceEntry,
    model: &LocalServiceModelEntry,
    agent: &LocalAgentEntry,
) -> bool {
    if !local_agent_source_is_local(agent) {
        return false;
    }
    let Some(agent_provider) = local_agent_provider(agent) else {
        return false;
    };
    if agent_provider != service.provider {
        return false;
    }
    let Some(service_base_url) = service
        .base_url
        .as_deref()
        .map(|base_url| canonical_match_base_url(&service.provider, base_url))
    else {
        return false;
    };
    let Some(agent_base_url) = agent.base_url.as_deref() else {
        return false;
    };
    if !is_local_http_base_url(agent_base_url) {
        return false;
    }
    if canonical_match_base_url(&agent_provider, agent_base_url) != service_base_url {
        return false;
    }
    let model_keys = service_model_keys(model);
    if model_keys.is_empty() {
        return false;
    }
    let agent_model_keys = local_agent_model_keys(agent);
    model_keys.iter().any(|key| agent_model_keys.contains(key))
}

fn local_agent_match(agent: &LocalAgentEntry) -> LocalMcodaAgentMatch {
    LocalMcodaAgentMatch {
        agent_id: agent.agent_id.clone(),
        agent_slug: agent.agent_slug.clone(),
        adapter: agent.adapter.clone(),
        default_model: agent.default_model.clone(),
        base_url: agent.base_url.clone(),
        runner_kind: agent.runner_kind.clone(),
        health_status: agent.health_status.clone(),
    }
}

fn compare_agent_matches(left: &LocalAgentEntry, right: &LocalAgentEntry) -> std::cmp::Ordering {
    right
        .rating
        .partial_cmp(&left.rating)
        .unwrap_or(std::cmp::Ordering::Equal)
        .then_with(|| {
            right
                .reasoning_rating
                .partial_cmp(&left.reasoning_rating)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| right.max_complexity.cmp(&left.max_complexity))
        .then_with(|| {
            left.cost_per_million
                .partial_cmp(&right.cost_per_million)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .then_with(|| left.agent_slug.cmp(&right.agent_slug))
        .then_with(|| left.agent_id.cmp(&right.agent_id))
}

fn mcoda_setup_hint_for_model(
    service: &LocalServiceEntry,
    model: &LocalServiceModelEntry,
) -> String {
    let model_name = model.raw_name.as_deref().unwrap_or(&model.name);
    let base_url = service.base_url.as_deref().unwrap_or("unknown");
    format!(
        "create or suggest a mcoda local agent for {} model {} at {}",
        service.provider.mcoda_runner_kind(),
        model_name,
        base_url
    )
}

fn reconcile_service_model_with_mcoda_agents(
    service: &LocalServiceEntry,
    model: &mut LocalServiceModelEntry,
    agents: &[LocalAgentEntry],
) {
    model.mcoda_agent_match = None;
    model.mcoda_setup_hint = None;
    if !model.delegation_ready {
        model.mcoda_reconciliation = McodaReconciliationStatus::NotApplicable;
        return;
    }

    let mut matches: Vec<&LocalAgentEntry> = agents
        .iter()
        .filter(|agent| local_agent_matches_service_model(service, model, agent))
        .collect();
    matches.sort_by(|left, right| compare_agent_matches(left, right));

    if let Some(agent) = matches
        .iter()
        .copied()
        .find(|agent| mcoda_agent_health_is_ready(agent.health_status.as_deref()))
    {
        model.mcoda_reconciliation = McodaReconciliationStatus::MatchingHealthyAgent;
        model.mcoda_agent_match = Some(local_agent_match(agent));
        return;
    }

    if let Some(agent) = matches.first().copied() {
        model.mcoda_reconciliation = McodaReconciliationStatus::MatchingUnhealthyAgent;
        model.mcoda_agent_match = Some(local_agent_match(agent));
        return;
    }

    model.mcoda_reconciliation = McodaReconciliationStatus::NoMatchingAgent;
    model.mcoda_setup_hint = Some(mcoda_setup_hint_for_model(service, model));
}

fn reconcile_services_with_mcoda_agents(
    services: &mut [LocalServiceEntry],
    agents: &[LocalAgentEntry],
) {
    for service in services {
        let service_context = LocalServiceEntry {
            models: Vec::new(),
            ..service.clone()
        };
        for model in &mut service.models {
            reconcile_service_model_with_mcoda_agents(&service_context, model, agents);
        }
    }
}

fn classification_method_counts(models: &[LocalModelEntry]) -> (usize, usize, usize, usize) {
    let mut known = 0;
    let mut heuristic = 0;
    let mut web = 0;
    let mut other = 0;
    for entry in models {
        match entry.classification_method.as_str() {
            "known_map" => known += 1,
            "heuristic" => heuristic += 1,
            "web" => web += 1,
            _ => other += 1,
        }
    }
    (known, heuristic, web, other)
}

fn is_web_candidate(capabilities: &[String]) -> bool {
    let has_chat =
        has_capability(capabilities, CAP_CHAT) || has_capability(capabilities, CAP_GENERAL_CHAT);
    let has_only_generic_chat = capabilities.iter().all(|cap| {
        cap.eq_ignore_ascii_case(CAP_CHAT) || cap.eq_ignore_ascii_case(CAP_GENERAL_CHAT)
    });
    has_chat && has_only_generic_chat
}

fn should_web_classify(existing: Option<&LocalModelEntry>, now_ms: u128) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    if existing.classification_method != "web" {
        return true;
    }
    let Some(last_ms) = existing.last_classified_at_ms else {
        return true;
    };
    now_ms.saturating_sub(last_ms) > web_classify_ttl().as_millis() as u128
}

fn is_candidate_capabilities(capabilities: &[String]) -> bool {
    if has_capability(capabilities, CAP_UNSUPPORTED_FOR_DELEGATION) {
        return false;
    }
    if capabilities.is_empty() {
        return true;
    }
    capabilities.iter().any(|cap| {
        cap == CAP_CODE
            || cap == CAP_CODE_WRITER
            || cap == CAP_CODE_REVIEWER
            || cap == CAP_CHAT
            || cap == CAP_GENERAL_CHAT
            || cap == CAP_REASONING
            || cap == CAP_TOOL_CAPABLE
    })
}

pub(crate) fn local_model_supports_legacy_ollama_target(entry: &LocalModelEntry) -> bool {
    let source = entry.source.trim();
    source.is_empty() || source.eq_ignore_ascii_case("ollama")
}

pub(crate) fn local_model_delegation_candidate(entry: &LocalModelEntry) -> bool {
    if !local_model_supports_legacy_ollama_target(entry) {
        return false;
    }
    if entry.delegation_ready {
        return true;
    }
    entry.delegation_readiness_reason.is_none()
        && !entry.capabilities.is_empty()
        && is_candidate_capabilities(&entry.capabilities)
}

pub(crate) fn local_model_execution_name(entry: &LocalModelEntry) -> String {
    entry
        .raw_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&entry.name)
        .to_string()
}

pub(crate) fn local_service_model_execution_name(entry: &LocalServiceModelEntry) -> String {
    entry
        .raw_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(&entry.name)
        .to_string()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalTargetFailureWindow {
    recent_failures: usize,
    last_failure_at_ms: u128,
}

#[derive(Debug, Deserialize)]
struct DelegationFailureHistoryLine {
    ts: String,
    kind: String,
    local_target: String,
    #[serde(default)]
    error: String,
}

fn blocking_failure_for_runtime_health(kind: &str, error: &str) -> bool {
    if kind == "local_completion_failed" {
        return true;
    }
    kind == "local_validation_failed"
        && !error
            .to_ascii_lowercase()
            .contains("delegation output must not include markdown fences")
}

fn ollama_failure_model(error: &str) -> Option<&str> {
    [
        "ollama generate failed for model ",
        "ollama generate request failed for model ",
    ]
    .iter()
    .find_map(|prefix| {
        error
            .strip_prefix(prefix)
            .and_then(|rest| rest.split(" at ").next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    })
}

fn failure_history_labels(local_target: &str, error: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let target = local_target.trim();
    if !target.is_empty() {
        labels.push(target.to_string());
        if let Some(model) = target.strip_prefix("model:") {
            let model = model.trim();
            if !model.is_empty() {
                labels.push(model.to_string());
            }
        }
    }
    if let Some(model) = ollama_failure_model(error) {
        labels.push(format!("model:{model}"));
        labels.push(model.to_string());
    }
    labels.sort();
    labels.dedup();
    labels
}

fn update_failure_window(
    failures: &mut HashMap<String, LocalTargetFailureWindow>,
    label: &str,
    failure_at_ms: u128,
) {
    let entry = failures.entry(label.to_string()).or_default();
    entry.recent_failures = entry.recent_failures.saturating_add(1);
    entry.last_failure_at_ms = entry.last_failure_at_ms.max(failure_at_ms);
}

fn local_target_failure_threshold() -> usize {
    env_u64(LOCAL_TARGET_FAILURE_THRESHOLD_ENV)
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_LOCAL_TARGET_FAILURE_THRESHOLD)
        .max(1)
}

fn local_target_failure_lookback() -> Duration {
    Duration::from_secs(
        env_u64(LOCAL_TARGET_FAILURE_LOOKBACK_ENV)
            .unwrap_or(DEFAULT_LOCAL_TARGET_FAILURE_LOOKBACK_SECS)
            .max(1),
    )
}

fn local_target_failure_cooldown() -> Duration {
    Duration::from_secs(
        env_u64(LOCAL_TARGET_FAILURE_COOLDOWN_ENV)
            .unwrap_or(DEFAULT_LOCAL_TARGET_FAILURE_COOLDOWN_SECS)
            .max(1),
    )
}

fn agent_recent_local_failure<'a>(
    agent: &McodaAgent,
    recent_failures: &'a HashMap<String, LocalTargetFailureWindow>,
) -> Option<&'a LocalTargetFailureWindow> {
    recent_failures
        .get(&format!("agent:{}", agent.id))
        .or_else(|| recent_failures.get(&format!("agent:{}", agent.slug)))
        .or_else(|| recent_failures.get(&agent.id))
        .or_else(|| recent_failures.get(&agent.slug))
        .or_else(|| {
            agent.default_model.as_deref().and_then(|model| {
                recent_failures
                    .get(&format!("model:{}", model.trim()))
                    .or_else(|| recent_failures.get(model.trim()))
            })
        })
}

fn usage_limit_window_ms(window_type: &str) -> u128 {
    match window_type.trim().to_ascii_lowercase().as_str() {
        "rolling_5h" => ROLLING_5H_WINDOW_MS,
        "daily" => DAILY_WINDOW_MS,
        "weekly" => WEEKLY_WINDOW_MS,
        _ => OTHER_WINDOW_MS,
    }
}

fn parse_timestamp_ms(value: Option<&str>) -> Option<u128> {
    let value = value?.trim();
    if value.is_empty() {
        return None;
    }
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|timestamp| timestamp.timestamp_millis().max(0) as u128)
}

fn usage_limit_reset_at_ms(limit: &McodaAgentUsageLimit) -> Option<u128> {
    parse_timestamp_ms(limit.reset_at.as_deref())
        .or_else(|| {
            limit
                .details
                .as_ref()
                .and_then(|details| details.get("estimatedResetAt"))
                .and_then(Value::as_str)
                .and_then(|value| parse_timestamp_ms(Some(value)))
        })
        .or_else(|| {
            parse_timestamp_ms(limit.observed_at.as_deref()).map(|observed_at_ms| {
                observed_at_ms.saturating_add(usage_limit_window_ms(&limit.window_type))
            })
        })
}

fn active_usage_limit<'a>(
    agent: &'a McodaAgent,
    now_ms: u128,
) -> Option<(&'a McodaAgentUsageLimit, Option<u128>)> {
    agent.usage_limits.iter().find_map(|limit| {
        if !limit.status.eq_ignore_ascii_case("exhausted") {
            return None;
        }
        let reset_at_ms = usage_limit_reset_at_ms(limit);
        match reset_at_ms {
            Some(reset_at_ms) if reset_at_ms <= now_ms => None,
            _ => Some((limit, reset_at_ms)),
        }
    })
}

fn usage_limit_note(limit: &McodaAgentUsageLimit, reset_at_ms: Option<u128>) -> String {
    let scope = format!("{}:{}", limit.limit_scope, limit.limit_key);
    match reset_at_ms {
        Some(reset_at_ms) => format!(
            "usage limit exhausted for {scope}; resets at {}",
            chrono::DateTime::<chrono::Utc>::from_timestamp_millis(reset_at_ms as i64)
                .map(|timestamp| timestamp.to_rfc3339())
                .unwrap_or_else(|| "unknown".to_string())
        ),
        None => format!("usage limit exhausted for {scope}"),
    }
}

fn mcoda_agent_health_allows(status: Option<&str>) -> bool {
    let Some(status) = status.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    status.eq_ignore_ascii_case("healthy")
        || status.eq_ignore_ascii_case("unknown")
        || status == "-"
}

fn mcoda_agent_health_is_ready(status: Option<&str>) -> bool {
    status
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value.eq_ignore_ascii_case("healthy"))
}

fn mcoda_agent_usage_implies_delegation(usage: Option<&str>) -> bool {
    let Some(usage) = usage.map(str::trim).filter(|value| !value.is_empty()) else {
        return false;
    };
    let normalized = usage.to_ascii_lowercase();
    key_contains_any(
        &normalized,
        &[
            "code", "writer", "review", "general", "chat", "question", "reason", "tool",
        ],
    )
}

fn mcoda_agent_has_nontrivial_rating(
    max_complexity: Option<i64>,
    rating: Option<f64>,
    reasoning_rating: Option<f64>,
) -> bool {
    let rating_ok = rating.is_some_and(|value| value.is_finite() && value >= 6.0);
    let reasoning_ok = reasoning_rating.is_some_and(|value| value.is_finite() && value >= 6.0);
    let complexity_ok = max_complexity.is_some_and(|value| value >= 3);
    rating_ok || reasoning_ok || complexity_ok
}

fn mcoda_agent_delegation_readiness(
    capabilities: &[String],
    usage: Option<&str>,
    health_status: Option<&str>,
    max_complexity: Option<i64>,
    rating: Option<f64>,
    reasoning_rating: Option<f64>,
) -> (bool, Option<String>) {
    if !mcoda_agent_health_is_ready(health_status) {
        return (false, Some("mcoda agent health is not healthy".to_string()));
    }
    if !((!capabilities.is_empty() && is_candidate_capabilities(capabilities))
        || mcoda_agent_usage_implies_delegation(usage))
    {
        return (
            false,
            Some("mcoda agent has no chat/code/reasoning/tool capability".to_string()),
        );
    }
    if !mcoda_agent_has_nontrivial_rating(max_complexity, rating, reasoning_rating) {
        return (
            false,
            Some(
                "mcoda agent has no non-trivial rating, reasoning rating, or complexity"
                    .to_string(),
            ),
        );
    }
    (
        true,
        Some("healthy mcoda agent with non-trivial capability rating".to_string()),
    )
}

pub(crate) fn local_agent_delegation_candidate(entry: &LocalAgentEntry) -> bool {
    if entry.delegation_ready {
        return true;
    }
    entry.delegation_readiness_reason.is_none()
        && mcoda_agent_health_allows(entry.health_status.as_deref())
        && ((!entry.capabilities.is_empty() && is_candidate_capabilities(&entry.capabilities))
            || mcoda_agent_usage_implies_delegation(entry.usage.as_deref()))
}

fn load_recent_local_target_failures(
    state_dir_override: Option<&Path>,
) -> HashMap<String, LocalTargetFailureWindow> {
    let Ok(root) = resolve_state_root(state_dir_override) else {
        return HashMap::new();
    };
    let path = root
        .join("logs")
        .join(DELEGATION_FAILURE_HISTORY_DIR)
        .join(DELEGATION_FAILURE_HISTORY_FILE);
    if !path.exists() {
        return HashMap::new();
    }
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                path = %path.display(),
                "failed to open delegation failure history for runtime health overlay"
            );
            return HashMap::new();
        }
    };
    let now_ms = now_ms();
    let lookback_ms = local_target_failure_lookback().as_millis() as u128;
    let cooldown_ms = local_target_failure_cooldown().as_millis() as u128;
    let threshold = local_target_failure_threshold();
    let mut failures: HashMap<String, LocalTargetFailureWindow> = HashMap::new();
    for line in BufReader::new(file)
        .lines()
        .map_while(std::result::Result::ok)
    {
        let Ok(record) = serde_json::from_str::<DelegationFailureHistoryLine>(&line) else {
            continue;
        };
        if !blocking_failure_for_runtime_health(&record.kind, &record.error) {
            continue;
        }
        let target = record.local_target.trim();
        if target.is_empty() {
            continue;
        }
        let Ok(ts) = chrono::DateTime::parse_from_rfc3339(record.ts.trim()) else {
            continue;
        };
        let failure_at_ms = ts.timestamp_millis().max(0) as u128;
        if now_ms.saturating_sub(failure_at_ms) > lookback_ms {
            continue;
        }
        for label in failure_history_labels(target, &record.error) {
            update_failure_window(&mut failures, &label, failure_at_ms);
        }
    }
    failures.retain(|_, window| {
        window.recent_failures >= threshold
            && window.last_failure_at_ms.saturating_add(cooldown_ms) > now_ms
    });
    failures
}

fn mcoda_agent_entry(
    agent: &McodaAgent,
    llm_config: &LlmConfig,
    now_ms: u128,
    recent_failures: Option<&HashMap<String, LocalTargetFailureWindow>>,
) -> LocalAgentEntry {
    let max_complexity = agent.max_complexity.filter(|value| *value >= 0);
    let usage = agent
        .best_usage
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let mut health_status = agent
        .health_status
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let source = if managed_mswarm_cloud_agent(agent) {
        LOCAL_AGENT_SOURCE_MCODA_CLOUD.to_string()
    } else {
        LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string()
    };
    let mut notes = None;
    if let Some((limit, reset_at_ms)) = active_usage_limit(agent, now_ms) {
        notes = Some(usage_limit_note(limit, reset_at_ms));
        health_status = Some("limited".to_string());
    }
    if let Some(failure) =
        recent_failures.and_then(|failures| agent_recent_local_failure(agent, failures))
    {
        let failure_note = format!(
            "recent local delegation failures: {} (cooldown active)",
            failure.recent_failures
        );
        notes = Some(match notes.take() {
            Some(existing) => format!("{existing}; {failure_note}"),
            None => failure_note,
        });
        if mcoda_agent_health_allows(health_status.as_deref()) {
            health_status = Some("degraded".to_string());
        }
    }
    let capabilities = normalize_agent_capabilities(&agent.adapter, &agent.capabilities);
    let model_names = mcoda_agent_model_names(agent);
    let base_url = mcoda_agent_base_url(agent, llm_config);
    let runner_kind = mcoda_agent_runner_kind(agent);
    let (delegation_ready, delegation_readiness_reason) = mcoda_agent_delegation_readiness(
        &capabilities,
        usage.as_deref(),
        health_status.as_deref(),
        max_complexity,
        agent.rating,
        agent.reasoning_rating,
    );
    LocalAgentEntry {
        agent_id: agent.id.clone(),
        agent_slug: agent.slug.clone(),
        source,
        adapter: agent.adapter.clone(),
        default_model: agent.default_model.clone(),
        model_names,
        base_url,
        runner_kind,
        max_complexity,
        rating: agent.rating,
        cost_per_million: agent.cost_per_million,
        usage,
        reasoning_rating: agent.reasoning_rating,
        health_status,
        capabilities,
        delegation_ready,
        delegation_readiness_reason,
        notes,
        classification_method: "registry".to_string(),
        last_seen_at_ms: now_ms,
        last_classified_at_ms: None,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host == "0.0.0.0" || host == "::1" {
        return true;
    }
    if host.starts_with("127.") {
        return true;
    }
    false
}

fn backup_corrupt_library(path: &Path) {
    let backup_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => format!("{}.corrupt-{}", name, now_ms()),
        None => format!("local_model_library.json.corrupt-{}", now_ms()),
    };
    let backup = path.with_file_name(backup_name);
    if let Err(err) = fs::rename(path, &backup) {
        warn!(
            target: "docdexd",
            error = ?err,
            path = %path.display(),
            backup = %backup.display(),
            "failed to back up corrupt local model library"
        );
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcoda::registry::McodaAgentModel;
    use crate::setup::test_support::ENV_LOCK;
    use rusqlite::{params, Connection};
    use std::fs;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.prev.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn test_service_model(
        name: &str,
        capabilities: &[&str],
        delegation_ready: bool,
    ) -> LocalServiceModelEntry {
        let capabilities: Vec<String> =
            capabilities.iter().map(|value| value.to_string()).collect();
        LocalServiceModelEntry {
            name: normalize_model_name(name),
            raw_name: Some(name.to_string()),
            capability_flags: capability_flags_from_caps(&capabilities),
            capabilities,
            delegation_ready,
            delegation_readiness_reason: delegation_ready
                .then(|| "healthy service with non-embedding chat/code-capable model".to_string()),
            ..LocalServiceModelEntry::default()
        }
    }

    fn test_legacy_model(
        name: &str,
        source: &str,
        capabilities: &[&str],
        delegation_ready: bool,
    ) -> LocalModelEntry {
        let capabilities: Vec<String> =
            capabilities.iter().map(|value| value.to_string()).collect();
        LocalModelEntry {
            name: normalize_model_name(name),
            raw_name: Some(name.to_string()),
            source: source.to_string(),
            capability_flags: capability_flags_from_caps(&capabilities),
            capabilities,
            delegation_ready,
            delegation_readiness_reason: delegation_ready
                .then(|| "healthy legacy Ollama delegation model".to_string()),
            last_seen_at_ms: 1,
            classification_method: "test".to_string(),
            ..LocalModelEntry::default()
        }
    }

    fn test_service(
        provider: LocalLlmProvider,
        base_url: &str,
        health: LocalServiceHealth,
        models: Vec<LocalServiceModelEntry>,
    ) -> LocalServiceEntry {
        LocalServiceEntry {
            service_id: format!("{}:{base_url}", provider.as_str()),
            provider,
            source_type: LocalLibrarySourceType::LocalProcess,
            base_url: Some(base_url.to_string()),
            health,
            capability_flags: aggregate_capability_flags(&models),
            models,
            last_seen_at_ms: 1,
            ..LocalServiceEntry::default()
        }
    }

    fn test_agent(
        agent_id: &str,
        source: &str,
        adapter: &str,
        default_model: Option<&str>,
        base_url: Option<&str>,
        capabilities: &[&str],
        cost_per_million: Option<f64>,
        health_status: Option<&str>,
        usage: Option<&str>,
    ) -> LocalAgentEntry {
        let capabilities: Vec<String> =
            capabilities.iter().map(|value| value.to_string()).collect();
        let delegation_ready = health_status
            .is_some_and(|status| status.eq_ignore_ascii_case("healthy"))
            && (!capabilities.is_empty() || usage.is_some());
        LocalAgentEntry {
            agent_id: agent_id.to_string(),
            agent_slug: agent_id.to_string(),
            source: source.to_string(),
            adapter: adapter.to_string(),
            default_model: default_model.map(ToOwned::to_owned),
            base_url: base_url.map(ToOwned::to_owned),
            runner_kind: Some(adapter.to_string()),
            max_complexity: Some(7),
            rating: Some(8.0),
            cost_per_million,
            usage: usage.map(ToOwned::to_owned),
            reasoning_rating: Some(8.0),
            health_status: health_status.map(ToOwned::to_owned),
            capabilities,
            delegation_ready,
            delegation_readiness_reason: delegation_ready
                .then(|| "healthy mcoda agent with non-trivial capability rating".to_string()),
            last_seen_at_ms: 1,
            classification_method: "test".to_string(),
            ..LocalAgentEntry::default()
        }
    }

    #[test]
    fn local_model_library_default_sets_schema_version() {
        assert_eq!(LocalModelLibrary::default().version, LIBRARY_VERSION);
    }

    #[test]
    fn local_library_roundtrip() -> Result<()> {
        let dir = TempDir::new()?;
        let library = LocalModelLibrary {
            updated_at_ms: 42,
            services: vec![LocalServiceEntry {
                service_id: "ollama:http://127.0.0.1:11434".to_string(),
                provider: LocalLlmProvider::Ollama,
                source_type: LocalLibrarySourceType::LocalProcess,
                display_name: Some("Ollama".to_string()),
                base_url: Some("http://127.0.0.1:11434".to_string()),
                endpoints: vec![LocalServiceEndpoint {
                    base_url: Some("http://127.0.0.1:11434".to_string()),
                    models_url: Some("http://127.0.0.1:11434/api/tags".to_string()),
                    ..LocalServiceEndpoint::default()
                }],
                health: LocalServiceHealth::Healthy,
                models: vec![LocalServiceModelEntry {
                    name: "phi3.5:3.8b".to_string(),
                    capabilities: vec!["code_writer".to_string()],
                    capability_flags: LocalCapabilityFlags {
                        chat: true,
                        delegation: true,
                        code: true,
                        ..LocalCapabilityFlags::default()
                    },
                    mcoda_reconciliation: McodaReconciliationStatus::Unknown,
                    ..LocalServiceModelEntry::default()
                }],
                capability_flags: LocalCapabilityFlags {
                    chat: true,
                    delegation: true,
                    code: true,
                    ..LocalCapabilityFlags::default()
                },
                last_seen_at_ms: 5,
                ..LocalServiceEntry::default()
            }],
            models: vec![LocalModelEntry {
                name: "phi3.5:3.8b".to_string(),
                source: "ollama".to_string(),
                capabilities: vec!["code_writer".to_string()],
                notes: Some("test".to_string()),
                classification_method: "known_map".to_string(),
                last_seen_at_ms: 1,
                last_classified_at_ms: Some(2),
                ..LocalModelEntry::default()
            }],
            agents: vec![LocalAgentEntry {
                agent_id: "agent-1".to_string(),
                agent_slug: "agent-one".to_string(),
                source: LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string(),
                adapter: "ollama".to_string(),
                default_model: Some("phi3.5".to_string()),
                max_complexity: Some(3),
                rating: Some(9.1),
                cost_per_million: Some(1.2),
                usage: Some("code_reviewer".to_string()),
                reasoning_rating: Some(7.4),
                health_status: Some("healthy".to_string()),
                capabilities: vec!["code_reviewer".to_string()],
                notes: None,
                classification_method: "heuristic".to_string(),
                last_seen_at_ms: 3,
                last_classified_at_ms: None,
                ..LocalAgentEntry::default()
            }],
            cached_local_agent_selection: Some(CachedLocalAgentSelection {
                policy: "mcoda_zero_cost_most_capable".to_string(),
                agent_id: "agent-1".to_string(),
                agent_slug: "agent-one".to_string(),
                task_kind: Some("code".to_string()),
                selected_at_ms: 4,
            }),
            ..LocalModelLibrary::default()
        };
        save_local_library(Some(dir.path()), &library)?;
        let loaded = load_local_library(Some(dir.path()))?;
        assert_eq!(loaded.updated_at_ms, 42);
        assert_eq!(loaded.services.len(), 1);
        assert_eq!(loaded.services[0].provider, LocalLlmProvider::Ollama);
        assert!(loaded.services[0].capability_flags.delegation);
        assert_eq!(loaded.services[0].models.len(), 1);
        assert_eq!(loaded.models.len(), 1);
        assert_eq!(loaded.agents.len(), 1);
        let cached = loaded
            .cached_local_agent_selection
            .as_ref()
            .expect("cached selection");
        assert_eq!(cached.agent_id, "agent-1");
        assert_eq!(cached.agent_slug, "agent-one");
        Ok(())
    }

    #[test]
    fn default_selection_prefers_valid_configured_embedding() {
        let mut config = LlmConfig::default();
        config.embedding_model = "bge-m3".to_string();
        let library = LocalModelLibrary {
            services: vec![
                test_service(
                    LocalLlmProvider::Vllm,
                    "http://127.0.0.1:8000",
                    LocalServiceHealth::Healthy,
                    vec![test_service_model("bge-m3", &[CAP_EMBEDDING], false)],
                ),
                test_service(
                    LocalLlmProvider::Ollama,
                    "http://127.0.0.1:11434",
                    LocalServiceHealth::Healthy,
                    vec![test_service_model(
                        "nomic-embed-text:latest",
                        &[CAP_EMBEDDING],
                        false,
                    )],
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        let selected = defaults
            .embedding
            .selected
            .as_ref()
            .expect("embedding default");
        assert_eq!(
            selected.kind,
            LocalDefaultCandidateKind::ConfiguredEmbedding
        );
        assert_eq!(selected.provider, Some(LocalLlmProvider::Vllm));
        assert_eq!(selected.model.as_deref(), Some("bge-m3"));
        assert!(selected.explicit);
    }

    #[test]
    fn default_selection_uses_installed_ollama_nomic_after_embedding_candidates() {
        let mut config = LlmConfig::default();
        config.embedding_model.clear();
        let library = LocalModelLibrary {
            services: vec![test_service(
                LocalLlmProvider::Ollama,
                "http://127.0.0.1:11434",
                LocalServiceHealth::Healthy,
                vec![test_service_model(
                    "nomic-embed-text:latest",
                    &[CAP_EMBEDDING],
                    false,
                )],
            )],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        let selected = defaults
            .embedding
            .selected
            .as_ref()
            .expect("embedding default");
        assert_eq!(
            selected.kind,
            LocalDefaultCandidateKind::OllamaInstalledModel
        );
        assert_eq!(selected.provider, Some(LocalLlmProvider::Ollama));
        assert_eq!(
            selected.raw_model.as_deref(),
            Some("nomic-embed-text:latest")
        );
    }

    #[test]
    fn default_selection_prefers_zero_cost_local_mcoda_for_delegation() {
        let library = LocalModelLibrary {
            services: vec![test_service(
                LocalLlmProvider::LlamaCpp,
                "http://127.0.0.1:8080",
                LocalServiceHealth::Healthy,
                vec![test_service_model(
                    "qwen3.6-coder",
                    &[CAP_CHAT, CAP_CODE, CAP_REASONING],
                    true,
                )],
            )],
            agents: vec![test_agent(
                "qwen-local",
                LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                "llama-cpp",
                Some("qwen3.6-coder"),
                Some("http://127.0.0.1:8080"),
                &[CAP_CODE_WRITER, CAP_REASONING],
                Some(0.0),
                Some("healthy"),
                Some("code_writer"),
            )],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &LlmConfig::default());
        let selected = defaults
            .delegation
            .selected
            .as_ref()
            .expect("delegation default");
        assert_eq!(selected.kind, LocalDefaultCandidateKind::McodaLocalAgent);
        assert_eq!(selected.agent_id.as_deref(), Some("qwen-local"));
    }

    #[test]
    fn default_selection_prefers_non_ollama_service_before_ollama_fallback() {
        let library = LocalModelLibrary {
            services: vec![
                test_service(
                    LocalLlmProvider::LlamaCpp,
                    "http://127.0.0.1:8080",
                    LocalServiceHealth::Healthy,
                    vec![test_service_model(
                        "qwen3.6-coder",
                        &[CAP_CHAT, CAP_CODE, CAP_REASONING],
                        true,
                    )],
                ),
                test_service(
                    LocalLlmProvider::Ollama,
                    "http://127.0.0.1:11434",
                    LocalServiceHealth::Healthy,
                    vec![test_service_model(
                        FALLBACK_DELEGATION_MODEL,
                        &[CAP_CHAT, CAP_CODE],
                        true,
                    )],
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &LlmConfig::default());
        let selected = defaults
            .delegation
            .selected
            .as_ref()
            .expect("delegation default");
        assert_eq!(selected.kind, LocalDefaultCandidateKind::LocalServiceModel);
        assert_eq!(selected.provider, Some(LocalLlmProvider::LlamaCpp));
        assert_eq!(selected.model.as_deref(), Some("qwen3.6-coder"));
    }

    #[test]
    fn default_selection_skips_paid_cloud_degraded_and_remote_without_config() {
        let mut config = LlmConfig::default();
        config.delegation.cloud.enabled = false;
        let library = LocalModelLibrary {
            services: vec![test_service(
                LocalLlmProvider::Ollama,
                "http://127.0.0.1:11434",
                LocalServiceHealth::Healthy,
                vec![test_service_model(
                    FALLBACK_DELEGATION_MODEL,
                    &[CAP_CHAT, CAP_CODE],
                    true,
                )],
            )],
            agents: vec![
                test_agent(
                    "paid-local",
                    LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                    "ollama",
                    Some("qwen-paid"),
                    Some("http://127.0.0.1:11434"),
                    &[CAP_CODE_WRITER],
                    Some(1.0),
                    Some("healthy"),
                    Some("code_writer"),
                ),
                test_agent(
                    "cloud-free",
                    LOCAL_AGENT_SOURCE_MCODA_CLOUD,
                    "openai-api",
                    Some("qwen-cloud"),
                    None,
                    &[CAP_CODE_WRITER],
                    Some(0.0),
                    Some("healthy"),
                    Some("code_writer"),
                ),
                test_agent(
                    "degraded-local",
                    LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                    "ollama",
                    Some("qwen-degraded"),
                    Some("http://127.0.0.1:11434"),
                    &[CAP_CODE_WRITER],
                    Some(0.0),
                    Some("degraded"),
                    Some("code_writer"),
                ),
                test_agent(
                    "remote-local",
                    LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                    "llama-cpp",
                    Some("qwen-remote"),
                    Some("http://10.0.0.2:8080"),
                    &[CAP_CODE_WRITER],
                    Some(0.0),
                    Some("healthy"),
                    Some("code_writer"),
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        let selected = defaults
            .delegation
            .selected
            .as_ref()
            .expect("delegation default");
        assert_eq!(
            selected.kind,
            LocalDefaultCandidateKind::OllamaInstalledModel
        );
        assert_eq!(selected.provider, Some(LocalLlmProvider::Ollama));
    }

    #[test]
    fn default_selection_allows_explicit_remote_paid_agent() {
        let mut config = LlmConfig::default();
        config.delegation.local_agent_id = "remote-qwen".to_string();
        let library = LocalModelLibrary {
            agents: vec![test_agent(
                "remote-qwen",
                LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                "llama-cpp",
                Some("qwen3.6-coder"),
                Some("https://self-hosted.example.test/v1"),
                &[CAP_CODE_WRITER, CAP_REASONING],
                Some(2.0),
                Some("healthy"),
                Some("code_writer"),
            )],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        let selected = defaults
            .delegation
            .selected
            .as_ref()
            .expect("delegation default");
        assert_eq!(
            selected.kind,
            LocalDefaultCandidateKind::ConfiguredDelegation
        );
        assert_eq!(selected.agent_id.as_deref(), Some("remote-qwen"));
        assert_eq!(
            selected.source_type,
            Some(LocalLibrarySourceType::McodaRemoteAgent)
        );
        assert!(selected.explicit);
    }

    #[test]
    fn default_selection_skips_configured_unusable_delegation_model_names() {
        let mut config = LlmConfig::default();
        config.delegation.code.local_agent_id = "model:qwen3.6-coder".to_string();
        config.delegation.general.local_agent_id = "model:nomic-embed-text".to_string();
        let library = LocalModelLibrary {
            services: vec![
                test_service(
                    LocalLlmProvider::LlamaCpp,
                    "http://127.0.0.1:8080",
                    LocalServiceHealth::Unavailable,
                    vec![test_service_model(
                        "qwen3.6-coder",
                        &[CAP_CHAT, CAP_CODE, CAP_REASONING],
                        true,
                    )],
                ),
                test_service(
                    LocalLlmProvider::Vllm,
                    "http://127.0.0.1:8000",
                    LocalServiceHealth::Healthy,
                    vec![test_service_model(
                        "nomic-embed-text",
                        &[CAP_EMBEDDING, CAP_UNSUPPORTED_FOR_DELEGATION],
                        false,
                    )],
                ),
                test_service(
                    LocalLlmProvider::Ollama,
                    "http://127.0.0.1:11434",
                    LocalServiceHealth::Healthy,
                    vec![test_service_model(
                        FALLBACK_DELEGATION_MODEL,
                        &[CAP_CHAT, CAP_CODE],
                        true,
                    )],
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        assert!(!defaults
            .delegation
            .candidates
            .iter()
            .any(|candidate| candidate.kind == LocalDefaultCandidateKind::ConfiguredDelegation));
        let selected = defaults
            .delegation
            .selected
            .as_ref()
            .expect("delegation default");
        assert_eq!(
            selected.kind,
            LocalDefaultCandidateKind::OllamaInstalledModel
        );
        assert_eq!(selected.model.as_deref(), Some(FALLBACK_DELEGATION_MODEL));
    }

    #[test]
    fn default_selection_does_not_treat_non_ollama_legacy_models_as_ollama_fallback() {
        let mut config = LlmConfig::default();
        config.embedding_model.clear();
        let library = LocalModelLibrary {
            models: vec![
                test_legacy_model("nomic-embed-text:latest", "vllm", &[CAP_EMBEDDING], false),
                test_legacy_model(
                    FALLBACK_DELEGATION_MODEL,
                    "llama-cpp",
                    &[CAP_CHAT, CAP_CODE],
                    true,
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        assert_eq!(
            defaults
                .embedding
                .selected
                .as_ref()
                .map(|candidate| &candidate.kind),
            Some(&LocalDefaultCandidateKind::OllamaSetupFallback)
        );
        assert_eq!(
            defaults
                .delegation
                .selected
                .as_ref()
                .map(|candidate| &candidate.kind),
            Some(&LocalDefaultCandidateKind::OllamaSetupFallback)
        );
    }

    #[test]
    fn default_selection_keeps_ollama_legacy_models_as_fallback() {
        let mut config = LlmConfig::default();
        config.embedding_model.clear();
        let library = LocalModelLibrary {
            models: vec![
                test_legacy_model("nomic-embed-text:latest", "ollama", &[CAP_EMBEDDING], false),
                test_legacy_model(
                    FALLBACK_DELEGATION_MODEL,
                    "ollama",
                    &[CAP_CHAT, CAP_CODE],
                    true,
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let defaults = resolve_local_default_selection(&library, &config);
        assert_eq!(
            defaults
                .embedding
                .selected
                .as_ref()
                .map(|candidate| &candidate.kind),
            Some(&LocalDefaultCandidateKind::OllamaInstalledModel)
        );
        assert_eq!(
            defaults
                .delegation
                .selected
                .as_ref()
                .map(|candidate| &candidate.kind),
            Some(&LocalDefaultCandidateKind::OllamaInstalledModel)
        );
    }

    #[test]
    fn default_selection_offers_ollama_setup_when_empty() {
        let mut config = LlmConfig::default();
        config.embedding_model.clear();
        let defaults = resolve_local_default_selection(&LocalModelLibrary::default(), &config);

        let embedding = defaults
            .embedding
            .selected
            .as_ref()
            .expect("embedding setup default");
        assert_eq!(
            embedding.kind,
            LocalDefaultCandidateKind::OllamaSetupFallback
        );
        assert_eq!(embedding.model.as_deref(), Some(FALLBACK_EMBEDDING_MODEL));
        assert!(defaults.embedding.setup_hint.is_some());

        let delegation = defaults
            .delegation
            .selected
            .as_ref()
            .expect("delegation setup default");
        assert_eq!(
            delegation.kind,
            LocalDefaultCandidateKind::OllamaSetupFallback
        );
        assert_eq!(delegation.model.as_deref(), Some(FALLBACK_DELEGATION_MODEL));
        assert!(defaults.delegation.setup_hint.is_some());
    }

    #[test]
    fn diagnostics_reports_installed_agent_embedding_and_selection_statuses() {
        let library = LocalModelLibrary {
            updated_at_ms: now_ms(),
            services: vec![
                test_service(
                    LocalLlmProvider::LlamaCpp,
                    "http://127.0.0.1:8080",
                    LocalServiceHealth::Healthy,
                    vec![
                        test_service_model(
                            "qwen3.6-coder",
                            &[CAP_CODE_WRITER, CAP_REASONING],
                            true,
                        ),
                        test_service_model("nomic-embed-text", &[CAP_EMBEDDING], false),
                        test_service_model("qwen-vl", &[CAP_VISION], false),
                    ],
                ),
                test_service(
                    LocalLlmProvider::Vllm,
                    "http://127.0.0.1:8000",
                    LocalServiceHealth::Unavailable,
                    Vec::new(),
                ),
            ],
            agents: vec![
                test_agent(
                    "qwen-local",
                    LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                    "llama-cpp",
                    Some("qwen3.6-coder"),
                    Some("http://127.0.0.1:8080"),
                    &[CAP_CODE_WRITER],
                    Some(0.0),
                    Some("healthy"),
                    Some("code_writer"),
                ),
                test_agent(
                    "broken-local",
                    LOCAL_AGENT_SOURCE_MCODA_LOCAL,
                    "llama-cpp",
                    Some("qwen3.6-coder"),
                    Some("http://127.0.0.1:8081"),
                    &[CAP_CODE_WRITER],
                    Some(0.0),
                    Some("unhealthy"),
                    Some("code_writer"),
                ),
            ],
            ..LocalModelLibrary::default()
        };

        let diagnostics = local_library_diagnostics(&library, &LlmConfig::default());
        let codes: Vec<&str> = diagnostics
            .status_messages
            .iter()
            .map(|message| message.code.as_str())
            .collect();

        assert!(codes.contains(&"installed_model_found"));
        assert!(codes.contains(&"local_service_unavailable"));
        assert!(codes.contains(&"model_skipped"));
        assert!(codes.contains(&"existing_mcoda_agent_found"));
        assert!(codes.contains(&"unhealthy_mcoda_agent"));
        assert!(codes.contains(&"embedding_model_selected"));
        assert!(codes.contains(&"delegation_model_selected"));
        assert!(!codes.contains(&"fallback_setup_needed"));
    }

    #[test]
    fn diagnostics_reports_fallback_setup_when_no_services_or_agents_exist() {
        let mut config = LlmConfig::default();
        config.embedding_model.clear();
        let diagnostics = local_library_diagnostics(&LocalModelLibrary::default(), &config);
        let fallback_count = diagnostics
            .status_messages
            .iter()
            .filter(|message| message.code == "fallback_setup_needed")
            .count();

        assert_eq!(fallback_count, 2);
        assert_eq!(
            diagnostics
                .defaults
                .delegation
                .selected
                .as_ref()
                .map(|candidate| &candidate.kind),
            Some(&LocalDefaultCandidateKind::OllamaSetupFallback)
        );
    }

    #[test]
    fn current_machine_fixture_roundtrips_provider_neutral_detection_shape() {
        let report: LocalServiceDetectionReport = serde_json::from_str(include_str!(
            "../../tests/fixtures/local_llm_current_machine.json"
        ))
        .expect("fixture should deserialize");
        assert_eq!(report.library.services.len(), 1);

        let ollama = &report.library.services[0];
        assert_eq!(ollama.provider, LocalLlmProvider::Ollama);
        assert_eq!(ollama.health, LocalServiceHealth::Healthy);
        let service_models: Vec<&str> = ollama
            .models
            .iter()
            .map(|model| model.name.as_str())
            .collect();
        assert!(service_models.contains(&"nomic-embed-text:latest"));
        assert!(service_models.contains(&"phi3.5:3.8b"));
        assert!(service_models.contains(&"phi3.5:latest"));
        assert!(service_models.contains(&"llama3.1:8b"));
        assert!(!service_models
            .iter()
            .any(|model| model.to_ascii_lowercase().contains("qwen3.6")));

        assert!(report.probes.iter().any(|probe| {
            probe.provider == LocalLlmProvider::Vllm
                && probe.health == LocalServiceHealth::Unavailable
                && probe.found_binaries.is_empty()
        }));
        assert!(report.probes.iter().any(|probe| {
            probe.provider == LocalLlmProvider::LlamaCpp
                && probe.health == LocalServiceHealth::Unavailable
                && probe.found_binaries.is_empty()
        }));

        let phi_agent = report
            .library
            .agents
            .iter()
            .find(|agent| agent.agent_slug == "phi3-reviewer")
            .expect("phi3 reviewer fixture agent");
        assert_eq!(phi_agent.health_status.as_deref(), Some("healthy"));
        assert_eq!(phi_agent.cost_per_million, Some(0.0));
        assert!(phi_agent.delegation_ready);

        let remote_qwen = report
            .library
            .agents
            .iter()
            .find(|agent| agent.agent_slug == "local-qwen-unreachable")
            .expect("unreachable qwen fixture agent");
        assert_eq!(remote_qwen.health_status.as_deref(), Some("unreachable"));
        assert!(!remote_qwen.delegation_ready);

        assert_eq!(
            report
                .library
                .defaults
                .embedding
                .selected
                .as_ref()
                .and_then(|candidate| candidate.model.as_deref()),
            Some("nomic-embed-text:latest")
        );
        assert_eq!(
            report
                .library
                .defaults
                .delegation
                .selected
                .as_ref()
                .and_then(|candidate| candidate.agent_slug.as_deref()),
            Some("phi3-reviewer")
        );
    }

    #[test]
    fn provider_and_source_type_serialize_exact_contract_names() -> Result<()> {
        let providers = [
            (LocalLlmProvider::Ollama, "ollama", "ollama"),
            (LocalLlmProvider::Vllm, "vllm", "vllm"),
            (LocalLlmProvider::LlamaCpp, "llama-cpp", "llama-cpp"),
            (
                LocalLlmProvider::LlamaCppPython,
                "llama-cpp-python",
                "llama-cpp-python",
            ),
            (LocalLlmProvider::LmStudio, "lm-studio", "lm-studio"),
            (LocalLlmProvider::LocalAi, "localai", "localai"),
            (LocalLlmProvider::Sglang, "sglang", "sglang"),
            (LocalLlmProvider::Tgi, "tgi", "tgi"),
            (
                LocalLlmProvider::CustomOpenAiCompatible,
                "custom-openai-compatible",
                "custom",
            ),
        ];
        for (provider, serialized, mcoda_runner_kind) in providers {
            assert_eq!(provider.as_str(), serialized);
            assert_eq!(provider.mcoda_runner_kind(), mcoda_runner_kind);
            assert_eq!(
                serde_json::to_value(&provider)?,
                serde_json::json!(serialized)
            );
        }

        let source_types = [
            (LocalLibrarySourceType::LocalProcess, "local_process"),
            (LocalLibrarySourceType::LocalConfig, "local_config"),
            (LocalLibrarySourceType::McodaLocalAgent, "mcoda_local_agent"),
            (
                LocalLibrarySourceType::McodaRemoteAgent,
                "mcoda_remote_agent",
            ),
            (LocalLibrarySourceType::McodaCloudAgent, "mcoda_cloud_agent"),
            (
                LocalLibrarySourceType::InstallerFallback,
                "installer_fallback",
            ),
        ];
        for (source_type, serialized) in source_types {
            assert_eq!(
                serde_json::to_value(source_type)?,
                serde_json::json!(serialized)
            );
        }

        let health_states = [
            (LocalServiceHealth::Unknown, "unknown"),
            (LocalServiceHealth::Healthy, "healthy"),
            (LocalServiceHealth::Degraded, "degraded"),
            (LocalServiceHealth::Unavailable, "unavailable"),
        ];
        for (health, serialized) in health_states {
            assert_eq!(serde_json::to_value(health)?, serde_json::json!(serialized));
        }

        let reconciliations = [
            (McodaReconciliationStatus::Unknown, "unknown"),
            (
                McodaReconciliationStatus::MatchingHealthyAgent,
                "matching_healthy_agent",
            ),
            (
                McodaReconciliationStatus::MatchingUnhealthyAgent,
                "matching_unhealthy_agent",
            ),
            (
                McodaReconciliationStatus::NoMatchingAgent,
                "no_matching_agent",
            ),
            (McodaReconciliationStatus::NotApplicable, "not_applicable"),
        ];
        for (reconciliation, serialized) in reconciliations {
            assert_eq!(
                serde_json::to_value(reconciliation)?,
                serde_json::json!(serialized)
            );
        }
        Ok(())
    }

    #[test]
    fn provider_contract_maps_mcoda_runner_kind_aliases() {
        assert_eq!(
            LocalLlmProvider::from_mcoda_runner_kind("vllm-local"),
            Some(LocalLlmProvider::Vllm)
        );
        assert_eq!(
            LocalLlmProvider::from_mcoda_runner_kind("llamacpp-local"),
            Some(LocalLlmProvider::LlamaCpp)
        );
        assert_eq!(
            LocalLlmProvider::from_mcoda_runner_kind("llama_cpp_python"),
            Some(LocalLlmProvider::LlamaCppPython)
        );
        assert_eq!(
            LocalLlmProvider::from_mcoda_runner_kind("openai-compatible-local"),
            Some(LocalLlmProvider::CustomOpenAiCompatible)
        );
        assert_eq!(LocalLlmProvider::from_mcoda_runner_kind("unknown"), None);
        assert!(!LocalLlmProvider::Ollama.is_openai_compatible());
        assert!(LocalLlmProvider::Vllm.is_openai_compatible());
    }

    #[test]
    fn local_http_base_url_accepts_only_loopback_http() {
        assert!(is_local_http_base_url("http://127.0.0.1:8000"));
        assert!(is_local_http_base_url("http://localhost:8000"));
        assert!(is_local_http_base_url("http://[::1]:8000"));
        assert!(!is_local_http_base_url("https://127.0.0.1:8000"));
        assert!(!is_local_http_base_url("http://192.168.1.10:8000"));
        assert!(!is_local_http_base_url("http://example.com:8000"));
        assert_eq!(
            canonical_match_base_url(&LocalLlmProvider::Ollama, "http://localhost:11434"),
            "http://127.0.0.1:11434"
        );
        assert_eq!(
            canonical_match_base_url(&LocalLlmProvider::Vllm, "http://localhost:8000/v1/"),
            "http://127.0.0.1:8000"
        );
    }

    #[test]
    fn configured_provider_base_urls_are_local_only() {
        let provider = LocalLlmProvider::Vllm;
        let mut config = LlmConfig {
            provider: "vllm".to_string(),
            base_url: "http://192.168.1.10:8000".to_string(),
            ..LlmConfig::default()
        };

        assert!(configured_base_urls_for_provider(&provider, &config).is_empty());

        config.base_url = "http://localhost:8000".to_string();
        assert_eq!(
            configured_base_urls_for_provider(&provider, &config),
            vec!["http://localhost:8000".to_string()]
        );
    }

    #[test]
    fn openai_compatible_service_endpoints_use_provider_health_urls() {
        let localai = openai_compatible_service_endpoints(
            &LocalLlmProvider::LocalAi,
            "http://127.0.0.1:8080/",
        );
        assert_eq!(
            localai[0].health_url.as_deref(),
            Some("http://127.0.0.1:8080/readyz")
        );
        assert_eq!(
            localai[0].models_url.as_deref(),
            Some("http://127.0.0.1:8080/v1/models")
        );

        let sglang = openai_compatible_service_endpoints(
            &LocalLlmProvider::Sglang,
            "http://127.0.0.1:30000",
        );
        assert_eq!(
            sglang[0].health_url.as_deref(),
            Some("http://127.0.0.1:30000/health")
        );

        let lm_studio = openai_compatible_service_endpoints(
            &LocalLlmProvider::LmStudio,
            "http://127.0.0.1:1234",
        );
        assert_eq!(
            lm_studio[0].health_url.as_deref(),
            Some("http://127.0.0.1:1234/v1/models")
        );
    }

    #[test]
    fn provider_probe_health_uses_attempted_endpoint_before_binary_presence() {
        let found_binaries = vec!["/usr/local/bin/vllm".to_string()];
        assert_eq!(
            provider_probe_health(&[], true, &found_binaries),
            LocalServiceHealth::Unavailable
        );
        assert_eq!(
            provider_probe_health(&[], false, &found_binaries),
            LocalServiceHealth::Unknown
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn probe_provider_explains_custom_provider_without_local_url() {
        let _guard = ENV_LOCK.lock();
        let _openai_base = EnvVarGuard::set("DOCDEX_OPENAI_COMPATIBLE_BASE_URL", "");
        let _llm_base = EnvVarGuard::set("DOCDEX_LLM_BASE_URL", "");

        let outcome = probe_provider(
            LocalLlmProvider::CustomOpenAiCompatible,
            &LlmConfig::default(),
            Duration::from_millis(1),
            false,
            99,
        )
        .await;

        assert_eq!(outcome.probe.health, LocalServiceHealth::Unavailable);
        assert!(!outcome.probe.service_detected);
        assert!(outcome.probe.endpoints.is_empty());
        assert!(outcome
            .probe
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("no local OpenAI-compatible base URL configured"));
    }

    #[tokio::test]
    async fn probe_provider_reads_openai_compatible_models() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 1024];
                let read = socket.read(&mut buffer).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buffer[..read]);
                assert!(request.starts_with("GET /v1/models "));
                let body = r#"{"data":[{"id":"qwen2.5-coder:7b"},{"id":"nomic-embed-text"}]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let base_url = format!("http://{}", addr);
        let config = LlmConfig {
            provider: "custom-openai-compatible".to_string(),
            base_url: base_url.clone(),
            ..LlmConfig::default()
        };
        let outcome = probe_provider(
            LocalLlmProvider::CustomOpenAiCompatible,
            &config,
            Duration::from_secs(1),
            false,
            99,
        )
        .await;
        server.await?;

        assert_eq!(outcome.probe.health, LocalServiceHealth::Healthy);
        assert!(outcome.probe.service_detected);
        assert_eq!(outcome.probe.model_count, 2);
        assert_eq!(outcome.services.len(), 1);
        assert_eq!(
            outcome.services[0].provider,
            LocalLlmProvider::CustomOpenAiCompatible
        );
        assert_eq!(
            outcome.services[0].endpoints[0].models_url.as_deref(),
            Some(format!("{base_url}/v1/models").as_str())
        );
        let service_qwen = outcome.services[0]
            .models
            .iter()
            .find(|entry| entry.name == "qwen2.5-coder:7b")
            .expect("qwen coder service model");
        assert_eq!(service_qwen.raw_name.as_deref(), Some("qwen2.5-coder:7b"));
        assert!(service_qwen.capability_flags.chat);
        assert!(service_qwen.capability_flags.code);
        assert!(service_qwen.capability_flags.reasoning);
        assert!(service_qwen.capability_flags.tool_capable);
        assert!(service_qwen.delegation_ready);
        let service_embed = outcome.services[0]
            .models
            .iter()
            .find(|entry| entry.name == "nomic-embed-text")
            .expect("embedding service model");
        assert!(service_embed.capability_flags.embedding);
        assert!(service_embed.capability_flags.unsupported_for_delegation);
        assert!(!service_embed.delegation_ready);
        assert!(outcome
            .models
            .iter()
            .any(|entry| entry.name == "qwen2.5-coder:7b"
                && entry.capabilities.contains(&CAP_CODE_WRITER.to_string())));
        assert!(outcome
            .models
            .iter()
            .any(|entry| entry.name == "nomic-embed-text"
                && entry.capabilities.contains(&CAP_EMBEDDING.to_string())));
        Ok(())
    }

    #[test]
    fn ollama_service_entry_captures_inventory_and_capabilities() {
        let models = vec![
            LocalModelEntry {
                name: "nomic-embed-text:latest".to_string(),
                source: "ollama".to_string(),
                capabilities: vec![CAP_EMBEDDING.to_string()],
                notes: None,
                classification_method: "heuristic".to_string(),
                last_seen_at_ms: 1,
                last_classified_at_ms: None,
                ..LocalModelEntry::default()
            },
            LocalModelEntry {
                name: "qwen-coder:latest".to_string(),
                source: "ollama".to_string(),
                capabilities: vec![CAP_CODE_WRITER.to_string(), CAP_CODE_REVIEWER.to_string()],
                notes: None,
                classification_method: "known_map".to_string(),
                last_seen_at_ms: 1,
                last_classified_at_ms: None,
                ..LocalModelEntry::default()
            },
        ];

        let service = build_ollama_service_entry("http://127.0.0.1:11434/", &models, 9);

        assert_eq!(service.service_id, "ollama:http://127.0.0.1:11434");
        assert_eq!(service.provider, LocalLlmProvider::Ollama);
        assert_eq!(service.source_type, LocalLibrarySourceType::LocalProcess);
        assert_eq!(service.health, LocalServiceHealth::Healthy);
        assert_eq!(service.models.len(), 2);
        assert!(service.capability_flags.embedding);
        assert!(service.capability_flags.chat);
        assert!(service.capability_flags.delegation);
        assert!(service.capability_flags.code);
        assert_eq!(
            service.endpoints[0].embeddings_url.as_deref(),
            Some("http://127.0.0.1:11434/api/embeddings")
        );
        assert_eq!(
            service.endpoints[0].delegation_url.as_deref(),
            Some("http://127.0.0.1:11434/api/generate")
        );
        assert_eq!(
            service.models[0].mcoda_reconciliation,
            McodaReconciliationStatus::Unknown
        );
    }

    #[test]
    fn local_library_corrupt_falls_back() -> Result<()> {
        let dir = TempDir::new()?;
        let path = library_path(Some(dir.path()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, "{not json")?;
        let loaded = load_local_library(Some(dir.path()))?;
        assert!(loaded.models.is_empty());
        assert!(loaded.agents.is_empty());
        Ok(())
    }

    #[test]
    fn ollama_base_url_local_detection() {
        assert!(is_local_ollama_base_url("http://127.0.0.1:11434"));
        assert!(is_local_ollama_base_url("http://localhost:11434"));
        assert!(is_local_ollama_base_url("http://[::1]:11434"));
        assert!(!is_local_ollama_base_url("https://127.0.0.1:11434"));
        assert!(!is_local_ollama_base_url("http://192.168.1.10:11434"));
    }

    #[test]
    fn ollama_model_name_normalization() {
        assert_eq!(normalize_model_name("  Phi3.5:3.8b  "), "Phi3.5:3.8b");
        assert_eq!(
            normalize_model_name(" models/qwen2.5-coder:7b "),
            "qwen2.5-coder:7b"
        );
        assert_eq!(normalize_model_name(""), "");
    }

    #[test]
    fn classify_model_known_families() {
        let phi = classify_model_known("phi3.5:3.8b").expect("phi mapping");
        assert!(phi.capabilities.contains(&CAP_CODE_WRITER.to_string()));
        assert!(phi.capabilities.contains(&CAP_GENERAL_CHAT.to_string()));
        let deepseek = classify_model_known("deepseek-coder:6.7b").expect("deepseek mapping");
        assert!(deepseek
            .capabilities
            .contains(&CAP_CODE_REVIEWER.to_string()));
        assert!(deepseek.capabilities.contains(&CAP_REASONING.to_string()));
        let qwen_coder = classify_model_known("Qwen2.5-Coder-7B").expect("qwen coder mapping");
        assert!(qwen_coder.capabilities.contains(&CAP_CODE.to_string()));
        assert!(qwen_coder.capabilities.contains(&CAP_CHAT.to_string()));
        assert!(qwen_coder.capabilities.contains(&CAP_REASONING.to_string()));
        assert!(qwen_coder
            .capabilities
            .contains(&CAP_TOOL_CAPABLE.to_string()));
        let qwen_vl = classify_model_known("qwen2-vl:7b").expect("qwen vl mapping");
        assert!(qwen_vl.capabilities.contains(&CAP_VISION.to_string()));
        assert!(qwen_vl.capabilities.contains(&CAP_CHAT.to_string()));
        let embedding = classify_model_known("BAAI/bge-small-en-v1.5").expect("bge mapping");
        assert!(embedding.capabilities.contains(&CAP_EMBEDDING.to_string()));
        assert!(embedding
            .capabilities
            .contains(&CAP_UNSUPPORTED_FOR_DELEGATION.to_string()));
    }

    #[test]
    fn classify_model_heuristics() {
        let embed = classify_model_heuristic("text-embedding-3-large");
        assert!(embed.capabilities.contains(&CAP_EMBEDDING.to_string()));
        let vision = classify_model_heuristic("llava:latest");
        assert!(vision.capabilities.contains(&CAP_VISION.to_string()));
        let code = classify_model_heuristic("my-code-model");
        assert!(code.capabilities.contains(&CAP_CODE_WRITER.to_string()));
        assert!(code.capabilities.contains(&CAP_CODE.to_string()));
        let tool = classify_model_heuristic("general-function-calling-chat");
        assert!(tool.capabilities.contains(&CAP_TOOL_CAPABLE.to_string()));
        assert!(tool.capabilities.contains(&CAP_CHAT.to_string()));
    }

    #[test]
    fn model_delegation_readiness_is_conservative() {
        let qwen = local_model_entry_from_probe(
            &LocalLlmProvider::Vllm,
            " models/qwen2.5-coder:7b ",
            &LocalServiceHealth::Healthy,
            7,
        );
        assert_eq!(qwen.name, "qwen2.5-coder:7b");
        assert_eq!(qwen.raw_name.as_deref(), Some("models/qwen2.5-coder:7b"));
        assert!(qwen.capability_flags.code);
        assert!(qwen.capability_flags.reasoning);
        assert!(qwen.capability_flags.tool_capable);
        assert!(qwen.delegation_ready);

        let embedding = local_model_entry_from_probe(
            &LocalLlmProvider::Ollama,
            "nomic-embed-text:latest",
            &LocalServiceHealth::Healthy,
            7,
        );
        assert!(embedding.capability_flags.embedding);
        assert!(embedding.capability_flags.unsupported_for_delegation);
        assert!(!embedding.delegation_ready);
        assert!(embedding
            .delegation_readiness_reason
            .as_deref()
            .unwrap_or_default()
            .contains("unsupported"));

        let unavailable = local_model_entry_from_probe(
            &LocalLlmProvider::Vllm,
            "qwen3:8b",
            &LocalServiceHealth::Unavailable,
            7,
        );
        assert!(!unavailable.delegation_ready);
        assert!(unavailable
            .delegation_readiness_reason
            .as_deref()
            .unwrap_or_default()
            .contains("service health"));

        let (ready, reason) = model_delegation_readiness(
            &[CAP_GENERAL_CHAT.to_string()],
            &LocalServiceHealth::Healthy,
            Some(2048),
        );
        assert!(!ready);
        assert!(reason.unwrap_or_default().contains("context window"));
    }

    #[test]
    fn mcoda_agent_mapping() {
        let agent = McodaAgent {
            id: "agent-1".to_string(),
            slug: "local-test".to_string(),
            adapter: "ollama".to_string(),
            default_model: Some("phi3.5:3.8b".to_string()),
            config: None,
            created_at: None,
            updated_at: None,
            rating: Some(7.5),
            cost_per_million: Some(2.25),
            max_complexity: Some(4),
            best_usage: Some("code_writer".to_string()),
            reasoning_rating: Some(8.5),
            health_status: Some("healthy".to_string()),
            health_details: None,
            cli_binary: None,
            capabilities: vec![
                "code_write".to_string(),
                "code_review".to_string(),
                "chat".to_string(),
            ],
            models: Vec::new(),
            auth: None,
            usage_limits: Vec::new(),
        };
        let entry = mcoda_agent_entry(&agent, &LlmConfig::default(), 10, None);
        assert_eq!(entry.agent_id, "agent-1");
        assert_eq!(entry.source, LOCAL_AGENT_SOURCE_MCODA_LOCAL);
        assert!(entry.capabilities.contains(&"code_writer".to_string()));
        assert!(entry.capabilities.contains(&"code_reviewer".to_string()));
        assert!(entry.capabilities.contains(&"code".to_string()));
        assert!(entry.capabilities.contains(&"chat".to_string()));
        assert!(entry.capabilities.contains(&"general_chat".to_string()));
        assert!(entry.capabilities.contains(&"local".to_string()));
        assert!(entry.delegation_ready);
        assert!(entry
            .delegation_readiness_reason
            .as_deref()
            .unwrap_or_default()
            .contains("healthy mcoda agent"));
        assert_eq!(entry.rating, Some(7.5));
        assert_eq!(entry.cost_per_million, Some(2.25));
        assert_eq!(entry.max_complexity, Some(4));
        assert_eq!(entry.usage.as_deref(), Some("code_writer"));
        assert_eq!(entry.reasoning_rating, Some(8.5));
        assert_eq!(entry.health_status.as_deref(), Some("healthy"));
        assert_eq!(entry.model_names, vec!["phi3.5:3.8b".to_string()]);
        assert_eq!(entry.runner_kind.as_deref(), Some("ollama"));
        assert_eq!(
            entry.base_url,
            resolve_local_ollama_base_url(&LlmConfig::default())
        );
        assert_eq!(entry.classification_method, "registry");
        assert_eq!(entry.last_seen_at_ms, 10);
    }

    #[test]
    fn mcoda_remote_ollama_agent_requires_explicit_loopback_base_url() {
        let agent = McodaAgent {
            id: "agent-remote".to_string(),
            slug: "remote-ollama".to_string(),
            adapter: "ollama-remote".to_string(),
            default_model: Some("phi3.5:latest".to_string()),
            config: None,
            created_at: None,
            updated_at: None,
            rating: Some(8.0),
            cost_per_million: Some(0.0),
            max_complexity: Some(5),
            best_usage: Some("code_writer".to_string()),
            reasoning_rating: Some(7.5),
            health_status: Some("healthy".to_string()),
            health_details: None,
            cli_binary: None,
            capabilities: vec!["code_write".to_string(), "chat".to_string()],
            models: Vec::new(),
            auth: None,
            usage_limits: Vec::new(),
        };

        let entry = mcoda_agent_entry(&agent, &LlmConfig::default(), 10, None);

        assert_eq!(entry.runner_kind.as_deref(), Some("ollama"));
        assert_eq!(entry.base_url, None);

        let mut services = vec![LocalServiceEntry {
            service_id: "ollama:http://127.0.0.1:11434".to_string(),
            provider: LocalLlmProvider::Ollama,
            source_type: LocalLibrarySourceType::LocalProcess,
            base_url: Some("http://127.0.0.1:11434".to_string()),
            health: LocalServiceHealth::Healthy,
            models: vec![LocalServiceModelEntry {
                name: "phi3.5:latest".to_string(),
                raw_name: Some("phi3.5:latest".to_string()),
                delegation_ready: true,
                ..LocalServiceModelEntry::default()
            }],
            ..LocalServiceEntry::default()
        }];
        reconcile_services_with_mcoda_agents(&mut services, &[entry]);

        assert_eq!(
            services[0].models[0].mcoda_reconciliation,
            McodaReconciliationStatus::NoMatchingAgent
        );
        assert!(services[0].models[0].mcoda_agent_match.is_none());
        assert!(services[0].models[0].mcoda_setup_hint.is_some());

        let explicit_agent = McodaAgent {
            config: Some(serde_json::json!({
                "baseUrl": "http://localhost:11434"
            })),
            ..agent
        };
        let explicit_entry = mcoda_agent_entry(&explicit_agent, &LlmConfig::default(), 10, None);

        assert_eq!(
            explicit_entry.base_url.as_deref(),
            Some("http://127.0.0.1:11434")
        );
    }

    #[test]
    fn mcoda_agent_entry_extracts_local_runner_metadata() {
        let agent = McodaAgent {
            id: "agent-vllm".to_string(),
            slug: "vllm-qwen".to_string(),
            adapter: "openai-compatible-local".to_string(),
            default_model: Some("models/qwen2.5-coder:7b".to_string()),
            config: Some(serde_json::json!({
                "localRunner": {
                    "baseUrl": "http://127.0.0.1:8000/v1/",
                    "runnerKind": "vllm"
                }
            })),
            created_at: None,
            updated_at: None,
            rating: Some(8.0),
            cost_per_million: Some(0.0),
            max_complexity: Some(5),
            best_usage: Some("code_writer".to_string()),
            reasoning_rating: Some(7.5),
            health_status: Some("healthy".to_string()),
            health_details: None,
            cli_binary: None,
            capabilities: vec!["code_write".to_string(), "chat".to_string()],
            models: vec![McodaAgentModel {
                model_name: "qwen2.5-coder:7b".to_string(),
                is_default: false,
                config: None,
            }],
            auth: None,
            usage_limits: Vec::new(),
        };

        let entry = mcoda_agent_entry(&agent, &LlmConfig::default(), 10, None);

        assert_eq!(entry.runner_kind.as_deref(), Some("vllm"));
        assert_eq!(entry.base_url.as_deref(), Some("http://127.0.0.1:8000"));
        assert_eq!(
            entry.model_names,
            vec![
                "models/qwen2.5-coder:7b".to_string(),
                "qwen2.5-coder:7b".to_string()
            ]
        );
        assert!(entry.delegation_ready);
    }

    #[test]
    fn mcoda_agent_readiness_requires_health_and_nontrivial_signal() {
        let caps = normalize_agent_capabilities("ollama", &["code_write".to_string()]);
        let (ready, reason) = mcoda_agent_delegation_readiness(
            &caps,
            Some("code_writer"),
            Some("healthy"),
            None,
            None,
            None,
        );
        assert!(!ready);
        assert!(reason.unwrap_or_default().contains("non-trivial"));

        let (ready, reason) = mcoda_agent_delegation_readiness(
            &caps,
            Some("code_writer"),
            Some("unhealthy"),
            Some(7),
            Some(8.0),
            Some(8.0),
        );
        assert!(!ready);
        assert!(reason.unwrap_or_default().contains("not healthy"));

        let (ready, reason) =
            mcoda_agent_delegation_readiness(&[], None, Some("healthy"), Some(7), Some(8.0), None);
        assert!(!ready);
        assert!(reason
            .unwrap_or_default()
            .contains("no chat/code/reasoning/tool capability"));
    }

    #[test]
    fn mcoda_reconciliation_reports_agent_states_for_service_models() {
        let mut services = vec![LocalServiceEntry {
            service_id: "vllm:http://127.0.0.1:8000".to_string(),
            provider: LocalLlmProvider::Vllm,
            source_type: LocalLibrarySourceType::LocalProcess,
            display_name: Some("vLLM".to_string()),
            base_url: Some("http://127.0.0.1:8000".to_string()),
            health: LocalServiceHealth::Healthy,
            models: vec![
                LocalServiceModelEntry {
                    name: "qwen2.5-coder:7b".to_string(),
                    raw_name: Some("models/qwen2.5-coder:7b".to_string()),
                    delegation_ready: true,
                    ..LocalServiceModelEntry::default()
                },
                LocalServiceModelEntry {
                    name: "deepseek-coder:6.7b".to_string(),
                    raw_name: Some("deepseek-coder:6.7b".to_string()),
                    delegation_ready: true,
                    ..LocalServiceModelEntry::default()
                },
                LocalServiceModelEntry {
                    name: "phi3.5:latest".to_string(),
                    raw_name: Some("phi3.5:latest".to_string()),
                    delegation_ready: true,
                    ..LocalServiceModelEntry::default()
                },
                LocalServiceModelEntry {
                    name: "nomic-embed-text:latest".to_string(),
                    raw_name: Some("nomic-embed-text:latest".to_string()),
                    capability_flags: LocalCapabilityFlags {
                        embedding: true,
                        unsupported_for_delegation: true,
                        ..LocalCapabilityFlags::default()
                    },
                    delegation_ready: false,
                    ..LocalServiceModelEntry::default()
                },
            ],
            ..LocalServiceEntry::default()
        }];
        let agents = vec![
            LocalAgentEntry {
                agent_id: "agent-qwen".to_string(),
                agent_slug: "vllm-qwen".to_string(),
                source: LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string(),
                adapter: "vllm-local".to_string(),
                default_model: Some("models/qwen2.5-coder:7b".to_string()),
                model_names: vec!["qwen2.5-coder:7b".to_string()],
                base_url: Some("http://localhost:8000/v1".to_string()),
                runner_kind: Some("vllm".to_string()),
                rating: Some(8.0),
                max_complexity: Some(5),
                health_status: Some("healthy".to_string()),
                ..LocalAgentEntry::default()
            },
            LocalAgentEntry {
                agent_id: "agent-deepseek".to_string(),
                agent_slug: "vllm-deepseek".to_string(),
                source: LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string(),
                adapter: "vllm-local".to_string(),
                default_model: Some("deepseek-coder:6.7b".to_string()),
                model_names: vec!["deepseek-coder:6.7b".to_string()],
                base_url: Some("http://127.0.0.1:8000".to_string()),
                runner_kind: Some("vllm".to_string()),
                rating: Some(8.0),
                max_complexity: Some(5),
                health_status: Some("unhealthy".to_string()),
                ..LocalAgentEntry::default()
            },
            LocalAgentEntry {
                agent_id: "agent-phi-remote".to_string(),
                agent_slug: "vllm-phi-remote".to_string(),
                source: LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string(),
                adapter: "vllm-local".to_string(),
                default_model: Some("phi3.5:latest".to_string()),
                model_names: vec!["phi3.5:latest".to_string()],
                base_url: Some("http://192.168.1.10:8000".to_string()),
                runner_kind: Some("vllm".to_string()),
                rating: Some(8.0),
                max_complexity: Some(5),
                health_status: Some("healthy".to_string()),
                ..LocalAgentEntry::default()
            },
            LocalAgentEntry {
                agent_id: "agent-phi-cloud".to_string(),
                agent_slug: "cloud-phi".to_string(),
                source: LOCAL_AGENT_SOURCE_MCODA_CLOUD.to_string(),
                adapter: "vllm-local".to_string(),
                default_model: Some("phi3.5:latest".to_string()),
                model_names: vec!["phi3.5:latest".to_string()],
                base_url: Some("http://127.0.0.1:8000".to_string()),
                runner_kind: Some("vllm".to_string()),
                rating: Some(8.0),
                max_complexity: Some(5),
                health_status: Some("healthy".to_string()),
                ..LocalAgentEntry::default()
            },
        ];

        reconcile_services_with_mcoda_agents(&mut services, &agents);

        let qwen = services[0]
            .models
            .iter()
            .find(|model| model.name == "qwen2.5-coder:7b")
            .expect("qwen service model");
        assert_eq!(
            qwen.mcoda_reconciliation,
            McodaReconciliationStatus::MatchingHealthyAgent
        );
        assert_eq!(
            qwen.mcoda_agent_match
                .as_ref()
                .map(|matched| matched.agent_slug.as_str()),
            Some("vllm-qwen")
        );

        let deepseek = services[0]
            .models
            .iter()
            .find(|model| model.name == "deepseek-coder:6.7b")
            .expect("deepseek service model");
        assert_eq!(
            deepseek.mcoda_reconciliation,
            McodaReconciliationStatus::MatchingUnhealthyAgent
        );
        assert_eq!(
            deepseek
                .mcoda_agent_match
                .as_ref()
                .map(|matched| matched.agent_slug.as_str()),
            Some("vllm-deepseek")
        );

        let phi = services[0]
            .models
            .iter()
            .find(|model| model.name == "phi3.5:latest")
            .expect("phi service model");
        assert_eq!(
            phi.mcoda_reconciliation,
            McodaReconciliationStatus::NoMatchingAgent
        );
        assert!(phi.mcoda_agent_match.is_none());
        assert!(phi
            .mcoda_setup_hint
            .as_deref()
            .unwrap_or_default()
            .contains("create or suggest a mcoda local agent"));

        let embedding = services[0]
            .models
            .iter()
            .find(|model| model.name == "nomic-embed-text:latest")
            .expect("embedding service model");
        assert_eq!(
            embedding.mcoda_reconciliation,
            McodaReconciliationStatus::NotApplicable
        );
        assert!(embedding.mcoda_agent_match.is_none());
        assert!(embedding.mcoda_setup_hint.is_none());
    }

    #[test]
    fn mcoda_cloud_agent_with_active_usage_limit_is_marked_limited() {
        let agent = McodaAgent {
            id: "agent-cloud".to_string(),
            slug: "cloud-coder".to_string(),
            adapter: "openai-api".to_string(),
            default_model: Some("openrouter/qwen3-coder".to_string()),
            config: Some(serde_json::json!({
                "mswarmCloud": {
                    "managed": true,
                    "remoteSlug": "openrouter-qwen-qwen3-coder"
                }
            })),
            created_at: None,
            updated_at: None,
            rating: Some(8.5),
            cost_per_million: Some(0.25),
            max_complexity: Some(8),
            best_usage: Some("code_writer".to_string()),
            reasoning_rating: Some(8.3),
            health_status: Some("healthy".to_string()),
            health_details: None,
            cli_binary: None,
            capabilities: vec!["code_write".to_string()],
            models: Vec::new(),
            auth: None,
            usage_limits: vec![McodaAgentUsageLimit {
                agent_id: "agent-cloud".to_string(),
                limit_scope: "model".to_string(),
                limit_key: "openrouter/qwen3-coder".to_string(),
                window_type: "daily".to_string(),
                status: "exhausted".to_string(),
                reset_at: Some((chrono::Utc::now() + chrono::Duration::hours(4)).to_rfc3339()),
                observed_at: Some(chrono::Utc::now().to_rfc3339()),
                source: Some("mswarm".to_string()),
                details: None,
            }],
        };

        let entry = mcoda_agent_entry(&agent, &LlmConfig::default(), now_ms(), None);
        assert_eq!(entry.source, LOCAL_AGENT_SOURCE_MCODA_CLOUD);
        assert_eq!(entry.health_status.as_deref(), Some("limited"));
        assert!(!entry.delegation_ready);
        assert!(entry
            .delegation_readiness_reason
            .as_deref()
            .unwrap_or_default()
            .contains("not healthy"));
        assert!(entry
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("usage limit exhausted"));
    }

    #[test]
    fn discover_mcoda_agents_reads_registry() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let mcoda_dir = dir.path().join(".mcoda");
        fs::create_dir_all(&mcoda_dir)?;
        let db_path = mcoda_dir.join("mcoda.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "CREATE TABLE agents (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL,
                adapter TEXT NOT NULL,
                default_model TEXT,
                config_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                rating REAL,
                cost_per_million REAL,
                max_complexity INTEGER,
                best_usage TEXT,
                reasoning_rating REAL
            );
            CREATE TABLE agent_capabilities (
                agent_id TEXT NOT NULL,
                capability TEXT NOT NULL
            );
            CREATE TABLE agent_health (
                agent_id TEXT PRIMARY KEY,
                status TEXT NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at, rating, cost_per_million, max_complexity, best_usage, reasoning_rating)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                "agent-1",
                "agent-one",
                "ollama",
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                8.25,
                1.5,
                6,
                "code_writer",
                9.0
            ],
        )?;
        conn.execute(
            "INSERT INTO agent_capabilities (agent_id, capability) VALUES (?1, ?2)",
            params!["agent-1", "Code_Writer"],
        )?;
        conn.execute(
            "INSERT INTO agent_health (agent_id, status) VALUES (?1, ?2)",
            params!["agent-1", "healthy"],
        )?;
        drop(conn);

        let _home = EnvVarGuard::set("HOME", dir.path());
        let _userprofile = EnvVarGuard::set("USERPROFILE", dir.path());
        let agents = discover_mcoda_agents(None, &LlmConfig::default());

        assert_eq!(agents.len(), 1);
        let entry = &agents[0];
        assert_eq!(entry.agent_id, "agent-1");
        assert_eq!(entry.agent_slug, "agent-one");
        assert_eq!(entry.adapter, "ollama");
        assert!(entry.capabilities.contains(&"code_writer".to_string()));
        assert!(entry.capabilities.contains(&"local".to_string()));
        assert_eq!(entry.rating, Some(8.25));
        assert_eq!(entry.cost_per_million, Some(1.5));
        assert_eq!(entry.max_complexity, Some(6));
        assert_eq!(entry.usage.as_deref(), Some("code_writer"));
        assert_eq!(entry.reasoning_rating, Some(9.0));
        assert_eq!(entry.health_status.as_deref(), Some("healthy"));
        assert_eq!(entry.classification_method, "registry");
        assert!(entry.delegation_ready);
        Ok(())
    }

    #[test]
    fn discover_mcoda_agents_marks_recent_runtime_failures_degraded() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let mcoda_dir = dir.path().join(".mcoda");
        fs::create_dir_all(&mcoda_dir)?;
        let db_path = mcoda_dir.join("mcoda.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "CREATE TABLE agents (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL,
                adapter TEXT NOT NULL,
                default_model TEXT,
                config_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                rating REAL,
                cost_per_million REAL,
                max_complexity INTEGER,
                best_usage TEXT,
                reasoning_rating REAL
            );
            CREATE TABLE agent_health (
                agent_id TEXT PRIMARY KEY,
                status TEXT NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at, rating, cost_per_million, max_complexity, best_usage, reasoning_rating)
             VALUES (?1, ?2, ?3, NULL, NULL, NULL, NULL, NULL, 0.0, NULL, NULL, NULL)",
            params!["agent-1", "agent-one", "ollama"],
        )?;
        conn.execute(
            "INSERT INTO agent_health (agent_id, status) VALUES (?1, ?2)",
            params!["agent-1", "healthy"],
        )?;
        drop(conn);

        let logs_dir = dir.path().join("logs").join("errors");
        fs::create_dir_all(&logs_dir)?;
        let now = chrono::Utc::now().to_rfc3339();
        let record = format!(
            "{{\"ts\":\"{now}\",\"kind\":\"local_completion_failed\",\"local_target\":\"agent:agent-1\",\"error\":\"gemini CLI timeout\"}}\n"
        );
        fs::write(
            logs_dir.join("delegation_local_failures.jsonl"),
            format!("{record}{record}"),
        )?;

        let _home = EnvVarGuard::set("HOME", dir.path());
        let _userprofile = EnvVarGuard::set("USERPROFILE", dir.path());
        let agents = discover_mcoda_agents(Some(dir.path()), &LlmConfig::default());

        assert_eq!(agents.len(), 1);
        let entry = &agents[0];
        assert_eq!(entry.health_status.as_deref(), Some("degraded"));
        assert!(entry
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("recent local delegation failures"));
        Ok(())
    }

    #[test]
    fn discover_mcoda_agents_marks_shared_model_failures_degraded() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let mcoda_dir = dir.path().join(".mcoda");
        fs::create_dir_all(&mcoda_dir)?;
        let db_path = mcoda_dir.join("mcoda.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "CREATE TABLE agents (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL,
                adapter TEXT NOT NULL,
                default_model TEXT,
                config_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                rating REAL,
                cost_per_million REAL,
                max_complexity INTEGER,
                best_usage TEXT,
                reasoning_rating REAL
            );
            CREATE TABLE agent_health (
                agent_id TEXT PRIMARY KEY,
                status TEXT NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at, rating, cost_per_million, max_complexity, best_usage, reasoning_rating)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, NULL, NULL, 0.0, NULL, NULL, NULL)",
            params!["agent-1", "agent-one", "ollama", "shared-model"],
        )?;
        conn.execute(
            "INSERT INTO agent_health (agent_id, status) VALUES (?1, ?2)",
            params!["agent-1", "healthy"],
        )?;
        drop(conn);

        let logs_dir = dir.path().join("logs").join("errors");
        fs::create_dir_all(&logs_dir)?;
        let now = chrono::Utc::now().to_rfc3339();
        let record = format!(
            "{{\"ts\":\"{now}\",\"kind\":\"local_completion_failed\",\"local_target\":\"agent:alias-agent\",\"error\":\"ollama generate failed for model shared-model at http://127.0.0.1:11434 with timeout 1000ms (500 Internal Server Error): model failed to load\"}}\n"
        );
        fs::write(
            logs_dir.join("delegation_local_failures.jsonl"),
            format!("{record}{record}"),
        )?;

        let _home = EnvVarGuard::set("HOME", dir.path());
        let _userprofile = EnvVarGuard::set("USERPROFILE", dir.path());
        let agents = discover_mcoda_agents(Some(dir.path()), &LlmConfig::default());

        assert_eq!(agents.len(), 1);
        let entry = &agents[0];
        assert_eq!(entry.health_status.as_deref(), Some("degraded"));
        assert!(entry
            .notes
            .as_deref()
            .unwrap_or_default()
            .contains("recent local delegation failures"));
        Ok(())
    }

    #[tokio::test]
    async fn discover_ollama_models_reads_tags() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 512];
                let _ = socket.read(&mut buffer).await;
                let body = "{\"models\":[{\"name\":\"phi3.5:3.8b\"},{\"name\":\"text-embedding-3-large\"},{\"name\":\" models/qwen2.5-coder:7b \"}]}";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let base_url = format!("http://{}", addr);
        let models = discover_ollama_models(&base_url, Duration::from_secs(1), false).await;
        let _ = server.await;
        assert!(models
            .iter()
            .any(|model| model.name == "phi3.5:3.8b" && model.raw_name == "phi3.5:3.8b"));
        assert!(models
            .iter()
            .any(|model| model.name == "text-embedding-3-large"));
        assert!(models
            .iter()
            .any(|model| model.name == "qwen2.5-coder:7b"
                && model.raw_name == "models/qwen2.5-coder:7b"));
        Ok(())
    }

    #[tokio::test]
    async fn classify_model_web_stub() -> Result<()> {
        let result = classify_model_with_web_text("mystery-model", |query| async move {
            assert!(query.contains("mystery-model"));
            Ok("Great for code generation and coding assistants.".to_string())
        })
        .await?;
        let classification = result.expect("web classification");
        assert!(classification
            .capabilities
            .contains(&CAP_CODE_WRITER.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn local_library_refresh_ttl() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let _ttl = EnvVarGuard::set("DOCDEX_LOCAL_LIBRARY_TTL_SECS", "99999");
        let mut library = LocalModelLibrary::default();
        library.updated_at_ms = now_ms();
        library.models.push(LocalModelEntry {
            name: "phi3.5:3.8b".to_string(),
            source: "ollama".to_string(),
            capabilities: vec![CAP_CODE_WRITER.to_string()],
            notes: None,
            classification_method: "known_map".to_string(),
            last_seen_at_ms: library.updated_at_ms,
            last_classified_at_ms: None,
            ..LocalModelEntry::default()
        });
        save_local_library(Some(dir.path()), &library)?;
        let refreshed =
            refresh_local_library_if_stale(Some(dir.path()), &LlmConfig::default(), false).await?;
        assert_eq!(refreshed.updated_at_ms, library.updated_at_ms);
        assert_eq!(refreshed.models.len(), 1);
        assert_eq!(
            refreshed
                .defaults
                .delegation
                .selected
                .as_ref()
                .and_then(|candidate| candidate.model.as_deref()),
            Some("phi3.5:3.8b")
        );
        Ok(())
    }

    #[test]
    fn local_library_refresh_has_candidates() {
        let mut library = LocalModelLibrary::default();
        library.models.push(LocalModelEntry {
            name: "embed-only".to_string(),
            source: "ollama".to_string(),
            capabilities: vec![CAP_EMBEDDING.to_string()],
            notes: None,
            classification_method: "heuristic".to_string(),
            last_seen_at_ms: 1,
            last_classified_at_ms: None,
            ..LocalModelEntry::default()
        });
        assert!(!library_has_candidates(&library));
        library.agents.push(LocalAgentEntry {
            agent_id: "agent".to_string(),
            agent_slug: "agent".to_string(),
            source: LOCAL_AGENT_SOURCE_MCODA_LOCAL.to_string(),
            adapter: "openai".to_string(),
            default_model: None,
            max_complexity: None,
            rating: None,
            cost_per_million: None,
            usage: None,
            reasoning_rating: None,
            health_status: None,
            capabilities: Vec::new(),
            notes: None,
            classification_method: "registry".to_string(),
            last_seen_at_ms: 2,
            last_classified_at_ms: None,
            ..LocalAgentEntry::default()
        });
        assert!(!library_has_candidates(&library));
        library.models.push(LocalModelEntry {
            name: "qwen2.5-coder:7b".to_string(),
            source: "vllm".to_string(),
            capabilities: vec![CAP_CODE_WRITER.to_string()],
            delegation_ready: true,
            delegation_readiness_reason: Some(
                "healthy service with non-embedding chat/code-capable model".to_string(),
            ),
            notes: None,
            classification_method: "known_map".to_string(),
            last_seen_at_ms: 3,
            last_classified_at_ms: None,
            ..LocalModelEntry::default()
        });
        assert!(!library_has_candidates(&library));
        library.models.push(LocalModelEntry {
            name: "qwen2.5-coder:7b".to_string(),
            source: "ollama".to_string(),
            capabilities: vec![CAP_CODE_WRITER.to_string()],
            delegation_ready: true,
            delegation_readiness_reason: Some(
                "healthy service with non-embedding chat/code-capable model".to_string(),
            ),
            notes: None,
            classification_method: "known_map".to_string(),
            last_seen_at_ms: 4,
            last_classified_at_ms: None,
            ..LocalModelEntry::default()
        });
        assert!(library_has_candidates(&library));
    }
}
