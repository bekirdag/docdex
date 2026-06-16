use crate::mcoda::registry::McodaAgent;
use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, RETRY_AFTER};
use reqwest::{Client, StatusCode};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout, Instant};
use which::which;

const DEFAULT_CODEX_MODEL: &str = "gpt-5.1-codex-max";
const DEFAULT_OLLAMA_CLI_MODEL: &str = "llama3";
const DEFAULT_LOCAL_OLLAMA_BASE_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com/v1";
const DEFAULT_ZHIPU_BASE_URL: &str = "https://open.bigmodel.cn/api/paas/v4";
const DEFAULT_ZHIPU_CODING_BASE_URL: &str = "https://open.bigmodel.cn/api/coding/paas/v4";
const CODEX_CLI_TIMEOUT_FLOOR: Duration = Duration::from_secs(300);
const GEMINI_CLI_TIMEOUT_FLOOR: Duration = Duration::from_secs(45);
const CLI_INLINE_PROMPT_MAX_BYTES: usize = 16 * 1024;

const CLI_BASED_ADAPTERS: [&str; 5] = [
    "codex-cli",
    "gemini-cli",
    "openai-cli",
    "ollama-cli",
    "claude-cli",
];

const DOCDEX_CODEX_BIN: &str = "DOCDEX_CODEX_BIN";
const DOCDEX_OPENAI_CLI_BIN: &str = "DOCDEX_OPENAI_CLI_BIN";
const DOCDEX_GEMINI_BIN: &str = "DOCDEX_GEMINI_BIN";
const DOCDEX_CLAUDE_BIN: &str = "DOCDEX_CLAUDE_BIN";
const DOCDEX_OLLAMA_BIN: &str = "DOCDEX_OLLAMA_BIN";

pub struct LlmCompletion {
    pub output: String,
    pub adapter: String,
    pub model: Option<String>,
    pub metadata: Option<Value>,
}

pub type LlmFuture<'a> = Pin<Box<dyn Future<Output = Result<LlmCompletion>> + Send + 'a>>;

pub trait LlmClient: Send + Sync {
    fn generate<'a>(&'a self, prompt: &'a str, max_tokens: u32, timeout: Duration)
        -> LlmFuture<'a>;
}

pub enum LlmAdapter {
    OllamaRemote(OllamaRemoteClient),
    OllamaCli(OllamaCliClient),
    CodexCli(CodexCliClient),
    OpenAiCli(CodexCliClient),
    GeminiCli(GeminiCliClient),
    ClaudeCli(ClaudeCliClient),
    OpenAiApi(OpenAiApiClient),
    ZhipuApi(ZhipuApiClient),
}

impl LlmAdapter {
    pub fn adapter_type(&self) -> &str {
        match self {
            LlmAdapter::OllamaRemote(_) => "ollama-remote",
            LlmAdapter::OllamaCli(_) => "ollama-cli",
            LlmAdapter::CodexCli(_) => "codex-cli",
            LlmAdapter::OpenAiCli(_) => "openai-cli",
            LlmAdapter::GeminiCli(_) => "gemini-cli",
            LlmAdapter::ClaudeCli(_) => "claude-cli",
            LlmAdapter::OpenAiApi(_) => "openai-api",
            LlmAdapter::ZhipuApi(_) => "zhipu-api",
        }
    }
}

impl LlmClient for LlmAdapter {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        max_tokens: u32,
        timeout: Duration,
    ) -> LlmFuture<'a> {
        match self {
            LlmAdapter::OllamaRemote(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::OllamaCli(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::CodexCli(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::OpenAiCli(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::GeminiCli(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::ClaudeCli(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::OpenAiApi(client) => client.generate(prompt, max_tokens, timeout),
            LlmAdapter::ZhipuApi(client) => client.generate(prompt, max_tokens, timeout),
        }
    }
}

pub fn resolve_agent_adapter(agent: &McodaAgent) -> Result<LlmAdapter> {
    let has_secret = agent
        .auth
        .as_ref()
        .and_then(|auth| auth.decrypted_secret.as_deref())
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let adapter_type = resolve_adapter_type(agent, has_secret)?;
    let model = resolve_model(agent);
    let config = agent.config.as_ref();
    let adapter = match adapter_type.as_str() {
        "ollama-remote" => {
            LlmAdapter::OllamaRemote(OllamaRemoteClient::new(model, adapter_type, config)?)
        }
        "ollama-cli" => {
            let command = resolve_cli_command(agent, adapter_type.as_str());
            ensure_cli_command_available(adapter_type.as_str(), &command)?;
            LlmAdapter::OllamaCli(OllamaCliClient::new(model, adapter_type, command))
        }
        "codex-cli" => {
            let command = resolve_cli_command(agent, adapter_type.as_str());
            ensure_cli_command_available(adapter_type.as_str(), &command)?;
            LlmAdapter::CodexCli(CodexCliClient::new(model, adapter_type, command))
        }
        "openai-cli" => {
            let command = resolve_cli_command(agent, adapter_type.as_str());
            ensure_cli_command_available(adapter_type.as_str(), &command)?;
            LlmAdapter::OpenAiCli(CodexCliClient::new(model, adapter_type, command))
        }
        "gemini-cli" => {
            let command = resolve_cli_command(agent, adapter_type.as_str());
            ensure_cli_command_available(adapter_type.as_str(), &command)?;
            LlmAdapter::GeminiCli(GeminiCliClient::new(model, adapter_type, command))
        }
        "claude-cli" => {
            let command = resolve_cli_command(agent, adapter_type.as_str());
            ensure_cli_command_available(adapter_type.as_str(), &command)?;
            LlmAdapter::ClaudeCli(ClaudeCliClient::new(model, adapter_type, command))
        }
        "openai-api" => {
            let api_key = non_empty_trimmed(
                agent
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.decrypted_secret.as_deref()),
            )
            .ok_or_else(|| anyhow!("AUTH_REQUIRED: OpenAI API key missing"))?;
            LlmAdapter::OpenAiApi(OpenAiApiClient::new(model, adapter_type, config, api_key)?)
        }
        "zhipu-api" => {
            let api_key = non_empty_trimmed(
                agent
                    .auth
                    .as_ref()
                    .and_then(|auth| auth.decrypted_secret.as_deref()),
            )
            .ok_or_else(|| anyhow!("AUTH_REQUIRED: Zhipu API key missing"))?;
            LlmAdapter::ZhipuApi(ZhipuApiClient::new(model, adapter_type, config, api_key)?)
        }
        _ => return Err(anyhow!("unsupported adapter type: {adapter_type}")),
    };
    Ok(adapter)
}

pub(crate) fn resolve_local_openai_compatible_adapter(
    base_url: &str,
    model: &str,
    adapter: &str,
) -> Result<LlmAdapter> {
    let base_url = base_url.trim();
    if base_url.is_empty() {
        return Err(anyhow!("local OpenAI-compatible base_url missing"));
    }
    let model = model.trim();
    if model.is_empty() {
        return Err(anyhow!("local OpenAI-compatible model missing"));
    }
    let adapter = adapter.trim();
    if adapter.is_empty() {
        return Err(anyhow!("local OpenAI-compatible adapter name missing"));
    }
    let config = json!({ "baseUrl": base_url });
    Ok(LlmAdapter::OpenAiApi(OpenAiApiClient::new(
        Some(model.to_string()),
        adapter.to_string(),
        Some(&config),
        String::new(),
    )?))
}

fn resolve_model(agent: &McodaAgent) -> Option<String> {
    if let Some(model) = agent.default_model.as_ref() {
        if !model.trim().is_empty() {
            return Some(model.trim().to_string());
        }
    }
    agent
        .models
        .iter()
        .find(|model| model.is_default)
        .map(|model| model.model_name.clone())
}

fn resolve_adapter_type(agent: &McodaAgent, has_secret: bool) -> Result<String> {
    let mut adapter_type = agent.adapter.trim().to_string();
    if adapter_type.is_empty() {
        return Err(anyhow!("agent adapter is empty"));
    }

    let config = agent.config.as_ref();
    let cli_adapter = config_string(config, "cliAdapter");
    let local_adapter = config_string(config, "localAdapter");

    if adapter_type.ends_with("-api") && !has_secret {
        if adapter_type == "codex-api" || adapter_type == "openai-api" {
            adapter_type = "codex-cli".to_string();
        } else if adapter_type == "gemini-api" {
            adapter_type = "gemini-cli".to_string();
        } else if let Some(cli_adapter) = cli_adapter {
            if CLI_BASED_ADAPTERS.contains(&cli_adapter.as_str()) {
                adapter_type = cli_adapter;
            } else {
                return Err(anyhow!("unsupported cliAdapter: {cli_adapter}"));
            }
        } else if let Some(local_adapter) = local_adapter {
            return Err(anyhow!(
                "AUTH_REQUIRED: API credentials missing for adapter {adapter_type}; configure cliAdapter ({local_adapter}) or provide credentials."
            ));
        } else {
            return Err(anyhow!(
                "AUTH_REQUIRED: API credentials missing for adapter {adapter_type}"
            ));
        }
    }
    Ok(adapter_type)
}

fn default_cli_command(adapter_type: &str) -> &str {
    match adapter_type {
        "openai-cli" | "codex-cli" => "codex",
        "gemini-cli" => "gemini",
        "claude-cli" => "claude",
        "ollama-cli" => "ollama",
        _ => adapter_type,
    }
}

fn env_override_for_cli(adapter_type: &str) -> Option<String> {
    match adapter_type {
        "openai-cli" => {
            env_trimmed(DOCDEX_OPENAI_CLI_BIN).or_else(|| env_trimmed(DOCDEX_CODEX_BIN))
        }
        "codex-cli" => env_trimmed(DOCDEX_CODEX_BIN),
        "gemini-cli" => env_trimmed(DOCDEX_GEMINI_BIN),
        "claude-cli" => env_trimmed(DOCDEX_CLAUDE_BIN),
        "ollama-cli" => env_trimmed(DOCDEX_OLLAMA_BIN),
        _ => None,
    }
}

fn resolve_cli_command(agent: &McodaAgent, adapter_type: &str) -> String {
    env_override_for_cli(adapter_type)
        .or_else(|| non_empty_trimmed(agent.cli_binary.as_deref()))
        .or_else(|| config_string(agent.config.as_ref(), "binary"))
        .or_else(|| config_string(agent.config.as_ref(), "cliBinary"))
        .unwrap_or_else(|| default_cli_command(adapter_type).to_string())
}

fn ensure_cli_command_available(adapter_type: &str, command: &str) -> Result<()> {
    let command = command.trim();
    if command.is_empty() {
        return Err(anyhow!("configured command for {adapter_type} is empty"));
    }
    which(command).with_context(|| {
        format!("configured command for {adapter_type} not found or not executable: {command}")
    })?;
    Ok(())
}

pub struct OllamaRemoteClient {
    client: Client,
    base_url: String,
    headers: HashMap<String, String>,
    model: Option<String>,
    adapter: String,
}

impl OllamaRemoteClient {
    fn new(model: Option<String>, adapter: String, config: Option<&Value>) -> Result<Self> {
        let base_url = normalize_base_url(config_string(config, "baseUrl"))
            .or_else(default_ollama_base_url)
            .ok_or_else(|| {
                anyhow!("Ollama baseUrl is not configured; set config.baseUrl or DOCDEX_OLLAMA_BASE_URL")
            })?;
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(anyhow!(
                "Ollama baseUrl must start with http:// or https://"
            ));
        }
        let verify_tls = config_bool(config, "verifyTls");
        let client = build_http_client(verify_tls)?;
        Ok(Self {
            client,
            base_url,
            headers: config_headers(config),
            model,
            adapter,
        })
    }
}

impl LlmClient for OllamaRemoteClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        max_tokens: u32,
        timeout: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let model = self
                .model
                .as_ref()
                .ok_or_else(|| anyhow!("Ollama model is not configured for this agent"))?;
            let url = format!("{}/api/generate", self.base_url);
            let mut body = json!({
                "model": model,
                "prompt": prompt,
                "stream": false,
            });
            if max_tokens > 0 {
                if let Value::Object(ref mut obj) = body {
                    obj.insert("num_predict".to_string(), Value::from(max_tokens as i64));
                }
            }
            let mut request = self.client.post(url).timeout(timeout).json(&body);
            if !self.headers.is_empty() {
                request = request.headers(to_header_map(&self.headers)?);
            }
            let resp = request.send().await.map_err(|err| {
                anyhow!(
                    "ollama generate request failed for model {model} at {} with timeout {}ms: {err}",
                    self.base_url,
                    timeout.as_millis()
                )
            })?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!(
                    "ollama generate failed for model {model} at {} with timeout {}ms ({status}): {text}",
                    self.base_url,
                    timeout.as_millis()
                ));
            }
            let data: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            let output = data
                .get("response")
                .and_then(|value| value.as_str())
                .or_else(|| data.get("message").and_then(|value| value.as_str()))
                .unwrap_or_default()
                .trim()
                .to_string();
            Ok(LlmCompletion {
                output,
                adapter: self.adapter.clone(),
                model: Some(model.clone()),
                metadata: Some(data),
            })
        })
    }
}

pub struct OllamaCliClient {
    model: Option<String>,
    adapter: String,
    command: String,
}

impl OllamaCliClient {
    fn new(model: Option<String>, adapter: String, command: String) -> Self {
        Self {
            model,
            adapter,
            command,
        }
    }
}

impl LlmClient for OllamaCliClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        _max_tokens: u32,
        timeout_duration: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let model = self
                .model
                .as_ref()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| DEFAULT_OLLAMA_CLI_MODEL.to_string());
            let mut command = Command::new(self.command.as_str());
            command
                .arg("run")
                .arg(model.as_str())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn ollama CLI")?;
            if let Some(mut stdin) = child.stdin.take() {
                tokio::io::AsyncWriteExt::write_all(&mut stdin, prompt.as_bytes()).await?;
            }
            let output = timeout(timeout_duration, child.wait_with_output())
                .await
                .context("ollama CLI timeout")??;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "ollama CLI failed (exit {:?}): {}",
                    output.status.code(),
                    stderr.trim()
                ));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(LlmCompletion {
                output: stdout.trim().to_string(),
                adapter: self.adapter.clone(),
                model: Some(model),
                metadata: None,
            })
        })
    }
}

pub struct CodexCliClient {
    model: Option<String>,
    adapter: String,
    command: String,
}

impl CodexCliClient {
    fn new(model: Option<String>, adapter: String, command: String) -> Self {
        Self {
            model,
            adapter,
            command,
        }
    }
}

fn codex_cli_args(model: &str) -> [&str; 5] {
    ["exec", "--model", model, "--json", "-"]
}

fn codex_cli_timeout(timeout_duration: Duration) -> Duration {
    timeout_duration.max(CODEX_CLI_TIMEOUT_FLOOR)
}

fn gemini_cli_timeout(timeout_duration: Duration) -> Duration {
    timeout_duration.max(GEMINI_CLI_TIMEOUT_FLOOR)
}

fn should_inline_cli_prompt(prompt: &str) -> bool {
    !prompt.contains('\0') && prompt.len() <= CLI_INLINE_PROMPT_MAX_BYTES
}

async fn write_prompt_to_child_stdin(
    stdin: Option<tokio::process::ChildStdin>,
    prompt: &str,
) -> Result<()> {
    let Some(mut stdin) = stdin else {
        return Ok(());
    };
    tokio::io::AsyncWriteExt::write_all(&mut stdin, prompt.as_bytes()).await?;
    tokio::io::AsyncWriteExt::flush(&mut stdin).await?;
    tokio::io::AsyncWriteExt::shutdown(&mut stdin).await?;
    Ok(())
}

impl LlmClient for CodexCliClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        _max_tokens: u32,
        timeout_duration: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let timeout_duration = codex_cli_timeout(timeout_duration);
            let model = self
                .model
                .clone()
                .unwrap_or_else(|| DEFAULT_CODEX_MODEL.to_string());
            let mut command = Command::new(self.command.as_str());
            command.args(codex_cli_args(model.as_str()));
            command.stdin(Stdio::piped());
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn codex CLI")?;
            write_prompt_to_child_stdin(child.stdin.take(), prompt).await?;
            let output = timeout(timeout_duration, child.wait_with_output())
                .await
                .context("codex CLI timeout")??;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "codex CLI failed (exit {:?}): {}",
                    output.status.code(),
                    stderr.trim()
                ));
            }
            let raw = String::from_utf8_lossy(&output.stdout);
            let output_text = extract_codex_message(&raw).unwrap_or_else(|| {
                raw.lines()
                    .rev()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or_default()
                    .to_string()
            });
            Ok(LlmCompletion {
                output: output_text.trim().to_string(),
                adapter: self.adapter.clone(),
                model: Some(model),
                metadata: None,
            })
        })
    }
}

pub struct GeminiCliClient {
    model: Option<String>,
    adapter: String,
    command: String,
}

impl GeminiCliClient {
    fn new(model: Option<String>, adapter: String, command: String) -> Self {
        Self {
            model,
            adapter,
            command,
        }
    }
}

impl LlmClient for GeminiCliClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        _max_tokens: u32,
        timeout_duration: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let timeout_duration = gemini_cli_timeout(timeout_duration);
            let use_inline_prompt = should_inline_cli_prompt(prompt);
            let mut command = Command::new(self.command.as_str());
            command.arg("--output-format").arg("text");
            if let Some(model) = self.model.as_ref() {
                if !model.trim().is_empty() {
                    command.arg("--model").arg(model.as_str());
                }
            }
            if use_inline_prompt {
                command.arg("--prompt").arg(prompt).stdin(Stdio::null());
            } else {
                command.arg("--prompt").arg("").stdin(Stdio::piped());
            }
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn gemini CLI")?;
            if !use_inline_prompt {
                write_prompt_to_child_stdin(child.stdin.take(), prompt).await?;
            }
            let output = timeout(timeout_duration, child.wait_with_output())
                .await
                .context("gemini CLI timeout")??;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "gemini CLI failed (exit {:?}): {}",
                    output.status.code(),
                    stderr.trim()
                ));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(LlmCompletion {
                output: stdout.trim().to_string(),
                adapter: self.adapter.clone(),
                model: self.model.clone(),
                metadata: None,
            })
        })
    }
}

pub struct ClaudeCliClient {
    model: Option<String>,
    adapter: String,
    command: String,
}

impl ClaudeCliClient {
    fn new(model: Option<String>, adapter: String, command: String) -> Self {
        Self {
            model,
            adapter,
            command,
        }
    }
}

impl LlmClient for ClaudeCliClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        _max_tokens: u32,
        timeout_duration: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let mut command = Command::new(self.command.as_str());
            command.arg("--print").arg("--output-format").arg("text");
            if let Some(model) = self.model.as_ref() {
                if !model.trim().is_empty() {
                    command.arg("--model").arg(model.as_str());
                }
            }
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn claude CLI")?;
            if let Some(mut stdin) = child.stdin.take() {
                tokio::io::AsyncWriteExt::write_all(&mut stdin, prompt.as_bytes()).await?;
            }
            let output = timeout(timeout_duration, child.wait_with_output())
                .await
                .context("claude CLI timeout")??;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(anyhow!(
                    "claude CLI failed (exit {:?}): {}",
                    output.status.code(),
                    stderr.trim()
                ));
            }
            let stdout = String::from_utf8_lossy(&output.stdout);
            Ok(LlmCompletion {
                output: stdout.trim().to_string(),
                adapter: self.adapter.clone(),
                model: self.model.clone(),
                metadata: None,
            })
        })
    }
}

pub struct OpenAiApiClient {
    client: Client,
    base_url: String,
    headers: HashMap<String, String>,
    temperature: Option<f64>,
    thinking: Option<bool>,
    extra_body: Option<Value>,
    api_key: String,
    model: Option<String>,
    adapter: String,
}

impl OpenAiApiClient {
    fn new(
        model: Option<String>,
        adapter: String,
        config: Option<&Value>,
        api_key: String,
    ) -> Result<Self> {
        let base_url = normalize_base_url(config_string(config, "baseUrl"))
            .unwrap_or_else(|| DEFAULT_OPENAI_BASE_URL.to_string());
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(anyhow!(
                "OpenAI baseUrl must start with http:// or https://"
            ));
        }
        let verify_tls = config_bool(config, "verifyTls");
        Ok(Self {
            client: build_http_client(verify_tls)?,
            base_url,
            headers: config_headers(config),
            temperature: config_number(config, "temperature"),
            thinking: config_bool(config, "thinking"),
            extra_body: config_object(config, "extraBody"),
            api_key,
            model,
            adapter,
        })
    }
}

fn retry_after_ms_from_headers(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    if value.is_empty() {
        return None;
    }
    value
        .parse::<u64>()
        .ok()
        .map(|seconds| seconds.saturating_mul(1_000))
}

fn retry_after_ms_from_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| {
            value
                .as_i64()
                .filter(|candidate| *candidate >= 0)
                .map(|candidate| candidate as u64)
        })
        .or_else(|| {
            value
                .as_str()
                .and_then(|candidate| candidate.trim().parse::<u64>().ok())
        })
}

fn retry_after_ms_from_body_json(value: &Value) -> Option<u64> {
    value
        .get("retry_after_ms")
        .and_then(retry_after_ms_from_value)
        .or_else(|| {
            value
                .get("retryAfterMs")
                .and_then(retry_after_ms_from_value)
        })
        .or_else(|| value.get("error").and_then(retry_after_ms_from_body_json))
        .or_else(|| value.get("details").and_then(retry_after_ms_from_body_json))
}

fn openai_rate_limit_retry_after_ms(headers: &HeaderMap, body: &str) -> Option<u64> {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|value| retry_after_ms_from_body_json(&value))
        .or_else(|| retry_after_ms_from_headers(headers))
}

impl LlmClient for OpenAiApiClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        max_tokens: u32,
        timeout: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let model = self
                .model
                .as_ref()
                .ok_or_else(|| anyhow!("OpenAI model is not configured for this agent"))?;
            let url = format!("{}/chat/completions", self.base_url);
            let mut body = Map::from_iter([
                ("model".to_string(), Value::String(model.clone())),
                (
                    "messages".to_string(),
                    json!([{"role":"user","content": prompt}]),
                ),
                ("stream".to_string(), Value::Bool(false)),
            ]);
            if max_tokens > 0 {
                body.insert("max_tokens".to_string(), Value::from(max_tokens as i64));
            }
            if let Some(temp) = self.temperature {
                body.insert("temperature".to_string(), Value::from(temp));
            }
            if let Some(thinking) = self.thinking {
                body.insert("thinking".to_string(), Value::from(thinking));
            }
            merge_extra_body(&mut body, self.extra_body.as_ref());
            let headers = build_auth_headers(&self.headers, &self.api_key);
            let request_body = Value::Object(body);
            let deadline = Instant::now() + timeout;
            let mut attempt = 0usize;
            loop {
                attempt += 1;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(anyhow!("openai chat timeout"));
                }
                let mut request = self
                    .client
                    .post(url.as_str())
                    .timeout(remaining)
                    .json(&request_body);
                request = request.headers(to_header_map(&headers)?);
                let resp = request.send().await.context("openai chat request")?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let response_headers = resp.headers().clone();
                    let text = resp.text().await.unwrap_or_default();
                    if status == StatusCode::TOO_MANY_REQUESTS && attempt == 1 {
                        if let Some(retry_after_ms) =
                            openai_rate_limit_retry_after_ms(&response_headers, &text)
                        {
                            let retry_after = Duration::from_millis(retry_after_ms);
                            let remaining = deadline.saturating_duration_since(Instant::now());
                            if retry_after > Duration::ZERO && retry_after < remaining {
                                sleep(retry_after).await;
                                continue;
                            }
                        }
                    }
                    return Err(anyhow!("openai chat failed ({status}): {text}"));
                }
                let data: Value = resp.json().await.unwrap_or_else(|_| json!({}));
                let output = extract_chat_completion_output(&data)
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                return Ok(LlmCompletion {
                    output,
                    adapter: self.adapter.clone(),
                    model: Some(model.clone()),
                    metadata: Some(data),
                });
            }
        })
    }
}

pub struct ZhipuApiClient {
    client: Client,
    base_url: String,
    headers: HashMap<String, String>,
    temperature: Option<f64>,
    thinking: Option<Value>,
    extra_body: Option<Value>,
    api_key: String,
    model: Option<String>,
    adapter: String,
}

impl ZhipuApiClient {
    fn new(
        model: Option<String>,
        adapter: String,
        config: Option<&Value>,
        api_key: String,
    ) -> Result<Self> {
        let base_url = normalize_base_url(config_string(config, "baseUrl"))
            .unwrap_or_else(|| default_zhipu_base_url(model.as_deref()).to_string());
        if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
            return Err(anyhow!("Zhipu baseUrl must start with http:// or https://"));
        }
        let verify_tls = config_bool(config, "verifyTls");
        Ok(Self {
            client: build_http_client(verify_tls)?,
            base_url,
            headers: config_headers(config),
            temperature: config_number(config, "temperature").or(Some(0.1)),
            thinking: config_zhipu_thinking(config),
            extra_body: config_object(config, "extraBody"),
            api_key,
            model,
            adapter,
        })
    }
}

impl LlmClient for ZhipuApiClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        max_tokens: u32,
        timeout: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let model = self
                .model
                .as_ref()
                .ok_or_else(|| anyhow!("Zhipu model is not configured for this agent"))?;
            let url = format!("{}/chat/completions", self.base_url);
            let mut body = Map::from_iter([
                ("model".to_string(), Value::String(model.clone())),
                (
                    "messages".to_string(),
                    json!([{"role":"user","content": prompt}]),
                ),
                ("stream".to_string(), Value::Bool(false)),
            ]);
            if max_tokens > 0 {
                body.insert("max_tokens".to_string(), Value::from(max_tokens as i64));
            }
            if let Some(temp) = self.temperature {
                body.insert("temperature".to_string(), Value::from(temp));
            }
            if let Some(thinking) = self.thinking.clone() {
                body.insert("thinking".to_string(), thinking);
            }
            merge_extra_body(&mut body, self.extra_body.as_ref());
            let mut request = self
                .client
                .post(url)
                .timeout(timeout)
                .json(&Value::Object(body));
            let headers = build_auth_headers(&self.headers, &self.api_key);
            request = request.headers(to_header_map(&headers)?);
            let resp = request.send().await.context("zhipu chat request")?;
            if !resp.status().is_success() {
                let status = resp.status();
                let text = resp.text().await.unwrap_or_default();
                return Err(anyhow!("zhipu chat failed ({status}): {text}"));
            }
            let data: Value = resp.json().await.unwrap_or_else(|_| json!({}));
            let output = extract_chat_completion_output(&data)
                .unwrap_or_default()
                .trim()
                .to_string();
            Ok(LlmCompletion {
                output,
                adapter: self.adapter.clone(),
                model: Some(model.clone()),
                metadata: Some(data),
            })
        })
    }
}

fn extract_codex_message(raw: &str) -> Option<String> {
    let mut message = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(value) = serde_json::from_str::<Value>(trimmed) {
            let event_type = value.get("type").and_then(|val| val.as_str());
            let item = value.get("item");
            let item_type = item
                .and_then(|val| val.get("type"))
                .and_then(|val| val.as_str());
            let item_text = item
                .and_then(|val| val.get("text"))
                .and_then(|val| val.as_str());
            if event_type == Some("item.completed") && item_type == Some("agent_message") {
                if let Some(text) = item_text {
                    message = Some(text.to_string());
                }
            }
        }
    }
    message
}

fn extract_chat_completion_output(data: &Value) -> Option<String> {
    data.pointer("/choices/0/message/content")
        .and_then(extract_text_content)
        .or_else(|| {
            data.pointer("/choices/0/message/reasoning_content")
                .and_then(extract_text_content)
        })
        .or_else(|| {
            data.pointer("/choices/0/text")
                .and_then(extract_text_content)
        })
        .or_else(|| data.get("output_text").and_then(extract_text_content))
}

fn extract_text_content(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => {
            if text.trim().is_empty() {
                None
            } else {
                Some(text.clone())
            }
        }
        Value::Array(parts) => {
            let text = parts
                .iter()
                .filter_map(extract_text_content)
                .collect::<Vec<_>>()
                .join("");
            non_empty_trimmed(Some(text.as_str()))
        }
        Value::Object(map) => map
            .get("text")
            .and_then(extract_text_content)
            .or_else(|| map.get("content").and_then(extract_text_content))
            .or_else(|| map.get("reasoning_content").and_then(extract_text_content))
            .or_else(|| map.get("output_text").and_then(extract_text_content)),
        _ => None,
    }
}

fn build_http_client(verify_tls: Option<bool>) -> Result<Client> {
    let mut builder = Client::builder();
    if verify_tls == Some(false) {
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().context("build http client")
}

fn non_empty_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn env_trimmed(key: &str) -> Option<String> {
    match std::env::var(key) {
        Ok(value) => non_empty_trimmed(Some(value.as_str())),
        Err(_) => None,
    }
}

fn default_ollama_base_url() -> Option<String> {
    default_ollama_base_url_from_env(
        env_trimmed("DOCDEX_OLLAMA_BASE_URL"),
        env_trimmed("DOCDEX_EMBEDDING_BASE_URL"),
    )
}

fn default_ollama_base_url_from_env(
    ollama_base_url: Option<String>,
    embedding_base_url: Option<String>,
) -> Option<String> {
    normalize_base_url(ollama_base_url)
        .or_else(|| normalize_base_url(embedding_base_url))
        .or_else(|| Some(DEFAULT_LOCAL_OLLAMA_BASE_URL.to_string()))
}

fn config_string(config: Option<&Value>, key: &str) -> Option<String> {
    config
        .and_then(|value| value.get(key))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

fn config_value<'a>(config: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    config.and_then(|value| value.get(key))
}

fn config_bool(config: Option<&Value>, key: &str) -> Option<bool> {
    config
        .and_then(|value| value.get(key))
        .and_then(|value| value.as_bool())
}

fn config_number(config: Option<&Value>, key: &str) -> Option<f64> {
    config
        .and_then(|value| value.get(key))
        .and_then(|value| value.as_f64())
}

fn config_object(config: Option<&Value>, key: &str) -> Option<Value> {
    config
        .and_then(|value| value.get(key))
        .and_then(|value| value.as_object().cloned().map(Value::Object))
}

fn config_zhipu_thinking(config: Option<&Value>) -> Option<Value> {
    match config_value(config, "thinking") {
        Some(Value::Bool(true)) => Some(json!({ "type": "enabled" })),
        Some(Value::Bool(false)) => Some(json!({ "type": "disabled" })),
        Some(Value::Object(object)) if !object.is_empty() => Some(Value::Object(object.clone())),
        _ => None,
    }
}

fn config_headers(config: Option<&Value>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    let Some(value) = config.and_then(|value| value.get("headers")) else {
        return headers;
    };
    let Some(obj) = value.as_object() else {
        return headers;
    };
    for (key, value) in obj {
        if let Some(text) = value.as_str() {
            headers.insert(key.clone(), text.to_string());
        }
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::post;
    use axum::{Json, Router};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn codex_timeout_applies_floor() {
        assert_eq!(
            codex_cli_timeout(Duration::from_secs(8)),
            CODEX_CLI_TIMEOUT_FLOOR
        );
        assert_eq!(
            codex_cli_timeout(Duration::from_secs(300)),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn gemini_timeout_applies_floor() {
        assert_eq!(
            gemini_cli_timeout(Duration::from_secs(8)),
            GEMINI_CLI_TIMEOUT_FLOOR
        );
        assert_eq!(
            gemini_cli_timeout(Duration::from_secs(90)),
            Duration::from_secs(90)
        );
    }

    #[test]
    fn cli_prompt_is_inlined_only_for_small_safe_payloads() {
        assert!(should_inline_cli_prompt("format this code"));
        assert!(!should_inline_cli_prompt(
            &"x".repeat(CLI_INLINE_PROMPT_MAX_BYTES + 1)
        ));
        assert!(!should_inline_cli_prompt("bad\0prompt"));
    }

    #[test]
    fn zhipu_bool_thinking_maps_to_documented_object_shape() {
        let enabled = json!({ "thinking": true });
        let disabled = json!({ "thinking": false });
        assert_eq!(
            config_zhipu_thinking(Some(&enabled)),
            Some(json!({ "type": "enabled" }))
        );
        assert_eq!(
            config_zhipu_thinking(Some(&disabled)),
            Some(json!({ "type": "disabled" }))
        );
    }

    #[test]
    fn zhipu_object_thinking_is_preserved() {
        let config = json!({ "thinking": { "type": "enabled" } });
        assert_eq!(
            config_zhipu_thinking(Some(&config)),
            Some(json!({ "type": "enabled" }))
        );
    }

    #[test]
    fn zhipu_glm_47_defaults_to_coding_base_url() {
        assert_eq!(
            default_zhipu_base_url(Some("glm-4.7")),
            DEFAULT_ZHIPU_CODING_BASE_URL
        );
        assert_eq!(
            default_zhipu_base_url(Some("GLM-4.7-FLASH")),
            DEFAULT_ZHIPU_CODING_BASE_URL
        );
    }

    #[test]
    fn zhipu_non_coding_models_keep_standard_base_url() {
        assert_eq!(
            default_zhipu_base_url(Some("glm-4-air")),
            DEFAULT_ZHIPU_BASE_URL
        );
        assert_eq!(default_zhipu_base_url(None), DEFAULT_ZHIPU_BASE_URL);
    }

    #[test]
    fn ollama_remote_defaults_to_local_base_url_when_missing() {
        assert_eq!(
            default_ollama_base_url_from_env(None, None),
            Some(DEFAULT_LOCAL_OLLAMA_BASE_URL.to_string())
        );
    }

    #[test]
    fn structured_chat_content_parts_are_flattened() {
        let payload = json!([
            { "type": "text", "text": "What" },
            { "type": "text", "text": " is 2+2?" }
        ]);
        assert_eq!(
            extract_text_content(&payload),
            Some("What is 2+2?".to_string())
        );
    }

    #[test]
    fn chat_completion_output_accepts_structured_content_and_reasoning_parts() {
        let openai_payload = json!({
            "choices": [{
                "message": {
                    "content": [
                        { "type": "text", "text": "4" }
                    ]
                }
            }]
        });
        assert_eq!(
            extract_chat_completion_output(&openai_payload),
            Some("4".to_string())
        );

        let zhipu_payload = json!({
            "choices": [{
                "message": {
                    "reasoning_content": [
                        { "type": "text", "text": "step 1" },
                        { "type": "text", "text": ", step 2" }
                    ]
                }
            }]
        });
        assert_eq!(
            extract_chat_completion_output(&zhipu_payload),
            Some("step 1, step 2".to_string())
        );
    }

    #[test]
    fn codex_cli_args_do_not_enable_full_auto() {
        let args = codex_cli_args("gpt-5.1-codex-max");
        assert_eq!(
            args,
            ["exec", "--model", "gpt-5.1-codex-max", "--json", "-"]
        );
        assert!(!args.contains(&"--full-auto"));
    }

    #[test]
    fn ensure_cli_command_available_rejects_missing_binary() {
        let err = ensure_cli_command_available("codex-cli", "/definitely/missing/docdex-codex")
            .expect_err("missing binary should fail");
        let message = err.to_string();
        assert!(message.contains("codex-cli"));
        assert!(message.contains("not found"));
    }

    #[test]
    fn ensure_cli_command_available_accepts_existing_binary() {
        let current_exe = std::env::current_exe().expect("current exe");
        ensure_cli_command_available("codex-cli", &current_exe.to_string_lossy())
            .expect("existing executable should pass");
    }

    #[tokio::test]
    async fn openai_api_client_retries_rate_limited_response_when_retry_after_fits_timeout() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let app = Router::new().route(
            "/chat/completions",
            post({
                let attempts = Arc::clone(&attempts);
                move || {
                    let attempts = Arc::clone(&attempts);
                    async move {
                        let attempt = attempts.fetch_add(1, Ordering::SeqCst);
                        if attempt == 0 {
                            (
                                StatusCode::TOO_MANY_REQUESTS,
                                Json(json!({
                                    "error": "mswarm_error",
                                    "code": "rate_limited",
                                    "retry_after_ms": 1
                                })),
                            )
                                .into_response()
                        } else {
                            (
                                StatusCode::OK,
                                Json(json!({
                                    "choices": [{
                                        "message": { "content": "ok" }
                                    }]
                                })),
                            )
                                .into_response()
                        }
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let config = json!({ "baseUrl": format!("http://{}", address) });
        let client = OpenAiApiClient::new(
            Some("test-model".to_string()),
            "openai-api".to_string(),
            Some(&config),
            "test-key".to_string(),
        )
        .expect("openai client");
        let completion = client
            .generate("hello", 32, Duration::from_secs(2))
            .await
            .expect("completion");

        assert_eq!(completion.output, "ok");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn local_openai_compatible_adapter_omits_authorization_when_api_key_is_empty() {
        let app = Router::new().route(
            "/chat/completions",
            post(|headers: HeaderMap| async move {
                assert!(headers.get("authorization").is_none());
                (
                    StatusCode::OK,
                    Json(json!({
                        "choices": [{
                            "message": { "content": "local-ok" }
                        }]
                    })),
                )
                    .into_response()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let address = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve test app");
        });

        let client = resolve_local_openai_compatible_adapter(
            &format!("http://{address}"),
            "qwen3.6-coder",
            "llama-cpp",
        )
        .expect("local adapter");
        let completion = client
            .generate("hello", 32, Duration::from_secs(2))
            .await
            .expect("completion");

        assert_eq!(completion.output, "local-ok");
        server.abort();
    }
}

fn build_auth_headers(headers: &HashMap<String, String>, api_key: &str) -> HashMap<String, String> {
    let mut out = headers.clone();
    let api_key = api_key.trim();
    if !api_key.is_empty() {
        out.entry("Authorization".to_string())
            .or_insert_with(|| format!("Bearer {api_key}"));
    }
    out.entry("Content-Type".to_string())
        .or_insert_with(|| "application/json".to_string());
    out
}

fn to_header_map(headers: &HashMap<String, String>) -> Result<reqwest::header::HeaderMap> {
    let mut map = reqwest::header::HeaderMap::new();
    for (key, value) in headers {
        let name = reqwest::header::HeaderName::from_bytes(key.as_bytes())
            .context("invalid header name")?;
        let value =
            reqwest::header::HeaderValue::from_str(value).context("invalid header value")?;
        map.insert(name, value);
    }
    Ok(map)
}

fn normalize_base_url(value: Option<String>) -> Option<String> {
    value
        .map(|raw| raw.trim().trim_end_matches('/').to_string())
        .filter(|raw| !raw.is_empty())
}

fn default_zhipu_base_url(model: Option<&str>) -> &'static str {
    if zhipu_model_uses_coding_endpoint(model) {
        DEFAULT_ZHIPU_CODING_BASE_URL
    } else {
        DEFAULT_ZHIPU_BASE_URL
    }
}

fn zhipu_model_uses_coding_endpoint(model: Option<&str>) -> bool {
    model
        .map(|value| value.trim().to_ascii_lowercase())
        .map(|value| value == "glm-4.7" || value.starts_with("glm-4.7-"))
        .unwrap_or(false)
}

fn merge_extra_body(target: &mut Map<String, Value>, extra: Option<&Value>) {
    let Some(extra) = extra else {
        return;
    };
    let Some(extra_obj) = extra.as_object() else {
        return;
    };
    for (key, value) in extra_obj {
        if !target.contains_key(key) {
            target.insert(key.clone(), value.clone());
        }
    }
}
