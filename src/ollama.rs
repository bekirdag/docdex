use crate::error::{
    AppError, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT,
    ERR_INVALID_ARGUMENT,
};
use crate::max_size::truncate_utf8_chars;
use anyhow::{anyhow, Context};
use serde::Deserialize;
use serde_json::json;
use serde_json::Value;
use std::collections::HashSet;
use std::env;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

#[derive(Clone)]
pub struct OllamaClient {
    host_header: String,
    connect_addr: String,
    path_prefix: String,
}

#[derive(Clone)]
pub struct OllamaEmbedder {
    client: OllamaClient,
    model: String,
    timeout: Duration,
}

impl OllamaClient {
    pub fn new(base_url: String) -> Result<Self, anyhow::Error> {
        let trimmed = base_url.trim().trim_end_matches('/');
        if trimmed.is_empty() {
            anyhow::bail!("ollama base_url must not be empty");
        }
        let without_scheme = trimmed
            .strip_prefix("http://")
            .ok_or_else(|| anyhow!("only http:// base URLs are supported (got {trimmed})"))?;
        let (authority, prefix) = match without_scheme.split_once('/') {
            Some((host, path)) => (host, format!("/{}", path.trim_matches('/'))),
            None => (without_scheme, String::new()),
        };

        let (host_header, connect_addr) = parse_authority(authority)?;
        Ok(Self {
            host_header,
            connect_addr,
            path_prefix: prefix,
        })
    }

    pub async fn embed(
        &self,
        model: &str,
        prompt: &str,
        timeout: Duration,
    ) -> Result<Vec<f32>, anyhow::Error> {
        let model = model.trim();
        if model.is_empty() {
            return Err(
                AppError::new(ERR_EMBEDDING_FAILED, "embedding model is not configured").into(),
            );
        }
        if prompt.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "prompt must not be empty").into());
        }
        if llm_debug_enabled() {
            let (snippet, _) = truncate_utf8_chars(prompt, llm_debug_max_chars());
            debug!(
                "ollama embed request model={} prompt_len={} prompt_snippet={}",
                model,
                prompt.len(),
                snippet
            );
        }

        let payload = json!({
            "model": model,
            "prompt": prompt,
        });
        let body = serde_json::to_vec(&payload).context("serialize ollama embeddings request")?;

        let path = if self.path_prefix.is_empty() {
            "/api/embeddings".to_string()
        } else {
            format!("{}/api/embeddings", self.path_prefix)
        };

        let host_header = self.host_header.clone();
        let connect_addr = self.connect_addr.clone();
        let embed_task = async move {
            let mut stream = TcpStream::connect(&connect_addr)
                .await
                .context("connect to ollama")?;

            let headers = format!(
                "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
                host = host_header,
                len = body.len()
            );
            stream
                .write_all(headers.as_bytes())
                .await
                .context("write request headers")?;
            stream.write_all(&body).await.context("write request body")?;
            stream.flush().await.ok();

            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await.context("read response")?;
            let (status_code, response_body) = parse_http_response(&raw)?;

            if let Some(error_message) = ollama_error_message(&response_body) {
                let error_message = redact_embedding_prompt(error_message, prompt);
                if is_ollama_model_not_found_error(&error_message) {
                    return Err(AppError::new(
                        ERR_EMBEDDING_MODEL_NOT_FOUND,
                        format!("ollama embedding model not found: {model}"),
                    )
                    .into());
                }
                return Err(AppError::new(
                    ERR_EMBEDDING_FAILED,
                    format!("ollama embedding request failed: {error_message}"),
                )
                .into());
            }

            if !(200..300).contains(&status_code) {
                let body_text = String::from_utf8_lossy(&response_body);
                let lowered = body_text.to_ascii_lowercase();
                if is_ollama_model_not_found_error(&lowered) {
                    return Err(AppError::new(
                        ERR_EMBEDDING_MODEL_NOT_FOUND,
                        format!("ollama embedding model not found: {model}"),
                    )
                    .into());
                }
                if status_code == 404 || lowered.contains("not found") {
                    return Err(AppError::new(
                        ERR_EMBEDDING_FAILED,
                        "ollama embeddings endpoint not found; check --embedding-base-url/--ollama-base-url",
                    )
                    .into());
                }
                return Err(AppError::new(
                    ERR_EMBEDDING_FAILED,
                    format!("ollama embedding request failed (status {status_code})"),
                )
                .into());
            }

            #[derive(Deserialize)]
            struct EmbeddingResponse {
                embedding: Vec<f32>,
            }

            let parsed: EmbeddingResponse =
                serde_json::from_slice(&response_body).context("parse ollama embeddings response")?;
            if parsed.embedding.is_empty() {
                return Err(AppError::new(ERR_EMBEDDING_FAILED, "ollama returned empty embedding")
                    .into());
            }
            Ok(parsed.embedding)
        };

        let result: Result<Result<Vec<f32>, anyhow::Error>, tokio::time::error::Elapsed> =
            if timeout.is_zero() {
                Ok(embed_task.await)
            } else {
                tokio::time::timeout(timeout, embed_task).await
            };

        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => {
                if err.downcast_ref::<AppError>().is_some() {
                    return Err(err);
                }
                // Harden error surfaces: never leak embedding inputs via error strings.
                let message = redact_embedding_prompt(err.to_string(), prompt);
                Err(AppError::new(
                    ERR_EMBEDDING_FAILED,
                    format!("ollama embedding request failed: {message}"),
                )
                .into())
            }
            Err(_) => Err(AppError::new(
                ERR_EMBEDDING_TIMEOUT,
                format!(
                    "ollama embedding request timed out after {}ms",
                    timeout.as_millis()
                ),
            )
            .into()),
        }
    }

    pub async fn generate(
        &self,
        model: &str,
        prompt: &str,
        max_tokens: u32,
        timeout: Duration,
    ) -> Result<String, anyhow::Error> {
        let model = model.trim();
        if model.is_empty() {
            anyhow::bail!("ollama model is not configured");
        }
        let prompt = prompt.trim();
        if prompt.is_empty() {
            anyhow::bail!("ollama prompt must not be empty");
        }
        if llm_debug_enabled() {
            let (snippet, _) = truncate_utf8_chars(prompt, llm_debug_max_chars());
            debug!(
                "ollama generate request model={} max_tokens={} prompt_len={} prompt_snippet={}",
                model,
                max_tokens,
                prompt.len(),
                snippet
            );
        }

        let num_predict = max_tokens.max(1) as i64;
        let payload = json!({
            "model": model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "num_predict": num_predict,
            },
        });
        let body = serde_json::to_vec(&payload).context("serialize ollama generate request")?;

        let path = if self.path_prefix.is_empty() {
            "/api/generate".to_string()
        } else {
            format!("{}/api/generate", self.path_prefix)
        };

        let host_header = self.host_header.clone();
        let connect_addr = self.connect_addr.clone();
        let result: Result<Result<String, anyhow::Error>, tokio::time::error::Elapsed> =
            tokio::time::timeout(timeout, async move {
                let mut stream = TcpStream::connect(&connect_addr)
                    .await
                    .context("connect to ollama")?;

                let headers = format!(
                    "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n",
                    host = host_header,
                    len = body.len()
                );
                stream
                    .write_all(headers.as_bytes())
                    .await
                    .context("write request headers")?;
                stream.write_all(&body).await.context("write request body")?;
                stream.flush().await.ok();

                let mut raw = Vec::new();
                stream.read_to_end(&mut raw).await.context("read response")?;
                let (status_code, response_body) = parse_http_response(&raw)?;

                if let Some(error_message) = ollama_error_message(&response_body) {
                    return Err(anyhow!("ollama generate request failed: {error_message}"));
                }

                if !(200..300).contains(&status_code) {
                    return Err(anyhow!(
                        "ollama generate request failed (status {status_code})"
                    ));
                }

                #[derive(Deserialize)]
                struct GenerateResponse {
                    response: String,
                }

                let parsed: GenerateResponse =
                    serde_json::from_slice(&response_body).context("parse ollama generate response")?;
                let response = parsed.response.trim();
                if response.is_empty() {
                    return Err(anyhow!("ollama generate returned empty response"));
                }
                Ok(response.to_string())
            })
            .await;

        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(err)) => Err(err),
            Err(_) => Err(anyhow!(
                "ollama generate request timed out after {}ms",
                timeout.as_millis()
            )),
        }
    }
}

pub async fn check_reachable(base_url: &str, timeout: Duration) -> Result<(), anyhow::Error> {
    let client = OllamaClient::new(base_url.to_string())?;
    let connect_addr = client.connect_addr.clone();
    let result = tokio::time::timeout(timeout, TcpStream::connect(&connect_addr)).await;
    match result {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err)
            .with_context(|| format!("connect to ollama at {base_url} (resolved {connect_addr})")),
        Err(_) => Err(anyhow!(
            "connect to ollama timed out after {}ms (base_url {base_url})",
            timeout.as_millis()
        )),
    }
}

pub async fn list_models(
    base_url: &str,
    timeout: Duration,
) -> Result<HashSet<String>, anyhow::Error> {
    let client = OllamaClient::new(base_url.to_string())?;
    let path = if client.path_prefix.is_empty() {
        "/api/tags".to_string()
    } else {
        format!("{}/api/tags", client.path_prefix)
    };
    let host_header = client.host_header.clone();
    let connect_addr = client.connect_addr.clone();
    let result: Result<Result<HashSet<String>, anyhow::Error>, tokio::time::error::Elapsed> =
        tokio::time::timeout(timeout, async move {
            let mut stream = TcpStream::connect(&connect_addr)
                .await
                .context("connect to ollama")?;
            let headers = format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
                host = host_header
            );
            stream
                .write_all(headers.as_bytes())
                .await
                .context("write request headers")?;
            stream.flush().await.ok();
            let mut raw = Vec::new();
            stream.read_to_end(&mut raw).await.context("read response")?;
            let (status_code, response_body) = parse_http_response(&raw)?;
            if let Some(error_message) = ollama_error_message(&response_body) {
                return Err(anyhow!("ollama tags request failed: {error_message}"));
            }
            if !(200..300).contains(&status_code) {
                return Err(anyhow!(
                    "ollama tags request failed (status {status_code})"
                ));
            }

            #[derive(Deserialize)]
            struct TagsResponse {
                models: Vec<TagsModel>,
            }

            #[derive(Deserialize)]
            struct TagsModel {
                name: String,
            }

            let parsed: TagsResponse =
                serde_json::from_slice(&response_body).context("parse ollama tags response")?;
            let mut models = HashSet::new();
            for model in parsed.models {
                let name = model.name.trim();
                if !name.is_empty() {
                    models.insert(name.to_string());
                }
            }
            Ok(models)
        })
        .await;

    match result {
        Ok(Ok(models)) => Ok(models),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(anyhow!(
            "ollama tags request timed out after {}ms",
            timeout.as_millis()
        )),
    }
}

fn llm_debug_enabled() -> bool {
    env_boolish("DOCDEX_LLM_DEBUG").unwrap_or(false)
        || env_boolish("DOCDEX_WEB_DEBUG").unwrap_or(false)
}

fn llm_debug_max_chars() -> usize {
    env_usize("DOCDEX_LLM_DEBUG_MAX_CHARS").unwrap_or(2000).max(1)
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_usize(key: &str) -> Option<usize> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok()
}

impl OllamaEmbedder {
    pub fn new(base_url: String, model: String, timeout: Duration) -> Result<Self, anyhow::Error> {
        let model = model.trim().to_string();
        if model.is_empty() {
            return Err(
                AppError::new(ERR_EMBEDDING_FAILED, "embedding model is not configured").into(),
            );
        }
        Ok(Self {
            client: OllamaClient::new(base_url)?,
            model,
            timeout,
        })
    }

    pub fn provider(&self) -> &'static str {
        "ollama"
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    pub async fn embed(&self, prompt: &str) -> Result<Vec<f32>, anyhow::Error> {
        self.client.embed(&self.model, prompt, self.timeout).await
    }
}

fn parse_authority(authority: &str) -> Result<(String, String), anyhow::Error> {
    let authority = authority.trim();
    if authority.is_empty() {
        anyhow::bail!("invalid base URL: missing host");
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| anyhow!("invalid IPv6 authority (missing ']')"))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            80
        } else if let Some(port_str) = after.strip_prefix(':') {
            port_str.parse::<u16>().context("parse port")?
        } else {
            anyhow::bail!("invalid IPv6 authority");
        };
        let host_header = format!("[{host}]:{port}");
        let connect_addr = host_header.clone();
        return Ok((host_header, connect_addr));
    }

    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if !host.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            let port = port_str.parse::<u16>().context("parse port")?;
            let host_header = format!("{host}:{port}");
            let connect_addr = host_header.clone();
            return Ok((host_header, connect_addr));
        }
    }

    let host = authority;
    let port = 80u16;

    let host = host.trim();
    if host.is_empty() {
        anyhow::bail!("invalid base URL: missing host");
    }
    let host_header = format!("{host}:{port}");
    let connect_addr = host_header.clone();
    Ok((host_header, connect_addr))
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), anyhow::Error> {
    let delimiter = b"\r\n\r\n";
    let Some(pos) = raw.windows(delimiter.len()).position(|w| w == delimiter) else {
        return Err(anyhow!("invalid HTTP response (missing header delimiter)"));
    };
    let header = &raw[..pos];
    let body = &raw[pos + delimiter.len()..];
    let header_text = String::from_utf8_lossy(header);
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("invalid HTTP response (missing status line)"))?;
    let mut parts = status_line.split_whitespace();
    let _http_version = parts.next().unwrap_or("");
    let status = parts
        .next()
        .ok_or_else(|| anyhow!("invalid HTTP status line"))?
        .parse::<u16>()
        .context("parse HTTP status code")?;

    let mut is_chunked = false;
    for line in lines {
        let lower = line.trim().to_ascii_lowercase();
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            is_chunked = true;
        }
    }

    let body = if is_chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    Ok((status, body))
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut out = Vec::new();
    loop {
        let Some(line_end) = input.windows(2).position(|w| w == b"\r\n") else {
            return Err(anyhow!("invalid chunked encoding (missing size line)"));
        };
        let size_line = &input[..line_end];
        input = &input[line_end + 2..];
        let size_str = String::from_utf8_lossy(size_line);
        let size_str = size_str.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16).context("parse chunk size")?;
        if size == 0 {
            break;
        }
        if input.len() < size + 2 {
            return Err(anyhow!("invalid chunked encoding (truncated chunk)"));
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..]; // skip chunk + trailing \r\n
    }
    Ok(out)
}

fn redact_embedding_prompt(message: String, prompt: &str) -> String {
    let prompt = prompt.trim();
    if prompt.is_empty() {
        return message;
    }
    if message.contains(prompt) {
        return message.replace(prompt, "<redacted>");
    }
    message
}

fn ollama_error_message(response_body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(response_body).ok()?;
    let error = value.get("error").and_then(|v| v.as_str()).map(str::trim);
    let message = value.get("message").and_then(|v| v.as_str()).map(str::trim);
    error
        .or(message)
        .filter(|text| !text.is_empty())
        .map(|text| text.to_string())
}

fn is_ollama_model_not_found_error(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    lowered.contains("model") && (lowered.contains("not found") || lowered.contains("unknown"))
}

#[cfg(test)]
mod tests;
