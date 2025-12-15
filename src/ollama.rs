use crate::error::{
    AppError, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT,
    ERR_INVALID_ARGUMENT,
};
use anyhow::{anyhow, Context};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct OllamaClient {
    host_header: String,
    connect_addr: String,
    path_prefix: String,
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
            return Err(AppError::new(
                ERR_EMBEDDING_FAILED,
                "embedding model is not configured",
            )
            .into());
        }
        if prompt.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "prompt must not be empty").into());
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
        let result = tokio::time::timeout(timeout, async move {
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

            if !(200..300).contains(&status_code) {
                let body_text = String::from_utf8_lossy(&response_body);
                let lowered = body_text.to_ascii_lowercase();
                if status_code == 404 || lowered.contains("not found") || lowered.contains("model") {
                    return Err(AppError::new(
                        ERR_EMBEDDING_MODEL_NOT_FOUND,
                        format!("ollama embedding model not found: {model}"),
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
        })
        .await;

        match result {
            Ok(value) => value,
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
            port_str
                .parse::<u16>()
                .context("parse port")?
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
        let Some(line_end) = input
            .windows(2)
            .position(|w| w == b"\r\n")
        else {
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
