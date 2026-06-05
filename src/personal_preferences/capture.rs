use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct PersonalPreferencesArchiveEnvelope {
    pub(super) capture_id: String,
    pub(super) created_at_ms: i64,
    pub(super) request: PersonalPreferencesCaptureRequest,
}

#[derive(Debug, Clone)]
pub(super) struct ContentCipher {
    env_name: String,
    key_id: String,
    key_bytes: [u8; 32],
}

pub(super) fn resolve_content_cipher(env_name: Option<&str>) -> Option<ContentCipher> {
    let env_name = env_name
        .map(str::trim)
        .filter(|value| !value.is_empty())?
        .to_string();
    let raw_secret = std::env::var(&env_name).ok()?;
    let key_bytes = derive_cipher_key(&raw_secret);
    Some(ContentCipher {
        key_id: sha256_hex(&raw_secret)[..16].to_string(),
        env_name,
        key_bytes,
    })
}

fn derive_cipher_key(secret: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest[..32]);
    key
}

pub(super) fn prepare_capture_request_for_storage(
    mut request: PersonalPreferencesCaptureRequest,
    secret_scrubber_enabled: bool,
    cipher: Option<&ContentCipher>,
) -> PersonalPreferencesCaptureRequest {
    let transcript_text = request
        .transcript_text
        .take()
        .map(|value| maybe_scrub_secret_text(value, secret_scrubber_enabled));
    let summary_text = request
        .summary_text
        .take()
        .map(|value| maybe_scrub_secret_text(value, secret_scrubber_enabled));
    let messages = request
        .messages
        .into_iter()
        .map(|mut message| {
            message.content = maybe_scrub_secret_text(message.content, secret_scrubber_enabled);
            message
        })
        .collect::<Vec<_>>();
    request.transcript_text = transcript_text;
    request.summary_text = summary_text;
    request.messages = messages;
    let mut metadata = request.metadata.as_object().cloned().unwrap_or_default();
    let mut subsystem = metadata
        .remove("_docdex_personal_preferences")
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    subsystem.insert(
        "secret_scrubber_enabled".to_string(),
        Value::Bool(secret_scrubber_enabled),
    );
    if let Some(cipher) = cipher {
        subsystem.insert("content_encrypted".to_string(), Value::Bool(true));
        subsystem.insert(
            "content_encryption_key_env".to_string(),
            Value::String(cipher.env_name.clone()),
        );
        subsystem.insert(
            "content_encryption_key_id".to_string(),
            Value::String(cipher.key_id.clone()),
        );
    }
    if let Some(external_ref) = external_ref_for_capture_request(&request) {
        subsystem.insert("external_ref".to_string(), Value::String(external_ref));
    }
    metadata.insert(
        "_docdex_personal_preferences".to_string(),
        Value::Object(subsystem),
    );
    request.metadata = Value::Object(metadata);
    request
}

fn maybe_scrub_secret_text(input: String, enabled: bool) -> String {
    if !enabled {
        return input;
    }
    scrub_secret_text(&input)
}

fn scrub_secret_text(input: &str) -> String {
    let mut output = input.to_string();
    for pattern in TRANSCRIPT_SECRET_PATTERNS.iter() {
        output = pattern
            .replace_all(&output, "[redacted_secret]")
            .into_owned();
    }
    output
}

pub(super) fn protect_text_for_storage(text: &str, cipher: Option<&ContentCipher>) -> String {
    let text = text.trim();
    if text.is_empty() {
        return String::new();
    }
    let Some(cipher) = cipher else {
        return text.to_string();
    };
    encrypt_text(cipher, text).unwrap_or_else(|_| text.to_string())
}

pub(super) fn unprotect_text_for_reading(text: &str, cipher: Option<&ContentCipher>) -> String {
    if !text.starts_with(ENCRYPTED_PREFIX) {
        return text.to_string();
    }
    let Some(cipher) = cipher else {
        return ENCRYPTED_UNAVAILABLE_TEXT.to_string();
    };
    decrypt_text(cipher, text).unwrap_or_else(|_| ENCRYPTED_UNREADABLE_TEXT.to_string())
}

fn encrypt_text(cipher: &ContentCipher, text: &str) -> Result<String> {
    let aes = Aes256Gcm::new_from_slice(&cipher.key_bytes)
        .context("initialize personal preferences content cipher")?;
    let nonce_seed = Uuid::new_v4().into_bytes();
    let nonce = Nonce::from_slice(&nonce_seed[..12]);
    let ciphertext = aes
        .encrypt(nonce, text.as_bytes())
        .map_err(|err| anyhow!("encrypt personal preferences content: {err}"))?;
    Ok(format!(
        "{ENCRYPTED_PREFIX}{}:{}:{}",
        cipher.key_id,
        Base64Engine.encode(&nonce_seed[..12]),
        Base64Engine.encode(ciphertext)
    ))
}

fn decrypt_text(cipher: &ContentCipher, text: &str) -> Result<String> {
    let payload = text
        .strip_prefix(ENCRYPTED_PREFIX)
        .ok_or_else(|| anyhow!("missing encrypted prefix"))?;
    let mut parts = payload.splitn(3, ':');
    let key_id = parts.next().unwrap_or_default();
    let nonce_b64 = parts.next().unwrap_or_default();
    let ciphertext_b64 = parts.next().unwrap_or_default();
    if key_id != cipher.key_id {
        return Err(anyhow!("content encryption key mismatch"));
    }
    let nonce_bytes = Base64Engine
        .decode(nonce_b64)
        .context("decode content nonce")?;
    if nonce_bytes.len() != 12 {
        return Err(anyhow!("invalid content nonce length"));
    }
    let ciphertext = Base64Engine
        .decode(ciphertext_b64)
        .context("decode encrypted content")?;
    let aes = Aes256Gcm::new_from_slice(&cipher.key_bytes)
        .context("initialize personal preferences decrypt cipher")?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = aes
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|err| anyhow!("decrypt personal preferences content: {err}"))?;
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

pub(super) fn resolve_cipher_from_metadata(metadata: &Value) -> Option<ContentCipher> {
    metadata
        .get("_docdex_personal_preferences")
        .and_then(Value::as_object)
        .and_then(|value| value.get("content_encryption_key_env"))
        .and_then(Value::as_str)
        .and_then(|value| resolve_content_cipher(Some(value)))
}

pub(super) fn protect_capture_request_payload(
    request: &PersonalPreferencesCaptureRequest,
    cipher: Option<&ContentCipher>,
) -> PersonalPreferencesCaptureRequest {
    let mut payload = request.clone();
    payload.transcript_text = payload
        .transcript_text
        .map(|value| protect_text_for_storage(&value, cipher));
    payload.summary_text = payload
        .summary_text
        .map(|value| protect_text_for_storage(&value, cipher));
    payload.messages = payload
        .messages
        .into_iter()
        .map(|mut message| {
            message.content = protect_text_for_storage(&message.content, cipher);
            message
        })
        .collect();
    payload
}

pub(super) fn hydrate_capture_content(capture: &mut PersonalPreferencesCaptureRecord) {
    let cipher = resolve_cipher_from_metadata(&capture.metadata);
    capture.transcript_text = unprotect_text_for_reading(&capture.transcript_text, cipher.as_ref());
}

pub(super) fn upsert_source_and_session_lineage(
    conn: &Connection,
    capture_id: &str,
    request: &PersonalPreferencesCaptureRequest,
    digest_status: &str,
    now: i64,
) -> Result<()> {
    let normalized_source = slugify_identifier(&request.source);
    let source_id = if normalized_source.is_empty() {
        "manual".to_string()
    } else {
        normalized_source
    };
    let source_type = if is_supported_client_transcript_source(&request.source) {
        "supported_client"
    } else if request
        .capture_kind
        .as_deref()
        .unwrap_or_default()
        .contains("hook")
    {
        "docdex_hook"
    } else if request
        .capture_kind
        .as_deref()
        .unwrap_or_default()
        .contains("import")
    {
        "conversation_import"
    } else {
        "docdex"
    };
    let external_ref = external_ref_for_capture_request(request);
    let external_ref_hash = external_ref.as_deref().map(sha256_hex);
    conn.execute(
        "INSERT INTO pp_sources(
            source_id, source_type, client_kind, agent_kind, enabled, last_seen_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6)
         ON CONFLICT(source_id) DO UPDATE SET
            source_type = excluded.source_type,
            client_kind = excluded.client_kind,
            agent_kind = excluded.agent_kind,
            enabled = excluded.enabled,
            last_seen_at_ms = excluded.last_seen_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            source_id,
            source_type,
            slugify_identifier(&request.source),
            request.agent_id.clone().unwrap_or_default(),
            now,
            serde_json::to_string(&json!({
                "source": request.source,
                "capture_kind": request.capture_kind,
                "transport": request.transport,
            }))?,
        ],
    )?;
    conn.execute(
        "INSERT INTO pp_sessions(
            capture_id, source_id, source_session_id, external_ref, external_ref_hash,
            capture_kind, title, digest_status, sensitivity_summary, started_at_ms,
            ended_at_ms, created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, ?9, ?10, ?11, ?11, ?12)
         ON CONFLICT(capture_id) DO UPDATE SET
            source_id = excluded.source_id,
            source_session_id = excluded.source_session_id,
            external_ref = excluded.external_ref,
            external_ref_hash = excluded.external_ref_hash,
            capture_kind = excluded.capture_kind,
            title = excluded.title,
            digest_status = excluded.digest_status,
            started_at_ms = excluded.started_at_ms,
            ended_at_ms = excluded.ended_at_ms,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            capture_id,
            source_id,
            request.source_session_id,
            external_ref,
            external_ref_hash,
            request.capture_kind,
            request.title,
            digest_status,
            request.started_at_ms,
            request.ended_at_ms,
            now,
            serde_json::to_string(&request.metadata)?,
        ],
    )?;
    Ok(())
}

pub(super) fn external_ref_for_capture_request(
    request: &PersonalPreferencesCaptureRequest,
) -> Option<String> {
    request
        .metadata
        .get("_docdex_personal_preferences")
        .and_then(Value::as_object)
        .and_then(|value| value.get("external_ref"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .or_else(|| {
            request
                .metadata
                .get("external_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            request
                .metadata
                .get("client_transcript_path")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .or_else(|| {
            request
                .source_session_id
                .as_deref()
                .map(|value| format!("{}:{value}", request.source))
        })
}
