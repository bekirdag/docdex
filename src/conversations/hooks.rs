use crate::conversations::{
    import_conversation_with_routing_options, normalize_import_request, record_diary_entry_episode,
    write_diary_entry, ConversationHookEnqueueResult, ConversationHookPayload,
    ConversationImportEnvelope, ConversationImportOptions, ConversationRouteTargets,
    ConversationStore,
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::time::Instant;
use tracing::warn;

pub async fn enqueue_conversation_hook(
    store: ConversationStore,
    payload: ConversationHookPayload,
    import_options: ConversationImportOptions,
    targets: ConversationRouteTargets,
    wait_for_processing: bool,
) -> Result<ConversationHookEnqueueResult> {
    let started = Instant::now();
    let queued = tokio::task::spawn_blocking({
        let store = store.clone();
        let payload = payload.clone();
        move || store.enqueue_hook_event(&payload)
    })
    .await??;
    if let Err(err) = record_hook_episode(&targets, &queued, &payload, "queued").await {
        warn!(
            target: "docdexd",
            event_id = %queued.event_id,
            error = ?err,
            "failed to record queued hook episode"
        );
    }
    crate::metrics::global()
        .record_conversation_hook_enqueue_latency(started.elapsed().as_millis());
    if wait_for_processing {
        return execute_conversation_hook(store, queued, payload, import_options, targets).await;
    }
    let queued_for_task = queued.clone();
    tokio::spawn(async move {
        let event_id = queued_for_task.event_id.clone();
        if let Err(err) = execute_conversation_hook(
            store.clone(),
            queued_for_task,
            payload,
            import_options,
            targets,
        )
        .await
        {
            warn!(
                target: "docdexd",
                event_id = %event_id,
                error = ?err,
                "conversation hook processing failed"
            );
        }
    });
    Ok(queued)
}

pub async fn execute_conversation_hook(
    store: ConversationStore,
    queued: ConversationHookEnqueueResult,
    payload: ConversationHookPayload,
    import_options: ConversationImportOptions,
    targets: ConversationRouteTargets,
) -> Result<ConversationHookEnqueueResult> {
    let has_messages = payload
        .messages
        .as_ref()
        .map(|items| !items.is_empty())
        .unwrap_or(false);
    let has_transcript = payload
        .transcript_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    let summary_text = payload
        .summary_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if !has_messages && !has_transcript && summary_text.is_none() {
        let message = "conversation hook requires transcript/messages or summary_text".to_string();
        record_hook_failure(store, &queued.event_id, &message).await?;
        bail!(message);
    }

    let event_id = queued.event_id.clone();
    let mut result = queued;

    let processing = async {
        let mut imported = None;
        if has_messages || has_transcript {
            let normalized = normalize_import_request(ConversationImportEnvelope {
                source: payload
                    .source
                    .clone()
                    .or_else(|| Some(format!("hook:{}", payload.action.as_str()))),
                source_session_id: payload.source_session_id.clone(),
                title: payload.title.clone(),
                agent_id: payload
                    .agent_id
                    .clone()
                    .or_else(|| targets.default_agent_id.clone()),
                transport: payload
                    .transport
                    .clone()
                    .or_else(|| Some("hook".to_string())),
                started_at_ms: payload.started_at_ms,
                ended_at_ms: payload.ended_at_ms,
                format: payload.format.clone(),
                messages: payload.messages.clone(),
                transcript_text: payload.transcript_text.clone(),
                metadata: merged_hook_metadata(&payload),
            })
            .map_err(anyhow::Error::msg)?;
            imported = Some(
                import_conversation_with_routing_options(
                    store.clone(),
                    normalized,
                    import_options.clone(),
                    targets.clone(),
                )
                .await?,
            );
        }

        let diary_entry = if let Some(summary_text) = summary_text {
            let entry = write_diary_entry(
                store.clone(),
                payload
                    .agent_id
                    .clone()
                    .or_else(|| targets.default_agent_id.clone()),
                payload.action.as_str().to_string(),
                summary_text,
                imported
                    .as_ref()
                    .map(|item| item.session_id.clone())
                    .or_else(|| payload.source_session_id.clone()),
                merged_hook_metadata(&payload),
            )
            .await?;
            if let Some(knowledge) = targets.knowledge.as_ref() {
                record_diary_entry_episode(knowledge.store.clone(), entry.clone()).await?;
            }
            Some(entry)
        } else {
            None
        };

        Ok::<_, anyhow::Error>((imported, diary_entry))
    }
    .await;

    match processing {
        Ok((imported, diary_entry)) => {
            result.status = "processed".to_string();
            result.processed_at_ms = Some(now_epoch_ms());
            if let Some(imported) = imported {
                result.session_id = Some(imported.session_id);
                result.deduplicated = Some(imported.deduplicated);
                result.summary = Some(imported.summary);
                result.working_memory = imported.working_memory;
                result.durable_memories = imported.durable_memories;
                result.knowledge_facts = imported.knowledge_facts;
            }
            result.diary_entry = diary_entry;
            if let Err(err) = record_hook_episode(&targets, &result, &payload, "processed").await {
                warn!(
                    target: "docdexd",
                    event_id = %event_id,
                    error = ?err,
                    "failed to record processed hook episode"
                );
            }
            tokio::task::spawn_blocking({
                let store = store.clone();
                let event_id = event_id.clone();
                let result = result.clone();
                move || store.mark_hook_event_processed(&event_id, &result)
            })
            .await??;
            Ok(result)
        }
        Err(err) => {
            let message = err.to_string();
            let failed = ConversationHookEnqueueResult {
                status: "failed".to_string(),
                processed_at_ms: Some(now_epoch_ms()),
                ..result.clone()
            };
            if let Err(record_err) =
                record_hook_episode(&targets, &failed, &payload, "failed").await
            {
                warn!(
                    target: "docdexd",
                    event_id = %event_id,
                    error = ?record_err,
                    "failed to record failed hook episode"
                );
            }
            record_hook_failure(store, &event_id, &message).await?;
            Err(err)
        }
    }
}

async fn record_hook_failure(
    store: ConversationStore,
    event_id: &str,
    message: &str,
) -> Result<()> {
    let event_id = event_id.to_string();
    let message = message.to_string();
    tokio::task::spawn_blocking(move || store.mark_hook_event_failed(&event_id, &message)).await?
}

fn merged_hook_metadata(payload: &ConversationHookPayload) -> Value {
    let mut metadata = match payload.metadata.clone() {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    metadata.insert(
        "conversation_hook_action".to_string(),
        json!(payload.action.as_str()),
    );
    metadata.insert("conversation_hook".to_string(), json!(true));
    Value::Object(metadata)
}

async fn record_hook_episode(
    targets: &ConversationRouteTargets,
    result: &ConversationHookEnqueueResult,
    payload: &ConversationHookPayload,
    status: &str,
) -> Result<()> {
    let Some(knowledge) = targets.knowledge.as_ref() else {
        return Ok(());
    };
    let summary = hook_episode_summary(result, payload, status);
    let source_session_id = result
        .session_id
        .clone()
        .or_else(|| payload.source_session_id.clone());
    let happened_at_ms = result.processed_at_ms.unwrap_or(result.queued_at_ms);
    let metadata = merge_json_objects(
        merged_hook_metadata(payload),
        json!({
            "source": "conversation_hook",
            "status": status,
            "event_id": result.event_id,
            "queued_at_ms": result.queued_at_ms,
            "processed_at_ms": result.processed_at_ms,
            "session_id": result.session_id,
            "source_session_id": payload.source_session_id,
            "diary_entry_id": result.diary_entry.as_ref().map(|item| item.entry_id.clone()),
        }),
    );
    let knowledge = knowledge.store.clone();
    let event_id = result.event_id.clone();
    tokio::task::spawn_blocking(move || {
        knowledge.record_episode_note(
            "hook_event",
            &event_id,
            source_session_id.as_deref(),
            &summary,
            metadata,
            happened_at_ms,
        )
    })
    .await??;
    Ok(())
}

fn hook_episode_summary(
    result: &ConversationHookEnqueueResult,
    payload: &ConversationHookPayload,
    status: &str,
) -> String {
    if let Some(summary) = result
        .summary
        .as_ref()
        .map(|item| item.summary.trim())
        .filter(|value| !value.is_empty())
    {
        return summary.to_string();
    }
    if let Some(summary) = payload
        .summary_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return summary.to_string();
    }
    let source = payload
        .source
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("hook");
    format!(
        "Hook event {}: {} from {}",
        status,
        payload.action.as_str(),
        source
    )
}

fn merge_json_objects(primary: Value, overlay: Value) -> Value {
    let mut merged = match primary {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    if let Value::Object(map) = overlay {
        for (key, value) in map {
            merged.insert(key, value);
        }
    }
    Value::Object(merged)
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}
