use super::*;

const CAPTURE_VOLUME_TARGET: usize = 25;
const SOURCE_DIVERSITY_TARGET: usize = 3;
const CLAIM_VOLUME_TARGET: usize = 100;
const PROFILE_PROJECTION_TARGET: usize = 10;
const EVIDENCE_RATIO_TARGET: usize = 1;
const ROUTINE_TARGET: usize = 1;
const OPERATOR_EVENT_TARGET: usize = 25;
const CLONE_CONTEXT_READY_TARGET: usize = 1;
const CLONE_CONTEXT_MATURITY_TARGET: usize = 5;
const REPLAY_EVALUATION_TARGET: usize = 25;
const FEEDBACK_EVENT_TARGET: usize = 10;

pub(super) fn build_clone_readiness(
    status: &PersonalPreferenceStatus,
    profile_projected_records_total: usize,
    noisy_claims_total: usize,
) -> PersonalPreferenceCloneReadiness {
    let queue_backlog =
        status.pending_captures + status.processing_captures + status.failed_captures;
    let queue_healthy = queue_backlog == 0 && status.digest_failure_breakdown.is_empty();
    let source_diversity_ready = status.sources_total >= SOURCE_DIVERSITY_TARGET;
    let capture_volume_ready = status.completed_captures >= CAPTURE_VOLUME_TARGET;
    let claims_ready = status.claims_total >= CLAIM_VOLUME_TARGET;
    let profile_projection_ready = profile_projected_records_total >= PROFILE_PROJECTION_TARGET;
    let evidence_ready = status.claims_total == 0
        || status.claim_evidence_total >= status.claims_total.saturating_mul(EVIDENCE_RATIO_TARGET);
    let routine_ready = status.operator_routines_total >= ROUTINE_TARGET
        && status.clone_context_packs_total >= CLONE_CONTEXT_READY_TARGET;
    let action_telemetry_ready = status.operator_events_total >= OPERATOR_EVENT_TARGET;
    let replay_ready = status.clone_evaluations_total >= REPLAY_EVALUATION_TARGET;
    let feedback_ready = status.feedback_events_total >= FEEDBACK_EVENT_TARGET;
    let noise_control_ready = status.retention_policies_total >= 3
        && (status.override_rules_total > 0 || noisy_claims_total == 0);
    let autonomy_ready = false;
    let collection_ready = queue_healthy
        && capture_volume_ready
        && source_diversity_ready
        && claims_ready
        && profile_projection_ready
        && evidence_ready;

    let mut metrics = vec![
        readiness_metric(
            "queue_health",
            "Digest queue health",
            queue_healthy,
            queue_backlog,
            0,
            "pending + processing + failed captures; target is zero backlog",
        ),
        readiness_metric(
            "capture_volume",
            "Completed capture volume",
            capture_volume_ready,
            status.completed_captures,
            CAPTURE_VOLUME_TARGET,
            "enough completed conversations to separate routine from anecdote",
        ),
        readiness_metric(
            "source_diversity",
            "Source diversity",
            source_diversity_ready,
            status.sources_total,
            SOURCE_DIVERSITY_TARGET,
            "distinct personal-preferences sources observed",
        ),
        readiness_metric(
            "claim_volume",
            "Stable claim volume",
            claims_ready,
            status.claims_total,
            CLAIM_VOLUME_TARGET,
            "materialized personal-preference claims available to the clone",
        ),
        readiness_metric(
            "profile_projection",
            "Profile projection",
            profile_projection_ready,
            profile_projected_records_total,
            PROFILE_PROJECTION_TARGET,
            "approved low-sensitivity records projected into global profile memory",
        ),
        readiness_metric(
            "evidence_links",
            "Evidence coverage",
            evidence_ready,
            status.claim_evidence_total,
            status.claims_total.saturating_mul(EVIDENCE_RATIO_TARGET),
            "claim evidence rows backing derived preferences and routines",
        ),
        readiness_metric(
            "operator_routines",
            "Operator routines",
            status.operator_routines_total >= ROUTINE_TARGET,
            status.operator_routines_total,
            ROUTINE_TARGET,
            "first-class routines synthesized from repeated operator behavior",
        ),
        readiness_metric(
            "operator_events",
            "Operator event telemetry",
            action_telemetry_ready,
            status.operator_events_total,
            OPERATOR_EVENT_TARGET,
            "first-class git/test/deploy/artifact/operator events captured outside transcript text",
        ),
        readiness_metric(
            "clone_context_packs",
            "Clone context packs",
            status.clone_context_packs_total >= CLONE_CONTEXT_READY_TARGET,
            status.clone_context_packs_total,
            CLONE_CONTEXT_MATURITY_TARGET,
            "agent-consumable clone context packs built from claims and routines",
        ),
        readiness_metric(
            "replay_evaluations",
            "Replay evaluations",
            replay_ready,
            status.clone_evaluations_total,
            REPLAY_EVALUATION_TARGET,
            "historical clone evaluations available for regression measurement",
        ),
        readiness_metric(
            "feedback_loop",
            "Feedback loop",
            feedback_ready,
            status.feedback_events_total,
            FEEDBACK_EVENT_TARGET,
            "explicit accept/reject/correction events that can update clone behavior",
        ),
        readiness_metric(
            "noise_control",
            "Noise control",
            noise_control_ready,
            noisy_claims_total,
            0,
            "rejected, superseded, expired, or contradicted claims tracked for review/compaction",
        ),
    ];

    let score = readiness_score(&metrics);
    let level = readiness_level(
        collection_ready,
        routine_ready && action_telemetry_ready,
        replay_ready,
        feedback_ready,
        autonomy_ready,
    );
    let stage = readiness_stage(level);
    let mut warnings = Vec::new();
    let mut next_actions = Vec::new();

    if !queue_healthy {
        warnings.push(format!(
            "{queue_backlog} captures are pending, processing, or failed; clone quality is stale until digestion is healthy."
        ));
        next_actions.push("Repair or process the personal-preferences digest queue.".to_string());
    }
    if !source_diversity_ready {
        warnings.push(format!(
            "Only {} source(s) are represented; clone behavior may overfit one capture channel.",
            status.sources_total
        ));
        next_actions.push(
            "Keep transcript and artifact capture enabled across supported local agents."
                .to_string(),
        );
    }
    if !capture_volume_ready || !claims_ready {
        warnings
            .push("Collection volume is still below the routine-learning threshold.".to_string());
        next_actions.push(
            "Continue automatic capture/digestion until repeated workflows appear across sessions."
                .to_string(),
        );
    }
    if !profile_projection_ready {
        warnings.push(format!(
            "Only {profile_projected_records_total} records have been projected to profile memory."
        ));
        next_actions.push(
            "Approve/project stable low-sensitivity records into profile memory.".to_string(),
        );
    }
    if !routine_ready {
        warnings.push(
            "Operator routines or clone context packs are not yet strong enough for directive use."
                .to_string(),
        );
        next_actions.push(
            "Rebuild operator routines and generate clone context packs from repeated workflows."
                .to_string(),
        );
    }
    if !action_telemetry_ready {
        warnings.push(format!(
            "Only {} operator event(s) exist; the clone cannot yet learn real git/test/deploy/artifact loops.",
            status.operator_events_total
        ));
        next_actions.push(
            "Capture operator events from commands, approvals, and planning/progress artifacts."
                .to_string(),
        );
    }
    if !replay_ready {
        warnings.push(format!(
            "Only {} replay/clone evaluations exist; accuracy is not yet statistically meaningful.",
            status.clone_evaluations_total
        ));
        next_actions.push("Run replay evaluation on historical sessions.".to_string());
    }
    if !feedback_ready {
        warnings.push(format!(
            "Only {} feedback event(s) exist; the clone has little supervised correction data.",
            status.feedback_events_total
        ));
        next_actions.push(
            "Capture explicit accept/reject/correction feedback from agent outputs.".to_string(),
        );
    }
    if noisy_claims_total > 0 {
        warnings.push(format!(
            "{noisy_claims_total} rejected, superseded, expired, or contradicted claim(s) need continued governance."
        ));
    }
    warnings.push(
        "Autonomy is intentionally disabled until operator events, clone directives, replay gates, and approval policies are implemented."
            .to_string(),
    );
    next_actions.push(
        "Use event-backed executable routines as the input for clone directives, replay gates, and approval policies."
            .to_string(),
    );
    next_actions.dedup();
    metrics.shrink_to_fit();

    PersonalPreferenceCloneReadiness {
        level,
        stage,
        score,
        collection_ready,
        profile_projection_ready,
        routine_ready,
        action_telemetry_ready,
        replay_ready,
        feedback_ready,
        autonomy_ready,
        queue_healthy,
        source_diversity_ready,
        evidence_ready,
        noise_control_ready,
        metrics,
        warnings,
        next_actions,
    }
}

fn readiness_metric(
    id: &str,
    label: &str,
    ready: bool,
    observed: usize,
    target: usize,
    detail: &str,
) -> PersonalPreferenceCloneReadinessMetric {
    PersonalPreferenceCloneReadinessMetric {
        id: id.to_string(),
        label: label.to_string(),
        ready,
        observed,
        target,
        detail: detail.to_string(),
    }
}

fn readiness_score(metrics: &[PersonalPreferenceCloneReadinessMetric]) -> f32 {
    if metrics.is_empty() {
        return 0.0;
    }
    let score: f32 = metrics
        .iter()
        .map(|metric| {
            if metric.target == 0 {
                if metric.observed == 0 {
                    1.0
                } else {
                    0.0
                }
            } else {
                (metric.observed as f32 / metric.target as f32).min(1.0)
            }
        })
        .sum::<f32>()
        / metrics.len() as f32;
    (score * 100.0).round() / 100.0
}

fn readiness_level(
    collection_ready: bool,
    routine_ready: bool,
    replay_ready: bool,
    feedback_ready: bool,
    autonomy_ready: bool,
) -> u8 {
    if autonomy_ready {
        5
    } else if collection_ready && routine_ready && replay_ready && feedback_ready {
        4
    } else if collection_ready && routine_ready {
        3
    } else if collection_ready {
        2
    } else if routine_ready {
        1
    } else {
        0
    }
}

fn readiness_stage(level: u8) -> String {
    match level {
        5 => "autonomous_low_risk_ready",
        4 => "supervised_clone_candidate",
        3 => "routine_clone_candidate",
        2 => "memory_substrate_ready",
        1 => "routine_seed_detected",
        _ => "insufficient_clone_signal",
    }
    .to_string()
}
