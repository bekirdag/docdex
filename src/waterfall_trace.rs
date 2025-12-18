use serde::{Deserialize, Serialize};

const MAX_TRACE_EVENTS: usize = 48;
const MAX_TRACE_DETAIL_BYTES: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WaterfallTier {
    Tier2,
    Tier3,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WaterfallOutcome {
    Started,
    Succeeded,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaterfallGate {
    pub decision: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WaterfallEvent {
    pub seq: u32,
    pub tier: WaterfallTier,
    pub outcome: WaterfallOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<WaterfallGate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WaterfallTrace {
    pub schema_version: u32,
    pub truncated: bool,
    pub events: Vec<WaterfallEvent>,
    #[serde(skip)]
    next_seq: u32,
}

impl Default for WaterfallTrace {
    fn default() -> Self {
        Self::new()
    }
}

impl WaterfallTrace {
    pub fn new() -> Self {
        Self {
            schema_version: 1,
            truncated: false,
            events: Vec::new(),
            next_seq: 1,
        }
    }

    pub fn record(
        &mut self,
        tier: WaterfallTier,
        outcome: WaterfallOutcome,
        gate: Option<WaterfallGateInput<'_>>,
    ) {
        if self.events.len() >= MAX_TRACE_EVENTS {
            self.truncated = true;
            return;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let gate = gate.map(|input| WaterfallGate {
            decision: truncate_bytes(input.decision, MAX_TRACE_DETAIL_BYTES),
            reason: truncate_bytes(input.reason, MAX_TRACE_DETAIL_BYTES),
            detail: input
                .detail
                .map(|value| truncate_bytes(value, MAX_TRACE_DETAIL_BYTES)),
        });
        self.events.push(WaterfallEvent {
            seq,
            tier,
            outcome,
            gate,
        });
    }
}

pub struct WaterfallGateInput<'a> {
    pub decision: &'a str,
    pub reason: &'a str,
    pub detail: Option<&'a str>,
}

fn truncate_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let ellipsis = "…";
    let ellipsis_bytes = ellipsis.len();
    if max_bytes < ellipsis_bytes {
        return String::new();
    }
    let mut end = max_bytes - ellipsis_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str(ellipsis);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_is_bounded_and_marks_truncated() {
        let mut trace = WaterfallTrace::new();
        for _ in 0..(MAX_TRACE_EVENTS + 10) {
            trace.record(
                WaterfallTier::Tier2,
                WaterfallOutcome::Started,
                Some(WaterfallGateInput {
                    decision: "attempt",
                    reason: "test",
                    detail: Some("x"),
                }),
            );
        }
        assert_eq!(trace.events.len(), MAX_TRACE_EVENTS);
        assert!(trace.truncated);
        assert_eq!(trace.events.first().unwrap().seq, 1);
        assert_eq!(trace.events.last().unwrap().seq as usize, MAX_TRACE_EVENTS);
    }

    #[test]
    fn trace_truncates_utf8_safely() {
        let mut trace = WaterfallTrace::new();
        let long = "界".repeat(512);
        trace.record(
            WaterfallTier::Tier2,
            WaterfallOutcome::Skipped,
            Some(WaterfallGateInput {
                decision: &long,
                reason: &long,
                detail: Some(&long),
            }),
        );
        let gate = trace.events[0].gate.as_ref().unwrap();
        assert!(gate.decision.len() <= MAX_TRACE_DETAIL_BYTES);
        assert!(gate.reason.len() <= MAX_TRACE_DETAIL_BYTES);
        assert!(gate.detail.as_ref().unwrap().len() <= MAX_TRACE_DETAIL_BYTES);
    }
}
