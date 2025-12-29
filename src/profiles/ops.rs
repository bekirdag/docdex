use crate::profiles::PreferenceCategory;
use serde::Serialize;

#[derive(Debug, Clone)]
pub struct ProfileCandidate {
    pub id: String,
    pub agent_id: String,
    pub content: String,
    pub category: PreferenceCategory,
    pub score: f32,
    pub last_updated: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileContextItem {
    pub id: String,
    pub agent_id: String,
    pub category: PreferenceCategory,
    pub last_updated: i64,
    pub score: f32,
    pub token_estimate: usize,
    pub truncated: bool,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileContextDropped {
    pub id: String,
    pub reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileContextPruneTrace {
    pub budget_tokens: usize,
    pub max_items: usize,
    pub candidates: usize,
    pub kept: usize,
    pub dropped: Vec<ProfileContextDropped>,
}

pub fn prune_and_truncate_profile_context(
    candidates: &[ProfileCandidate],
    max_items: usize,
    budget_tokens: usize,
) -> (Vec<ProfileContextItem>, ProfileContextPruneTrace) {
    let mut ordered: Vec<ProfileCandidate> = candidates.to_vec();
    ordered.sort_by(|a, b| {
        b.score
            .total_cmp(&a.score)
            .then_with(|| b.last_updated.cmp(&a.last_updated))
            .then_with(|| a.id.cmp(&b.id))
    });

    let mut remaining = budget_tokens;
    let mut kept = Vec::new();
    let mut dropped = Vec::new();

    for (idx, candidate) in ordered.into_iter().enumerate() {
        if idx >= max_items {
            dropped.push(ProfileContextDropped {
                id: candidate.id,
                reason: "max_items",
            });
            continue;
        }
        if remaining == 0 {
            dropped.push(ProfileContextDropped {
                id: candidate.id,
                reason: "budget_exhausted",
            });
            continue;
        }

        let token_estimate = estimate_tokens(&candidate.content);
        let (content, truncated, used_tokens) = if token_estimate <= remaining {
            let used = token_estimate;
            (candidate.content, false, used)
        } else {
            let (truncated_content, was_truncated) =
                truncate_to_tokens(&candidate.content, remaining);
            let used = estimate_tokens(&truncated_content);
            (truncated_content, was_truncated, used)
        };

        remaining = remaining.saturating_sub(used_tokens);
        kept.push(ProfileContextItem {
            id: candidate.id,
            agent_id: candidate.agent_id,
            category: candidate.category,
            last_updated: candidate.last_updated,
            score: candidate.score,
            token_estimate: used_tokens,
            truncated,
            content,
        });
    }

    let trace = ProfileContextPruneTrace {
        budget_tokens,
        max_items,
        candidates: candidates.len(),
        kept: kept.len(),
        dropped,
    };
    (kept, trace)
}

fn estimate_tokens(text: &str) -> usize {
    text.split_whitespace().count()
}

fn truncate_to_tokens(text: &str, max_tokens: usize) -> (String, bool) {
    if max_tokens == 0 {
        return (String::new(), !text.trim().is_empty());
    }
    let mut iter = text.split_whitespace();
    let mut out = String::new();
    let mut remaining = max_tokens;
    while remaining > 0 {
        let Some(token) = iter.next() else {
            break;
        };
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(token);
        remaining -= 1;
    }
    let truncated = iter.next().is_some();
    if truncated && !out.is_empty() {
        out.push('…');
    }
    (out, truncated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(
        id: &str,
        score: f32,
        last_updated: i64,
        content: &str,
    ) -> ProfileCandidate {
        ProfileCandidate {
            id: id.to_string(),
            agent_id: "agent".to_string(),
            content: content.to_string(),
            category: PreferenceCategory::Style,
            score,
            last_updated,
        }
    }

    #[test]
    fn ordering_prefers_score_then_recency_then_id() {
        let a = candidate("a", 0.7, 5, "alpha beta");
        let b = candidate("b", 0.9, 3, "bravo");
        let c = candidate("c", 0.9, 6, "charlie");
        let d = candidate("d", 0.7, 9, "delta");

        let (kept, trace) = prune_and_truncate_profile_context(&[a, b, c, d], 4, 100);
        let ids: Vec<_> = kept.iter().map(|item| item.id.as_str()).collect();
        assert_eq!(ids, vec!["c", "b", "d", "a"]);
        assert_eq!(trace.kept, 4);
        assert_eq!(trace.dropped.len(), 0);
    }

    #[test]
    fn budget_exhaustion_truncates_then_drops() {
        let c1 = candidate("c1", 0.9, 1, "one two three four five");
        let c2 = candidate("c2", 0.8, 2, "six seven eight");
        let c3 = candidate("c3", 0.7, 3, "nine ten");

        let (kept, trace) = prune_and_truncate_profile_context(&[c1, c2, c3], 3, 4);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].id, "c1");
        assert_eq!(kept[0].content, "one two three four…");
        assert!(kept[0].truncated);

        assert_eq!(trace.dropped.len(), 2);
        assert_eq!(trace.dropped[0].id, "c2");
        assert_eq!(trace.dropped[0].reason, "budget_exhausted");
        assert_eq!(trace.dropped[1].id, "c3");
        assert_eq!(trace.dropped[1].reason, "budget_exhausted");
    }
}
