use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashSet;

static BACKTICK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"`([^`\n]{2,120})`").expect("backtick entity regex"));
static PATHISH_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:[A-Za-z0-9_.-]+/)+[A-Za-z0-9_.:-]+\b").expect("pathish entity regex")
});
static IDENT_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z][A-Za-z0-9_./:-]{2,}\b").expect("identifier entity regex"));
static RELATION_RE: Lazy<Vec<(Regex, &'static str)>> = Lazy::new(|| {
    vec![
        (
            Regex::new(r"(?i)^\s*(?:repo fact:\s*)?(.+?)\s+lives in\s+(.+?)\s*$")
                .expect("lives in regex"),
            "located_in",
        ),
        (
            Regex::new(r"(?i)^\s*(?:repo fact:\s*)?(.+?)\s+uses\s+(.+?)\s*$").expect("uses regex"),
            "uses",
        ),
        (
            Regex::new(r"(?i)^\s*(?:repo fact:\s*)?(.+?)\s+depends on\s+(.+?)\s*$")
                .expect("depends on regex"),
            "depends_on",
        ),
        (
            Regex::new(r"(?i)^\s*(?:repo fact:\s*)?(.+?)\s+prefers\s+(.+?)\s*$")
                .expect("prefers regex"),
            "prefers",
        ),
        (
            Regex::new(r"(?i)^\s*do not use\s+(.+?)(?:[;,.]\s*|\s+)prefer\s+(.+?)\s*$")
                .expect("avoid/prefer regex"),
            "avoid_prefer",
        ),
        (
            Regex::new(r"(?i)^\s*(?:we\s+)?decided to\s+(.+?)\s*$").expect("decision regex"),
            "decision",
        ),
    ]
});

#[derive(Debug, Clone)]
pub struct RelationInference {
    pub subject: Option<String>,
    pub relation: String,
    pub object_entity: Option<String>,
    pub object_text: String,
}

pub fn normalize_entity_name(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|item| !item.trim().is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
        .to_ascii_lowercase()
}

pub fn normalize_relation_name(value: &str) -> String {
    value
        .trim()
        .to_ascii_lowercase()
        .replace('-', "_")
        .replace(' ', "_")
}

pub fn extract_entity_hints(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut items = Vec::new();

    for captures in BACKTICK_RE.captures_iter(text) {
        push_hint(&mut items, &mut seen, captures.get(1).map(|m| m.as_str()));
    }
    for captures in PATHISH_RE.captures_iter(text) {
        push_hint(&mut items, &mut seen, captures.get(0).map(|m| m.as_str()));
    }
    for captures in IDENT_RE.captures_iter(text) {
        push_hint(&mut items, &mut seen, captures.get(0).map(|m| m.as_str()));
        if items.len() >= 6 {
            break;
        }
    }

    items
}

pub fn infer_fact_shape(text: &str, fallback_relation: &str) -> RelationInference {
    let trimmed = text.trim();
    for (regex, relation) in RELATION_RE.iter() {
        if let Some(captures) = regex.captures(trimmed) {
            let subject = captures.get(1).map(|m| clean_fragment(m.as_str()));
            let object = captures
                .get(2)
                .map(|m| clean_fragment(m.as_str()))
                .filter(|value| !value.is_empty());
            return RelationInference {
                subject,
                relation: normalize_relation_name(relation),
                object_entity: object.clone(),
                object_text: object.unwrap_or_else(|| clean_fragment(trimmed)),
            };
        }
    }

    RelationInference {
        subject: None,
        relation: normalize_relation_name(fallback_relation),
        object_entity: extract_entity_hints(trimmed).into_iter().nth(1),
        object_text: clean_fragment(trimmed),
    }
}

fn push_hint(items: &mut Vec<String>, seen: &mut HashSet<String>, raw: Option<&str>) {
    let Some(raw) = raw else {
        return;
    };
    let candidate = clean_fragment(raw);
    if candidate.len() < 2 || candidate.len() > 120 {
        return;
    }
    let normalized = normalize_entity_name(&candidate);
    if normalized.is_empty() || is_stopword(&normalized) || !seen.insert(normalized) {
        return;
    }
    items.push(candidate);
}

fn clean_fragment(value: &str) -> String {
    value
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | '.' | ',' | ';' | ':'))
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_stopword(value: &str) -> bool {
    matches!(
        value,
        "the"
            | "this"
            | "that"
            | "with"
            | "from"
            | "into"
            | "then"
            | "next"
            | "step"
            | "please"
            | "assistant"
            | "developer"
            | "system"
            | "user"
            | "manual"
            | "auto"
            | "conversation"
            | "recent"
            | "goal"
    )
}
