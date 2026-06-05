use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde_json::Value;

pub(super) fn empty_to_null(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn estimate_tokens(text: &str) -> usize {
    text.split_whitespace()
        .filter(|part| !part.is_empty())
        .count()
}

pub(super) fn truncate_to_tokens(text: &str, max_tokens: usize) -> String {
    if max_tokens == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    let mut truncated = false;
    for (index, token) in text.split_whitespace().enumerate() {
        if index >= max_tokens {
            truncated = true;
            break;
        }
        out.push(token);
    }
    if out.is_empty() {
        String::new()
    } else {
        let mut text = out.join(" ");
        if truncated {
            text.push('…');
        }
        text
    }
}

pub(super) fn normalize_category(value: &str) -> String {
    let normalized = slugify_identifier(value);
    if normalized.is_empty() {
        return "other".to_string();
    }
    normalized
}

pub(super) fn normalize_record_type(value: &str) -> String {
    match normalize_text(value).as_str() {
        "preference" | "method" | "goal" | "project" | "trait" | "capability" | "context"
        | "like" | "dislike" | "bridge" | "other" => normalize_text(value),
        _ => "other".to_string(),
    }
}

pub(super) fn normalize_sensitivity(value: &str) -> String {
    match normalize_text(value).as_str() {
        "low" => "low".to_string(),
        "medium" | "private" => "private".to_string(),
        "high" | "sensitive" => "sensitive".to_string(),
        "special" => "special".to_string(),
        _ => "private".to_string(),
    }
}

pub(super) fn is_sensitive_level(value: &str) -> bool {
    matches!(value, "private" | "sensitive" | "special")
}

pub(super) fn normalize_optional_text(value: Option<&str>) -> Option<String> {
    let value = value?;
    let normalized = normalize_text(value);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(super) fn normalize_non_empty_text(value: &str) -> Option<String> {
    let normalized = normalize_text(value);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(super) fn normalize_text(value: &str) -> String {
    value.trim().replace('\n', " ")
}

pub(super) fn slugify_identifier(value: &str) -> String {
    let mut out = String::new();
    let mut last_was_sep = false;
    for ch in value.trim().chars() {
        let normalized = ch.to_ascii_lowercase();
        if normalized.is_ascii_alphanumeric() {
            out.push(normalized);
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    out.trim_matches('_').to_string()
}

pub(super) fn parse_json_value(text: &str) -> Value {
    serde_json::from_str(text).unwrap_or_else(|_| Value::Object(Default::default()))
}

pub(super) fn parse_json_string_array(text: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(text).unwrap_or_default()
}

pub(super) fn extract_balanced_json_candidates(text: &str) -> Vec<&str> {
    let mut candidates = Vec::new();
    let mut stack: Vec<(char, usize)> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;

    for (idx, ch) in text.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            continue;
        }

        match ch {
            '{' | '[' => stack.push((ch, idx)),
            '}' | ']' => {
                let Some((open, start)) = stack.pop() else {
                    continue;
                };
                let matched = matches!((open, ch), ('{', '}') | ('[', ']'));
                if !matched {
                    stack.clear();
                    continue;
                }
                if stack.is_empty() {
                    candidates.push(&text[start..idx + ch.len_utf8()]);
                }
            }
            _ => {}
        }
    }

    candidates
}

pub(super) fn extract_balanced_json_candidate_from(text: &str, start: usize) -> Option<&str> {
    let opening = text[start..].chars().next()?;
    if !matches!(opening, '{' | '[') {
        return None;
    }
    let mut stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut escaped = false;
    for (relative_idx, ch) in text[start..].char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        if ch == '"' {
            in_string = true;
            continue;
        }

        match ch {
            '{' | '[' => stack.push(ch),
            '}' | ']' => {
                let open = stack.pop()?;
                let matched = matches!((open, ch), ('{', '}') | ('[', ']'));
                if !matched {
                    return None;
                }
                if stack.is_empty() {
                    let end = start + relative_idx + ch.len_utf8();
                    return Some(&text[start..end]);
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out = String::new();
    for ch in text.chars().take(max_chars) {
        out.push(ch);
    }
    out.push('…');
    out
}

pub(super) fn count_files(dir: &Path) -> Result<usize> {
    let mut count = 0usize;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            count += 1;
        }
    }
    Ok(count)
}

pub(super) fn remove_dir_contents(dir: &Path) -> Result<usize> {
    let mut removed = 0usize;
    for entry in fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_file() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
            removed += 1;
        }
    }
    Ok(removed)
}

pub(super) fn delete_if_exists(path: &Path) -> Result<bool> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
        Ok(true)
    } else {
        Ok(false)
    }
}

pub(super) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}
