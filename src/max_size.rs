// Centralized, server-scoped size limits for tool outputs and truncation helpers.
#[derive(Clone, Copy, Debug)]
pub struct MaxSizePolicy {
    pub max_results: usize,
}

impl MaxSizePolicy {
    pub fn new(max_results: usize) -> Self {
        Self {
            max_results: clamp_value(max_results, 1, usize::MAX),
        }
    }
}

pub const DEFAULT_SEARCH_LIMIT: usize = 8;
pub const DEFAULT_SNIPPET_WINDOW: usize = 40;
pub const MIN_SNIPPET_WINDOW: usize = 10;
pub const MAX_SNIPPET_WINDOW: usize = 400;
pub const MAX_SUMMARY_CHARS: usize = 360;
pub const MAX_SUMMARY_SEGMENTS: usize = 4;
pub const MAX_SNIPPET_CHARS: usize = 420;
pub const FILES_DEFAULT_LIMIT: usize = 200;
pub const FILES_MAX_LIMIT: usize = 1000;
pub const FILES_MAX_OFFSET: usize = 50_000;
// Guard rail for returning file content via tools like docdex_open.
pub const OPEN_MAX_BYTES: usize = 512 * 1024;
pub const DEFAULT_MEMORY_RECALL: usize = 5;
pub const MAX_MEMORY_RECALL: usize = 50;
pub const MAX_ERROR_MESSAGE_BYTES: usize = 256;
pub const MAX_ERROR_REASON_BYTES: usize = 768;
pub const MAX_RATE_LIMIT_MESSAGE_BYTES: usize = 256;

pub fn clamp_value(value: usize, min: usize, max: usize) -> usize {
    value.clamp(min, max)
}

pub fn clamp_option(value: Option<usize>, default: usize, min: usize, max: usize) -> usize {
    value.unwrap_or(default).clamp(min, max)
}

pub fn truncate_utf8_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str("…");
    out
}

pub fn truncate_utf8_chars(text: &str, max_chars: usize) -> (String, bool) {
    if max_chars == 0 {
        return (String::new(), true);
    }
    let char_count = text.chars().count();
    if char_count <= max_chars {
        return (text.to_string(), false);
    }
    let take_chars = max_chars.saturating_sub(1);
    let mut truncated = String::new();
    for (idx, ch) in text.chars().enumerate() {
        if idx >= take_chars {
            break;
        }
        truncated.push(ch);
    }
    while truncated
        .chars()
        .last()
        .map(|c| c.is_whitespace())
        .unwrap_or(false)
    {
        truncated.pop();
    }
    truncated.push('…');
    (truncated, true)
}
