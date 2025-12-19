use crate::index;

pub const MCP_FILES_DEFAULT_LIMIT: usize = 200;
pub const MCP_FILES_MAX_LIMIT: usize = 1000;
pub const MCP_FILES_MAX_OFFSET: usize = 50_000;
pub const MCP_MEMORY_MAX_ITEMS: usize = 50;
pub const MCP_SYMBOLS_MAX_ITEMS: usize = 1000;
pub const MCP_INDEX_MAX_ITEMS: usize = 1000;
pub const MCP_CONTENT_MAX_BYTES: usize = 512 * 1024;
pub const MCP_SNIPPET_MAX_CHARS: usize = index::MAX_SNIPPET_CHARS;
pub const MCP_SUMMARY_MAX_CHARS: usize = index::MAX_SUMMARY_CHARS;

#[derive(Clone, Copy, Debug)]
pub struct MaxSizePolicy {
    pub max_search_items: usize,
    pub max_files_limit: usize,
    pub max_files_offset: usize,
    pub max_memory_items: usize,
    pub max_symbols_items: usize,
    pub max_index_items: usize,
    pub max_content_bytes: usize,
    pub max_snippet_chars: usize,
    pub max_summary_chars: usize,
}

impl MaxSizePolicy {
    pub fn for_mcp(max_results: usize) -> Self {
        Self {
            max_search_items: max_results.max(1),
            max_files_limit: MCP_FILES_MAX_LIMIT.max(1),
            max_files_offset: MCP_FILES_MAX_OFFSET,
            max_memory_items: MCP_MEMORY_MAX_ITEMS.max(1),
            max_symbols_items: MCP_SYMBOLS_MAX_ITEMS.max(1),
            max_index_items: MCP_INDEX_MAX_ITEMS.max(1),
            max_content_bytes: MCP_CONTENT_MAX_BYTES.max(1),
            max_snippet_chars: MCP_SNIPPET_MAX_CHARS.max(1),
            max_summary_chars: MCP_SUMMARY_MAX_CHARS.max(1),
        }
    }
}

pub fn truncate_bytes(input: &str, max_bytes: usize) -> (String, bool) {
    if max_bytes == 0 {
        return (String::new(), !input.is_empty());
    }
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }
    let ellipsis = "…";
    if max_bytes <= ellipsis.len() {
        let mut end = max_bytes;
        while end > 0 && !input.is_char_boundary(end) {
            end -= 1;
        }
        return (input[..end].to_string(), true);
    }
    let mut end = max_bytes.saturating_sub(ellipsis.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str(ellipsis);
    (out, true)
}

pub fn truncate_chars(input: &str, max_chars: usize) -> (String, bool) {
    if max_chars == 0 {
        return (String::new(), !input.is_empty());
    }
    if input.chars().count() <= max_chars {
        return (input.to_string(), false);
    }
    let take_chars = max_chars.saturating_sub(1);
    let mut truncated = String::new();
    for (idx, ch) in input.chars().enumerate() {
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
