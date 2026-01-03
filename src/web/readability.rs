use once_cell::sync::Lazy;
use readability::extractor::extract;
use regex::Regex;
use url::Url;

static READABILITY_STRIP_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?is)<(svg|math|noscript|template)[^>]*>.*?</\\1>")
        .expect("valid readability strip regex")
});

pub fn extract_readable_text(html: &str, base_url: &Url) -> Option<String> {
    let cleaned = READABILITY_STRIP_RE.replace_all(html, " ");
    let mut cursor = std::io::Cursor::new(cleaned.as_bytes());
    let article = extract(&mut cursor, base_url).ok()?;
    let text = article.text;
    let text = text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}
