use readability::extractor::extract;
use url::Url;

pub fn extract_readable_text(html: &str, base_url: &Url) -> Option<String> {
    let mut cursor = std::io::Cursor::new(html.as_bytes());
    let article = extract(&mut cursor, base_url).ok()?;
    let text = article.text;
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}
