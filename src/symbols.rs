use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

const MAX_SYMBOLS_PER_FILE: usize = 512;
const MAX_SYMBOL_NAME_CHARS: usize = 200;
const MAX_SYMBOL_KIND_CHARS: usize = 32;
const MAX_SYMBOL_SIGNATURE_CHARS: usize = 240;
const MAX_OUTCOME_REASON_CHARS: usize = 160;
const MAX_OUTCOME_ERROR_SUMMARY_CHARS: usize = 360;
const MAX_METADATA_NAME_CHARS: usize = 64;
const MAX_METADATA_VERSION_CHARS: usize = 64;
const SYMBOL_PARSER_NAME: &str = "regex";
const SYMBOL_PARSER_VERSION: &str = "1";
const SYMBOL_RUNTIME_NAME: &str = "docdexd";

fn default_symbols_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.symbols".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaInfo {
    pub name: String,
    pub version: u32,
    pub compatible: SchemaCompatibleRange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaCompatibleRange {
    pub min: u32,
    pub max: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolOutcomeStatus {
    Ok,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolToolInfo {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolOutcome {
    pub status: SymbolOutcomeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_summary: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser: Option<SymbolToolInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<SymbolToolInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolRange {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolItem {
    #[serde(default)]
    pub symbol_id: String,
    pub name: String,
    pub kind: String,
    pub range: SymbolRange,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// `docdex.symbols` response schema v1 (see `docs/contracts/code_intelligence_schema_v1.md`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolsResponseV1 {
    #[serde(default = "default_symbols_schema")]
    pub schema: SchemaInfo,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub symbols: Vec<SymbolItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<SymbolOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceLanguage {
    Markdown,
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
}

impl SourceLanguage {
    pub fn as_str(&self) -> &'static str {
        match self {
            SourceLanguage::Markdown => "markdown",
            SourceLanguage::Rust => "rust",
            SourceLanguage::Python => "python",
            SourceLanguage::JavaScript => "javascript",
            SourceLanguage::TypeScript => "typescript",
            SourceLanguage::Go => "go",
        }
    }
}

pub fn language_for_path(rel_path: &str) -> Option<SourceLanguage> {
    let lower = rel_path.to_lowercase();
    if lower.ends_with(".md") || lower.ends_with(".markdown") || lower.ends_with(".mdx") {
        return Some(SourceLanguage::Markdown);
    }
    if lower.ends_with(".rs") {
        return Some(SourceLanguage::Rust);
    }
    if lower.ends_with(".py") {
        return Some(SourceLanguage::Python);
    }
    if lower.ends_with(".ts") || lower.ends_with(".tsx") {
        return Some(SourceLanguage::TypeScript);
    }
    if lower.ends_with(".js") || lower.ends_with(".jsx") {
        return Some(SourceLanguage::JavaScript);
    }
    if lower.ends_with(".go") {
        return Some(SourceLanguage::Go);
    }
    None
}

pub fn repo_id_for_root(repo_root: &Path) -> Result<String> {
    crate::repo_identity::repo_fingerprint_sha256(repo_root)
}

fn file_key(rel_path: &str) -> String {
    hex::encode(Sha256::digest(rel_path.as_bytes()))
}

#[derive(Clone)]
pub struct SymbolsStore {
    repo_id: String,
    base_dir: PathBuf,
}

impl SymbolsStore {
    pub fn new(repo_root: &Path, state_dir: &Path) -> Result<Self> {
        Ok(Self {
            repo_id: repo_id_for_root(repo_root)?,
            base_dir: state_dir.join("symbols.db"),
        })
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn reset(&self) -> Result<()> {
        if self.base_dir.exists() {
            fs::remove_dir_all(&self.base_dir)
                .with_context(|| format!("remove {}", self.base_dir.display()))?;
        }
        fs::create_dir_all(self.files_dir())
            .with_context(|| format!("create {}", self.files_dir().display()))?;
        Ok(())
    }

    pub fn upsert_symbols(&self, rel_path: &str, payload: &SymbolsResponseV1) -> Result<()> {
        fs::create_dir_all(self.files_dir())
            .with_context(|| format!("create {}", self.files_dir().display()))?;
        let dest = self.file_record_path(rel_path);
        let tmp = dest.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
        let bytes = serde_json::to_vec_pretty(payload).context("serialize symbols payload")?;
        fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        if dest.exists() {
            let _ = fs::remove_file(&dest);
        }
        fs::rename(&tmp, &dest).with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;
        Ok(())
    }

    pub fn read_symbols(&self, rel_path: &str) -> Result<Option<SymbolsResponseV1>> {
        let path = self.file_record_path(rel_path);
        let data = match fs::read_to_string(&path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        };
        let mut parsed: SymbolsResponseV1 =
            serde_json::from_str(&data).context("parse symbols payload")?;
        if parsed.repo_id.is_empty() {
            parsed.repo_id = self.repo_id.clone();
        }
        if parsed.file.is_empty() {
            parsed.file = rel_path.to_string();
        }
        normalize_symbols_payload(&mut parsed);
        Ok(Some(parsed))
    }

    pub fn delete_symbols(&self, rel_path: &str) -> Result<()> {
        let path = self.file_record_path(rel_path);
        if path.exists() {
            fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
        }
        Ok(())
    }

    fn files_dir(&self) -> PathBuf {
        self.base_dir.join("files")
    }

    fn file_record_path(&self, rel_path: &str) -> PathBuf {
        self.files_dir().join(format!("{}.json", file_key(rel_path)))
    }
}

pub fn build_symbols_payload(
    repo_id: &str,
    file: &str,
    symbols: Vec<SymbolItem>,
    outcome: SymbolOutcome,
) -> SymbolsResponseV1 {
    let mut payload = SymbolsResponseV1 {
        schema: default_symbols_schema(),
        repo_id: repo_id.to_string(),
        file: file.to_string(),
        symbols,
        outcome: Some(outcome),
    };
    normalize_symbols_payload(&mut payload);
    payload
}

pub fn extract_symbols_best_effort(
    repo_id: &str,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
) -> Result<Vec<SymbolItem>> {
    let mut symbols = match language {
        SourceLanguage::Markdown => extract_markdown_symbols(repo_id, rel_path, content),
        SourceLanguage::Rust => extract_rust_symbols(repo_id, rel_path, content),
        SourceLanguage::Python => extract_python_symbols(repo_id, rel_path, content),
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => {
            extract_js_ts_symbols(repo_id, rel_path, content)
        }
        SourceLanguage::Go => extract_go_symbols(repo_id, rel_path, content),
    }?;
    symbols.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
    Ok(symbols)
}

pub fn build_symbol_outcome(
    status: SymbolOutcomeStatus,
    reason: Option<String>,
    error_summary: Option<String>,
    language: Option<SourceLanguage>,
) -> SymbolOutcome {
    let mut outcome = SymbolOutcome {
        status,
        reason,
        error_summary,
        parser: language.map(symbol_parser_info),
        runtime: Some(symbol_runtime_info()),
    };
    normalize_outcome(&mut outcome);
    outcome
}

fn make_symbol_id(repo_id: &str, file: &str, range: &SymbolRange, kind: &str, name: &str) -> String {
    format!(
        "{repo_id}:{file}#{}:{}-{}:{}:{kind}:{name}",
        range.start_line, range.start_col, range.end_line, range.end_col
    )
}

fn make_symbol(
    repo_id: &str,
    file: &str,
    name: String,
    kind: &'static str,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    signature: Option<String>,
) -> SymbolItem {
    let name = clamp_chars(&name, MAX_SYMBOL_NAME_CHARS);
    let kind = clamp_chars(kind, MAX_SYMBOL_KIND_CHARS);
    let signature = signature.map(|sig| clamp_chars(&sig, MAX_SYMBOL_SIGNATURE_CHARS));
    let range = SymbolRange {
        start_line,
        start_col,
        end_line,
        end_col,
    };
    let symbol_id = make_symbol_id(repo_id, file, &range, &kind, &name);
    SymbolItem {
        symbol_id,
        name,
        kind,
        range,
        signature,
    }
}

fn symbol_parser_info(language: SourceLanguage) -> SymbolToolInfo {
    let name = format!("{SYMBOL_PARSER_NAME}-{}", language.as_str());
    SymbolToolInfo {
        name: clamp_chars(&name, MAX_METADATA_NAME_CHARS),
        version: Some(clamp_chars(SYMBOL_PARSER_VERSION, MAX_METADATA_VERSION_CHARS)),
    }
}

fn symbol_runtime_info() -> SymbolToolInfo {
    SymbolToolInfo {
        name: clamp_chars(SYMBOL_RUNTIME_NAME, MAX_METADATA_NAME_CHARS),
        version: Some(clamp_chars(env!("CARGO_PKG_VERSION"), MAX_METADATA_VERSION_CHARS)),
    }
}

fn normalize_symbols_payload(payload: &mut SymbolsResponseV1) {
    if let Some(outcome) = payload.outcome.as_mut() {
        normalize_outcome(outcome);
    }
    let repo_id = payload.repo_id.clone();
    let file = payload.file.clone();
    for symbol in &mut payload.symbols {
        normalize_symbol_item(&repo_id, &file, symbol);
    }
    payload.symbols.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
    if payload.symbols.len() > MAX_SYMBOLS_PER_FILE {
        payload.symbols.truncate(MAX_SYMBOLS_PER_FILE);
    }
}

fn normalize_symbol_item(repo_id: &str, file: &str, symbol: &mut SymbolItem) {
    symbol.name = clamp_chars(&symbol.name, MAX_SYMBOL_NAME_CHARS);
    symbol.kind = clamp_chars(&symbol.kind, MAX_SYMBOL_KIND_CHARS);
    symbol.signature = symbol
        .signature
        .as_ref()
        .map(|sig| clamp_chars(sig, MAX_SYMBOL_SIGNATURE_CHARS));
    symbol.symbol_id = make_symbol_id(repo_id, file, &symbol.range, &symbol.kind, &symbol.name);
}

fn normalize_outcome(outcome: &mut SymbolOutcome) {
    outcome.reason = outcome
        .reason
        .as_ref()
        .map(|reason| clamp_chars(reason, MAX_OUTCOME_REASON_CHARS));
    outcome.error_summary = outcome
        .error_summary
        .as_ref()
        .map(|summary| clamp_chars(summary, MAX_OUTCOME_ERROR_SUMMARY_CHARS));
    if let Some(parser) = outcome.parser.as_mut() {
        normalize_tool_info(parser);
    }
    if let Some(runtime) = outcome.runtime.as_mut() {
        normalize_tool_info(runtime);
    }
}

fn normalize_tool_info(info: &mut SymbolToolInfo) {
    info.name = clamp_chars(&info.name, MAX_METADATA_NAME_CHARS);
    info.version = info
        .version
        .as_ref()
        .map(|version| clamp_chars(version, MAX_METADATA_VERSION_CHARS));
}

fn clamp_chars(input: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    input.chars().take(max_chars).collect()
}

fn extract_markdown_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    static HEADING: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^(?P<hashes>#{1,6})\s+(?P<title>.+?)\s*$").unwrap());
    let mut symbols = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if let Some(caps) = HEADING.captures(line) {
            let title = caps
                .name("title")
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();
            if title.is_empty() {
                continue;
            }
            let end_col = line.chars().count().max(1) as u32;
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                title,
                "section",
                line_num,
                1,
                line_num,
                end_col,
                Some(line.trim().to_string()),
            ));
        }
    }
    Ok(symbols)
}

fn extract_rust_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    static FN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)").unwrap());
    static TYPE: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(struct|enum|trait)\s+([A-Za-z_][A-Za-z0-9_]*)")
            .unwrap()
    });
    static MOD: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*[;{]").unwrap());

    let mut symbols = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if let Some(caps) = FN.captures(line) {
            let name = caps.get(1).unwrap().as_str().to_string();
            let start_col = (caps.get(1).unwrap().start() + 1) as u32;
            let end_col = (caps.get(1).unwrap().end().max(caps.get(1).unwrap().start() + 1)) as u32;
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                name,
                "function",
                line_num,
                start_col,
                line_num,
                end_col,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = TYPE.captures(line) {
            let name = caps.get(2).unwrap().as_str().to_string();
            let start_col = (caps.get(2).unwrap().start() + 1) as u32;
            let end_col = (caps.get(2).unwrap().end().max(caps.get(2).unwrap().start() + 1)) as u32;
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                name,
                "type",
                line_num,
                start_col,
                line_num,
                end_col,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = MOD.captures(line) {
            let name = caps.get(1).unwrap().as_str().to_string();
            let start_col = (caps.get(1).unwrap().start() + 1) as u32;
            let end_col = (caps.get(1).unwrap().end().max(caps.get(1).unwrap().start() + 1)) as u32;
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                name,
                "module",
                line_num,
                start_col,
                line_num,
                end_col,
                Some(line.trim().to_string()),
            ));
        }
    }
    Ok(symbols)
}

fn extract_python_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    static DEF: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());
    static CLASS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*class\s+([A-Za-z_][A-Za-z0-9_]*)\b").unwrap());
    let mut symbols = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if let Some(caps) = DEF.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "function",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = CLASS.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "class",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
        }
    }
    Ok(symbols)
}

fn extract_js_ts_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    static FN: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*(?:export\s+)?function\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*\(").unwrap());
    static CLASS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][A-Za-z0-9_$]*)\b").unwrap());
    static ARROW: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][A-Za-z0-9_$]*)\s*=>")
            .unwrap()
    });
    static TYPE_ALIAS: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][A-Za-z0-9_$]*)\b").unwrap());
    static INTERFACE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][A-Za-z0-9_$]*)\b").unwrap());

    let mut symbols = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if let Some(caps) = FN.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "function",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = CLASS.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "class",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = ARROW.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "function",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = INTERFACE.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "type",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = TYPE_ALIAS.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "type",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
        }
    }
    Ok(symbols)
}

fn extract_go_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    static FUNC: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][A-Za-z0-9_]*)\s*\(").unwrap());
    static TYPE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*type\s+([A-Za-z_][A-Za-z0-9_]*)\b").unwrap());
    static PACKAGE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*package\s+([A-Za-z_][A-Za-z0-9_]*)\b").unwrap());
    let mut symbols = Vec::new();
    for (idx, line) in content.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        if let Some(caps) = PACKAGE.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "module",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = FUNC.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "function",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
            continue;
        }
        if let Some(caps) = TYPE.captures(line) {
            let m = caps.get(1).unwrap();
            symbols.push(make_symbol(
                repo_id,
                rel_path,
                m.as_str().to_string(),
                "type",
                line_num,
                (m.start() + 1) as u32,
                line_num,
                (m.end().max(m.start() + 1)) as u32,
                Some(line.trim().to_string()),
            ));
        }
    }
    Ok(symbols)
}
