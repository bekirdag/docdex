use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tree_sitter::{Language, Node, Parser};
use tree_sitter_go as ts_go;
use tree_sitter_javascript as ts_javascript;
use tree_sitter_python as ts_python;
use tree_sitter_rust as ts_rust;
use tree_sitter_typescript as ts_typescript;
use tracing::warn;

const SYMBOLS_SCHEMA_VERSION: u32 = 5;
const SYMBOLS_SCHEMA_MIN_VERSION: u32 = 1;
const AST_NODE_STORE_LIMIT: usize = 50_000;
const AST_NODE_NAME_LIMIT: usize = 120;
const TREE_SITTER_VERSION: &str = "0.20";
const TREE_SITTER_GO_VERSION: &str = "0.20.0";
const TREE_SITTER_JAVASCRIPT_VERSION: &str = "0.20.4";
const TREE_SITTER_PYTHON_VERSION: &str = "0.20.4";
const TREE_SITTER_RUST_VERSION: &str = "0.20.4";
const TREE_SITTER_TYPESCRIPT_VERSION: &str = "0.20.5";
fn default_symbols_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.symbols".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

fn default_symbols_status_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.symbols_status".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

fn default_ast_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.ast".to_string(),
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
pub struct SymbolOutcome {
    pub status: SymbolOutcomeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_summary: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstNode {
    pub id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<u32>,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub is_named: bool,
    pub range: SymbolRange,
}

/// `docdex.ast` response schema v1 (see `docs/contracts/code_intelligence_schema_v1.md`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstResponseV1 {
    #[serde(default = "default_ast_schema")]
    pub schema: SchemaInfo,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default)]
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    #[serde(default)]
    pub nodes: Vec<AstNode>,
    #[serde(default)]
    pub total_nodes: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<SymbolOutcome>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SymbolsParserStatus {
    #[serde(default = "default_symbols_status_schema")]
    pub schema: SchemaInfo,
    #[serde(default)]
    pub repo_id: String,
    pub current_parser_versions: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stored_parser_versions: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_versions_previous: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parser_versions_changed_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_invalidated_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbols_invalidation_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docdex_version: Option<String>,
    pub parser_versions_changed: bool,
    pub requires_reindex: bool,
    pub drift: bool,
}

#[derive(Debug, Clone)]
pub struct SymbolSearchMatch {
    pub file: String,
    pub symbols: Vec<SymbolItem>,
}

#[derive(Debug, Clone)]
pub struct AstSearchMatch {
    pub file: String,
    pub match_count: usize,
}

#[derive(Debug, Clone)]
pub struct AstQuery {
    pub kinds: Vec<String>,
    pub name: Option<String>,
    pub field: Option<String>,
    pub path_prefix: Option<String>,
    pub mode: AstSearchMode,
    pub limit: usize,
    pub sample_limit: usize,
}

#[derive(Debug, Clone)]
pub struct AstQueryMatch {
    pub file: String,
    pub match_count: usize,
    pub samples: Vec<AstNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AstSearchMode {
    Any,
    All,
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
    crate::repo_manager::repo_fingerprint_sha256(repo_root)
}

#[derive(Clone)]
pub struct SymbolsStore {
    repo_id: String,
    db_path: PathBuf,
    legacy_db_path: Option<PathBuf>,
}

impl SymbolsStore {
    pub fn new(repo_root: &Path, state_dir: &Path) -> Result<Self> {
        fs::create_dir_all(state_dir)
            .with_context(|| format!("create {}", state_dir.display()))?;
        let (db_path, legacy_db_path) = if state_dir.file_name().and_then(|s| s.to_str())
            == Some("index")
        {
            let repo_state_root = state_dir
                .parent()
                .unwrap_or(state_dir)
                .to_path_buf();
            (
                repo_state_root.join("symbols.db"),
                Some(state_dir.join("symbols.db")),
            )
        } else {
            (state_dir.join("symbols.db"), None)
        };
        let store = Self {
            repo_id: repo_id_for_root(repo_root)?,
            db_path,
            legacy_db_path,
        };
        store.ensure_schema_version()?;
        Ok(store)
    }

    pub fn check_access(&self) -> Result<()> {
        let conn = self.connection()?;
        conn.execute_batch(
            "CREATE TEMP TABLE IF NOT EXISTS docdex_symbols_check (id INTEGER); \
             DROP TABLE IF EXISTS docdex_symbols_check;",
        )
        .context("check symbols db write access")?;
        Ok(())
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn reset(&self) -> Result<()> {
        if self.db_path.exists() {
            if self.db_path.is_dir() {
                fs::remove_dir_all(&self.db_path)
                    .with_context(|| format!("remove {}", self.db_path.display()))?;
            } else {
                fs::remove_file(&self.db_path)
                    .with_context(|| format!("remove {}", self.db_path.display()))?;
            }
        }
        self.ensure_schema_version()?;
        self.clear_reindex_required()?;
        Ok(())
    }

    pub fn upsert_symbols(&self, rel_path: &str, payload: &SymbolsResponseV1) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction().context("start symbols transaction")?;
        self.upsert_symbols_tx(&tx, rel_path, payload)?;
        tx.commit().context("commit symbols transaction")?;
        Ok(())
    }

    pub fn upsert_ast(&self, rel_path: &str, payload: &AstResponseV1) -> Result<()> {
        let mut conn = self.connection()?;
        let tx = conn.transaction().context("start ast transaction")?;
        self.upsert_ast_tx(&tx, rel_path, payload)?;
        tx.commit().context("commit ast transaction")?;
        Ok(())
    }

    pub fn read_symbols(&self, rel_path: &str) -> Result<Option<SymbolsResponseV1>> {
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(
                "SELECT symbol_id, name, kind, line_start, start_col, line_end, end_col, signature \
                 FROM symbols WHERE file_path = ?1",
            )
            .context("prepare symbols read")?;
        let mut symbols: Vec<SymbolItem> = Vec::new();
        let rows = stmt
            .query_map(params![rel_path], |row| {
                let symbol_id: Option<String> = row.get(0)?;
                let name: String = row.get(1)?;
                let kind: String = row.get(2)?;
                let line_start: u32 = row.get::<_, i64>(3)? as u32;
                let start_col: u32 = row.get::<_, i64>(4)? as u32;
                let line_end: u32 = row.get::<_, i64>(5)? as u32;
                let end_col: u32 = row.get::<_, i64>(6)? as u32;
                let signature: Option<String> = row.get(7)?;
                Ok((symbol_id, name, kind, line_start, start_col, line_end, end_col, signature))
            })
            .context("query symbols rows")?;
        for row in rows {
            let (symbol_id, name, kind, line_start, start_col, line_end, end_col, signature) =
                row?;
            let range = SymbolRange {
                start_line: line_start,
                start_col,
                end_line: line_end,
                end_col,
            };
            let computed_id = match symbol_id {
                Some(id) if !id.trim().is_empty() => id,
                _ => make_symbol_id(&self.repo_id, rel_path, &range, &kind, &name),
            };
            symbols.push(SymbolItem {
                symbol_id: computed_id,
                name,
                kind,
                range,
                signature,
            });
        }

        let outcome_row: Option<(String, Option<String>, Option<String>)> = conn
            .query_row(
                "SELECT outcome_status, outcome_reason, outcome_error_summary \
                 FROM symbols_files WHERE file_path = ?1",
                params![rel_path],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .context("query symbols outcome")?;

        if symbols.is_empty() && outcome_row.is_none() {
            return Ok(None);
        }

        let outcome = outcome_row.and_then(|(status, reason, error_summary)| {
            outcome_status_from_str(&status).map(|status| SymbolOutcome {
                status,
                reason,
                error_summary,
            })
        });

        symbols.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
        Ok(Some(SymbolsResponseV1 {
            schema: default_symbols_schema(),
            repo_id: self.repo_id.clone(),
            file: rel_path.to_string(),
            symbols,
            outcome,
        }))
    }

    pub fn read_ast(&self, rel_path: &str, max_nodes: usize) -> Result<Option<AstResponseV1>> {
        let conn = self.connection()?;
        let max_nodes = max_nodes.max(1);
        let mut nodes: Vec<AstNode> = Vec::new();
        let mut stmt = conn
            .prepare(
                "SELECT node_id, parent_id, kind, field_name, name, is_named, line_start, start_col, line_end, end_col \
                 FROM ast_nodes WHERE file_path = ?1 ORDER BY node_id LIMIT ?2",
            )
            .context("prepare ast read")?;
        let rows = stmt
            .query_map(params![rel_path, max_nodes as i64], |row| {
                let node_id: i64 = row.get(0)?;
                let parent_id: Option<i64> = row.get(1)?;
                let kind: String = row.get(2)?;
                let field_name: Option<String> = row.get(3)?;
                let name: Option<String> = row.get(4)?;
                let is_named: i64 = row.get(5)?;
                let start_line: u32 = row.get::<_, i64>(6)? as u32;
                let start_col: u32 = row.get::<_, i64>(7)? as u32;
                let end_line: u32 = row.get::<_, i64>(8)? as u32;
                let end_col: u32 = row.get::<_, i64>(9)? as u32;
                Ok(AstNode {
                    id: node_id as u32,
                    parent_id: parent_id.map(|value| value as u32),
                    kind,
                    field: field_name,
                    name,
                    is_named: is_named != 0,
                    range: SymbolRange {
                        start_line,
                        start_col,
                        end_line,
                        end_col,
                    },
                })
            })
            .context("query ast nodes")?;
        for row in rows {
            nodes.push(row?);
        }

        let outcome_row: Option<(String, Option<String>, Option<String>, Option<i64>, Option<i64>, Option<String>)> = conn
            .query_row(
                "SELECT outcome_status, outcome_reason, outcome_error_summary, node_count, truncated, file_lang \
                 FROM ast_files WHERE file_path = ?1",
                params![rel_path],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
            )
            .optional()
            .context("query ast outcome")?;

        if nodes.is_empty() && outcome_row.is_none() {
            return Ok(None);
        }

        let (outcome, total_nodes, truncated, language) = if let Some((
            status,
            reason,
            error_summary,
            node_count,
            truncated,
            file_lang,
        )) = outcome_row
        {
            let outcome = outcome_status_from_str(&status).map(|status| SymbolOutcome {
                status,
                reason,
                error_summary,
            });
            let total_nodes = node_count.unwrap_or(nodes.len() as i64).max(0) as usize;
            let truncated_flag = truncated.unwrap_or(0) != 0;
            let truncated = truncated_flag || total_nodes > nodes.len();
            (outcome, total_nodes, truncated, file_lang)
        } else {
            let total_nodes = nodes.len();
            (None, total_nodes, false, None)
        };

        Ok(Some(AstResponseV1 {
            schema: default_ast_schema(),
            repo_id: self.repo_id.clone(),
            file: rel_path.to_string(),
            language,
            nodes,
            total_nodes,
            truncated,
            outcome,
        }))
    }

    pub fn parser_status(&self) -> Result<SymbolsParserStatus> {
        let conn = self.connection()?;
        let current_parser_versions = current_parser_versions();
        let stored_parser_versions = self.read_meta_json(&conn, "parser_versions")?;
        let parser_versions_previous = self.read_meta_json(&conn, "parser_versions_previous")?;
        let parser_versions_changed_at_ms = self.read_meta_i64(&conn, "parser_versions_changed_at_ms")?;
        let symbols_invalidated_at_ms = self.read_meta_i64(&conn, "symbols_invalidated_at_ms")?;
        let symbols_invalidation_reason = self.read_meta_text(&conn, "symbols_invalidation_reason")?;
        let docdex_version = self.read_meta_text(&conn, "docdex_version")?;
        let requires_reindex = self
            .read_meta_bool(&conn, "symbols_reindex_required")?
            .unwrap_or(false);
        let drift = stored_parser_versions
            .as_ref()
            .map(|stored| stored != &current_parser_versions)
            .unwrap_or(false);
        let parser_versions_changed =
            parser_versions_changed_at_ms.is_some() || parser_versions_previous.is_some();
        Ok(SymbolsParserStatus {
            schema: default_symbols_status_schema(),
            repo_id: self.repo_id.clone(),
            current_parser_versions,
            stored_parser_versions,
            parser_versions_previous,
            parser_versions_changed_at_ms,
            symbols_invalidated_at_ms,
            symbols_invalidation_reason,
            docdex_version,
            parser_versions_changed,
            requires_reindex,
            drift,
        })
    }

    pub fn requires_reindex(&self) -> Result<bool> {
        let conn = self.connection()?;
        Ok(self
            .read_meta_bool(&conn, "symbols_reindex_required")?
            .unwrap_or(false))
    }

    pub fn search_symbols(
        &self,
        query: &str,
        max_files: usize,
        max_symbols_per_file: usize,
    ) -> Result<Vec<SymbolSearchMatch>> {
        let tokens = extract_symbol_query_tokens(query);
        if tokens.is_empty() || max_files == 0 || max_symbols_per_file == 0 {
            return Ok(Vec::new());
        }
        let max_rows = max_files
            .saturating_mul(max_symbols_per_file)
            .max(1);
        let mut clauses = Vec::new();
        for idx in 0..tokens.len() {
            let param = idx + 1;
            clauses.push(format!(
                "(LOWER(name) LIKE ?{param} ESCAPE '\\' OR LOWER(signature) LIKE ?{param} ESCAPE '\\')"
            ));
        }
        let sql = format!(
            "SELECT file_path, symbol_id, name, kind, line_start, start_col, line_end, end_col, signature \
             FROM symbols WHERE {} ORDER BY file_path, name LIMIT {}",
            clauses.join(" OR "),
            max_rows
        );
        let conn = self.connection()?;
        let mut stmt = conn
            .prepare(&sql)
            .context("prepare symbols search")?;
        let patterns = tokens
            .iter()
            .map(|token| format!("%{}%", escape_like_token(token)));
        let rows = stmt
            .query_map(params_from_iter(patterns), |row| {
                let file_path: String = row.get(0)?;
                let symbol_id: Option<String> = row.get(1)?;
                let name: String = row.get(2)?;
                let kind: String = row.get(3)?;
                let line_start: u32 = row.get::<_, i64>(4)? as u32;
                let start_col: u32 = row.get::<_, i64>(5)? as u32;
                let line_end: u32 = row.get::<_, i64>(6)? as u32;
                let end_col: u32 = row.get::<_, i64>(7)? as u32;
                let signature: Option<String> = row.get(8)?;
                Ok((
                    file_path,
                    symbol_id,
                    name,
                    kind,
                    line_start,
                    start_col,
                    line_end,
                    end_col,
                    signature,
                ))
            })
            .context("query symbols search")?;
        let mut matches: BTreeMap<String, Vec<SymbolItem>> = BTreeMap::new();
        for row in rows {
            let (
                file_path,
                symbol_id,
                name,
                kind,
                line_start,
                start_col,
                line_end,
                end_col,
                signature,
            ) = row?;
            if matches.len() >= max_files && !matches.contains_key(&file_path) {
                continue;
            }
            let entry = matches.entry(file_path.clone()).or_default();
            if entry.len() >= max_symbols_per_file {
                continue;
            }
            let range = SymbolRange {
                start_line: line_start,
                start_col,
                end_line: line_end,
                end_col,
            };
            let computed_id = match symbol_id {
                Some(id) if !id.trim().is_empty() => id,
                _ => make_symbol_id(&self.repo_id, &file_path, &range, &kind, &name),
            };
            entry.push(SymbolItem {
                symbol_id: computed_id,
                name,
                kind,
                range,
                signature,
            });
        }
        let mut results = Vec::new();
        for (file, mut symbols) in matches {
            symbols.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
            results.push(SymbolSearchMatch { file, symbols });
        }
        Ok(results)
    }

    pub fn search_ast_kinds(
        &self,
        kinds: &[String],
        max_files: usize,
    ) -> Result<Vec<AstSearchMatch>> {
        self.search_ast_kinds_with_mode(kinds, max_files, AstSearchMode::Any)
    }

    pub fn ast_kind_counts_for_file(
        &self,
        rel_path: &str,
        kinds: &[String],
    ) -> Result<BTreeMap<String, usize>> {
        let mut counts = BTreeMap::new();
        if kinds.is_empty() {
            return Ok(counts);
        }
        let conn = self.connection()?;
        let mut sql = String::from(
            "SELECT kind, COUNT(*) as match_count FROM ast_nodes WHERE file_path = ?1 AND kind IN (",
        );
        for idx in 0..kinds.len() {
            if idx > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("?{}", idx + 2));
        }
        sql.push_str(") GROUP BY kind");
        let mut params: Vec<rusqlite::types::Value> = Vec::with_capacity(kinds.len() + 1);
        params.push(rel_path.to_string().into());
        params.extend(kinds.iter().cloned().map(Into::into));
        let mut stmt = conn
            .prepare(&sql)
            .context("prepare ast kind counts")?;
        let mut rows = stmt
            .query(params_from_iter(params.iter()))
            .context("query ast kind counts")?;
        while let Some(row) = rows.next().context("read ast kind count row")? {
            let kind: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            counts.insert(kind, count.max(0) as usize);
        }
        Ok(counts)
    }

    pub fn search_ast_kinds_with_mode(
        &self,
        kinds: &[String],
        max_files: usize,
        mode: AstSearchMode,
    ) -> Result<Vec<AstSearchMatch>> {
        if kinds.is_empty() || max_files == 0 {
            return Ok(Vec::new());
        }
        let conn = self.connection()?;
        let mut sql =
            String::from("SELECT file_path, COUNT(*) as match_count FROM ast_nodes WHERE kind IN (");
        for idx in 0..kinds.len() {
            if idx > 0 {
                sql.push(',');
            }
            sql.push_str(&format!("?{}", idx + 1));
        }
        sql.push(')');
        if mode == AstSearchMode::All {
            sql.push_str(" GROUP BY file_path HAVING COUNT(DISTINCT kind) = ?");
        } else {
            sql.push_str(" GROUP BY file_path");
        }
        sql.push_str(" ORDER BY match_count DESC, file_path ASC LIMIT ?");
        let mut params: Vec<rusqlite::types::Value> =
            kinds.iter().cloned().map(Into::into).collect();
        if mode == AstSearchMode::All {
            params.push((kinds.len() as i64).into());
        }
        params.push((max_files as i64).into());
        let mut stmt = conn
            .prepare(&sql)
            .context("prepare ast kind search")?;
        let mut rows = stmt
            .query(params_from_iter(params.iter()))
            .context("query ast kind matches")?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().context("read ast kind row")? {
            let file: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            let count = count.max(0) as usize;
            out.push(AstSearchMatch {
                file,
                match_count: count,
            });
        }
        Ok(out)
    }

    pub fn query_ast(&self, query: &AstQuery) -> Result<Vec<AstQueryMatch>> {
        if query.kinds.is_empty() || query.limit == 0 || query.sample_limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.connection()?;
        let (filter_sql, mut params) = build_ast_query_filters(query, None);
        let mut sql = format!(
            "SELECT file_path, COUNT(*) as match_count FROM ast_nodes{filter_sql} GROUP BY file_path"
        );
        if query.mode == AstSearchMode::All {
            sql.push_str(" HAVING COUNT(DISTINCT kind) >= ?");
            params.push((query.kinds.len() as i64).into());
        }
        sql.push_str(" ORDER BY match_count DESC, file_path ASC LIMIT ?");
        params.push((query.limit as i64).into());
        let mut stmt = conn.prepare(&sql).context("prepare ast query")?;
        let mut rows = stmt
            .query(params_from_iter(params.iter()))
            .context("query ast matches")?;
        let mut matches = Vec::new();
        while let Some(row) = rows.next().context("read ast match row")? {
            let file: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            matches.push(AstQueryMatch {
                file,
                match_count: count.max(0) as usize,
                samples: Vec::new(),
            });
        }
        for item in &mut matches {
            item.samples = query_ast_samples(&conn, query, &item.file)?;
        }
        Ok(matches)
    }

    pub fn delete_symbols(&self, rel_path: &str) -> Result<()> {
        let conn = self.connection()?;
        conn.execute("DELETE FROM symbols WHERE file_path = ?1", params![rel_path])
            .context("delete symbols rows")?;
        conn.execute(
            "DELETE FROM symbols_files WHERE file_path = ?1",
            params![rel_path],
        )
        .context("delete symbols outcome")?;
        conn.execute("DELETE FROM ast_nodes WHERE file_path = ?1", params![rel_path])
            .context("delete ast nodes")?;
        conn.execute(
            "DELETE FROM ast_files WHERE file_path = ?1",
            params![rel_path],
        )
        .context("delete ast outcome")?;
        Ok(())
    }

    fn ensure_schema_version(&self) -> Result<()> {
        let legacy_dir = self.prepare_legacy_dir()?;
        let conn = self.connection()?;
        self.init_schema(&conn)?;
        self.validate_migration_steps()?;
        let version = self
            .read_schema_version(&conn)?
            .unwrap_or(SYMBOLS_SCHEMA_VERSION);
        match version {
            v if v == SYMBOLS_SCHEMA_VERSION => {}
            v if v > SYMBOLS_SCHEMA_VERSION => {
                return Err(anyhow!(
                    "symbols schema version {v} is newer than supported {SYMBOLS_SCHEMA_VERSION}"
                ));
            }
            v => {
                self.migrate_schema(&conn, v, SYMBOLS_SCHEMA_VERSION)?;
                self.store_schema_version(&conn, SYMBOLS_SCHEMA_VERSION)?;
            }
        }
        self.ensure_parser_versions(&conn)?;
        if let Some(legacy_dir) = legacy_dir {
            self.migrate_from_legacy(&conn, &legacy_dir)?;
        }
        Ok(())
    }

    fn connection(&self) -> Result<Connection> {
        Connection::open(&self.db_path)
            .with_context(|| format!("open {}", self.db_path.display()))
    }

    fn init_schema(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS symbols_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); \
             CREATE TABLE IF NOT EXISTS symbols_files ( \
                 file_path TEXT PRIMARY KEY, \
                 outcome_status TEXT, \
                 outcome_reason TEXT, \
                 outcome_error_summary TEXT, \
                 file_lang TEXT \
             ); \
             CREATE TABLE IF NOT EXISTS symbols ( \
                 id INTEGER PRIMARY KEY AUTOINCREMENT, \
                 file_path TEXT NOT NULL, \
                 symbol_id TEXT, \
                 name TEXT NOT NULL, \
                 kind TEXT NOT NULL, \
                 line_start INTEGER NOT NULL, \
                 start_col INTEGER NOT NULL, \
                 line_end INTEGER NOT NULL, \
                 end_col INTEGER NOT NULL, \
                 signature TEXT \
             ); \
             CREATE INDEX IF NOT EXISTS symbols_file_idx ON symbols(file_path); \
             CREATE INDEX IF NOT EXISTS symbols_name_idx ON symbols(name); \
             CREATE INDEX IF NOT EXISTS symbols_kind_idx ON symbols(kind); \
             CREATE INDEX IF NOT EXISTS symbols_lang_idx ON symbols_files(file_lang); \
             CREATE TABLE IF NOT EXISTS ast_files ( \
                 file_path TEXT PRIMARY KEY, \
                 outcome_status TEXT, \
                 outcome_reason TEXT, \
                 outcome_error_summary TEXT, \
                 node_count INTEGER, \
                 truncated INTEGER, \
                 file_lang TEXT \
             ); \
             CREATE TABLE IF NOT EXISTS ast_nodes ( \
                 file_path TEXT NOT NULL, \
                 node_id INTEGER NOT NULL, \
                 parent_id INTEGER, \
                 kind TEXT NOT NULL, \
                 field_name TEXT, \
                 name TEXT, \
                 is_named INTEGER NOT NULL, \
                 line_start INTEGER NOT NULL, \
                 start_col INTEGER NOT NULL, \
                 line_end INTEGER NOT NULL, \
                 end_col INTEGER NOT NULL, \
                 PRIMARY KEY (file_path, node_id) \
             ); \
             CREATE INDEX IF NOT EXISTS ast_nodes_file_idx ON ast_nodes(file_path); \
             CREATE INDEX IF NOT EXISTS ast_nodes_kind_idx ON ast_nodes(kind); \
             CREATE INDEX IF NOT EXISTS ast_nodes_field_idx ON ast_nodes(field_name); \
             CREATE INDEX IF NOT EXISTS ast_nodes_name_idx ON ast_nodes(name); \
             CREATE INDEX IF NOT EXISTS ast_files_lang_idx ON ast_files(file_lang);",
        )
        .context("init symbols schema")?;
        if self.read_schema_version(conn)?.is_none() {
            self.store_schema_version(conn, SYMBOLS_SCHEMA_VERSION)?;
        }
        Ok(())
    }

    fn read_schema_version(&self, conn: &Connection) -> Result<Option<u32>> {
        let raw: Option<String> = conn
            .query_row(
                "SELECT value FROM symbols_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("read symbols schema version")?;
        Ok(raw.and_then(|value| value.parse::<u32>().ok()))
    }

    fn store_schema_version(&self, conn: &Connection, version: u32) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO symbols_meta (key, value) VALUES ('schema_version', ?1)",
            params![version as i64],
        )
        .context("write symbols schema version")?;
        Ok(())
    }

    fn read_meta_text(&self, conn: &Connection, key: &str) -> Result<Option<String>> {
        let value: Option<String> = conn
            .query_row(
                "SELECT value FROM symbols_meta WHERE key = ?1",
                params![key],
                |row| row.get(0),
            )
            .optional()
            .with_context(|| format!("read symbols meta {key}"))?;
        Ok(value)
    }

    fn read_meta_json(&self, conn: &Connection, key: &str) -> Result<Option<serde_json::Value>> {
        let raw = self.read_meta_text(conn, key)?;
        match raw {
            None => Ok(None),
            Some(value) => {
                let parsed = serde_json::from_str(&value)
                    .with_context(|| format!("parse symbols meta {key}"))?;
                Ok(Some(parsed))
            }
        }
    }

    fn read_meta_i64(&self, conn: &Connection, key: &str) -> Result<Option<i64>> {
        let raw = self.read_meta_text(conn, key)?;
        match raw {
            None => Ok(None),
            Some(value) => Ok(value.parse::<i64>().ok()),
        }
    }

    fn read_meta_bool(&self, conn: &Connection, key: &str) -> Result<Option<bool>> {
        let raw = self.read_meta_text(conn, key)?;
        match raw {
            None => Ok(None),
            Some(value) => {
                let trimmed = value.trim().to_lowercase();
                Ok(Some(matches!(trimmed.as_str(), "1" | "true" | "yes" | "on")))
            }
        }
    }

    fn store_meta_text(&self, conn: &Connection, key: &str, value: &str) -> Result<()> {
        conn.execute(
            "INSERT OR REPLACE INTO symbols_meta (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .with_context(|| format!("write symbols meta {key}"))?;
        Ok(())
    }

    fn clear_reindex_required(&self) -> Result<()> {
        let conn = self.connection()?;
        conn.execute(
            "DELETE FROM symbols_meta WHERE key = 'symbols_reindex_required'",
            [],
        )
        .context("clear symbols reindex flag")?;
        Ok(())
    }

    fn ensure_parser_versions(&self, conn: &Connection) -> Result<()> {
        let current = current_parser_versions();
        let current_str =
            serde_json::to_string(&current).context("serialize parser versions")?;
        if let Some(prev) = self.read_meta_text(conn, "parser_versions")? {
            if prev != current_str {
                warn!(
                    target: "docdexd",
                    previous = %prev,
                    current = %current_str,
                    "tree-sitter parser versions changed; invalidating symbols until reindex"
                );
                self.invalidate_symbols(conn, "parser_versions_changed")?;
                self.store_meta_text(conn, "symbols_reindex_required", "1")?;
                self.store_meta_text(conn, "parser_versions_previous", &prev)?;
                let now_ms = now_epoch_ms().to_string();
                self.store_meta_text(conn, "parser_versions_changed_at_ms", &now_ms)?;
            }
        }
        self.store_meta_text(conn, "parser_versions", &current_str)?;
        self.store_meta_text(conn, "docdex_version", env!("CARGO_PKG_VERSION"))?;
        Ok(())
    }

    fn invalidate_symbols(&self, conn: &Connection, reason: &str) -> Result<()> {
        conn.execute("DELETE FROM symbols", [])
            .context("clear symbols rows")?;
        conn.execute("DELETE FROM symbols_files", [])
            .context("clear symbols outcomes")?;
        conn.execute("DELETE FROM ast_nodes", [])
            .context("clear ast nodes")?;
        conn.execute("DELETE FROM ast_files", [])
            .context("clear ast outcomes")?;
        let now_ms = now_epoch_ms().to_string();
        self.store_meta_text(conn, "symbols_invalidated_at_ms", &now_ms)?;
        self.store_meta_text(conn, "symbols_invalidation_reason", reason)?;
        Ok(())
    }

    fn migrate_schema(&self, conn: &Connection, from: u32, to: u32) -> Result<()> {
        if from < SYMBOLS_SCHEMA_MIN_VERSION {
            return Err(anyhow!(
                "symbols schema version {from} is below minimum supported {SYMBOLS_SCHEMA_MIN_VERSION}"
            ));
        }
        let steps = Self::migration_steps();
        let mut current = from;
        while current < to {
            let next = current + 1;
            let Some(step) = steps.get(&next) else {
                return Err(anyhow!(
                    "missing symbols schema migration step for v{next}"
                ));
            };
            step(self, conn)?;
            current = next;
        }
        Ok(())
    }

    fn validate_migration_steps(&self) -> Result<()> {
        let steps = Self::migration_steps();
        for version in SYMBOLS_SCHEMA_MIN_VERSION..=SYMBOLS_SCHEMA_VERSION {
            if !steps.contains_key(&version) {
                return Err(anyhow!(
                    "missing symbols schema migration step for v{version}"
                ));
            }
        }
        Ok(())
    }

    fn migration_steps() -> BTreeMap<u32, fn(&SymbolsStore, &Connection) -> Result<()>> {
        let mut steps: BTreeMap<u32, fn(&SymbolsStore, &Connection) -> Result<()>> =
            BTreeMap::new();
        steps.insert(1, SymbolsStore::migrate_to_v1);
        steps.insert(2, SymbolsStore::migrate_to_v2);
        steps.insert(3, SymbolsStore::migrate_to_v3);
        steps.insert(4, SymbolsStore::migrate_to_v4);
        steps.insert(5, SymbolsStore::migrate_to_v5);
        steps
    }

    fn migrate_to_v1(&self, _conn: &Connection) -> Result<()> {
        Ok(())
    }

    fn migrate_to_v2(&self, conn: &Connection) -> Result<()> {
        if !self.column_exists(conn, "symbols_files", "file_lang")? {
            conn.execute("ALTER TABLE symbols_files ADD COLUMN file_lang TEXT", [])
                .context("add symbols_files.file_lang")?;
        }
        let mut stmt = conn
            .prepare("SELECT file_path FROM symbols_files")
            .context("select symbols_files file_path")?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .context("read symbols_files file_path")?;
        for row in rows {
            let path = row?;
            let lang = language_for_path(&path).map(|l| l.as_str().to_string());
            if let Some(lang) = lang {
                conn.execute(
                    "UPDATE symbols_files SET file_lang = ?1 WHERE file_path = ?2 AND (file_lang IS NULL OR file_lang = '')",
                    params![lang, path],
                )
                .context("backfill symbols_files.file_lang")?;
            }
        }
        Ok(())
    }

    fn migrate_to_v3(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS symbols_name_idx ON symbols(name); \
             CREATE INDEX IF NOT EXISTS symbols_kind_idx ON symbols(kind); \
             CREATE INDEX IF NOT EXISTS symbols_lang_idx ON symbols_files(file_lang);",
        )
        .context("add symbols indexes")?;
        Ok(())
    }

    fn migrate_to_v4(&self, conn: &Connection) -> Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS ast_files ( \
                file_path TEXT PRIMARY KEY, \
                outcome_status TEXT, \
                outcome_reason TEXT, \
                outcome_error_summary TEXT, \
                node_count INTEGER, \
                truncated INTEGER, \
                file_lang TEXT \
            ); \
            CREATE TABLE IF NOT EXISTS ast_nodes ( \
                file_path TEXT NOT NULL, \
                node_id INTEGER NOT NULL, \
                parent_id INTEGER, \
                kind TEXT NOT NULL, \
                field_name TEXT, \
                name TEXT, \
                is_named INTEGER NOT NULL, \
                line_start INTEGER NOT NULL, \
                start_col INTEGER NOT NULL, \
                line_end INTEGER NOT NULL, \
                end_col INTEGER NOT NULL, \
                PRIMARY KEY (file_path, node_id) \
            ); \
            CREATE INDEX IF NOT EXISTS ast_nodes_file_idx ON ast_nodes(file_path); \
            CREATE INDEX IF NOT EXISTS ast_nodes_kind_idx ON ast_nodes(kind); \
            CREATE INDEX IF NOT EXISTS ast_nodes_field_idx ON ast_nodes(field_name); \
            CREATE INDEX IF NOT EXISTS ast_nodes_name_idx ON ast_nodes(name); \
            CREATE INDEX IF NOT EXISTS ast_files_lang_idx ON ast_files(file_lang);",
        )
        .context("add ast tables")?;
        Ok(())
    }

    fn migrate_to_v5(&self, conn: &Connection) -> Result<()> {
        if !self.column_exists(conn, "ast_nodes", "field_name")? {
            conn.execute("ALTER TABLE ast_nodes ADD COLUMN field_name TEXT", [])
                .context("add ast_nodes.field_name")?;
        }
        if !self.column_exists(conn, "ast_nodes", "name")? {
            conn.execute("ALTER TABLE ast_nodes ADD COLUMN name TEXT", [])
                .context("add ast_nodes.name")?;
        }
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS ast_nodes_field_idx ON ast_nodes(field_name); \
             CREATE INDEX IF NOT EXISTS ast_nodes_name_idx ON ast_nodes(name);",
        )
        .context("add ast node metadata indexes")?;
        Ok(())
    }

    fn column_exists(&self, conn: &Connection, table: &str, column: &str) -> Result<bool> {
        let mut stmt = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .with_context(|| format!("table_info for {table}"))?;
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .with_context(|| format!("read columns for {table}"))?;
        for row in rows {
            if row? == column {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn prepare_legacy_dir(&self) -> Result<Option<PathBuf>> {
        if let Some(legacy_path) = self.legacy_db_path.as_ref() {
            if legacy_path.exists() && !self.db_path.exists() {
                if legacy_path.is_file() {
                    fs::rename(legacy_path, &self.db_path).with_context(|| {
                        format!(
                            "move legacy symbols db {} -> {}",
                            legacy_path.display(),
                            self.db_path.display()
                        )
                    })?;
                    return Ok(None);
                }
                let moved = self.rename_legacy_dir(legacy_path)?;
                return Ok(Some(moved));
            }
        }

        if self.db_path.exists() && self.db_path.is_dir() {
            let moved = self.rename_legacy_dir(&self.db_path)?;
            return Ok(Some(moved));
        }
        Ok(None)
    }

    fn rename_legacy_dir(&self, path: &Path) -> Result<PathBuf> {
        let legacy_path = legacy_path_for(path);
        let target = if legacy_path.exists() {
            unique_legacy_path(&legacy_path)
        } else {
            legacy_path
        };
        fs::rename(path, &target)
            .with_context(|| format!("move legacy {}", path.display()))?;
        Ok(target)
    }

    fn migrate_from_legacy(&self, conn: &Connection, legacy_dir: &Path) -> Result<()> {
        let files_dir = legacy_dir.join("files");
        if !files_dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&files_dir)
            .with_context(|| format!("read {}", files_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let raw = match fs::read_to_string(&path) {
                Ok(raw) => raw,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
            };
            let payload: SymbolsResponseV1 = match serde_json::from_str(&raw) {
                Ok(payload) => payload,
                Err(err) => {
                    tracing::warn!(
                        target: "docdexd",
                        error = ?err,
                        path = %path.display(),
                        "failed to parse legacy symbols payload"
                    );
                    continue;
                }
            };
            let rel_path = if payload.file.is_empty() {
                continue;
            } else {
                payload.file.as_str()
            };
            self.upsert_symbols_tx(conn, rel_path, &payload)?;
        }
        Ok(())
    }

    fn upsert_symbols_tx(
        &self,
        conn: &Connection,
        rel_path: &str,
        payload: &SymbolsResponseV1,
    ) -> Result<()> {
        conn.execute("DELETE FROM symbols WHERE file_path = ?1", params![rel_path])
            .context("clear symbols rows")?;

        if let Some(outcome) = payload.outcome.as_ref() {
            let file_lang = language_for_path(rel_path).map(|lang| lang.as_str().to_string());
            conn.execute(
                "INSERT OR REPLACE INTO symbols_files \
                 (file_path, outcome_status, outcome_reason, outcome_error_summary, file_lang) \
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    rel_path,
                    outcome_status_to_str(&outcome.status),
                    outcome.reason,
                    outcome.error_summary,
                    file_lang
                ],
            )
            .context("upsert symbols outcome")?;
        } else {
            conn.execute(
                "DELETE FROM symbols_files WHERE file_path = ?1",
                params![rel_path],
            )
            .context("clear symbols outcome")?;
        }

        for symbol in &payload.symbols {
            let symbol_id = if symbol.symbol_id.is_empty() {
                make_symbol_id(
                    &self.repo_id,
                    rel_path,
                    &symbol.range,
                    &symbol.kind,
                    &symbol.name,
                )
            } else {
                symbol.symbol_id.clone()
            };
            conn.execute(
                "INSERT INTO symbols \
                 (file_path, symbol_id, name, kind, line_start, start_col, line_end, end_col, signature) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    rel_path,
                    symbol_id,
                    symbol.name,
                    symbol.kind,
                    symbol.range.start_line as i64,
                    symbol.range.start_col as i64,
                    symbol.range.end_line as i64,
                    symbol.range.end_col as i64,
                    symbol.signature
                ],
            )
            .context("insert symbol row")?;
        }
        Ok(())
    }

    fn upsert_ast_tx(
        &self,
        conn: &Connection,
        rel_path: &str,
        payload: &AstResponseV1,
    ) -> Result<()> {
        conn.execute("DELETE FROM ast_nodes WHERE file_path = ?1", params![rel_path])
            .context("clear ast nodes")?;
        if let Some(outcome) = payload.outcome.as_ref() {
            conn.execute(
                "INSERT OR REPLACE INTO ast_files \
                 (file_path, outcome_status, outcome_reason, outcome_error_summary, node_count, truncated, file_lang) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    rel_path,
                    outcome_status_to_str(&outcome.status),
                    outcome.reason,
                    outcome.error_summary,
                    payload.total_nodes as i64,
                    if payload.truncated { 1 } else { 0 },
                    payload.language.as_deref()
                ],
            )
            .context("upsert ast outcome")?;
        } else {
            conn.execute(
                "DELETE FROM ast_files WHERE file_path = ?1",
                params![rel_path],
            )
            .context("clear ast outcome")?;
        }
        for node in &payload.nodes {
            let range = &node.range;
            conn.execute(
                "INSERT INTO ast_nodes \
                 (file_path, node_id, parent_id, kind, field_name, name, is_named, line_start, start_col, line_end, end_col) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    rel_path,
                    node.id as i64,
                    node.parent_id.map(|value| value as i64),
                    node.kind,
                    node.field,
                    node.name,
                    if node.is_named { 1 } else { 0 },
                    range.start_line as i64,
                    range.start_col as i64,
                    range.end_line as i64,
                    range.end_col as i64,
                ],
            )
            .context("insert ast node")?;
        }
        Ok(())
    }
}

fn build_ast_query_filters(
    query: &AstQuery,
    file_path: Option<&str>,
) -> (String, Vec<rusqlite::types::Value>) {
    let mut clauses = Vec::new();
    let mut params: Vec<rusqlite::types::Value> = Vec::new();

    if let Some(path) = file_path {
        clauses.push("file_path = ?".to_string());
        params.push(path.to_string().into());
    } else if let Some(prefix) = query.path_prefix.as_deref() {
        let trimmed = prefix.trim().trim_matches('/');
        if !trimmed.is_empty() {
            let mut pattern = trimmed.to_string();
            pattern.push('/');
            pattern.push('%');
            clauses.push("(file_path = ? OR file_path LIKE ? ESCAPE '\\')".to_string());
            params.push(trimmed.to_string().into());
            params.push(pattern.into());
        }
    }

    if !query.kinds.is_empty() {
        let mut clause = String::from("kind IN (");
        for idx in 0..query.kinds.len() {
            if idx > 0 {
                clause.push(',');
            }
            clause.push('?');
        }
        clause.push(')');
        clauses.push(clause);
        params.extend(query.kinds.iter().cloned().map(Into::into));
    }

    if let Some(name) = query.name.as_deref().map(str::trim) {
        if !name.is_empty() {
            clauses.push("name = ?".to_string());
            params.push(name.to_string().into());
        }
    }

    if let Some(field) = query.field.as_deref().map(str::trim) {
        if !field.is_empty() {
            clauses.push("field_name = ?".to_string());
            params.push(field.to_string().into());
        }
    }

    let filter_sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    (filter_sql, params)
}

fn query_ast_samples(conn: &Connection, query: &AstQuery, file_path: &str) -> Result<Vec<AstNode>> {
    if query.sample_limit == 0 {
        return Ok(Vec::new());
    }
    let (filter_sql, mut params) = build_ast_query_filters(query, Some(file_path));
    let sql = format!(
        "SELECT node_id, parent_id, kind, field_name, name, is_named, line_start, start_col, line_end, end_col \
         FROM ast_nodes{filter_sql} ORDER BY node_id LIMIT ?"
    );
    params.push((query.sample_limit as i64).into());
    let mut stmt = conn.prepare(&sql).context("prepare ast query samples")?;
    let rows = stmt
        .query_map(params_from_iter(params.iter()), |row| {
            let node_id: i64 = row.get(0)?;
            let parent_id: Option<i64> = row.get(1)?;
            let kind: String = row.get(2)?;
            let field_name: Option<String> = row.get(3)?;
            let name: Option<String> = row.get(4)?;
            let is_named: i64 = row.get(5)?;
            let start_line: u32 = row.get::<_, i64>(6)? as u32;
            let start_col: u32 = row.get::<_, i64>(7)? as u32;
            let end_line: u32 = row.get::<_, i64>(8)? as u32;
            let end_col: u32 = row.get::<_, i64>(9)? as u32;
            Ok(AstNode {
                id: node_id as u32,
                parent_id: parent_id.map(|value| value as u32),
                kind,
                field: field_name,
                name,
                is_named: is_named != 0,
                range: SymbolRange {
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                },
            })
        })
        .context("query ast samples")?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn legacy_path_for(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("symbols.db");
    path.with_file_name(format!("{file_name}.legacy"))
}

fn unique_legacy_path(base: &Path) -> PathBuf {
    let mut candidate = base.to_path_buf();
    let mut idx = 1;
    while candidate.exists() {
        candidate = base.with_file_name(format!(
            "{}.{}",
            base.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("symbols.db.legacy"),
            idx
        ));
        idx += 1;
    }
    candidate
}

fn current_parser_versions() -> serde_json::Value {
    serde_json::json!({
        "tree_sitter": TREE_SITTER_VERSION,
        "tree_sitter_rust": TREE_SITTER_RUST_VERSION,
        "tree_sitter_python": TREE_SITTER_PYTHON_VERSION,
        "tree_sitter_javascript": TREE_SITTER_JAVASCRIPT_VERSION,
        "tree_sitter_typescript": TREE_SITTER_TYPESCRIPT_VERSION,
        "tree_sitter_go": TREE_SITTER_GO_VERSION,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbols_migration_steps_cover_all_versions() {
        let steps = SymbolsStore::migration_steps();
        for version in SYMBOLS_SCHEMA_MIN_VERSION..=SYMBOLS_SCHEMA_VERSION {
            assert!(
                steps.contains_key(&version),
                "missing migration step for v{version}"
            );
        }
    }
}

fn extract_symbol_query_tokens(query: &str) -> Vec<String> {
    const MAX_TOKENS: usize = 6;
    const MIN_LEN: usize = 2;

    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for raw in query.split_whitespace() {
        for part in raw.split(|ch: char| !ch.is_alphanumeric() && ch != '_') {
            let trimmed = part.trim();
            if trimmed.len() < MIN_LEN {
                continue;
            }
            let lowered = trimmed.to_lowercase();
            if seen.insert(lowered.clone()) {
                out.push(lowered);
                if out.len() >= MAX_TOKENS {
                    return out;
                }
            }
        }
    }
    out
}

fn escape_like_token(token: &str) -> String {
    token.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_")
}

fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn outcome_status_to_str(status: &SymbolOutcomeStatus) -> &'static str {
    match status {
        SymbolOutcomeStatus::Ok => "ok",
        SymbolOutcomeStatus::Skipped => "skipped",
        SymbolOutcomeStatus::Failed => "failed",
    }
}

fn outcome_status_from_str(status: &str) -> Option<SymbolOutcomeStatus> {
    match status {
        "ok" => Some(SymbolOutcomeStatus::Ok),
        "skipped" => Some(SymbolOutcomeStatus::Skipped),
        "failed" => Some(SymbolOutcomeStatus::Failed),
        _ => None,
    }
}

pub fn build_symbols_payload(
    repo_id: &str,
    file: &str,
    symbols: Vec<SymbolItem>,
    outcome: SymbolOutcome,
) -> SymbolsResponseV1 {
    SymbolsResponseV1 {
        schema: default_symbols_schema(),
        repo_id: repo_id.to_string(),
        file: file.to_string(),
        symbols,
        outcome: Some(outcome),
    }
}

pub fn build_ast_payload(
    repo_id: &str,
    file: &str,
    language: Option<String>,
    nodes: Vec<AstNode>,
    total_nodes: usize,
    truncated: bool,
    outcome: SymbolOutcome,
) -> AstResponseV1 {
    let total_nodes = total_nodes.max(nodes.len());
    AstResponseV1 {
        schema: default_ast_schema(),
        repo_id: repo_id.to_string(),
        file: file.to_string(),
        language,
        nodes,
        total_nodes,
        truncated,
        outcome: Some(outcome),
    }
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
            extract_js_ts_symbols(repo_id, rel_path, content, language)
        }
        SourceLanguage::Go => extract_go_symbols(repo_id, rel_path, content),
    }?;
    symbols.sort_by(|a, b| a.symbol_id.cmp(&b.symbol_id));
    Ok(symbols)
}

pub struct AstExtractionResult {
    pub nodes: Vec<AstNode>,
    pub total_nodes: usize,
    pub truncated: bool,
}

pub fn extract_ast_nodes_best_effort(
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
) -> Result<AstExtractionResult> {
    let Some(ts_language) = tree_sitter_language(language, rel_path) else {
        return Err(anyhow!(
            "tree-sitter language unavailable for {}",
            language.as_str()
        ));
    };
    let mut parser = Parser::new();
    parser
        .set_language(ts_language)
        .map_err(|err| anyhow!("tree-sitter language init failed: {err}"))?;
    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow!("tree-sitter parse failed"))?;
    let mut nodes = Vec::new();
    let mut next_id: u32 = 0;
    let mut total_nodes: usize = 0;
    let mut truncated = false;
    collect_ast_nodes(
        &mut nodes,
        content,
        tree.root_node(),
        None,
        None,
        &mut next_id,
        &mut total_nodes,
        &mut truncated,
    );
    Ok(AstExtractionResult {
        nodes,
        total_nodes,
        truncated,
    })
}

fn make_symbol_id(
    repo_id: &str,
    file: &str,
    range: &SymbolRange,
    kind: &str,
    name: &str,
) -> String {
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
    let range = SymbolRange {
        start_line,
        start_col,
        end_line,
        end_col,
    };
    let symbol_id = make_symbol_id(repo_id, file, &range, kind, &name);
    SymbolItem {
        symbol_id,
        name,
        kind: kind.to_string(),
        range,
        signature,
    }
}

fn extract_markdown_symbols(
    repo_id: &str,
    rel_path: &str,
    content: &str,
) -> Result<Vec<SymbolItem>> {
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
    extract_tree_sitter_symbols(repo_id, rel_path, content, SourceLanguage::Rust)
}

fn extract_python_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    extract_tree_sitter_symbols(repo_id, rel_path, content, SourceLanguage::Python)
}

fn extract_js_ts_symbols(
    repo_id: &str,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
) -> Result<Vec<SymbolItem>> {
    extract_tree_sitter_symbols(repo_id, rel_path, content, language)
}

fn extract_go_symbols(repo_id: &str, rel_path: &str, content: &str) -> Result<Vec<SymbolItem>> {
    extract_tree_sitter_symbols(repo_id, rel_path, content, SourceLanguage::Go)
}

fn extract_tree_sitter_symbols(
    repo_id: &str,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
) -> Result<Vec<SymbolItem>> {
    let Some(ts_language) = tree_sitter_language(language, rel_path) else {
        return Err(anyhow!(
            "tree-sitter language unavailable for {}",
            language.as_str()
        ));
    };
    let mut parser = Parser::new();
    parser
        .set_language(ts_language)
        .map_err(|err| anyhow!("tree-sitter language init failed: {err}"))?;
    let tree = parser
        .parse(content, None)
        .ok_or_else(|| anyhow!("tree-sitter parse failed"))?;
    let mut symbols = Vec::new();
    collect_tree_sitter_symbols(
        &mut symbols,
        repo_id,
        rel_path,
        content,
        language,
        tree.root_node(),
    );
    Ok(symbols)
}

fn tree_sitter_language(language: SourceLanguage, rel_path: &str) -> Option<Language> {
    match language {
        SourceLanguage::Rust => Some(ts_rust::language()),
        SourceLanguage::Python => Some(ts_python::language()),
        SourceLanguage::JavaScript => Some(ts_javascript::language()),
        SourceLanguage::TypeScript => {
            if rel_path.to_lowercase().ends_with(".tsx") {
                Some(ts_typescript::language_tsx())
            } else {
                Some(ts_typescript::language_typescript())
            }
        }
        SourceLanguage::Go => Some(ts_go::language()),
        SourceLanguage::Markdown => None,
    }
}

fn collect_tree_sitter_symbols(
    symbols: &mut Vec<SymbolItem>,
    repo_id: &str,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
    node: Node,
) {
    if let Some(symbol) = symbol_from_node(repo_id, rel_path, content, language, node) {
        symbols.push(symbol);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_tree_sitter_symbols(symbols, repo_id, rel_path, content, language, child);
    }
}

fn symbol_from_node(
    repo_id: &str,
    rel_path: &str,
    content: &str,
    language: SourceLanguage,
    node: Node,
) -> Option<SymbolItem> {
    match language {
        SourceLanguage::Rust => match node.kind() {
            "function_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "function",
                Some(&['{']),
            ),
            "struct_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "struct",
                None,
            ),
            "enum_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "enum",
                None,
            ),
            "trait_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "trait",
                None,
            ),
            "type_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "type",
                None,
            ),
            "mod_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "module",
                None,
            ),
            "const_item" | "static_item" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "variable",
                None,
            ),
            "macro_definition" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "macro",
                None,
            ),
            _ => None,
        },
        SourceLanguage::Python => match node.kind() {
            "function_definition" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "function",
                Some(&[':']),
            ),
            "class_definition" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "class",
                None,
            ),
            _ => None,
        },
        SourceLanguage::JavaScript | SourceLanguage::TypeScript => match node.kind() {
            "function_declaration" | "generator_function_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "function",
                Some(&['{']),
            ),
            "class_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "class",
                None,
            ),
            "method_definition" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "method",
                Some(&['{']),
            ),
            "interface_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "interface",
                None,
            ),
            "type_alias_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "type",
                None,
            ),
            "enum_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "enum",
                None,
            ),
            _ => None,
        },
        SourceLanguage::Go => match node.kind() {
            "function_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "function",
                Some(&['{']),
            ),
            "method_declaration" => symbol_from_named_node(
                repo_id,
                rel_path,
                content,
                node,
                "name",
                "method",
                Some(&['{']),
            ),
            "type_spec" => {
                let name = node_name(content, node, "name")?;
                let kind = match node.child_by_field_name("type") {
                    Some(type_node) => match type_node.kind() {
                        "struct_type" => "struct",
                        "interface_type" => "interface",
                        _ => "type",
                    },
                    None => "type",
                };
                let (start_line, start_col, end_line, end_col) = node_range(node);
                Some(make_symbol(
                    repo_id,
                    rel_path,
                    name,
                    kind,
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                    None,
                ))
            }
            _ => None,
        },
        SourceLanguage::Markdown => None,
    }
}

fn symbol_from_named_node(
    repo_id: &str,
    rel_path: &str,
    content: &str,
    node: Node,
    name_field: &str,
    kind: &'static str,
    signature_terms: Option<&[char]>,
) -> Option<SymbolItem> {
    let name = node_name(content, node, name_field)?;
    let (start_line, start_col, end_line, end_col) = node_range(node);
    let signature = signature_terms.and_then(|terms| signature_from_node(content, node, terms));
    Some(make_symbol(
        repo_id,
        rel_path,
        name,
        kind,
        start_line,
        start_col,
        end_line,
        end_col,
        signature,
    ))
}

fn node_range(node: Node) -> (u32, u32, u32, u32) {
    let start = node.start_position();
    let end = node.end_position();
    (
        start.row as u32 + 1,
        start.column as u32 + 1,
        end.row as u32 + 1,
        end.column as u32 + 1,
    )
}

fn node_name_value(content: &str, node: Node) -> Option<String> {
    if let Some(name_node) = node.child_by_field_name("name") {
        return normalize_node_name_text(content, name_node);
    }
    if is_identifier_kind(node.kind()) {
        return normalize_node_name_text(content, node);
    }
    None
}

fn normalize_node_name_text(content: &str, node: Node) -> Option<String> {
    let raw = node_text(content, node)?.trim();
    if raw.is_empty() {
        return None;
    }
    let mut value = raw.to_string();
    if let Some(stripped) = strip_surrounding_quotes(raw) {
        value = stripped.to_string();
    }
    if value.len() > AST_NODE_NAME_LIMIT {
        return None;
    }
    if value.contains('\n') || value.contains('\r') {
        return None;
    }
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn strip_surrounding_quotes(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.len() < 2 {
        return None;
    }
    let first = trimmed.chars().next()?;
    let last = trimmed.chars().last()?;
    if (first == '"' || first == '\'' || first == '`') && last == first {
        return Some(&trimmed[1..trimmed.len() - 1]);
    }
    None
}

fn is_identifier_kind(kind: &str) -> bool {
    matches!(
        kind,
        "identifier"
            | "field_identifier"
            | "type_identifier"
            | "property_identifier"
            | "shorthand_property_identifier_pattern"
            | "shorthand_property_identifier"
            | "namespace_identifier"
            | "label"
            | "module_identifier"
    )
}

fn collect_ast_nodes(
    nodes: &mut Vec<AstNode>,
    content: &str,
    node: Node,
    parent_id: Option<u32>,
    field_name: Option<String>,
    next_id: &mut u32,
    total_nodes: &mut usize,
    truncated: &mut bool,
) {
    let id = *next_id;
    *next_id = (*next_id).saturating_add(1);
    *total_nodes = (*total_nodes).saturating_add(1);
    if nodes.len() < AST_NODE_STORE_LIMIT {
        let (start_line, start_col, end_line, end_col) = node_range(node);
        let name = node_name_value(content, node);
        nodes.push(AstNode {
            id,
            parent_id,
            kind: node.kind().to_string(),
            field: field_name.clone(),
            name,
            is_named: node.is_named(),
            range: SymbolRange {
                start_line,
                start_col,
                end_line,
                end_col,
            },
        });
    } else {
        *truncated = true;
    }

    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            let child_field = cursor.field_name().map(|value| value.to_string());
            collect_ast_nodes(
                nodes,
                content,
                child,
                Some(id),
                child_field,
                next_id,
                total_nodes,
                truncated,
            );
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
}

fn node_name(content: &str, node: Node, field: &str) -> Option<String> {
    let name_node = node.child_by_field_name(field)?;
    let name = node_text(content, name_node)?.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn node_text<'a>(content: &'a str, node: Node) -> Option<&'a str> {
    content.get(node.start_byte()..node.end_byte())
}

fn signature_from_node(content: &str, node: Node, terminators: &[char]) -> Option<String> {
    let text = node_text(content, node)?;
    let line = text.lines().next()?.trim();
    if line.is_empty() {
        return None;
    }
    let mut trimmed = line;
    for terminator in terminators {
        if let Some(idx) = trimmed.find(*terminator) {
            trimmed = trimmed[..idx].trim();
            break;
        }
    }
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
