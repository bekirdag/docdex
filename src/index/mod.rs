pub(crate) mod libs;
mod symbols;

use crate::error::{
    repo_resolution_details, AppError, ERR_BACKOFF_REQUIRED, ERR_INVALID_ARGUMENT,
    ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
};
use crate::symbols::SymbolsStore;
use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, FAST, STORED, STRING, TEXT};
use tantivy::DocAddress;
use tantivy::{
    doc, Document, Index, IndexReader, IndexWriter, ReloadPolicy, SnippetGenerator, Term,
};
use thiserror::Error;
use tracing::warn;
use walkdir::WalkDir;

const MAX_INDEX_RAM_BYTES: usize = 50 * 1024 * 1024;
const MAX_BINARY_FILE_BYTES: u64 = 5 * 1024 * 1024;
const BINARY_SNIFF_BYTES: usize = 8192;
const DEFAULT_EXTENSIONS: &[&str] = &[".md", ".markdown", ".mdx", ".txt"];
const DEFAULT_EXCLUDED_DIR_NAMES: &[&str] = &[
    // Core VCS / tooling
    ".git",
    ".idea",
    ".vscode",
    ".cache",
    "tmp",
    "temp",
    ".hg",
    ".svn",
    ".bzr",
    ".darcs",
    ".fossil",
    ".pijul",
    "cvs",
    // JS / TS / Node ecosystem
    "node_modules",
    ".pnpm-store",
    ".yarn",
    ".yarn-cache",
    ".npm",
    "dist",
    "build",
    "coverage",
    ".vite",
    ".turbo",
    ".nx",
    ".parcel-cache",
    ".rollup-cache",
    ".webpack-cache",
    ".tsbuildinfo",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".angular",
    ".expo",
    // Python
    "__pycache__",
    ".venv",
    "venv",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".ipynb_checkpoints",
    // Rust
    "target",
    ".cargo",
    // Go
    "bin",
    "pkg",
    "go-build",
    // Java / Kotlin / JVM
    ".gradle",
    ".mvn",
    "out",
    // .NET / C# / Visual Studio
    "obj",
    ".vs",
    // Swift / Xcode / Apple
    "deriveddata",
    // PHP / Composer
    "vendor",
    // Ruby / Bundler
    ".bundle",
    // Dart / Flutter
    ".dart_tool",
    ".flutter-plugins",
    ".flutter-plugins-dependencies",
    ".pub-cache",
    // Android
    ".android",
    // iOS / CocoaPods
    "pods",
    // C / C++ / CMake / native
    "debug",
    "release",
    "cmake-build-debug",
    "cmake-build-release",
    "cmakefiles",
    ".conan",
    "vcpkg_installed",
    // Haskell
    ".stack-work",
    "dist-newstyle",
    "cabal-dev",
    // Elixir / Erlang
    "_build",
    "deps",
    ".elixir_ls",
    // Scala / Metals / Bloop
    ".bloop",
    ".metals",
    // Clojure
    ".cpcache",
    // Elm
    "elm-stuff",
    // Nim
    "nimcache",
    // OCaml / Dune / opam
    "_opam",
    // R / RStudio
    ".rproj.user",
    // Game engines: Unity / Unreal / Godot
    "library",
    "logs",
    "obj",
    "binaries",
    "deriveddatacache",
    "intermediate",
    ".godot",
    // Infra / deployment / serverless
    ".docker",
    "docker-data",
    ".terraform",
    ".serverless",
    ".vercel",
    ".netlify",
];
const DEFAULT_EXCLUDED_RELATIVE_PREFIXES: &[&str] = &[
    "logs/",
    ".docdex/",
    ".docdex/logs/",
    ".docdex/tmp/",
    ".gpt-creator/logs/",
    ".gpt-creator/tmp/",
    ".mastercoda/logs/",
    ".mastercoda/tmp/",
    "docker/.data/",
    "docker-data/",
    ".docker/",
];
const MAX_SUMMARY_CHARS: usize = 360;
const MAX_SUMMARY_SEGMENTS: usize = 4;
const MAX_SNIPPET_CHARS: usize = 420;
const FALLBACK_PREVIEW_LINES: usize = 60;

#[derive(Clone)]
pub struct IndexConfig {
    state_dir: PathBuf,
    excluded_dir_names: Vec<String>,
    excluded_relative_prefixes: Vec<String>,
    symbols_enabled: bool,
}

#[derive(Clone)]
pub struct Indexer {
    repo_root: PathBuf,
    config: IndexConfig,
    index: Index,
    reader: IndexReader,
    doc_id_field: tantivy::schema::Field,
    path_field: tantivy::schema::Field,
    body_field: tantivy::schema::Field,
    summary_field: tantivy::schema::Field,
    token_field: tantivy::schema::Field,
    writer: Option<Arc<Mutex<IndexWriter>>>,
    symbols_store: Option<SymbolsStore>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    pub doc_id: String,
    pub rel_path: String,
    // Stable search contract alias for `rel_path` (preferred by downstream clients).
    pub path: String,
    pub score: f32,
    pub summary: String,
    pub snippet: String,
    pub token_estimate: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_origin: Option<SearchSnippetOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<usize>,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchSnippetOrigin {
    Query,
    Preview,
    Summary,
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryRewrite {
    None,
    Sanitized,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchQueryMeta {
    pub raw: String,
    pub effective: String,
    pub rewrite: QueryRewrite,
}

#[derive(Error, Debug)]
pub enum SearchError {
    #[error("invalid query: {reason}")]
    InvalidQuery { reason: String },
}

#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnippetOrigin {
    Query,
    Preview,
}

#[derive(Debug, Clone)]
pub struct SnippetResult {
    pub text: String,
    pub html: Option<String>,
    pub truncated: bool,
    pub origin: SnippetOrigin,
    pub line_start: Option<usize>,
    pub line_end: Option<usize>,
}

#[derive(Debug, serde::Serialize)]
pub struct DocSnapshot {
    pub doc_id: String,
    pub rel_path: String,
    pub summary: String,
    pub token_estimate: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IndexStats {
    pub num_docs: u64,
    pub state_dir: PathBuf,
    pub index_size_bytes: u64,
    pub segments: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_bytes_per_doc: Option<u64>,
    pub generated_at_epoch_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated_epoch_ms: Option<u128>,
}

impl IndexConfig {
    #[allow(dead_code)]
    pub fn for_repo(repo_root: &Path) -> Result<Self> {
        Self::with_overrides(
            repo_root,
            None,
            Vec::new(),
            Vec::new(),
            env_flag_enabled("DOCDEX_ENABLE_SYMBOL_EXTRACTION"),
        )
    }

    pub fn with_overrides(
        repo_root: &Path,
        state_dir: Option<PathBuf>,
        extra_excluded_dirs: Vec<String>,
        extra_excluded_prefixes: Vec<String>,
        symbols_enabled: bool,
    ) -> Result<Self> {
        let state_dir = resolve_state_dir(repo_root, state_dir)?;
        let mut excluded_dir_names: Vec<String> = DEFAULT_EXCLUDED_DIR_NAMES
            .iter()
            .map(|value| value.to_string())
            .collect();
        for dir in extra_excluded_dirs {
            let lowered = dir.trim().to_lowercase();
            if lowered.is_empty() {
                continue;
            }
            if !excluded_dir_names.contains(&lowered) {
                excluded_dir_names.push(lowered);
            }
        }
        let mut excluded_relative_prefixes: Vec<String> = DEFAULT_EXCLUDED_RELATIVE_PREFIXES
            .iter()
            .map(|value| value.to_string())
            .collect();
        for prefix in extra_excluded_prefixes {
            let normalized = normalize_prefix(&prefix);
            if normalized.is_empty() {
                continue;
            }
            if !excluded_relative_prefixes.contains(&normalized) {
                excluded_relative_prefixes.push(normalized);
            }
        }
        if let Ok(rel_state) = state_dir.strip_prefix(repo_root) {
            let normalized = normalize_prefix(rel_state.to_string_lossy().as_ref());
            if !normalized.is_empty() && !excluded_relative_prefixes.contains(&normalized) {
                excluded_relative_prefixes.push(normalized);
            }
        }
        Ok(Self {
            state_dir,
            excluded_dir_names,
            excluded_relative_prefixes,
            symbols_enabled,
        })
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn excluded_dir_names(&self) -> &[String] {
        &self.excluded_dir_names
    }

    pub fn excluded_relative_prefixes(&self) -> &[String] {
        &self.excluded_relative_prefixes
    }

    pub fn symbols_enabled(&self) -> bool {
        self.symbols_enabled
    }
}

impl Indexer {
    #[allow(dead_code)]
    pub fn new(repo_root: PathBuf) -> Result<Self> {
        if !repo_root.exists() {
            return Err(missing_repo_path_error(&repo_root).into());
        }
        if !repo_root.is_dir() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("repo root is not a directory: {}", repo_root.display()),
            )
            .into());
        }
        let repo_root = repo_root.canonicalize().context("resolve repo root")?;
        let config = IndexConfig::for_repo(&repo_root)?;
        Self::with_config(repo_root, config)
    }

    pub fn with_config(repo_root: PathBuf, config: IndexConfig) -> Result<Self> {
        if !repo_root.exists() {
            return Err(missing_repo_path_error(&repo_root).into());
        }
        if !repo_root.is_dir() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("repo root is not a directory: {}", repo_root.display()),
            )
            .into());
        }
        let repo_root = repo_root.canonicalize().context("resolve repo root")?;
        ensure_state_dir_secure(config.state_dir())?;
        let (schema, doc_id_field, path_field, body_field, summary_field, token_field) =
            build_schema();
        let index = Index::open_or_create(
            tantivy::directory::MmapDirectory::open(config.state_dir())?,
            schema.clone(),
        )?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        let writer = index.writer(MAX_INDEX_RAM_BYTES)?;
        let symbols_store = if config.symbols_enabled() {
            symbols::open_symbols_store(&repo_root, config.state_dir(), true)
        } else {
            None
        };
        if let Err(err) = crate::repo_manager::record_repo_opened(&repo_root, config.state_dir()) {
            if let Some(identity) = err.downcast_ref::<crate::repo_manager::RepoIdentityError>() {
                return Err(repo_state_mismatch_error(
                    &repo_root,
                    Some(config.state_dir()),
                    identity,
                )
                .into());
            }
            return Err(err).context("record repo identity metadata");
        }
        Ok(Self {
            repo_root,
            config,
            index,
            reader,
            doc_id_field,
            path_field,
            body_field,
            summary_field,
            token_field,
            writer: Some(Arc::new(Mutex::new(writer))),
            symbols_store,
        })
    }

    pub fn with_config_read_only(repo_root: PathBuf, config: IndexConfig) -> Result<Self> {
        if !repo_root.exists() {
            return Err(missing_repo_path_error(&repo_root).into());
        }
        if !repo_root.is_dir() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("repo root is not a directory: {}", repo_root.display()),
            )
            .into());
        }
        let repo_root = repo_root.canonicalize().context("resolve repo root")?;
        if !config.state_dir().exists() {
            return Err(AppError::new(
                ERR_MISSING_INDEX,
                format!(
                    "index not found at {}; run `docdexd index --repo <repo>` first",
                    config.state_dir().display()
                ),
            )
            .into());
        }
        let index = Index::open_in_dir(config.state_dir())?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        let schema = index.schema();
        let doc_id_field = schema.get_field("doc_id").unwrap();
        let path_field = schema.get_field("rel_path").unwrap();
        let body_field = schema.get_field("body").unwrap();
        let summary_field = schema.get_field("summary").unwrap();
        let token_field = schema.get_field("token_estimate").unwrap();
        let symbols_store = if config.symbols_enabled() {
            symbols::open_symbols_store(&repo_root, config.state_dir(), false)
        } else {
            None
        };
        if let Err(err) =
            crate::repo_manager::validate_repo_state_dir(&repo_root, config.state_dir())
        {
            if let Some(identity) = err.downcast_ref::<crate::repo_manager::RepoIdentityError>() {
                return Err(repo_state_mismatch_error(
                    &repo_root,
                    Some(config.state_dir()),
                    identity,
                )
                .into());
            }
            return Err(err).context("validate repo identity metadata");
        }
        Ok(Self {
            repo_root,
            config,
            index,
            reader,
            doc_id_field,
            path_field,
            body_field,
            summary_field,
            token_field,
            writer: None,
            symbols_store,
        })
    }

    pub async fn reindex_all(&self) -> Result<()> {
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        writer.delete_all_documents()?;
        self.reset_symbols_store();
        for entry in WalkDir::new(&self.repo_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let decision = decide_file(path, &self.repo_root, &self.config);
            if !decision.should_index() {
                continue;
            }
            let ingest = self.add_document(&mut writer, path)?;
            self.maybe_update_symbols(&ingest);
        }
        writer.commit()?;
        self.reader.reload()?;
        Ok(())
    }

    pub async fn ingest_file(&self, file: PathBuf) -> Result<FileDecision> {
        let path = file.canonicalize().context("resolve file")?;
        let decision = decide_file(&path, &self.repo_root, &self.config);
        if !decision.should_index() {
            return Ok(decision);
        }
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        let rel = self.rel_path(&path)?;
        let term = Term::from_field_text(self.doc_id_field, &rel);
        writer.delete_term(term);
        let ingest = self.add_document(&mut writer, &path)?;
        self.maybe_update_symbols(&ingest);
        writer.commit()?;
        self.reader.reload()?;
        Ok(decision)
    }

    pub async fn delete_file(&self, file: PathBuf) -> Result<()> {
        let rel = match self.rel_path(&file) {
            Ok(rel) => rel,
            Err(_) => return Ok(()),
        };
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        let term = Term::from_field_text(self.doc_id_field, &rel);
        writer.delete_term(term);
        writer.commit()?;
        self.reader.reload()?;
        self.delete_symbols_record(&rel);
        Ok(())
    }

    #[allow(dead_code)]
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        let (hits, _meta) = self.search_with_query_meta(query, limit)?;
        Ok(hits)
    }

    pub fn search_with_query_meta(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<(Vec<Hit>, SearchQueryMeta)> {
        let raw = query.trim();
        if raw.is_empty() {
            return Err(SearchError::InvalidQuery {
                reason: "query must not be empty".to_string(),
            }
            .into());
        }
        // Tantivy's query parser accepts some operator-only inputs (e.g. "!!!") that contain
        // no searchable terms. Enforce a strict "must contain at least one term" rule for
        // determinism and predictable validation behavior.
        if sanitize_query(raw).trim().is_empty() {
            return Err(SearchError::InvalidQuery {
                reason: "query contains no searchable terms".to_string(),
            }
            .into());
        }
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(
            &self.index,
            vec![self.body_field, self.summary_field, self.path_field],
        );
        let (tantivy_query, query_meta) = match parser.parse_query(raw) {
            Ok(q) => (
                q,
                SearchQueryMeta {
                    raw: raw.to_string(),
                    effective: raw.to_string(),
                    rewrite: QueryRewrite::None,
                },
            ),
            Err(err) => {
                let sanitized = sanitize_query(raw);
                if sanitized.trim().is_empty() {
                    return Err(SearchError::InvalidQuery {
                        reason: "query contains no searchable terms".to_string(),
                    }
                    .into());
                }
                match parser.parse_query(&sanitized) {
                    Ok(q) => (
                        q,
                        SearchQueryMeta {
                            raw: raw.to_string(),
                            effective: sanitized.clone(),
                            rewrite: QueryRewrite::Sanitized,
                        },
                    ),
                    Err(err2) => {
                        return Err(SearchError::InvalidQuery {
                            reason: format!(
                                "query parse failed: {err}; sanitized parse failed: {err2}"
                            ),
                        }
                        .into());
                    }
                }
            }
        };
        let mut snippet_generator =
            SnippetGenerator::create(&searcher, tantivy_query.as_ref(), self.body_field).ok();
        if let Some(generator) = snippet_generator.as_mut() {
            generator.set_max_num_chars(MAX_SNIPPET_CHARS);
        }
        let top_docs = searcher.search(&tantivy_query, &TopDocs::with_limit(limit))?;
        let mut results = Vec::with_capacity(top_docs.len());
        for (score, addr) in top_docs {
            let retrieved = searcher.doc(addr)?;
            let body_text = retrieved
                .get_first(self.body_field)
                .and_then(|v| v.as_text())
                .unwrap_or_default()
                .to_string();
            let doc_id = retrieved
                .get_first(self.doc_id_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let rel_path = retrieved
                .get_first(self.path_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let path = rel_path.clone();
            let summary = retrieved
                .get_first(self.summary_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let token_estimate = retrieved
                .get_first(self.token_field)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let (snippet, snippet_origin, snippet_truncated, line_start, line_end) =
                snippet_generator
                .as_ref()
                .and_then(|gen| {
                    let snippet = gen.snippet_from_doc(&retrieved);
                    let fragment = snippet.fragment().trim().to_string();
                    if fragment.is_empty() {
                        None
                    } else {
                        let range = line_range_for_fragment(&body_text, &fragment);
                        let inferred_truncated =
                            fragment.chars().count() >= MAX_SNIPPET_CHARS.saturating_sub(1);
                        Some((
                            fragment,
                            SearchSnippetOrigin::Query,
                            inferred_truncated,
                            range.map(|r| r.0),
                            range.map(|r| r.1),
                        ))
                    }
                })
                .or_else(|| {
                    match self.preview_snippet(&rel_path, FALLBACK_PREVIEW_LINES) {
                        Ok(Some((text, truncated, start_line, end_line))) => {
                            Some((
                                text,
                                SearchSnippetOrigin::Preview,
                                truncated,
                                Some(start_line),
                                Some(end_line),
                            ))
                        }
                        Ok(None) => None,
                        Err(err) => {
                            warn!(target: "docdexd", error = ?err, %rel_path, "failed to build fallback snippet");
                            None
                        }
                    }
                })
                .unwrap_or_else(|| {
                    (
                        summary.clone(),
                        SearchSnippetOrigin::Summary,
                        false,
                        None,
                        None,
                    )
                });
            results.push(Hit {
                doc_id,
                rel_path,
                path,
                score,
                summary,
                snippet,
                token_estimate,
                snippet_origin: Some(snippet_origin),
                snippet_truncated: Some(snippet_truncated),
                line_start,
                line_end,
            });
        }
        sort_hits_deterministically(&mut results);
        Ok((results, query_meta))
    }

    fn fetch_document(&self, doc_id: &str) -> Result<Option<Document>> {
        let searcher = self.reader.searcher();
        let term = Term::from_field_text(self.doc_id_field, doc_id);
        let term_query =
            tantivy::query::TermQuery::new(term, tantivy::schema::IndexRecordOption::Basic);
        let top_docs = searcher.search(&term_query, &TopDocs::with_limit(1))?;
        if let Some((_score, addr)) = top_docs.into_iter().next() {
            let doc = searcher.doc(addr)?;
            return Ok(Some(doc));
        }
        Ok(None)
    }

    pub fn preview_snippet(
        &self,
        rel_path: &str,
        max_lines: usize,
    ) -> Result<Option<(String, bool, usize, usize)>> {
        if max_lines == 0 {
            return Ok(None);
        }
        if !is_safe_rel_path(rel_path) {
            return Ok(None);
        }
        let path = self.repo_root.join(rel_path);
        let file = match File::open(&path) {
            Ok(file) => file,
            Err(err) => {
                if err.kind() == io::ErrorKind::NotFound {
                    return Ok(None);
                }
                return Err(err).with_context(|| format!("open {}", path.display()));
            }
        };
        let reader = BufReader::new(file);
        let mut preview_lines: Vec<(usize, String)> = Vec::new();
        let mut truncated = false;
        for (idx, line_res) in reader.lines().enumerate() {
            if idx >= max_lines {
                truncated = true;
                break;
            }
            let line = line_res?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                preview_lines.push((idx + 1, trimmed.to_string()));
            }
        }
        if preview_lines.is_empty() {
            return Ok(None);
        }
        let (snippet, snippet_truncated) = condense_snippet(
            &preview_lines
                .iter()
                .map(|(_, text)| text.clone())
                .collect::<Vec<_>>(),
            MAX_SNIPPET_CHARS,
        );
        if snippet.is_empty() {
            return Ok(None);
        }
        let start_line = preview_lines.first().map(|(line, _)| *line).unwrap_or(1);
        let end_line = preview_lines
            .last()
            .map(|(line, _)| *line)
            .unwrap_or(start_line);
        Ok(Some((
            snippet,
            truncated || snippet_truncated,
            start_line,
            end_line,
        )))
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn state_dir(&self) -> &Path {
        self.config.state_dir()
    }

    fn writer(&self) -> Result<Arc<Mutex<IndexWriter>>> {
        self.writer.clone().ok_or_else(|| {
            AppError::new(
                ERR_BACKOFF_REQUIRED,
                "index writer unavailable (another docdexd may be indexing); retry later",
            )
            .into()
        })
    }

    pub fn config(&self) -> &IndexConfig {
        &self.config
    }

    pub fn stats(&self) -> Result<IndexStats> {
        let searcher = self.reader.searcher();
        let mut num_docs: u64 = 0;
        let mut segments: usize = 0;
        for segment_reader in searcher.segment_readers() {
            segments += 1;
            let live_docs = segment_reader
                .alive_bitset()
                .map(|bits| bits.num_alive_docs() as u64)
                .unwrap_or_else(|| segment_reader.max_doc() as u64);
            num_docs = num_docs.saturating_add(live_docs);
        }
        let state_dir = self.config.state_dir().to_path_buf();
        let index_size_bytes = walkdir::WalkDir::new(&state_dir)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.metadata().ok())
            .map(|meta| meta.len())
            .sum();
        let mut last_updated_epoch_ms: Option<u128> = None;
        for entry in walkdir::WalkDir::new(&state_dir).into_iter().flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                        let millis = dur.as_millis();
                        if last_updated_epoch_ms
                            .map(|current| millis > current)
                            .unwrap_or(true)
                        {
                            last_updated_epoch_ms = Some(millis);
                        }
                    }
                }
            }
        }
        let generated_at_epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let avg_bytes_per_doc = if num_docs > 0 {
            Some(index_size_bytes / num_docs)
        } else {
            None
        };
        Ok(IndexStats {
            num_docs,
            state_dir,
            index_size_bytes,
            segments,
            avg_bytes_per_doc,
            generated_at_epoch_ms,
            last_updated_epoch_ms,
        })
    }

    pub fn snapshot_with_snippet(
        &self,
        doc_id: &str,
        query: Option<&str>,
        fallback_lines: usize,
    ) -> Result<Option<(DocSnapshot, Option<SnippetResult>)>> {
        let Some(doc) = self.fetch_document(doc_id)? else {
            return Ok(None);
        };
        let snapshot = self.snapshot_from_document(doc_id, &doc);
        let snippet =
            self.snippet_from_document(&doc, Some(&snapshot.rel_path), query, fallback_lines)?;
        Ok(Some((snapshot, snippet)))
    }

    pub fn list_docs(&self, offset: usize, limit: usize) -> Result<(Vec<DocSnapshot>, u64)> {
        let searcher = self.reader.searcher();
        let mut snapshots = Vec::new();
        let mut skipped = 0usize;
        let mut total_live: u64 = 0;
        'outer: for (segment_ord, segment_reader) in searcher.segment_readers().iter().enumerate() {
            let alive = segment_reader.alive_bitset();
            let max_doc = segment_reader.max_doc();
            let live_in_segment = alive
                .map(|bits| bits.num_alive_docs() as u64)
                .unwrap_or_else(|| max_doc as u64);
            total_live = total_live.saturating_add(live_in_segment);
            let doc_iter: Box<dyn Iterator<Item = u32>> = if let Some(bits) = alive {
                Box::new(bits.iter_alive())
            } else {
                Box::new(0..max_doc)
            };
            for doc_id in doc_iter {
                if skipped < offset {
                    skipped += 1;
                    continue;
                }
                if snapshots.len() >= limit {
                    break 'outer;
                }
                let address = DocAddress::new(segment_ord as u32, doc_id);
                let doc = searcher.doc(address)?;
                let doc_id_text = doc
                    .get_first(self.doc_id_field)
                    .and_then(|v| v.as_text())
                    .unwrap_or_default();
                snapshots.push(self.snapshot_from_document(doc_id_text, &doc));
            }
        }
        Ok((snapshots, total_live))
    }

    fn add_document(&self, writer: &mut IndexWriter, path: &Path) -> Result<DocumentIngest> {
        let rel = self.rel_path(path)?;
        let rel_for_return = rel.clone();
        let (content, read_error) = match fs::read_to_string(path) {
            Ok(content) => (content, None),
            Err(err) => (String::new(), Some(err.to_string())),
        };
        let content_for_symbols = if self.symbols_store.is_some() {
            content.clone()
        } else {
            String::new()
        };
        let summary = summarize(&content);
        let tokens = estimate_tokens(&content);
        writer.add_document(doc!(
            self.doc_id_field => rel.clone(),
            self.path_field => rel,
            self.body_field => content,
            self.summary_field => summary,
            self.token_field => tokens,
        ))?;
        Ok(DocumentIngest {
            rel_path: rel_for_return,
            content: content_for_symbols,
            read_error,
        })
    }

    fn rel_path(&self, path: &Path) -> Result<String> {
        let rel = path
            .strip_prefix(&self.repo_root)
            .map_err(|_| anyhow!("{} is outside repo root", path.display()))?;
        Ok(rel.to_string_lossy().replace('\\', "/"))
    }

    fn snapshot_from_document(&self, doc_id: &str, doc: &Document) -> DocSnapshot {
        let rel_path = doc
            .get_first(self.path_field)
            .and_then(|v| v.as_text().map(|s| s.to_string()))
            .unwrap_or_default();
        let summary = doc
            .get_first(self.summary_field)
            .and_then(|v| v.as_text().map(|s| s.to_string()))
            .unwrap_or_default();
        let token_estimate = doc
            .get_first(self.token_field)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        DocSnapshot {
            doc_id: doc_id.to_string(),
            rel_path,
            summary,
            token_estimate,
        }
    }

    fn snippet_from_document(
        &self,
        doc: &Document,
        rel_path_hint: Option<&str>,
        query: Option<&str>,
        fallback_lines: usize,
    ) -> Result<Option<SnippetResult>> {
        let searcher = self.reader.searcher();
        if let Some(query) = query.and_then(|q| {
            let trimmed = q.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        }) {
            let parser = QueryParser::for_index(&self.index, vec![self.body_field]);
            if let Ok(parsed) = parser.parse_query(query) {
                if let Ok(mut generator) =
                    SnippetGenerator::create(&searcher, parsed.as_ref(), self.body_field)
                {
                    generator.set_max_num_chars(MAX_SNIPPET_CHARS);
                    let snippet = generator.snippet_from_doc(doc);
                    let fragment = snippet.fragment().trim();
                    if !fragment.is_empty() {
                        return Ok(Some(SnippetResult {
                            text: fragment.to_string(),
                            html: Some(snippet.to_html()),
                            truncated: false,
                            origin: SnippetOrigin::Query,
                            line_start: None,
                            line_end: None,
                        }));
                    }
                }
            }
        }

        let rel_path = rel_path_hint.map(|p| p.to_string()).or_else(|| {
            doc.get_first(self.path_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .map(|text| text.to_string())
        });
        if let Some(rel_path) = rel_path {
            if let Some((text, truncated, line_start, line_end)) =
                self.preview_snippet(&rel_path, fallback_lines)?
            {
                return Ok(Some(SnippetResult {
                    text,
                    html: None,
                    truncated,
                    origin: SnippetOrigin::Preview,
                    line_start: Some(line_start),
                    line_end: Some(line_end),
                }));
            }
        }
        Ok(None)
    }
}

struct DocumentIngest {
    rel_path: String,
    content: String,
    read_error: Option<String>,
}

fn env_flag_enabled(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

fn build_schema() -> (
    Schema,
    tantivy::schema::Field,
    tantivy::schema::Field,
    tantivy::schema::Field,
    tantivy::schema::Field,
    tantivy::schema::Field,
) {
    let mut builder = Schema::builder();
    let doc_id_field = builder.add_text_field("doc_id", STRING | STORED);
    let path_field = builder.add_text_field("rel_path", STRING | STORED);
    let body_field = builder.add_text_field("body", TEXT | STORED);
    let summary_field = builder.add_text_field("summary", TEXT | STORED);
    let token_field = builder.add_u64_field("token_estimate", FAST | STORED);
    let schema = builder.build();
    (
        schema,
        doc_id_field,
        path_field,
        body_field,
        summary_field,
        token_field,
    )
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileDecisionOutcome {
    Include,
    Exclude,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "code")]
pub enum FileDecisionReason {
    OutsideRepo,
    StateDir,
    NotAFile,
    ExcludedPrefix { prefix: String },
    ExcludedDirName { name: String },
    MissingExtension,
    UnsupportedExtension { extension: String },
    BinaryTooLarge { bytes: u64 },
    AllowedExtension { extension: String },
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FileDecision {
    pub decision: FileDecisionOutcome,
    pub reason: FileDecisionReason,
}

impl FileDecision {
    fn include(reason: FileDecisionReason) -> Self {
        Self {
            decision: FileDecisionOutcome::Include,
            reason,
        }
    }

    fn exclude(reason: FileDecisionReason) -> Self {
        Self {
            decision: FileDecisionOutcome::Exclude,
            reason,
        }
    }

    pub fn should_index(&self) -> bool {
        matches!(self.decision, FileDecisionOutcome::Include)
    }
}

pub(crate) fn decide_file(path: &Path, repo_root: &Path, config: &IndexConfig) -> FileDecision {
    if path.starts_with(config.state_dir()) {
        return FileDecision::exclude(FileDecisionReason::StateDir);
    }
    if let (Ok(state_dir), Ok(canonical)) = (config.state_dir().canonicalize(), path.canonicalize())
    {
        if canonical.starts_with(state_dir) {
            return FileDecision::exclude(FileDecisionReason::StateDir);
        }
    }

    if path.exists() && !path.is_file() {
        return FileDecision::exclude(FileDecisionReason::NotAFile);
    }

    let relative: PathBuf = if path.starts_with(repo_root) {
        match path.strip_prefix(repo_root) {
            Ok(value) => value.to_path_buf(),
            Err(_) => {
                return FileDecision::exclude(FileDecisionReason::OutsideRepo);
            }
        }
    } else if let (Ok(repo_canon), Ok(path_canon)) = (repo_root.canonicalize(), path.canonicalize())
    {
        if path_canon.starts_with(&repo_canon) {
            match path_canon.strip_prefix(&repo_canon) {
                Ok(value) => value.to_path_buf(),
                Err(_) => {
                    return FileDecision::exclude(FileDecisionReason::OutsideRepo);
                }
            }
        } else {
            return FileDecision::exclude(FileDecisionReason::OutsideRepo);
        }
    } else {
        return FileDecision::exclude(FileDecisionReason::OutsideRepo);
    };

    let normalized = relative
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
        .to_lowercase();

    let mut best_prefix: Option<&String> = None;
    for prefix in config.excluded_relative_prefixes().iter() {
        if !normalized.starts_with(prefix) {
            continue;
        }
        best_prefix = match best_prefix {
            None => Some(prefix),
            Some(current) => {
                if prefix.len() > current.len()
                    || (prefix.len() == current.len() && prefix.as_str() < current.as_str())
                {
                    Some(prefix)
                } else {
                    Some(current)
                }
            }
        };
    }
    if let Some(prefix) = best_prefix {
        return FileDecision::exclude(FileDecisionReason::ExcludedPrefix {
            prefix: prefix.clone(),
        });
    }

    for component in relative.components() {
        if let Component::Normal(name) = component {
            let name_lower = name.to_string_lossy().to_lowercase();
            if config
                .excluded_dir_names()
                .iter()
                .any(|excluded| excluded == &name_lower)
            {
                return FileDecision::exclude(FileDecisionReason::ExcludedDirName {
                    name: name_lower,
                });
            }
        }
    }

    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return FileDecision::exclude(FileDecisionReason::MissingExtension);
    };
    let extension = format!(".{}", ext.to_lowercase());
    if !DEFAULT_EXTENSIONS.contains(&extension.as_str()) {
        return FileDecision::exclude(FileDecisionReason::UnsupportedExtension { extension });
    }

    if let Ok(meta) = path.metadata() {
        if meta.len() > MAX_BINARY_FILE_BYTES {
            if is_probably_binary(path).unwrap_or(true) {
                return FileDecision::exclude(FileDecisionReason::BinaryTooLarge {
                    bytes: meta.len(),
                });
            }
        }
    }

    FileDecision::include(FileDecisionReason::AllowedExtension { extension })
}

pub(crate) fn should_index(path: &Path, repo_root: &Path, config: &IndexConfig) -> bool {
    decide_file(path, repo_root, config).should_index()
}

fn is_probably_binary(path: &Path) -> io::Result<bool> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; BINARY_SNIFF_BYTES];
    let read = file.read(&mut buffer)?;
    let sample = &buffer[..read];
    if sample.iter().any(|byte| *byte == 0) {
        return Ok(true);
    }
    Ok(std::str::from_utf8(sample).is_err())
}

#[cfg(test)]
mod file_decision_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn decide_file_picks_longest_excluded_prefix() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            None,
            Vec::new(),
            vec!["docs/".into(), "docs/private/".into()],
            false,
        )
        .expect("config");
        let file = repo_root.join("docs/private/a.md");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "# test\n").expect("write file");

        let decision = decide_file(&file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(
            decision.reason,
            FileDecisionReason::ExcludedPrefix {
                prefix: "docs/private/".to_string()
            }
        );
    }

    #[test]
    fn decide_file_excludes_state_dir_before_prefix_rules() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(&repo_root, None, Vec::new(), Vec::new(), false)
            .expect("config");
        let file = config.state_dir().join("doc.md");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "# state dir\n").expect("write file");

        let decision = decide_file(&file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(decision.reason, FileDecisionReason::StateDir);
    }

    #[test]
    fn decide_file_excludes_default_vendor_dir() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(&repo_root, None, Vec::new(), Vec::new(), false)
            .expect("config");
        let file = repo_root.join("vendor/doc.md");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "# vendor\n").expect("write file");

        let decision = decide_file(&file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(
            decision.reason,
            FileDecisionReason::ExcludedDirName {
                name: "vendor".to_string()
            }
        );
    }

    #[test]
    fn decide_file_excludes_outside_repo() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(&repo_root, None, Vec::new(), Vec::new(), false)
            .expect("config");

        let other = TempDir::new().expect("other repo");
        let outside = other.path().join("note.md");
        fs::write(&outside, "# outside\n").expect("write file");

        let decision = decide_file(&outside, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(decision.reason, FileDecisionReason::OutsideRepo);
    }

    #[test]
    fn decide_file_excludes_large_binary() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            None,
            Vec::new(),
            Vec::new(),
            false,
        )
        .expect("config");
        let binary_path = repo_root.join("large.md");
        let blob = vec![0u8; (MAX_BINARY_FILE_BYTES as usize) + 1];
        fs::write(&binary_path, blob).expect("write binary");

        let decision = decide_file(&binary_path, &repo_root, &config);
        assert_eq!(
            decision.reason,
            FileDecisionReason::BinaryTooLarge {
                bytes: (MAX_BINARY_FILE_BYTES + 1)
            }
        );
    }

    #[test]
    fn decide_file_includes_supported_extensions() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(&repo_root, None, Vec::new(), Vec::new(), false)
            .expect("config");
        let file = repo_root.join("docs/notes.txt");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "hello\n").expect("write file");

        let decision = decide_file(&file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Include);
        assert_eq!(
            decision.reason,
            FileDecisionReason::AllowedExtension {
                extension: ".txt".to_string()
            }
        );
    }
}

pub(crate) fn ensure_state_dir_secure(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;

        let mut builder = DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(path)?;
        let metadata = fs::metadata(path)?;
        let current = metadata.permissions().mode() & 0o777;
        if current != 0o700 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(path, perms)?;
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    if cfg!(debug_assertions) {
        if let Ok(value) = std::env::var("DOCDEX_TEST_HOLD_AFTER_STATE_DIR_CREATED_MS") {
            if let Ok(ms) = value.trim().parse::<u64>() {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
    }
    Ok(())
}

fn normalize_for_error(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn known_canonical_path_from_repo_meta(index_state_dir: &Path) -> Option<String> {
    if index_state_dir.file_name().and_then(|s| s.to_str())? != "index" {
        return None;
    }
    let state_key_dir = index_state_dir.parent()?;
    let state_key = state_key_dir.file_name()?.to_string_lossy().to_string();
    let repos_dir = state_key_dir.parent()?;
    if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
        return None;
    }
    let base_dir = repos_dir.parent()?;
    let registry_path = base_dir.join("repos").join("repo_registry.json");
    if let Ok(raw) = fs::read_to_string(&registry_path) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(repos) = parsed.get("repos").and_then(|v| v.as_object()) {
                for entry in repos.values() {
                    let entry_state_key = entry.get("state_key").and_then(|v| v.as_str())?;
                    if entry_state_key == state_key {
                        return entry
                            .get("canonical_path")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn canonical_path_from_repo_meta(repo_root: &Path) -> Option<String> {
    let meta_path = repo_root.join("repo_meta.json");
    let raw = fs::read_to_string(&meta_path).ok()?;
    let parsed = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    parsed
        .get("canonical_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn missing_repo_path_error(repo_root: &Path) -> AppError {
    AppError::new(ERR_MISSING_REPO_PATH, "repo path not found").with_details(repo_resolution_details(
        normalize_for_error(repo_root),
        None,
        None,
        vec![
            "Repo may have moved or been renamed.".to_string(),
            "Re-run with the repo's current path.".to_string(),
            "If you previously indexed this repo, you may need to reindex after moving it: `docdexd index --repo <repo>`."
                .to_string(),
        ],
    ))
}

fn repo_state_mismatch_error(
    repo_root: &Path,
    index_state_dir: Option<&Path>,
    identity: &crate::repo_manager::RepoIdentityError,
) -> AppError {
    let attempted_fingerprint = crate::repo_manager::repo_fingerprint_sha256(repo_root).ok();
    let mut known_canonical_path = index_state_dir.and_then(known_canonical_path_from_repo_meta);
    if known_canonical_path.is_none() {
        known_canonical_path = canonical_path_from_repo_meta(repo_root);
    }
    if let crate::repo_manager::RepoIdentityError::CanonicalPathCollision {
        canonical_path, ..
    } = identity
    {
        known_canonical_path = Some(canonical_path.clone());
    }
    if let crate::repo_manager::RepoIdentityError::ReassociationRequired {
        registered_canonical_path,
        ..
    } = identity
    {
        known_canonical_path = Some(registered_canonical_path.clone());
    }
    AppError::new(
        ERR_REPO_STATE_MISMATCH,
        "repo state mismatch; refusing to associate this repo with the existing state directory",
    )
    .with_details(repo_resolution_details(
        normalize_for_error(repo_root),
        attempted_fingerprint,
        known_canonical_path,
        vec![
            "Repo may have moved or been renamed.".to_string(),
            "Verify you are using the correct `--repo` and `--state-dir` combination.".to_string(),
            "Run: `docdexd repo inspect --repo <repo> --state-dir <shared_state_dir>` to see the repo fingerprint and any known canonical/alias mappings.".to_string(),
            "To explicitly re-associate a moved repo to existing shared state, run: `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <knownCanonicalPath>` (or `--fingerprint <attemptedFingerprint>`)."
                .to_string(),
            "Do not reuse a shared `--state-dir` across unrelated repos; choose a different state dir or clear the conflicting state."
                .to_string(),
        ],
    ))
}

fn resolve_state_dir(repo_root: &Path, state_dir: Option<PathBuf>) -> Result<PathBuf> {
    if !repo_root.exists() {
        return Err(missing_repo_path_error(repo_root).into());
    }
    if !repo_root.is_dir() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("repo root is not a directory: {}", repo_root.display()),
        )
        .into());
    }

    match state_dir {
        Some(custom) if custom.is_absolute() => {
            // Guardrail: when an absolute state dir is provided outside the repo root,
            // treat it as a shared *base* directory and scope all state under a repo id.
            // This prevents accidental cross-repo mixing when the same `--state-dir` is
            // used across multiple repos.
            let repo_root = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            if custom.starts_with(&repo_root) {
                return Ok(custom);
            }
            match crate::repo_manager::resolve_shared_index_state_dir(&repo_root, &custom) {
                Ok(path) => Ok(path),
                Err(err) => {
                    if let Some(identity) =
                        err.downcast_ref::<crate::repo_manager::RepoIdentityError>()
                    {
                        let index_dir_hint = match identity {
                            crate::repo_manager::RepoIdentityError::StateMetaFingerprintMismatch { state_key, .. } => {
                                Some(custom.join("repos").join(state_key).join("index"))
                            }
                            crate::repo_manager::RepoIdentityError::StateKeyConflict {
                                existing_state_key,
                                ..
                            } => Some(custom.join("repos").join(existing_state_key).join("index")),
                            _ => None,
                        };
                        return Err(repo_state_mismatch_error(
                            &repo_root,
                            index_dir_hint.as_deref(),
                            identity,
                        )
                        .into());
                    }
                    Err(err)
                }
            }
        }
        Some(custom) => Ok(repo_root.join(custom)),
        None => {
            let base_dir = crate::state_paths::default_state_base_dir()?;
            let repo_root = repo_root
                .canonicalize()
                .unwrap_or_else(|_| repo_root.to_path_buf());
            crate::repo_manager::resolve_shared_index_state_dir(&repo_root, &base_dir)
        }
    }
}

fn normalize_prefix(input: &str) -> String {
    let mut cleaned = input
        .replace('\\', "/")
        .trim()
        .trim_start_matches('/')
        .to_lowercase();
    if cleaned.is_empty() {
        return String::new();
    }
    if !cleaned.ends_with('/') {
        cleaned.push('/');
    }
    cleaned
}

fn summarize(content: &str) -> String {
    let cleaned = strip_front_matter(content);
    let segments = collect_segments(cleaned, MAX_SUMMARY_SEGMENTS);
    if segments.is_empty() {
        let collapsed = collapse_whitespace(cleaned);
        let (truncated, was_truncated) = truncate_to_limit(&collapsed, MAX_SUMMARY_CHARS);
        return if was_truncated { truncated } else { collapsed };
    }
    let mut summary = String::new();
    let mut awaiting_break_after_heading = false;
    for segment in segments {
        if summary.is_empty() {
            summary.push_str(&segment.text);
            awaiting_break_after_heading = segment.is_heading;
            continue;
        }
        if awaiting_break_after_heading {
            summary.push_str(" — ");
            awaiting_break_after_heading = false;
        } else {
            summary.push(' ');
        }
        summary.push_str(&segment.text);
        if summary.chars().count() >= MAX_SUMMARY_CHARS {
            break;
        }
    }
    let summary = summary.trim().to_string();
    if summary.is_empty() {
        let fallback = cleaned
            .split_whitespace()
            .take(60)
            .collect::<Vec<_>>()
            .join(" ");
        let (truncated, was_truncated) = truncate_to_limit(&fallback, MAX_SUMMARY_CHARS);
        return if was_truncated { truncated } else { fallback };
    }
    let (truncated, was_truncated) = truncate_to_limit(&summary, MAX_SUMMARY_CHARS);
    if was_truncated {
        truncated
    } else {
        summary
    }
}

fn strip_front_matter(content: &str) -> &str {
    let text = content.trim_start_matches('\u{feff}');
    if !text.starts_with("---") {
        return text;
    }
    let mut iter = text.split_inclusive('\n');
    let Some(first_line) = iter.next() else {
        return text;
    };
    if first_line.trim_end() != "---" {
        return text;
    }
    let mut offset = first_line.len();
    for line in iter {
        offset += line.len();
        if line.trim_end() == "---" {
            let remainder = text[offset..].trim_start_matches(|c| c == '\n' || c == '\r');
            return remainder;
        }
    }
    text
}

#[derive(Clone)]
struct Segment {
    text: String,
    is_heading: bool,
}

fn collect_segments(text: &str, max_segments: usize) -> Vec<Segment> {
    let mut segments = Vec::with_capacity(max_segments);
    let mut buffer: Vec<String> = Vec::new();
    let mut in_code_block = false;
    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        if is_code_fence(trimmed) {
            in_code_block = !in_code_block;
            continue;
        }
        if in_code_block {
            continue;
        }
        if trimmed.is_empty() {
            push_buffer_segment(&mut segments, &mut buffer, max_segments);
            if segments.len() >= max_segments {
                break;
            }
            continue;
        }
        let Some((normalized, is_heading)) = normalize_line(trimmed) else {
            continue;
        };
        if is_heading {
            push_buffer_segment(&mut segments, &mut buffer, max_segments);
            if segments.len() >= max_segments {
                break;
            }
            segments.push(Segment {
                text: normalized,
                is_heading: true,
            });
            if segments.len() >= max_segments {
                break;
            }
        } else {
            buffer.push(normalized);
        }
    }
    if segments.len() < max_segments {
        push_buffer_segment(&mut segments, &mut buffer, max_segments);
    }
    segments
}

fn push_buffer_segment(segments: &mut Vec<Segment>, buffer: &mut Vec<String>, max_segments: usize) {
    if buffer.is_empty() {
        return;
    }
    let joined = buffer.join(" ");
    buffer.clear();
    if joined.trim().is_empty() {
        return;
    }
    if segments.len() >= max_segments {
        return;
    }
    let collapsed = collapse_whitespace(&joined);
    if collapsed.is_empty() {
        return;
    }
    segments.push(Segment {
        text: collapsed,
        is_heading: false,
    });
}

fn normalize_line(line: &str) -> Option<(String, bool)> {
    let mut text = line.trim();
    if text.is_empty() {
        return None;
    }
    let mut is_heading = false;
    if text.starts_with('#') {
        is_heading = true;
        text = text.trim_start_matches('#').trim_start();
    }
    while text.starts_with('>') {
        text = text[1..].trim_start();
    }
    text = strip_list_prefix(text);
    if text.is_empty() {
        return None;
    }
    let mut owned = text.to_string();
    owned = MARKDOWN_LINK_RE.replace_all(&owned, "$1").into_owned();
    owned = INLINE_CODE_RE.replace_all(&owned, "$1").into_owned();
    owned = HTML_TAG_RE.replace_all(&owned, "").into_owned();
    owned = owned.replace('`', "");
    let collapsed = collapse_whitespace(&owned);
    if collapsed.is_empty() {
        return None;
    }
    Some((collapsed, is_heading))
}

fn strip_list_prefix(text: &str) -> &str {
    let working = text.trim_start();
    for prefix in &["- [ ]", "- [x]", "- [X]", "* [ ]", "* [x]", "* [X]"] {
        if starts_with_case_insensitive(working, prefix) {
            let (_, rest) = working.split_at(prefix.len());
            return rest.trim_start();
        }
    }
    for prefix in &["- ", "* ", "+ "] {
        if working.starts_with(prefix) {
            let (_, rest) = working.split_at(prefix.len());
            return rest.trim_start();
        }
    }
    if let Some(mat) = ORDERED_LIST_RE.find(working) {
        let rest = working[mat.end()..].trim_start_matches(|c: char| c == ')' || c == '.');
        return rest.trim_start();
    }
    working
}

fn starts_with_case_insensitive(value: &str, prefix: &str) -> bool {
    value
        .get(0..prefix.len())
        .map(|candidate| candidate.eq_ignore_ascii_case(prefix))
        .unwrap_or(false)
}

fn is_code_fence(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

fn collapse_whitespace(text: &str) -> String {
    MULTISPACE_RE.replace_all(text, " ").trim().to_string()
}

fn truncate_to_limit(text: &str, max_chars: usize) -> (String, bool) {
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

fn condense_snippet(lines: &[String], max_chars: usize) -> (String, bool) {
    if lines.is_empty() {
        return (String::new(), false);
    }
    let joined = lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    if joined.is_empty() {
        return (String::new(), false);
    }
    let normalized = collapse_whitespace(&joined);
    let mut snippet = String::new();
    let mut total_chars = 0usize;
    for part in SENTENCE_SPLIT_RE.split(&normalized) {
        let sentence = part.trim();
        if sentence.is_empty() {
            continue;
        }
        if !snippet.is_empty() {
            snippet.push(' ');
            total_chars += 1;
        }
        snippet.push_str(sentence);
        total_chars += sentence.chars().count();
        if total_chars >= max_chars {
            break;
        }
    }
    if snippet.is_empty() {
        return (String::new(), false);
    }
    if total_chars > max_chars || snippet.chars().count() > max_chars {
        let (truncated, _) = truncate_to_limit(&snippet, max_chars);
        return (truncated, true);
    }
    (snippet, false)
}

fn is_safe_rel_path(rel_path: &str) -> bool {
    let path = Path::new(rel_path);
    if path.is_absolute() {
        return false;
    }
    path.components()
        .all(|component| matches!(component, Component::CurDir | Component::Normal(_)))
}

fn sanitize_query(input: &str) -> String {
    let cleaned: String = input
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c.is_whitespace() || c == '_' {
                c
            } else {
                ' '
            }
        })
        .collect();
    cleaned
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn estimate_tokens(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

static MARKDOWN_LINK_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\[([^\]]+)\]\([^)]+\)").unwrap());
static INLINE_CODE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"`([^`]+)`").unwrap());
static HTML_TAG_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"<[^>]+>").unwrap());
static MULTISPACE_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\s+").unwrap());
static SENTENCE_SPLIT_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"[.!?]+\s+").unwrap());
static ORDERED_LIST_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:\d+[\.)])+").unwrap());

fn line_range_for_fragment(body: &str, fragment: &str) -> Option<(usize, usize)> {
    if fragment.is_empty() {
        return None;
    }
    if let Some(idx) = body.find(fragment) {
        let prefix = &body[..idx];
        let start_line = prefix.chars().filter(|&c| c == '\n').count() + 1;
        let lines_in_fragment = fragment.lines().count().max(1);
        let end_line = start_line + lines_in_fragment - 1;
        return Some((start_line, end_line));
    }
    // fallback: match on first/last non-empty lines of the fragment
    let frag_lines: Vec<&str> = fragment.lines().filter(|l| !l.trim().is_empty()).collect();
    if frag_lines.is_empty() {
        return None;
    }
    let body_lines: Vec<&str> = body.lines().collect();
    let first = frag_lines.first().copied().unwrap_or("");
    let last = frag_lines.last().copied().unwrap_or(first);
    let mut start_line = None;
    for (idx, line) in body_lines.iter().enumerate() {
        if line.contains(first) {
            start_line = Some(idx + 1);
            break;
        }
    }
    let Some(start) = start_line else {
        return None;
    };
    let mut end_line_val = start;
    for (idx, line) in body_lines.iter().enumerate().skip(start - 1) {
        if line.contains(last) {
            end_line_val = idx + 1;
            break;
        }
    }
    Some((start, end_line_val))
}

fn sort_hits_deterministically(hits: &mut [Hit]) {
    hits.sort_by(|a, b| {
        let score_cmp = b.score.total_cmp(&a.score);
        if score_cmp != Ordering::Equal {
            return score_cmp;
        }
        let path_cmp = a.rel_path.cmp(&b.rel_path);
        if path_cmp != Ordering::Equal {
            return path_cmp;
        }
        a.doc_id.cmp(&b.doc_id)
    });
}

#[cfg(test)]
mod tests {
    use super::{sort_hits_deterministically, Hit};

    fn hit(doc_id: &str, rel_path: &str, score: f32) -> Hit {
        Hit {
            doc_id: doc_id.to_string(),
            rel_path: rel_path.to_string(),
            path: rel_path.to_string(),
            score,
            summary: String::new(),
            snippet: String::new(),
            token_estimate: 0,
            snippet_origin: None,
            snippet_truncated: None,
            line_start: None,
            line_end: None,
        }
    }

    #[test]
    fn deterministic_sorting_orders_by_score_then_path_then_doc_id() {
        let mut hits = vec![
            hit("b", "docs/b.md", 1.0),
            hit("a", "docs/a.md", 1.0),
            hit("z", "docs/c.md", 2.0),
            hit("c", "docs/a.md", 1.0),
        ];
        sort_hits_deterministically(&mut hits);
        let ordered = hits
            .iter()
            .map(|h| (h.score, h.rel_path.as_str(), h.doc_id.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            ordered,
            vec![
                (2.0, "docs/c.md", "z"),
                (1.0, "docs/a.md", "a"),
                (1.0, "docs/a.md", "c"),
                (1.0, "docs/b.md", "b"),
            ]
        );
    }
}
