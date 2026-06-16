mod ignore_rules;
mod impact;
pub(crate) mod libs;
mod symbols;

use crate::error::{
    repo_resolution_details, AppError, ERR_BACKOFF_REQUIRED, ERR_INTERNAL_ERROR,
    ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH,
    ERR_REPO_ENCRYPTION_UNSUPPORTED, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX,
};
use crate::impact::{extract_import_edges, impact_graph_path, ImpactGraphEdge};
use crate::repo_encryption::{repo_encryption_domain_id, RepoEncryptionConfig};
use crate::symbols::{
    AstQuery, AstQueryMatch, AstResponseV1, AstSearchMatch, AstSearchMode, SymbolSearchMatch,
    SymbolsParserStatus, SymbolsResponseV1, SymbolsStore,
};
use anyhow::{anyhow, Context, Result};
use ignore_rules::{build_ignore_matcher, IgnoreMatcher};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex as StdMutex, Once};
use std::time::Duration;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, TextOptions, FAST, STORED, STRING, TEXT};
use tantivy::DocAddress;
use tantivy::{
    doc, Document, Index, IndexReader, IndexWriter, ReloadPolicy, SnippetGenerator, Term,
};
use thiserror::Error;
use tracing::{debug, warn};
use walkdir::WalkDir;

const MAX_INDEX_RAM_BYTES: usize = 50 * 1024 * 1024;
const MAX_BINARY_FILE_BYTES: u64 = 5 * 1024 * 1024;
const BINARY_SNIFF_BYTES: usize = 8192;
const INDEX_READY_FILENAME: &str = "index_ready.json";
const RUN_TESTS_CONFIG_PATH: &str = ".docdex/run-tests.json";
const MAX_EXPLANATION_SUMMARY_CHARS: usize = crate::capabilities::EXPLANATION_MAX_CHARS;
const DOC_EXTENSIONS: &[&str] = &[".md", ".markdown", ".mdx", ".txt", ".yaml", ".yml"];
const CODE_EXTENSIONS: &[&str] = &[
    ".rs", ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".go",
    ".java", ".cs", ".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".php", ".kt",
    ".kts", ".swift", ".rb", ".lua", ".dart", ".gradle",
];
const DEFAULT_EXTENSIONS: &[&str] = &[
    ".md",
    ".markdown",
    ".mdx",
    ".txt",
    ".json",
    ".sh",
    ".toml",
    ".cfg",
    ".xml",
    ".mod",
    ".sum",
    ".yaml",
    ".yml",
    ".rs",
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".mts",
    ".cts",
    ".go",
    ".java",
    ".cs",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".cxx",
    ".hh",
    ".hpp",
    ".hxx",
    ".php",
    ".kt",
    ".kts",
    ".swift",
    ".rb",
    ".lua",
    ".dart",
    ".gradle",
];
const DEFAULT_EXCLUDED_DIR_NAMES: &[&str] = &[
    // Core VCS / tooling
    ".git",
    ".idea",
    ".vscode",
    ".cache",
    ".mcoda",
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
    "go-build",
    // Java / Kotlin / JVM
    ".gradle",
    ".mvn",
    "out",
    // .NET / C# / Visual Studio
    "obj",
    ".vs",
    ".nuget",
    "testresults",
    // Swift / Xcode / Apple
    "deriveddata",
    ".build",
    ".swiftpm",
    "carthage",
    // PHP / Composer
    "vendor",
    // Ruby / Bundler
    ".bundle",
    // Dart / Flutter
    ".dart_tool",
    ".flutter-plugins",
    ".flutter-plugins-dependencies",
    ".pub-cache",
    // Kotlin
    ".kotlin",
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
    // Lua
    ".luarocks",
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
    ".mcoda/",
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
    ignore_matcher: Option<Arc<IgnoreMatcher>>,
    repo_encryption: RepoEncryptionConfig,
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
    body_index_field: Option<tantivy::schema::Field>,
    summary_index_field: Option<tantivy::schema::Field>,
    protected_body_field: Option<tantivy::schema::Field>,
    protected_summary_field: Option<tantivy::schema::Field>,
    protection_key_id_field: Option<tantivy::schema::Field>,
    token_field: tantivy::schema::Field,
    kind_field: Option<tantivy::schema::Field>,
    writer: Option<Arc<Mutex<IndexWriter>>>,
    symbols_store: Option<SymbolsStore>,
    indexing_gate: Arc<IndexingGate>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IndexReadyRecord {
    indexed_at_epoch_ms: u128,
    docs_indexed: u64,
}

struct IndexingGate {
    state: StdMutex<IndexingGateState>,
    cvar: Condvar,
}

struct IndexingGateState {
    in_progress: bool,
}

impl IndexingGate {
    fn new() -> Self {
        Self {
            state: StdMutex::new(IndexingGateState { in_progress: false }),
            cvar: Condvar::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocumentKind {
    Doc,
    Code,
}

impl DocumentKind {
    fn as_str(&self) -> &'static str {
        match self {
            DocumentKind::Doc => "doc",
            DocumentKind::Code => "code",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DocType {
    Pdr,
    Sds,
    Openapi,
    Code,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HitScoreBreakdown {
    pub query_relevance: f32,
    pub structural_relevance: f32,
    pub recency_diff_relevance: f32,
    pub total: f32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceAnchorKind {
    ExactLineWindow,
    FileLevelFallback,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HitProvenance {
    pub doc_id: String,
    pub rel_path: String,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line_end: Option<usize>,
    pub anchor_kind: ProvenanceAnchorKind,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RetrievalExplanation {
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Hit {
    pub doc_id: String,
    pub rel_path: String,
    // Stable search contract alias for `rel_path` (preferred by downstream clients).
    pub path: String,
    pub kind: DocumentKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<DocType>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_breakdown: Option<HitScoreBreakdown>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<HitProvenance>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieval_explanation: Option<RetrievalExplanation>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
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

pub(crate) fn build_hit_score_breakdown(
    query_relevance: f32,
    structural_relevance: f32,
    recency_diff_relevance: f32,
) -> HitScoreBreakdown {
    HitScoreBreakdown {
        query_relevance,
        structural_relevance,
        recency_diff_relevance,
        total: query_relevance + structural_relevance + recency_diff_relevance,
    }
}

pub(crate) fn build_hit_provenance(
    doc_id: &str,
    rel_path: &str,
    path: &str,
    line_start: Option<usize>,
    line_end: Option<usize>,
) -> HitProvenance {
    let anchor_kind = if line_start.is_some() && line_end.is_some() {
        ProvenanceAnchorKind::ExactLineWindow
    } else {
        ProvenanceAnchorKind::FileLevelFallback
    };
    HitProvenance {
        doc_id: doc_id.to_string(),
        rel_path: rel_path.to_string(),
        path: path.to_string(),
        line_start,
        line_end,
        anchor_kind,
    }
}

pub(crate) fn build_retrieval_explanation(
    summary: impl Into<String>,
    signals: Vec<String>,
) -> RetrievalExplanation {
    let summary = summary.into();
    let truncated = if summary.chars().count() <= MAX_EXPLANATION_SUMMARY_CHARS {
        summary
    } else {
        summary
            .chars()
            .take(MAX_EXPLANATION_SUMMARY_CHARS.saturating_sub(1))
            .collect::<String>()
            + "…"
    };
    RetrievalExplanation {
        summary: truncated,
        signals,
    }
}

#[derive(Debug, serde::Serialize)]
pub struct DocSnapshot {
    pub doc_id: String,
    pub rel_path: String,
    pub kind: DocumentKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_type: Option<DocType>,
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
        if env_flag_disabled("DOCDEX_ENABLE_SYMBOL_EXTRACTION") {
            warn!(
                target: "docdexd",
                "symbol + impact extraction are always enabled; ignoring DOCDEX_ENABLE_SYMBOL_EXTRACTION=0"
            );
        }
        Self::with_overrides(repo_root, None, Vec::new(), Vec::new(), true)
    }

    pub fn with_overrides(
        repo_root: &Path,
        state_dir: Option<PathBuf>,
        extra_excluded_dirs: Vec<String>,
        extra_excluded_prefixes: Vec<String>,
        symbols_enabled: bool,
    ) -> Result<Self> {
        if !symbols_enabled {
            warn!(
                target: "docdexd",
                "symbol + impact extraction are always enabled; ignoring symbols_enabled=false"
            );
        }
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
        let ignore_matcher = build_ignore_matcher(repo_root, &excluded_dir_names).map(Arc::new);
        Ok(Self {
            state_dir,
            excluded_dir_names,
            excluded_relative_prefixes,
            symbols_enabled: true,
            ignore_matcher,
            repo_encryption: RepoEncryptionConfig::default(),
        })
    }

    pub fn with_repo_encryption(mut self, mut repo_encryption: RepoEncryptionConfig) -> Self {
        repo_encryption.apply_defaults();
        self.repo_encryption = repo_encryption;
        self
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

    pub fn ignore_matcher(&self) -> Option<&IgnoreMatcher> {
        self.ignore_matcher.as_deref()
    }

    pub fn repo_encryption(&self) -> &RepoEncryptionConfig {
        &self.repo_encryption
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
        Self::open_with_auto_reindex(repo_root, config, false)
    }

    pub fn with_config_read_only(repo_root: PathBuf, config: IndexConfig) -> Result<Self> {
        Self::open_with_auto_reindex(repo_root, config, true)
    }

    fn open_with_auto_reindex(
        repo_root: PathBuf,
        config: IndexConfig,
        read_only: bool,
    ) -> Result<Self> {
        match Self::open_indexer(repo_root.clone(), config.clone(), read_only) {
            Ok(indexer) => Ok(indexer),
            Err(err) => {
                if is_stale_index_error(&err) {
                    Self::reindex_stale_index(&repo_root, &config)?;
                    Self::open_indexer(repo_root, config, read_only)
                } else {
                    Err(err)
                }
            }
        }
    }

    fn open_indexer(repo_root: PathBuf, config: IndexConfig, read_only: bool) -> Result<Self> {
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
        if read_only && !config.state_dir().exists() {
            return Err(AppError::new(
                ERR_MISSING_INDEX,
                format!(
                    "index not found at {}; run `docdexd index --repo {}` first",
                    config.state_dir().display(),
                    repo_root.display()
                ),
            )
            .into());
        }
        let created_state_dir = !config.state_dir().exists();
        if created_state_dir {
            ensure_state_dir_secure(config.state_dir())?;
        }
        let (schema, _, _, _, _, _, _, _, _, _, _, _) = build_schema();
        let index = if config.state_dir().join("meta.json").exists() {
            Index::open_in_dir(config.state_dir())
                .map_err(|_| stale_index_error(config.state_dir(), Some(&repo_root)))?
        } else {
            Index::create_in_dir(config.state_dir(), schema.clone())?
        };
        if !read_only {
            ensure_state_dir_secure(config.state_dir())?;
            hold_after_state_dir_created();
        }
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        let schema = index.schema();
        let doc_id_field = schema
            .get_field("doc_id")
            .map_err(|_| stale_index_error(config.state_dir(), Some(&repo_root)))?;
        let path_field = schema
            .get_field("rel_path")
            .map_err(|_| stale_index_error(config.state_dir(), Some(&repo_root)))?;
        let body_field = schema
            .get_field("body")
            .map_err(|_| stale_index_error(config.state_dir(), Some(&repo_root)))?;
        let summary_field = schema
            .get_field("summary")
            .map_err(|_| stale_index_error(config.state_dir(), Some(&repo_root)))?;
        let body_index_field = schema.get_field("body_index").ok();
        let summary_index_field = schema.get_field("summary_index").ok();
        let protected_body_field = schema.get_field("protected_body").ok();
        let protected_summary_field = schema.get_field("protected_summary").ok();
        let protection_key_id_field = schema.get_field("protection_key_id").ok();
        if config.repo_encryption().is_enabled()
            && (body_index_field.is_none()
                || summary_index_field.is_none()
                || protected_body_field.is_none()
                || protected_summary_field.is_none()
                || protection_key_id_field.is_none())
        {
            return Err(stale_index_error(config.state_dir(), Some(&repo_root)).into());
        }
        let token_field = schema
            .get_field("token_estimate")
            .map_err(|_| stale_index_error(config.state_dir(), Some(&repo_root)))?;
        let kind_field = schema.get_field("kind").ok();
        let writer = if read_only {
            None
        } else {
            Some(index.writer(MAX_INDEX_RAM_BYTES)?)
        };
        if config.repo_encryption().is_enabled() && !read_only {
            purge_unprotected_code_intelligence_state(config.state_dir());
        }
        let warn_on_error = !read_only;
        let symbols_store = if config.symbols_enabled() && !config.repo_encryption().is_enabled() {
            symbols::open_symbols_store(&repo_root, config.state_dir(), warn_on_error)
        } else {
            None
        };
        if read_only {
            if let Err(err) =
                crate::repo_manager::validate_repo_state_dir(&repo_root, config.state_dir())
            {
                if let Some(identity) = err.downcast_ref::<crate::repo_manager::RepoIdentityError>()
                {
                    return Err(repo_state_mismatch_error(
                        &repo_root,
                        Some(config.state_dir()),
                        identity,
                    )
                    .into());
                }
                return Err(err).context("validate repo identity metadata");
            }
        } else if let Err(err) =
            crate::repo_manager::record_repo_opened(&repo_root, config.state_dir())
        {
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
            body_index_field,
            summary_index_field,
            protected_body_field,
            protected_summary_field,
            protection_key_id_field,
            token_field,
            kind_field,
            writer: writer.map(|writer| Arc::new(Mutex::new(writer))),
            symbols_store,
            indexing_gate: Arc::new(IndexingGate::new()),
        })
    }

    fn reindex_stale_index(repo_root: &Path, config: &IndexConfig) -> Result<()> {
        let state_dir = config.state_dir();
        if state_dir.exists() {
            Self::remove_dir_all_with_retries(state_dir)
                .with_context(|| format!("remove stale index {}", state_dir.display()))?;
        }
        let indexer = Self::open_indexer(repo_root.to_path_buf(), config.clone(), false)?;
        indexer.reindex_all_blocking()?;
        Ok(())
    }

    fn remove_dir_all_with_retries(path: &Path) -> io::Result<()> {
        const ATTEMPTS: usize = 5;
        for attempt in 0..ATTEMPTS {
            match fs::remove_dir_all(path) {
                Ok(()) => return Ok(()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(_) if attempt + 1 < ATTEMPTS => {
                    std::thread::sleep(Duration::from_millis(20 * (attempt as u64 + 1)));
                    if !path.exists() {
                        return Ok(());
                    }
                    if attempt + 2 == ATTEMPTS {
                        fs::remove_dir_all(path)?;
                    }
                }
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub fn ensure_indexed_blocking(&self) -> Result<bool> {
        if self.index_ready_marker_exists() {
            return Ok(false);
        }
        if self.seed_index_ready_marker()? {
            return Ok(false);
        }
        let mut state = self
            .indexing_gate
            .state
            .lock()
            .map_err(|_| AppError::new(ERR_INTERNAL_ERROR, "indexing gate poisoned"))?;
        while state.in_progress {
            state = self
                .indexing_gate
                .cvar
                .wait(state)
                .map_err(|_| AppError::new(ERR_INTERNAL_ERROR, "indexing gate poisoned"))?;
        }
        if self.index_ready_marker_exists() {
            return Ok(false);
        }
        if self.seed_index_ready_marker()? {
            return Ok(false);
        }
        state.in_progress = true;
        drop(state);

        let result = self.reindex_all_blocking();

        let mut state = self
            .indexing_gate
            .state
            .lock()
            .map_err(|_| AppError::new(ERR_INTERNAL_ERROR, "indexing gate poisoned"))?;
        state.in_progress = false;
        self.indexing_gate.cvar.notify_all();
        drop(state);

        result?;
        Ok(true)
    }

    pub async fn reindex_all(&self) -> Result<()> {
        self.reindex_all_blocking()
    }

    fn reindex_all_blocking(&self) -> Result<()> {
        self.clear_index_ready_marker();
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        writer.delete_all_documents()?;
        self.reset_symbols_store();
        let mut impact_edges: BTreeSet<ImpactGraphEdge> = BTreeSet::new();
        let mut impact_diagnostics: HashMap<String, crate::impact::ImpactDiagnostics> =
            HashMap::new();
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
            if self.symbols_store.is_some() {
                for edge in ingest.impact_edges {
                    impact_edges.insert(edge);
                }
                if let Some(diag) = ingest.impact_diagnostics {
                    impact_diagnostics.insert(ingest.rel_path.clone(), diag);
                }
            }
        }
        writer.commit()?;
        self.reader.reload()?;
        if self.symbols_store.is_some() {
            self.write_impact_graph(impact_edges.into_iter().collect(), impact_diagnostics)?;
        }
        self.write_index_ready_marker(self.num_docs())?;
        if let Err(err) = self.ensure_run_tests_config() {
            warn!(
                target: "docdexd",
                error = ?err,
                "run-tests config initialization failed"
            );
        }
        Ok(())
    }

    fn ensure_run_tests_config(&self) -> Result<()> {
        let config_path = self.repo_root.join(RUN_TESTS_CONFIG_PATH);
        if config_path.exists() {
            return Ok(());
        }
        let (command, args) = Self::detect_run_tests_command(&self.repo_root)
            .unwrap_or_else(Self::fallback_run_tests_command);
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create run-tests config dir {}", parent.display()))?;
        }
        let payload = serde_json::to_vec_pretty(&serde_json::json!({
            "command": command,
            "args": args,
            "env": {},
        }))?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&config_path)
        {
            Ok(mut file) => {
                file.write_all(&payload)?;
                file.write_all(b"\n")?;
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    fn detect_run_tests_command(repo_root: &Path) -> Option<(String, Vec<String>)> {
        if Self::has_repo_file(repo_root, "Cargo.toml") {
            return Some(("cargo".to_string(), vec!["test".to_string()]));
        }
        if Self::has_repo_file(repo_root, "go.mod") {
            return Some((
                "go".to_string(),
                vec!["test".to_string(), "./...".to_string()],
            ));
        }
        if Self::has_repo_file(repo_root, "package.json") {
            return Some(("npm".to_string(), vec!["test".to_string()]));
        }
        if Self::has_any_repo_file(
            repo_root,
            &[
                "pyproject.toml",
                "setup.cfg",
                "setup.py",
                "requirements.txt",
                "Pipfile",
            ],
        ) {
            return Some((
                "python".to_string(),
                vec!["-m".to_string(), "pytest".to_string()],
            ));
        }
        if Self::has_repo_file(repo_root, "pom.xml") {
            return Some(("mvn".to_string(), vec!["test".to_string()]));
        }
        if Self::has_any_repo_file(repo_root, &["build.gradle", "build.gradle.kts"]) {
            #[cfg(windows)]
            {
                if Self::has_repo_file(repo_root, "gradlew.bat") {
                    return Some(("gradlew.bat".to_string(), vec!["test".to_string()]));
                }
            }
            #[cfg(unix)]
            {
                if Self::has_repo_file(repo_root, "gradlew") {
                    return Some(("./gradlew".to_string(), vec!["test".to_string()]));
                }
            }
            return Some(("gradle".to_string(), vec!["test".to_string()]));
        }
        if Self::has_repo_file(repo_root, "Makefile") {
            return Some(("make".to_string(), vec!["test".to_string()]));
        }
        None
    }

    #[cfg(unix)]
    fn fallback_run_tests_command() -> (String, Vec<String>) {
        let script = "echo 'No test runner detected; update .docdex/run-tests.json' 1>&2; exit 1";
        ("sh".to_string(), vec!["-c".to_string(), script.to_string()])
    }

    #[cfg(windows)]
    fn fallback_run_tests_command() -> (String, Vec<String>) {
        let script = "echo No test runner detected; update .docdex\\run-tests.json & exit /b 1";
        (
            "cmd".to_string(),
            vec!["/c".to_string(), script.to_string()],
        )
    }

    fn has_repo_file(repo_root: &Path, name: &str) -> bool {
        repo_root.join(name).is_file()
    }

    fn has_any_repo_file(repo_root: &Path, names: &[&str]) -> bool {
        names.iter().any(|name| repo_root.join(name).is_file())
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
        if self.symbols_store.is_some() {
            self.update_impact_graph_for_file(
                &rel,
                &ingest.impact_edges,
                ingest.impact_diagnostics,
            )?;
        }
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
        if self.symbols_store.is_some() {
            self.remove_impact_edges_for_file(&rel)?;
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        let (hits, _meta) = self.search_with_query_meta(query, limit)?;
        Ok(hits)
    }

    fn search_hit_still_exists(&self, rel_path: &str) -> bool {
        if self.config.repo_encryption().is_enabled() {
            return true;
        }
        if !is_safe_rel_path(rel_path) {
            return false;
        }
        self.repo_root.join(rel_path).is_file()
    }

    fn searchable_fields(&self) -> Result<Vec<tantivy::schema::Field>> {
        if !self.config.repo_encryption().is_enabled() {
            return Ok(vec![self.body_field, self.summary_field, self.path_field]);
        }
        let _key = self.config.repo_encryption().require_key()?;
        if !self.config.repo_encryption().plaintext_term_index_enabled {
            return Err(AppError::new(
                ERR_REPO_ENCRYPTION_UNSUPPORTED,
                "repository encryption search is disabled because plaintext term indexing is disabled",
            )
            .into());
        }
        let Some(body_index_field) = self.body_index_field else {
            return Err(stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into());
        };
        let Some(summary_index_field) = self.summary_index_field else {
            return Err(stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into());
        };
        Ok(vec![body_index_field, summary_index_field, self.path_field])
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
        let parser = QueryParser::for_index(&self.index, self.searchable_fields()?);
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
        let mut snippet_generator = if self.config.repo_encryption().is_enabled() {
            None
        } else {
            SnippetGenerator::create(&searcher, tantivy_query.as_ref(), self.body_field).ok()
        };
        if let Some(generator) = snippet_generator.as_mut() {
            generator.set_max_num_chars(MAX_SNIPPET_CHARS);
        }
        let top_docs = searcher.search(&tantivy_query, &TopDocs::with_limit(limit))?;
        let mut results = Vec::with_capacity(top_docs.len());
        for (score, addr) in top_docs {
            let retrieved = match searcher.doc(addr) {
                Ok(doc) => doc,
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        ?addr,
                        "failed to load search hit; skipping"
                    );
                    continue;
                }
            };
            let doc_id = retrieved
                .get_first(self.doc_id_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let rel_path = retrieved
                .get_first(self.path_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            if !self.search_hit_still_exists(&rel_path) {
                debug!(
                    target: "docdexd",
                    %rel_path,
                    "skipping stale search hit for missing repo file"
                );
                continue;
            }
            let path = rel_path.clone();
            let body_text = self.document_body_text(&retrieved, &rel_path)?;
            let summary = self.document_summary_text(&retrieved, &rel_path)?;
            let kind = self.document_kind_from_doc(&retrieved, &rel_path);
            let doc_type = document_type_for_path(&rel_path, kind);
            let token_estimate = retrieved
                .get_first(self.token_field)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let (snippet, snippet_origin, snippet_truncated, line_start, line_end) =
                if self.config.repo_encryption().is_enabled() {
                    line_safe_snippet_for_query(&body_text, raw, MAX_SNIPPET_CHARS).map(
                        |(text, snippet_truncated, start_line, end_line)| {
                            (
                                text,
                                SearchSnippetOrigin::Query,
                                snippet_truncated,
                                Some(start_line),
                                Some(end_line),
                            )
                        },
                    )
                } else {
                    snippet_generator.as_ref().and_then(|gen| {
                        let snippet = gen.snippet_from_doc(&retrieved);
                        let fragment = snippet.fragment().trim();
                        if fragment.is_empty() {
                            None
                        } else {
                            let inferred_truncated =
                                fragment.chars().count() >= MAX_SNIPPET_CHARS.saturating_sub(1);
                            line_safe_snippet_for_fragment(&body_text, fragment, MAX_SNIPPET_CHARS)
                                .map(|(text, snippet_truncated, start_line, end_line)| {
                                    (
                                        text,
                                        SearchSnippetOrigin::Query,
                                        snippet_truncated || inferred_truncated,
                                        Some(start_line),
                                        Some(end_line),
                                    )
                                })
                        }
                    })
                }
                .or_else(|| {
                    if self.config.repo_encryption().is_enabled() {
                        line_safe_snippet_preview_from_text(&body_text, MAX_SNIPPET_CHARS).map(
                            |(text, truncated, start_line, end_line)| {
                                (
                                    text,
                                    SearchSnippetOrigin::Preview,
                                    truncated,
                                    Some(start_line),
                                    Some(end_line),
                                )
                            },
                        )
                    } else {
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
            let snippet_signal = match snippet_origin {
                SearchSnippetOrigin::Query => "query_snippet",
                SearchSnippetOrigin::Preview => "preview_snippet",
                SearchSnippetOrigin::Summary => "summary_fallback",
            };
            let score_breakdown = Some(build_hit_score_breakdown(score, 0.0, 0.0));
            let provenance = Some(build_hit_provenance(
                &doc_id, &rel_path, &path, line_start, line_end,
            ));
            let retrieval_explanation = Some(build_retrieval_explanation(
                format!("Ranked by lexical query relevance ({snippet_signal})."),
                vec!["bm25_query_match".to_string(), snippet_signal.to_string()],
            ));
            results.push(Hit {
                doc_id,
                rel_path,
                path,
                kind,
                doc_type,
                score,
                summary,
                snippet,
                token_estimate,
                snippet_origin: Some(snippet_origin),
                snippet_truncated: Some(snippet_truncated),
                line_start,
                line_end,
                score_breakdown,
                provenance,
                retrieval_explanation,
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
        if self.config.repo_encryption().is_enabled() {
            return Err(AppError::new(
                ERR_REPO_ENCRYPTION_UNSUPPORTED,
                "direct source preview snippets are disabled for encrypted repositories",
            )
            .into());
        }
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
        let (snippet, snippet_truncated, start_line, end_line) =
            line_safe_snippet_from_lines(&preview_lines, MAX_SNIPPET_CHARS);
        if snippet.is_empty() {
            return Ok(None);
        }
        let start_line =
            start_line.unwrap_or_else(|| preview_lines.first().map(|(line, _)| *line).unwrap_or(1));
        let end_line = end_line.unwrap_or(start_line);
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

    pub fn read_symbols(&self, rel_path: &str) -> Result<Option<SymbolsResponseV1>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(None);
        };
        if store.requires_reindex()? {
            return Ok(None);
        }
        store.read_symbols(rel_path)
    }

    pub fn read_ast(&self, rel_path: &str, max_nodes: usize) -> Result<Option<AstResponseV1>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(None);
        };
        if store.requires_reindex()? {
            return Ok(None);
        }
        store.read_ast(rel_path, max_nodes)
    }

    pub fn symbols_parser_status(&self) -> Result<SymbolsParserStatus> {
        self.ensure_code_intelligence_allowed()?;
        match self.symbols_store.as_ref() {
            Some(store) => store.parser_status(),
            None => {
                let store = SymbolsStore::new(self.repo_root(), self.config.state_dir())?;
                store.parser_status()
            }
        }
    }

    pub fn symbols_reindex_required(&self) -> Result<bool> {
        self.ensure_code_intelligence_allowed()?;
        let status = match self.symbols_store.as_ref() {
            Some(store) => store.parser_status()?,
            None => {
                let store = SymbolsStore::new(self.repo_root(), self.config.state_dir())?;
                store.parser_status()?
            }
        };
        Ok(status.requires_reindex || status.drift)
    }

    pub fn search_symbols(
        &self,
        query: &str,
        max_files: usize,
        max_symbols_per_file: usize,
    ) -> Result<Vec<SymbolSearchMatch>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(Vec::new());
        };
        if store.requires_reindex()? {
            return Ok(Vec::new());
        }
        store.search_symbols(query, max_files, max_symbols_per_file)
    }

    pub fn search_ast_kinds(
        &self,
        kinds: &[String],
        max_files: usize,
    ) -> Result<Vec<AstSearchMatch>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(Vec::new());
        };
        if store.requires_reindex()? {
            return Ok(Vec::new());
        }
        store.search_ast_kinds(kinds, max_files)
    }

    pub fn search_ast_kinds_with_mode(
        &self,
        kinds: &[String],
        max_files: usize,
        mode: AstSearchMode,
    ) -> Result<Vec<AstSearchMatch>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(Vec::new());
        };
        if store.requires_reindex()? {
            return Ok(Vec::new());
        }
        store.search_ast_kinds_with_mode(kinds, max_files, mode)
    }

    pub fn ast_kind_counts_for_file(
        &self,
        rel_path: &str,
        kinds: &[String],
    ) -> Result<BTreeMap<String, usize>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(BTreeMap::new());
        };
        if store.requires_reindex()? {
            return Ok(BTreeMap::new());
        }
        store.ast_kind_counts_for_file(rel_path, kinds)
    }

    pub fn query_ast(&self, query: &AstQuery) -> Result<Vec<AstQueryMatch>> {
        self.ensure_code_intelligence_allowed()?;
        let Some(store) = self.symbols_store.as_ref() else {
            return Ok(Vec::new());
        };
        if store.requires_reindex()? {
            return Ok(Vec::new());
        }
        store.query_ast(query)
    }

    fn ensure_code_intelligence_allowed(&self) -> Result<()> {
        if self.config.repo_encryption().is_enabled() {
            return Err(AppError::new(
                ERR_REPO_ENCRYPTION_UNSUPPORTED,
                "symbols, AST, and impact graph are disabled for encrypted repositories until their stores are protected",
            )
            .into());
        }
        Ok(())
    }

    pub fn state_dir(&self) -> &Path {
        self.config.state_dir()
    }

    pub fn index_ready(&self) -> bool {
        self.index_ready_marker_exists() || self.num_docs() > 0
    }

    pub fn indexing_in_progress(&self) -> Result<bool> {
        let state = self
            .indexing_gate
            .state
            .lock()
            .map_err(|_| AppError::new(ERR_INTERNAL_ERROR, "indexing gate poisoned"))?;
        Ok(state.in_progress)
    }

    pub fn is_read_only(&self) -> bool {
        self.writer.is_none()
    }

    fn index_ready_path(&self) -> PathBuf {
        self.config.state_dir().join(INDEX_READY_FILENAME)
    }

    fn index_ready_marker_exists(&self) -> bool {
        self.index_ready_path().exists()
    }

    fn seed_index_ready_marker(&self) -> Result<bool> {
        if self.index_ready_marker_exists() {
            return Ok(false);
        }
        let docs_indexed = self.num_docs();
        if docs_indexed == 0 {
            return Ok(false);
        }
        self.write_index_ready_marker(docs_indexed)?;
        Ok(true)
    }

    fn clear_index_ready_marker(&self) {
        let path = self.index_ready_path();
        if path.exists() {
            let _ = fs::remove_file(path);
        }
    }

    fn write_index_ready_marker(&self, docs_indexed: u64) -> Result<()> {
        let indexed_at_epoch_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis();
        let record = IndexReadyRecord {
            indexed_at_epoch_ms,
            docs_indexed,
        };
        let payload = serde_json::to_vec(&record)?;
        fs::write(self.index_ready_path(), payload)?;
        Ok(())
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

    pub fn symbols_enabled(&self) -> bool {
        self.config.symbols_enabled()
    }

    pub fn num_docs(&self) -> u64 {
        let searcher = self.reader.searcher();
        let mut num_docs: u64 = 0;
        for segment_reader in searcher.segment_readers() {
            let live_docs = segment_reader
                .alive_bitset()
                .map(|bits| bits.num_alive_docs() as u64)
                .unwrap_or_else(|| segment_reader.max_doc() as u64);
            num_docs = num_docs.saturating_add(live_docs);
        }
        num_docs
    }

    pub fn stats(&self) -> Result<IndexStats> {
        let searcher = self.reader.searcher();
        let num_docs = self.num_docs();
        let mut segments: usize = 0;
        for _ in searcher.segment_readers() {
            segments += 1;
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
        let snapshot = self.snapshot_from_document(doc_id, &doc)?;
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
                snapshots.push(self.snapshot_from_document(doc_id_text, &doc)?);
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
        let (impact_edges, impact_diagnostics) =
            if self.symbols_store.is_some() && read_error.is_none() {
                let result = extract_import_edges(
                    &self.repo_root,
                    self.config.state_dir(),
                    &rel_for_return,
                    &content,
                );
                (result.edges, result.diagnostics)
            } else {
                (Vec::new(), None)
            };
        let summary = summarize(&content);
        let tokens = estimate_tokens(&content);
        let kind = document_kind_for_path(&rel_for_return);
        let mut document = Document::default();
        document.add_text(self.doc_id_field, rel.clone());
        document.add_text(self.path_field, rel);
        if self.config.repo_encryption().is_enabled() {
            let key = self.config.repo_encryption().require_key()?;
            let domain_id = repo_encryption_domain_id(&self.repo_root);
            let protected_body = self.config.repo_encryption().protect_text(
                &key,
                &domain_id,
                &rel_for_return,
                "body",
                &content,
            )?;
            let protected_summary = self.config.repo_encryption().protect_text(
                &key,
                &domain_id,
                &rel_for_return,
                "summary",
                &summary,
            )?;
            let Some(protected_body_field) = self.protected_body_field else {
                return Err(
                    stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into(),
                );
            };
            let Some(protected_summary_field) = self.protected_summary_field else {
                return Err(
                    stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into(),
                );
            };
            let Some(protection_key_id_field) = self.protection_key_id_field else {
                return Err(
                    stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into(),
                );
            };
            document.add_text(protected_body_field, protected_body);
            document.add_text(protected_summary_field, protected_summary);
            document.add_text(protection_key_id_field, key.key_id.clone());
            if self.config.repo_encryption().plaintext_term_index_enabled {
                let Some(body_index_field) = self.body_index_field else {
                    return Err(
                        stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into(),
                    );
                };
                let Some(summary_index_field) = self.summary_index_field else {
                    return Err(
                        stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into(),
                    );
                };
                document.add_text(body_index_field, content);
                document.add_text(summary_index_field, summary);
            }
        } else {
            document.add_text(self.body_field, content);
            document.add_text(self.summary_field, summary);
        }
        document.add_u64(self.token_field, tokens);
        if let Some(kind_field) = self.kind_field {
            document.add_text(kind_field, kind.as_str());
        }
        writer.add_document(document)?;
        Ok(DocumentIngest {
            rel_path: rel_for_return,
            content: content_for_symbols,
            read_error,
            impact_edges,
            impact_diagnostics,
        })
    }

    fn rel_path(&self, path: &Path) -> Result<String> {
        let rel = path
            .strip_prefix(&self.repo_root)
            .map_err(|_| anyhow!("{} is outside repo root", path.display()))?;
        Ok(rel.to_string_lossy().replace('\\', "/"))
    }

    fn snapshot_from_document(&self, doc_id: &str, doc: &Document) -> Result<DocSnapshot> {
        let rel_path = doc
            .get_first(self.path_field)
            .and_then(|v| v.as_text().map(|s| s.to_string()))
            .unwrap_or_default();
        let summary = self.document_summary_text(doc, &rel_path)?;
        let kind = self.document_kind_from_doc(doc, &rel_path);
        let doc_type = document_type_for_path(&rel_path, kind);
        let token_estimate = doc
            .get_first(self.token_field)
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        Ok(DocSnapshot {
            doc_id: doc_id.to_string(),
            rel_path,
            kind,
            doc_type,
            summary,
            token_estimate,
        })
    }

    fn document_body_text(&self, doc: &Document, rel_path: &str) -> Result<String> {
        if !self.config.repo_encryption().is_enabled() {
            return Ok(doc
                .get_first(self.body_field)
                .and_then(|v| v.as_text())
                .unwrap_or_default()
                .to_string());
        }
        let key = self.config.repo_encryption().require_key()?;
        let Some(field) = self.protected_body_field else {
            return Err(stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into());
        };
        let protected = doc
            .get_first(field)
            .and_then(|v| v.as_text())
            .ok_or_else(|| {
                AppError::new(
                    ERR_REPO_ENCRYPTION_UNSUPPORTED,
                    "encrypted repository document is missing protected body content",
                )
            })?;
        self.config.repo_encryption().unprotect_text(
            &key,
            &repo_encryption_domain_id(&self.repo_root),
            rel_path,
            "body",
            protected,
        )
    }

    fn document_summary_text(&self, doc: &Document, rel_path: &str) -> Result<String> {
        if !self.config.repo_encryption().is_enabled() {
            return Ok(doc
                .get_first(self.summary_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default());
        }
        let key = self.config.repo_encryption().require_key()?;
        let Some(field) = self.protected_summary_field else {
            return Err(stale_index_error(self.config.state_dir(), Some(&self.repo_root)).into());
        };
        let protected = doc
            .get_first(field)
            .and_then(|v| v.as_text())
            .ok_or_else(|| {
                AppError::new(
                    ERR_REPO_ENCRYPTION_UNSUPPORTED,
                    "encrypted repository document is missing protected summary content",
                )
            })?;
        self.config.repo_encryption().unprotect_text(
            &key,
            &repo_encryption_domain_id(&self.repo_root),
            rel_path,
            "summary",
            protected,
        )
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
            if self.config.repo_encryption().is_enabled() {
                let rel_path = rel_path_hint
                    .map(|value| value.to_string())
                    .or_else(|| {
                        doc.get_first(self.path_field)
                            .and_then(|v| v.as_text().map(|s| s.to_string()))
                    })
                    .unwrap_or_default();
                let body_text = self.document_body_text(doc, &rel_path)?;
                if let Some((text, truncated, start_line, end_line)) =
                    line_safe_snippet_for_query(&body_text, query, MAX_SNIPPET_CHARS)
                {
                    return Ok(Some(SnippetResult {
                        text,
                        html: None,
                        truncated,
                        origin: SnippetOrigin::Query,
                        line_start: Some(start_line),
                        line_end: Some(end_line),
                    }));
                }
            } else {
                let parser = QueryParser::for_index(&self.index, vec![self.body_field]);
                if let Ok(parsed) = parser.parse_query(query) {
                    if let Ok(mut generator) =
                        SnippetGenerator::create(&searcher, parsed.as_ref(), self.body_field)
                    {
                        generator.set_max_num_chars(MAX_SNIPPET_CHARS);
                        let snippet = generator.snippet_from_doc(doc);
                        let fragment = snippet.fragment().trim();
                        if !fragment.is_empty() {
                            let inferred_truncated =
                                fragment.chars().count() >= MAX_SNIPPET_CHARS.saturating_sub(1);
                            let body_text = doc
                                .get_first(self.body_field)
                                .and_then(|v| v.as_text())
                                .unwrap_or_default();
                            if let Some((text, snippet_truncated, start_line, end_line)) =
                                line_safe_snippet_for_fragment(
                                    body_text,
                                    fragment,
                                    MAX_SNIPPET_CHARS,
                                )
                            {
                                let html = if text.trim() == fragment {
                                    Some(snippet.to_html())
                                } else {
                                    None
                                };
                                return Ok(Some(SnippetResult {
                                    text,
                                    html,
                                    truncated: snippet_truncated || inferred_truncated,
                                    origin: SnippetOrigin::Query,
                                    line_start: Some(start_line),
                                    line_end: Some(end_line),
                                }));
                            }
                        }
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
            let snippet = if self.config.repo_encryption().is_enabled() {
                let body_text = self.document_body_text(doc, &rel_path)?;
                line_safe_snippet_preview_from_text(&body_text, MAX_SNIPPET_CHARS)
            } else {
                self.preview_snippet(&rel_path, fallback_lines)?
            };
            if let Some((text, truncated, line_start, line_end)) = snippet {
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

pub async fn ensure_indexed(indexer: Arc<Indexer>) -> Result<bool> {
    if tokio::runtime::Handle::try_current().is_err() {
        return indexer.ensure_indexed_blocking();
    }
    let indexer_clone = indexer.clone();
    tokio::task::spawn_blocking(move || indexer_clone.ensure_indexed_blocking())
        .await
        .map_err(|err| anyhow!("indexing task aborted: {err}"))?
}

struct DocumentIngest {
    rel_path: String,
    content: String,
    read_error: Option<String>,
    impact_edges: Vec<ImpactGraphEdge>,
    impact_diagnostics: Option<crate::impact::ImpactDiagnostics>,
}

fn env_flag_disabled(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            matches!(
                v.trim().to_lowercase().as_str(),
                "0" | "false" | "no" | "off"
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
    tantivy::schema::Field,
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
    let body_index_field = builder.add_text_field("body_index", TEXT);
    let summary_index_field = builder.add_text_field("summary_index", TEXT);
    let protected_body_field =
        builder.add_text_field("protected_body", TextOptions::default().set_stored());
    let protected_summary_field =
        builder.add_text_field("protected_summary", TextOptions::default().set_stored());
    let protection_key_id_field = builder.add_text_field("protection_key_id", STRING | STORED);
    let token_field = builder.add_u64_field("token_estimate", FAST | STORED);
    let kind_field = builder.add_text_field("kind", STRING | STORED);
    let schema = builder.build();
    (
        schema,
        doc_id_field,
        path_field,
        body_field,
        summary_field,
        body_index_field,
        summary_index_field,
        protected_body_field,
        protected_summary_field,
        protection_key_id_field,
        token_field,
        kind_field,
    )
}

fn document_kind_from_text(value: &str) -> Option<DocumentKind> {
    match value.trim() {
        "doc" => Some(DocumentKind::Doc),
        "code" => Some(DocumentKind::Code),
        _ => None,
    }
}

fn document_kind_for_path(rel_path: &str) -> DocumentKind {
    let extension = Path::new(rel_path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{}", ext.to_lowercase()));
    if let Some(extension) = extension {
        if DOC_EXTENSIONS.contains(&extension.as_str()) {
            return DocumentKind::Doc;
        }
        if CODE_EXTENSIONS.contains(&extension.as_str()) {
            return DocumentKind::Code;
        }
    }
    DocumentKind::Doc
}

fn document_type_for_path(rel_path: &str, kind: DocumentKind) -> Option<DocType> {
    if matches!(kind, DocumentKind::Code) {
        return Some(DocType::Code);
    }
    let lowered = rel_path.to_ascii_lowercase();
    if lowered.starts_with("pdr/")
        || lowered.contains("/pdr/")
        || lowered.contains("pdr_")
        || lowered.contains("pdr-")
    {
        return Some(DocType::Pdr);
    }
    if lowered.starts_with("sds/")
        || lowered.contains("/sds/")
        || lowered.contains("sds_")
        || lowered.contains("sds-")
    {
        return Some(DocType::Sds);
    }
    if lowered.starts_with("openapi/")
        || lowered.contains("/openapi/")
        || lowered.contains("openapi")
    {
        return Some(DocType::Openapi);
    }
    None
}

impl Indexer {
    fn document_kind_from_doc(&self, doc: &Document, rel_path: &str) -> DocumentKind {
        if let Some(kind_field) = self.kind_field {
            if let Some(raw) = doc.get_first(kind_field).and_then(|v| v.as_text()) {
                if let Some(kind) = document_kind_from_text(raw) {
                    return kind;
                }
            }
        }
        document_kind_for_path(rel_path)
    }
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
    IgnoredByPattern,
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

    if let Some(matcher) = config.ignore_matcher() {
        let is_dir = path.is_dir();
        if matcher.is_ignored(path, is_dir) {
            return FileDecision::exclude(FileDecisionReason::IgnoredByPattern);
        }
    }

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
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            vec!["docs/".into(), "docs/private/".into()],
            true,
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
        let state_dir = repo_root.join(".docdex-state");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(state_dir.clone()),
            Vec::new(),
            Vec::new(),
            true,
        )
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
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
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
    fn decide_file_excludes_default_tool_artifacts() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
        .expect("config");

        let mcoda_file = repo_root.join(".mcoda/notes.md");
        fs::create_dir_all(mcoda_file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&mcoda_file, "# mcoda\n").expect("write mcoda file");
        let decision = decide_file(&mcoda_file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(
            decision.reason,
            FileDecisionReason::ExcludedPrefix {
                prefix: ".mcoda/".to_string()
            }
        );

        let node_file = repo_root.join("node_modules/pkg/readme.md");
        fs::create_dir_all(node_file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&node_file, "# node\n").expect("write node file");
        let decision = decide_file(&node_file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(
            decision.reason,
            FileDecisionReason::ExcludedDirName {
                name: "node_modules".to_string()
            }
        );

        let build_file = repo_root.join("build/output.md");
        fs::create_dir_all(build_file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&build_file, "# build\n").expect("write build file");
        let decision = decide_file(&build_file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(
            decision.reason,
            FileDecisionReason::ExcludedDirName {
                name: "build".to_string()
            }
        );
    }

    #[test]
    fn decide_file_excludes_outside_repo() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
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
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
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
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
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

        let json_file = repo_root.join("docs/config.json");
        fs::write(&json_file, "{\"ok\":true}\n").expect("write json file");
        let json_decision = decide_file(&json_file, &repo_root, &config);
        assert_eq!(json_decision.decision, FileDecisionOutcome::Include);
        assert_eq!(
            json_decision.reason,
            FileDecisionReason::AllowedExtension {
                extension: ".json".to_string()
            }
        );

        let sh_file = repo_root.join("docs/run.sh");
        fs::write(&sh_file, "echo test\n").expect("write sh file");
        let sh_decision = decide_file(&sh_file, &repo_root, &config);
        assert_eq!(sh_decision.decision, FileDecisionOutcome::Include);
        assert_eq!(
            sh_decision.reason,
            FileDecisionReason::AllowedExtension {
                extension: ".sh".to_string()
            }
        );

        let toml_file = repo_root.join("docs/config.toml");
        fs::write(&toml_file, "key = \"value\"\n").expect("write toml file");
        let toml_decision = decide_file(&toml_file, &repo_root, &config);
        assert_eq!(toml_decision.decision, FileDecisionOutcome::Include);
        assert_eq!(
            toml_decision.reason,
            FileDecisionReason::AllowedExtension {
                extension: ".toml".to_string()
            }
        );

        let cjs_file = repo_root.join("docs/release.cjs");
        fs::write(&cjs_file, "module.exports = {}\n").expect("write cjs file");
        let cjs_decision = decide_file(&cjs_file, &repo_root, &config);
        assert_eq!(cjs_decision.decision, FileDecisionOutcome::Include);
        assert_eq!(
            cjs_decision.reason,
            FileDecisionReason::AllowedExtension {
                extension: ".cjs".to_string()
            }
        );

        for (rel_path, contents, extension) in [
            ("docs/module.mjs", "export const v = 1;\n", ".mjs"),
            ("docs/module.mts", "export const v: number = 1;\n", ".mts"),
            ("docs/module.cts", "export const v: number = 1;\n", ".cts"),
            ("docs/types.pyi", "def f(x: int) -> int: ...\n", ".pyi"),
            ("docs/settings.cfg", "[tool]\nname=value\n", ".cfg"),
            ("docs/pom.xml", "<project></project>\n", ".xml"),
            ("go.mod", "module example.com/app\n", ".mod"),
            ("go.sum", "example.com/mod v1.0.0 h1:abc\n", ".sum"),
            ("build.gradle", "plugins { id 'java' }\n", ".gradle"),
        ] {
            let path = repo_root.join(rel_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(&path, contents).expect("write supported extension file");
            let decision = decide_file(&path, &repo_root, &config);
            assert_eq!(decision.decision, FileDecisionOutcome::Include);
            assert_eq!(
                decision.reason,
                FileDecisionReason::AllowedExtension {
                    extension: extension.to_string()
                }
            );
        }
    }

    #[test]
    fn decide_file_respects_gitignore() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let ignore_path = repo_root.join(".gitignore");
        fs::write(&ignore_path, "ignored.md\n").expect("write gitignore");
        let file = repo_root.join("ignored.md");
        fs::write(&file, "ignore me\n").expect("write file");

        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
        .expect("config");
        let decision = decide_file(&file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(decision.reason, FileDecisionReason::IgnoredByPattern);
    }

    #[test]
    fn decide_file_scopes_nested_gitignore() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let root_file = repo_root.join("README.md");
        fs::write(&root_file, "hello\n").expect("write root file");

        let nested_dir = repo_root.join("nested");
        fs::create_dir_all(&nested_dir).expect("mkdir");
        fs::write(nested_dir.join(".gitignore"), "*\n").expect("write nested gitignore");
        let nested_file = nested_dir.join("notes.md");
        fs::write(&nested_file, "ignore me\n").expect("write nested file");

        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
        .expect("config");

        let root_decision = decide_file(&root_file, &repo_root, &config);
        assert_eq!(root_decision.decision, FileDecisionOutcome::Include);

        let nested_decision = decide_file(&nested_file, &repo_root, &config);
        assert_eq!(nested_decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(nested_decision.reason, FileDecisionReason::IgnoredByPattern);
    }

    #[test]
    fn decide_file_respects_docdexignore() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let ignore_path = repo_root.join(".docdexignore");
        fs::write(&ignore_path, "docs/private/\n").expect("write docdexignore");
        let file = repo_root.join("docs/private/notes.md");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "ignore me\n").expect("write file");

        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(repo_root.join(".docdex-state")),
            Vec::new(),
            Vec::new(),
            true,
        )
        .expect("config");
        let decision = decide_file(&file, &repo_root, &config);
        assert_eq!(decision.decision, FileDecisionOutcome::Exclude);
        assert_eq!(decision.reason, FileDecisionReason::IgnoredByPattern);
    }
}

fn hold_after_state_dir_created() {
    let Ok(value) = std::env::var("DOCDEX_TEST_HOLD_AFTER_STATE_DIR_CREATED_MS") else {
        return;
    };
    let Ok(ms) = value.trim().parse::<u64>() else {
        return;
    };
    static HOLD_ONCE: Once = Once::new();
    HOLD_ONCE.call_once(|| std::thread::sleep(std::time::Duration::from_millis(ms)));
}

pub(crate) fn ensure_state_dir_secure(path: &Path) -> Result<()> {
    crate::state_layout::ensure_state_dir_secure(path)
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

fn canonical_path_from_repo_meta(
    repo_root: &Path,
    index_state_dir: Option<&Path>,
) -> Option<String> {
    if let Some(index_state_dir) = index_state_dir {
        if index_state_dir.file_name().and_then(|s| s.to_str())? == "index" {
            let state_key_dir = index_state_dir.parent()?;
            let meta_path = state_key_dir.join("repo_meta.json");
            if let Ok(raw) = fs::read_to_string(&meta_path) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
                    if let Some(path) = parsed.get("canonical_path").and_then(|v| v.as_str()) {
                        return Some(path.to_string());
                    }
                }
            }
        }
    }

    let workspace_meta = repo_root.join(".docdex").join("repo_meta.json");
    if let Ok(raw) = fs::read_to_string(&workspace_meta) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(path) = parsed.get("canonical_path").and_then(|v| v.as_str()) {
                return Some(path.to_string());
            }
        }
    }

    let legacy_meta = repo_root.join("repo_meta.json");
    let raw = fs::read_to_string(&legacy_meta).ok()?;
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
            format!(
                "If you previously indexed this repo, you may need to reindex after moving it: `docdexd index --repo {}`.",
                normalize_for_error(repo_root)
            ),
        ],
    ))
}

fn stale_index_error(state_dir: &Path, repo_root: Option<&Path>) -> AppError {
    let reindex_hint = repo_root
        .map(|root| format!("docdexd index --repo {}", normalize_for_error(root)))
        .unwrap_or_else(|| "docdexd index --repo <repo>".to_string());
    AppError::new(
        ERR_STALE_INDEX,
        format!(
            "index schema mismatch at {}; reindex with `{}`",
            state_dir.display(),
            reindex_hint
        ),
    )
    .with_details(serde_json::json!({
        "staleIndex": true,
        "stateDir": state_dir.display().to_string(),
        "reindexHint": reindex_hint,
    }))
}

fn is_stale_index_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<AppError>()
        .map(|app| app.code == ERR_STALE_INDEX)
        .unwrap_or(false)
}

fn repo_state_mismatch_error(
    repo_root: &Path,
    index_state_dir: Option<&Path>,
    identity: &crate::repo_manager::RepoIdentityError,
) -> AppError {
    let attempted_fingerprint = crate::repo_manager::repo_fingerprint_sha256(repo_root).ok();
    let mut known_canonical_path = index_state_dir.and_then(known_canonical_path_from_repo_meta);
    if known_canonical_path.is_none() {
        known_canonical_path = canonical_path_from_repo_meta(repo_root, index_state_dir);
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

fn purge_unprotected_code_intelligence_state(state_dir: &Path) {
    let mut candidates = vec![state_dir.join("symbols.db"), impact_graph_path(state_dir)];
    if state_dir.file_name().and_then(|name| name.to_str()) == Some("index") {
        if let Some(repo_state_root) = state_dir.parent() {
            candidates.push(repo_state_root.join("symbols.db"));
        }
    }
    for path in candidates {
        if path.exists() {
            if let Err(err) = fs::remove_file(&path) {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    path = %path.display(),
                    "failed to remove unprotected code-intelligence state for encrypted repository"
                );
            }
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

fn line_safe_snippet_from_lines(
    lines: &[(usize, String)],
    max_chars: usize,
) -> (String, bool, Option<usize>, Option<usize>) {
    if lines.is_empty() {
        return (String::new(), false, None, None);
    }
    let mut selected: Vec<(usize, String)> = Vec::new();
    let mut used_chars = 0usize;
    let mut truncated = false;
    for (line_no, line) in lines {
        if max_chars == 0 {
            truncated = true;
            break;
        }
        let line_text = line.trim_end();
        let line_len = line_text.chars().count();
        let extra = if selected.is_empty() { 0 } else { 1 };
        if !selected.is_empty() && used_chars + extra + line_len > max_chars {
            truncated = true;
            break;
        }
        if selected.is_empty() && line_len > max_chars {
            selected.push((*line_no, line_text.to_string()));
            truncated = lines.len() > 1;
            break;
        }
        selected.push((*line_no, line_text.to_string()));
        used_chars += line_len + extra;
    }
    if selected.is_empty() {
        return (String::new(), truncated, None, None);
    }
    if selected.len() < lines.len() {
        truncated = true;
    }
    let mut snippet = selected
        .iter()
        .map(|(_, line)| line.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    if truncated && !snippet.is_empty() && !snippet.ends_with('…') {
        snippet.push('\n');
        snippet.push('…');
    }
    let start_line = selected.first().map(|(line_no, _)| *line_no);
    let end_line = selected.last().map(|(line_no, _)| *line_no);
    (snippet, truncated, start_line, end_line)
}

fn line_safe_snippet_for_fragment(
    body: &str,
    fragment: &str,
    max_chars: usize,
) -> Option<(String, bool, usize, usize)> {
    let (start_line, end_line) = line_range_for_fragment(body, fragment)?;
    let lines = body
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let line_no = idx + 1;
            if line_no < start_line || line_no > end_line {
                return None;
            }
            Some((line_no, line.to_string()))
        })
        .collect::<Vec<_>>();
    let (snippet, truncated, safe_start, safe_end) =
        line_safe_snippet_from_lines(&lines, max_chars);
    if snippet.trim().is_empty() {
        return None;
    }
    let start = safe_start.unwrap_or(start_line);
    let end = safe_end.unwrap_or(end_line);
    Some((snippet, truncated, start, end))
}

fn line_safe_snippet_for_query(
    body: &str,
    query: &str,
    max_chars: usize,
) -> Option<(String, bool, usize, usize)> {
    let terms = query_terms(query);
    if terms.is_empty() {
        return line_safe_snippet_preview_from_text(body, max_chars);
    }
    let lowered_terms = terms
        .into_iter()
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let lines = body
        .lines()
        .enumerate()
        .map(|(idx, line)| (idx + 1, line.trim()))
        .collect::<Vec<_>>();
    let Some((idx, _)) = lines.iter().enumerate().find(|(_, (_, line))| {
        let lowered = line.to_ascii_lowercase();
        lowered_terms.iter().any(|term| lowered.contains(term))
    }) else {
        return line_safe_snippet_preview_from_text(body, max_chars);
    };
    let start_idx = idx.saturating_sub(1);
    let end_idx = (idx + 2).min(lines.len().saturating_sub(1));
    let selected = lines[start_idx..=end_idx]
        .iter()
        .filter_map(|(line_no, line)| {
            if line.is_empty() {
                None
            } else {
                Some((*line_no, (*line).to_string()))
            }
        })
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return line_safe_snippet_preview_from_text(body, max_chars);
    }
    let (text, truncated, start_line, end_line) =
        line_safe_snippet_from_lines(&selected, max_chars);
    Some((
        text,
        truncated,
        start_line.unwrap_or(selected[0].0),
        end_line.unwrap_or(selected[0].0),
    ))
}

fn line_safe_snippet_preview_from_text(
    body: &str,
    max_chars: usize,
) -> Option<(String, bool, usize, usize)> {
    let preview_lines = body
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some((idx + 1, trimmed.to_string()))
            }
        })
        .take(FALLBACK_PREVIEW_LINES)
        .collect::<Vec<_>>();
    if preview_lines.is_empty() {
        return None;
    }
    let (text, truncated, start_line, end_line) =
        line_safe_snippet_from_lines(&preview_lines, max_chars);
    if text.trim().is_empty() {
        return None;
    }
    Some((
        text,
        truncated,
        start_line.unwrap_or(preview_lines[0].0),
        end_line.unwrap_or(preview_lines[0].0),
    ))
}

fn query_terms(query: &str) -> Vec<String> {
    static TERM_RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"[A-Za-z0-9_]{2,}").expect("query term regex"));
    TERM_RE
        .find_iter(query)
        .map(|mat| mat.as_str().to_string())
        .take(8)
        .collect()
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
    use super::{sort_hits_deterministically, DocumentKind, Hit, IndexConfig, Indexer};
    use anyhow::Result;
    use tempfile::TempDir;

    fn hit(doc_id: &str, rel_path: &str, score: f32) -> Hit {
        Hit {
            doc_id: doc_id.to_string(),
            rel_path: rel_path.to_string(),
            path: rel_path.to_string(),
            kind: DocumentKind::Doc,
            doc_type: None,
            score,
            summary: String::new(),
            snippet: String::new(),
            token_estimate: 0,
            snippet_origin: None,
            snippet_truncated: None,
            line_start: None,
            line_end: None,
            score_breakdown: None,
            provenance: None,
            retrieval_explanation: None,
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

    #[test]
    fn search_filters_missing_repo_docs() -> Result<()> {
        let repo = TempDir::new()?;
        let state = TempDir::new()?;
        let docs = repo.path().join("docs");
        std::fs::create_dir_all(&docs)?;
        let doomed = docs.join("deleted.md");
        std::fs::write(&doomed, "# Deleted\nSTALE_SEARCH_NEEDLE\n")?;
        let config = IndexConfig::with_overrides(
            repo.path(),
            Some(state.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        indexer.ensure_indexed_blocking()?;

        assert_eq!(indexer.search("STALE_SEARCH_NEEDLE", 5)?.len(), 1);

        std::fs::remove_file(&doomed)?;

        assert!(indexer.search("STALE_SEARCH_NEEDLE", 5)?.is_empty());
        Ok(())
    }
}

#[cfg(test)]
mod snippet_integrity_tests {
    use super::{line_safe_snippet_for_fragment, line_safe_snippet_from_lines, MAX_SNIPPET_CHARS};

    #[test]
    fn line_safe_snippet_from_fragment_returns_full_line() {
        let body = "alpha beta\ngamma delta\nepsilon zeta\n";
        let fragment = "mma del";
        let (snippet, truncated, start, end) =
            line_safe_snippet_for_fragment(body, fragment, MAX_SNIPPET_CHARS).expect("snippet");
        assert_eq!(snippet, "gamma delta");
        assert!(!truncated);
        assert_eq!(start, 2);
        assert_eq!(end, 2);
    }

    #[test]
    fn line_safe_snippet_does_not_cut_lines_on_budget() {
        let lines = vec![
            (1, "alpha beta".to_string()),
            (2, "gamma delta".to_string()),
        ];
        let (snippet, truncated, start, end) = line_safe_snippet_from_lines(&lines, 12);
        assert_eq!(snippet, "alpha beta\n…");
        assert!(truncated);
        assert_eq!(start, Some(1));
        assert_eq!(end, Some(1));
    }
}

#[cfg(test)]
mod reindex_tests {
    use super::{IndexConfig, Indexer};
    use anyhow::Result;
    use std::fs;
    use tantivy::schema::{Schema, STORED, TEXT};
    use tantivy::{doc, Index};
    use tempfile::TempDir;

    fn write_repo(repo_root: &std::path::Path) -> Result<()> {
        fs::create_dir_all(repo_root)?;
        fs::write(repo_root.join("doc.md"), "# Fixture\n\nSCHEMA_TOKEN\n")?;
        Ok(())
    }

    fn create_incompatible_index(index_dir: &std::path::Path) -> Result<()> {
        fs::create_dir_all(index_dir)?;
        let mut builder = Schema::builder();
        let title = builder.add_text_field("legacy_title", TEXT | STORED);
        let schema = builder.build();
        let index = Index::create_in_dir(index_dir, schema)?;
        let mut writer = index.writer(15_000_000)?;
        writer.add_document(doc!(title => "legacy"))?;
        writer.commit()?;
        Ok(())
    }

    #[test]
    fn with_config_auto_reindexes_stale_index() -> Result<()> {
        let repo = TempDir::new()?;
        write_repo(repo.path())?;
        let state_root = TempDir::new()?;
        let config = IndexConfig::with_overrides(
            repo.path(),
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let index_dir = config.state_dir().to_path_buf();
        create_incompatible_index(&index_dir)?;

        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        let hits = indexer.search("SCHEMA_TOKEN", 1)?;
        assert!(!hits.is_empty(), "expected hits after auto reindex");
        Ok(())
    }
}

#[cfg(test)]
mod repo_encryption_index_tests {
    use super::{IndexConfig, Indexer};
    use crate::repo_encryption::{
        RepoEncryptionConfig, RepoEncryptionMode, DEFAULT_REPO_ENCRYPTION_KEY_ENV,
    };
    use anyhow::Result;
    use std::fs;
    use tempfile::TempDir;
    use walkdir::WalkDir;

    const TEST_KEY: &str = "01234567890123456789012345678901";
    const OTHER_TEST_KEY: &str = "abcdefghijklmnopqrstuvwxyz123456";
    const SECRET_PHRASE: &str = "ULTRA_SECRET_PHRASE_FOR_STORED_FIELD_TEST";

    fn encrypted_index_config(
        repo_root: &std::path::Path,
        state_root: &std::path::Path,
    ) -> Result<IndexConfig> {
        encrypted_index_config_with_key_id(repo_root, state_root, None)
    }

    fn encrypted_index_config_with_key_id(
        repo_root: &std::path::Path,
        state_root: &std::path::Path,
        key_id: Option<&str>,
    ) -> Result<IndexConfig> {
        let mut repo_encryption = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            key_id: key_id.map(str::to_string),
            ..RepoEncryptionConfig::default()
        };
        repo_encryption.apply_defaults();
        Ok(IndexConfig::with_overrides(
            repo_root,
            Some(state_root.to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )?
        .with_repo_encryption(repo_encryption))
    }

    fn state_contains(path: &std::path::Path, needle: &[u8]) -> bool {
        WalkDir::new(path)
            .into_iter()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_type().is_file())
            .any(|entry| {
                fs::read(entry.path())
                    .map(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
                    .unwrap_or(false)
            })
    }

    fn copy_dir_all(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
        for entry in WalkDir::new(src) {
            let entry = entry?;
            let rel = entry.path().strip_prefix(src)?;
            let target = dst.join(rel);
            if entry.file_type().is_dir() {
                fs::create_dir_all(&target)?;
            } else {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(entry.path(), &target)?;
            }
        }
        Ok(())
    }

    #[test]
    fn encrypted_index_searches_without_plaintext_stored_body() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let repo = TempDir::new()?;
        fs::write(
            repo.path().join("doc.md"),
            format!("# Secret\n\n{SECRET_PHRASE} appears here.\n"),
        )?;
        let state_root = TempDir::new()?;
        let config = encrypted_index_config(repo.path(), state_root.path())?;
        let state_dir = config.state_dir().to_path_buf();
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;

        indexer.reindex_all_blocking()?;
        let hits = indexer.search(SECRET_PHRASE, 3)?;

        assert_eq!(hits.len(), 1);
        assert!(hits[0].snippet.contains(SECRET_PHRASE));
        assert!(
            !state_contains(&state_dir, SECRET_PHRASE.as_bytes()),
            "protected index state must not store the raw body phrase"
        );
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        Ok(())
    }

    #[test]
    fn encrypted_indexing_fails_closed_without_key_material() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        let repo = TempDir::new()?;
        fs::write(repo.path().join("doc.md"), SECRET_PHRASE)?;
        let state_root = TempDir::new()?;
        let config = encrypted_index_config(repo.path(), state_root.path())?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;

        let err = indexer
            .reindex_all_blocking()
            .expect_err("missing key must fail closed");
        assert!(err.to_string().contains("key material"));
        Ok(())
    }

    #[test]
    fn encrypted_index_search_fails_closed_after_key_removal() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let repo = TempDir::new()?;
        fs::write(repo.path().join("doc.md"), SECRET_PHRASE)?;
        let state_root = TempDir::new()?;
        let config = encrypted_index_config(repo.path(), state_root.path())?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        indexer.reindex_all_blocking()?;
        drop(indexer);

        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        let config = encrypted_index_config(repo.path(), state_root.path())?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        let err = indexer
            .search(SECRET_PHRASE, 3)
            .expect_err("removed key must fail closed");

        assert!(err.to_string().contains("key material"));
        Ok(())
    }

    #[test]
    fn encrypted_index_search_fails_closed_with_wrong_key_material() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let repo = TempDir::new()?;
        fs::write(repo.path().join("doc.md"), SECRET_PHRASE)?;
        let state_root = TempDir::new()?;
        let config =
            encrypted_index_config_with_key_id(repo.path(), state_root.path(), Some("stable-key"))?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        indexer.reindex_all_blocking()?;
        drop(indexer);

        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, OTHER_TEST_KEY);
        let config =
            encrypted_index_config_with_key_id(repo.path(), state_root.path(), Some("stable-key"))?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        let err = indexer
            .search(SECRET_PHRASE, 3)
            .expect_err("wrong key must fail closed");

        assert!(err.to_string().contains("cannot decrypt"));
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        Ok(())
    }

    #[test]
    fn encrypted_index_state_restore_preserves_authorized_search() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let repo = TempDir::new()?;
        fs::write(repo.path().join("doc.md"), SECRET_PHRASE)?;
        let state_root = TempDir::new()?;
        let config = encrypted_index_config(repo.path(), state_root.path())?;
        let state_dir = config.state_dir().to_path_buf();
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        indexer.reindex_all_blocking()?;
        drop(indexer);

        let backup_root = TempDir::new()?;
        let backup_config = encrypted_index_config(repo.path(), backup_root.path())?;
        let backup_state_dir = backup_config.state_dir().to_path_buf();
        copy_dir_all(&state_dir, &backup_state_dir)?;
        let restored = Indexer::with_config(repo.path().to_path_buf(), backup_config)?;
        let hits = restored.search(SECRET_PHRASE, 3)?;

        assert_eq!(hits.len(), 1);
        assert!(hits[0].snippet.contains(SECRET_PHRASE));
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        Ok(())
    }

    #[test]
    fn encrypted_index_state_cannot_be_reused_for_another_repository() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let source_repo = TempDir::new()?;
        fs::write(source_repo.path().join("doc.md"), SECRET_PHRASE)?;
        let source_state_root = TempDir::new()?;
        let source_config = encrypted_index_config(source_repo.path(), source_state_root.path())?;
        let source_state_dir = source_config.state_dir().to_path_buf();
        let source_indexer = Indexer::with_config(source_repo.path().to_path_buf(), source_config)?;
        source_indexer.reindex_all_blocking()?;
        drop(source_indexer);

        let other_repo = TempDir::new()?;
        fs::write(
            other_repo.path().join("doc.md"),
            "not the protected repository",
        )?;
        let other_state_root = TempDir::new()?;
        let other_config = encrypted_index_config(other_repo.path(), other_state_root.path())?;
        let other_state_dir = other_config.state_dir().to_path_buf();
        copy_dir_all(&source_state_dir, &other_state_dir)?;
        let other_indexer = Indexer::with_config(other_repo.path().to_path_buf(), other_config)?;
        let err = other_indexer
            .search(SECRET_PHRASE, 3)
            .expect_err("cross-repo encrypted state must fail closed");

        assert!(err.to_string().contains("cannot decrypt"));
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        Ok(())
    }
}

#[cfg(test)]
mod doc_type_tests {
    use super::{document_type_for_path, DocType, DocumentKind};

    #[test]
    fn doc_type_classifies_paths() {
        assert_eq!(
            document_type_for_path("docs/pdr/overview.md", DocumentKind::Doc),
            Some(DocType::Pdr)
        );
        assert_eq!(
            document_type_for_path("docs/sds/sds.md", DocumentKind::Doc),
            Some(DocType::Sds)
        );
        assert_eq!(
            document_type_for_path("openapi/mcoda.yaml", DocumentKind::Doc),
            Some(DocType::Openapi)
        );
        assert_eq!(
            document_type_for_path("src/main.rs", DocumentKind::Code),
            Some(DocType::Code)
        );
    }
}
