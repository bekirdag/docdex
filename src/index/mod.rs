use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use regex::Regex;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
use serde::{Deserialize, Serialize};
=======
use serde_json::json;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
use serde::{Deserialize, Serialize};
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
use serde::{Deserialize, Serialize};
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
use serde_json::json;
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
use serde::{Deserialize, Serialize};
use serde_json::json;
>>>>>>> mcoda/task/bck-05-us-08-t11
use std::cmp::Ordering;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Component, Path, PathBuf};
<<<<<<< HEAD
<<<<<<< HEAD
use std::sync::Arc;
<<<<<<< HEAD
use std::time::Duration;
=======
use std::time::{SystemTime, UNIX_EPOCH};
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
use std::sync::{
    atomic::{AtomicU64, Ordering as AtomicOrdering},
    Arc,
};
use serde::{Deserialize, Serialize};
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
use std::sync::{
    atomic::{AtomicUsize, Ordering as AtomicOrdering},
    Arc,
};
>>>>>>> mcoda/task/bck-05-us-08-t10
use tantivy::collector::TopDocs;
use tantivy::directory::error::LockError;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, FAST, STORED, STRING, TEXT};
use tantivy::DocAddress;
use tantivy::{
<<<<<<< HEAD
    doc, Document, Index, IndexReader, IndexWriter, ReloadPolicy, Searcher, SnippetGenerator,
=======
    doc, Document, Index, IndexReader, IndexWriter, ReloadPolicy, SnippetGenerator, TantivyError,
>>>>>>> mcoda/task/bck-05-us-09-t13
    Term,
};
<<<<<<< HEAD
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::warn;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
use crate::error::{AppError, ERR_BACKOFF_REQUIRED, ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX};
use crate::state_layout::{
    ensure_state_dir_secure, missing_repo_path_error, repo_state_mismatch_error, resolve_state_paths,
    StatePaths,
=======
=======
use serde_json::json;
>>>>>>> mcoda/task/bck-05-us-08-t10
use crate::error::{
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    repo_resolution_details, AppError, BackoffRequired, ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX,
    ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
>>>>>>> mcoda/task/bck-05-us-09-t07
=======
use uuid::Uuid;

use crate::error::{
<<<<<<< HEAD
    repo_resolution_details, AppError, ERR_BACKOFF_REQUIRED, ERR_INVALID_ARGUMENT,
    ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX,
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
    repo_resolution_details, retry_hint_details, AppError, DEFAULT_BACKOFF_RETRY_AFTER_MS,
    ERR_BACKOFF_REQUIRED, ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH,
    ERR_REPO_STATE_MISMATCH,
>>>>>>> mcoda/task/bck-05-us-09-t28
=======
    backoff_retry_details, repo_resolution_details, AppError, DEFAULT_BACKOFF_RETRY_AFTER_MS,
    ERR_BACKOFF_REQUIRED, ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH,
    ERR_REPO_STATE_MISMATCH,
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
    index_state_error, repo_resolution_details, AppError, IndexState, ERR_BACKOFF_REQUIRED,
    ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
    backoff_required_details, repo_resolution_details, AppError, ERR_BACKOFF_REQUIRED,
    ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
>>>>>>> mcoda/task/bck-05-us-09-t37
=======
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
    repo_resolution_details, AppError, ERR_BACKOFF_REQUIRED, ERR_INTERNAL_ERROR,
    ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
    ERR_STALE_INDEX,
>>>>>>> mcoda/task/bck-05-us-08-t11
};
use crate::state_paths::{default_state_base_dir, RepoStatePaths, StatePaths};
=======
use crate::error::{
<<<<<<< HEAD
    repo_resolution_details, AppError, BackoffRequired, ERR_INVALID_ARGUMENT,
    ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
=======
    repo_resolution_details, AppError, BackoffRequired, ERR_INVALID_ARGUMENT, ERR_MISSING_INDEX,
    ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH,
>>>>>>> mcoda/task/bck-05-us-09-t22
};
use crate::max_size::{
    truncate_utf8_chars, MAX_SNIPPET_CHARS, MAX_SUMMARY_CHARS, MAX_SUMMARY_SEGMENTS,
};
>>>>>>> mcoda/task/bck-05-us-10-t25
use crate::symbols;
<<<<<<< HEAD
use crate::symbols::{SymbolOutcome, SymbolOutcomeStatus, SymbolsStore};
use thiserror::Error;
use tracing::warn;
<<<<<<< HEAD
=======
use crate::symbols::{SymbolOutcomeStatus, SymbolsStore};
>>>>>>> mcoda/task/bck-05-us-10-t04
=======
use crate::error::{
    repo_resolution_details, AppError, ERR_BACKOFF_REQUIRED, ERR_INVALID_ARGUMENT,
    ERR_MISSING_INDEX, ERR_MISSING_REPO_PATH, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX,
};
use crate::symbols;
use crate::symbols::{SymbolOutcome, SymbolOutcomeStatus, SymbolsStore};
>>>>>>> mcoda/task/bck-05-us-08-t06
use walkdir::WalkDir;

const MAX_INDEX_RAM_BYTES: usize = 50 * 1024 * 1024;
<<<<<<< HEAD
const INDEX_STATE_FILENAME: &str = "index_state.json";
const INDEX_STATE_VERSION: u32 = 1;
=======
const INDEX_WRITER_BACKOFF_MS: u64 = 1000;
>>>>>>> mcoda/task/bck-05-us-09-t13
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
<<<<<<< HEAD
pub(crate) const MAX_SUMMARY_CHARS: usize = 360;
const MAX_SUMMARY_SEGMENTS: usize = 4;
pub(crate) const MAX_SNIPPET_CHARS: usize = 420;
=======
>>>>>>> mcoda/task/bck-05-us-10-t25
const FALLBACK_PREVIEW_LINES: usize = 60;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
pub const RUN_SUMMARY_DEFAULT_LIMIT: usize = 5;
pub const RUN_SUMMARY_MAX_LIMIT: usize = 20;
const RUN_SUMMARY_MAX_SKIP_SAMPLES: usize = 25;
const RUN_SUMMARY_MAX_ERROR_SAMPLES: usize = 25;
const RUN_SUMMARY_MAX_ERROR_CHARS: usize = 240;
const RUN_HISTORY_FILENAME: &str = "run_summaries.json";
const RUN_HISTORY_SCHEMA_VERSION: u32 = 1;
const SYMBOL_ERROR_SUMMARY_MAX_CHARS: usize = RUN_SUMMARY_MAX_ERROR_CHARS;
=======
const INDEX_STATE_FILENAME: &str = "index_state.json";
const INDEX_STATE_VERSION: u32 = 1;
const INDEX_STATE_CACHE_TTL_MS: u128 = 2000;
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
const INDEX_STATE_VERSION: u32 = 1;
const INDEX_STATE_FILENAME: &str = "index_state.json";
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
const INDEX_STATE_VERSION: u32 = 1;
const INDEX_STATE_FILENAME: &str = "docdex_index_state.json";
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
const INDEX_STATE_FILENAME: &str = "index_state.json";
const INDEX_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum IndexStateStatus {
    Ready,
    Stale,
}

impl IndexStateStatus {
    fn as_str(&self) -> &'static str {
        match self {
            IndexStateStatus::Ready => "ready",
            IndexStateStatus::Stale => "stale",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexStateFile {
    version: u32,
    status: IndexStateStatus,
    generation: u64,
    updated_at_epoch_ms: u64,
}

enum IndexStateOutcome {
    Ready(IndexStateFile),
    Missing,
    Stale { reason: String },
}

#[derive(Clone)]
struct ReaderSnapshot {
    _reader: Arc<IndexReader>,
    searcher: Searcher,
}

impl ReaderSnapshot {
    fn new(reader: Arc<IndexReader>) -> Self {
        let searcher = reader.searcher();
        Self {
            _reader: reader,
            searcher,
        }
    }
}
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
const INDEX_STATE_FILENAME: &str = "index_state.json";
const MAX_INDEX_STATE_ERROR_BYTES: usize = 512;
>>>>>>> mcoda/task/bck-05-us-08-t11
=======
const INDEX_STATE_FILENAME: &str = "index_state.json";
const INDEX_STATE_VERSION: u32 = 1;
const MAX_PENDING_WRITES: usize = 256;
>>>>>>> mcoda/task/bck-05-us-08-t10
=======
const INDEX_STATE_FILENAME: &str = "index_state.json";
const INDEX_STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IndexStateFile {
    version: u32,
    last_indexed_epoch_ms: u64,
}
>>>>>>> mcoda/task/bck-05-us-08-t06

#[derive(Clone)]
pub struct IndexConfig {
<<<<<<< HEAD
    state_dir: PathBuf,
    repo_state_dir: PathBuf,
=======
    state_paths: StatePaths,
>>>>>>> mcoda/task/ops-01-us-03-t02
    excluded_dir_names: Vec<String>,
    excluded_relative_prefixes: Vec<String>,
    symbols_enabled: bool,
}

#[derive(Clone)]
pub struct Indexer {
    repo_root: PathBuf,
    config: IndexConfig,
    index: Index,
    reader: Arc<RwLock<Arc<IndexReader>>>,
    doc_id_field: tantivy::schema::Field,
    path_field: tantivy::schema::Field,
    body_field: tantivy::schema::Field,
    summary_field: tantivy::schema::Field,
    token_field: tantivy::schema::Field,
    index_state_preexisting: bool,
    writer: Option<Arc<Mutex<IndexWriter>>>,
    symbols_store: Option<SymbolsStore>,
<<<<<<< HEAD
<<<<<<< HEAD
    index_state_cache: Arc<Mutex<IndexStateCache>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexStateV1 {
    version: u32,
    last_indexed_epoch_ms: u128,
}

#[derive(Default)]
struct IndexStateCache {
    last_scan_epoch_ms: Option<u128>,
    last_repo_mtime_epoch_ms: Option<u128>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct IndexStateFile {
    version: u32,
    indexed_at_epoch_ms: u128,
=======
    generation: Arc<AtomicU64>,
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
    write_gate: Arc<WriteGate>,
    state_lock: Arc<Mutex<()>>,
}

struct WriteGate {
    semaphore: Arc<Semaphore>,
    pending: AtomicUsize,
    max_pending: usize,
}

struct WritePermit {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl WriteGate {
    fn new(max_pending: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(1)),
            pending: AtomicUsize::new(0),
            max_pending,
        }
    }

    async fn acquire(&self) -> Result<WritePermit> {
        let pending = self.pending.fetch_add(1, AtomicOrdering::SeqCst);
        if pending >= self.max_pending {
            self.pending.fetch_sub(1, AtomicOrdering::SeqCst);
            return Err(AppError::new(
                ERR_BACKOFF_REQUIRED,
                "index writer busy; retry later",
            )
            .with_details(json!({
                "pending_writes": pending,
                "max_pending_writes": self.max_pending,
                "recoverySteps": [
                    "Wait for the current indexing batch to finish, then retry.".to_string(),
                    "If another docdexd instance is indexing this repo, stop it and retry.".to_string()
                ]
            }))
            .into());
        }
        let permit = match self.semaphore.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(err) => {
                self.pending.fetch_sub(1, AtomicOrdering::SeqCst);
                return Err(anyhow!("index writer gate closed: {err}"));
            }
        };
        self.pending.fetch_sub(1, AtomicOrdering::SeqCst);
        Ok(WritePermit { _permit: permit })
    }
>>>>>>> mcoda/task/bck-05-us-08-t10
}

#[derive(Debug, serde::Serialize)]
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

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexStatus {
    NotStarted,
    Fresh,
    Stale,
    Missing,
}

#[derive(Debug, Default)]
struct RepoIndexSnapshot {
    indexable_files: u64,
    latest_mtime_ms: Option<u128>,
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
    pub index_status: IndexStatus,
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexRunType {
    Reindex,
    Ingest,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexSkipSample {
    pub path: String,
    pub reason: FileDecisionReason,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexErrorSample {
    pub path: String,
    pub error: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolsSkipSample {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolsErrorSample {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_summary: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SymbolsRunSummary {
    pub enabled: bool,
    pub store_ready: bool,
    pub ok: usize,
    pub skipped: usize,
    pub failed: usize,
    pub skipped_samples: Vec<SymbolsSkipSample>,
    pub skipped_truncated: bool,
    pub error_samples: Vec<SymbolsErrorSample>,
    pub errors_truncated: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct IndexRunSummary {
    pub run_type: IndexRunType,
    pub started_at_epoch_ms: u128,
    pub finished_at_epoch_ms: u128,
    pub files_seen: usize,
    pub files_indexed: usize,
    pub files_skipped: usize,
    pub read_errors: usize,
    pub skipped_samples: Vec<IndexSkipSample>,
    pub skipped_truncated: bool,
    pub error_samples: Vec<IndexErrorSample>,
    pub errors_truncated: bool,
    pub symbols: SymbolsRunSummary,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RunSummaryResponse {
    pub total: usize,
    pub limit: usize,
    pub runs: Vec<IndexRunSummary>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RunHistory {
    version: u32,
    #[serde(default)]
    runs: Vec<IndexRunSummary>,
=======
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexStateManifest {
    version: u32,
    index_last_updated_epoch_ms: u128,
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexStateFile {
    version: u32,
    indexed_at_epoch_ms: u64,
}

#[derive(Debug, Clone)]
pub struct IndexStateSnapshot {
    pub indexed_at_epoch_ms: u64,
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IndexStateStatus {
    Fresh,
    Stale,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexState {
    status: IndexStateStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_success_epoch_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_attempt_epoch_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

impl IndexState {
    fn fresh(epoch_ms: u128) -> Self {
        Self {
            status: IndexStateStatus::Fresh,
            last_success_epoch_ms: Some(epoch_ms),
            last_attempt_epoch_ms: Some(epoch_ms),
            last_error: None,
        }
    }

    fn missing() -> Self {
        Self {
            status: IndexStateStatus::Missing,
            last_success_epoch_ms: None,
            last_attempt_epoch_ms: None,
            last_error: None,
        }
    }
>>>>>>> mcoda/task/bck-05-us-08-t11
=======
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct IndexStateFile {
    #[serde(default = "default_index_state_version")]
    version: u32,
    #[serde(default)]
    created_at_epoch_ms: u128,
    #[serde(default)]
    last_indexed_epoch_ms: Option<u128>,
    #[serde(default)]
    stale: bool,
    #[serde(default)]
    stale_reason: Option<String>,
    #[serde(default)]
    stale_since_epoch_ms: Option<u128>,
    #[serde(default)]
    stale_events_dropped: Option<u64>,
}

fn default_index_state_version() -> u32 {
    INDEX_STATE_VERSION
}

impl IndexStateFile {
    fn new(now: u128) -> Self {
        Self {
            version: INDEX_STATE_VERSION,
            created_at_epoch_ms: now,
            last_indexed_epoch_ms: None,
            stale: false,
            stale_reason: None,
            stale_since_epoch_ms: None,
            stale_events_dropped: None,
        }
    }
>>>>>>> mcoda/task/bck-05-us-08-t10
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
        let state_paths = resolve_state_paths(repo_root, state_dir)?;
<<<<<<< HEAD
        state_paths.log_if_unexpected();
        let state_dir = state_paths.index_dir().to_path_buf();
        let repo_state_dir = state_paths.repo_state_dir().to_path_buf();
=======
        state_paths.ensure_dirs()?;
>>>>>>> mcoda/task/ops-01-us-03-t02
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
        if let Ok(rel_state) = state_paths.index_dir().strip_prefix(repo_root) {
            let normalized = normalize_prefix(rel_state.to_string_lossy().as_ref());
            if !normalized.is_empty() && !excluded_relative_prefixes.contains(&normalized) {
                excluded_relative_prefixes.push(normalized);
            }
        }
        if let Ok(rel_state) = state_paths.repo_root().strip_prefix(repo_root) {
            let normalized = normalize_prefix(rel_state.to_string_lossy().as_ref());
            if !normalized.is_empty() && !excluded_relative_prefixes.contains(&normalized) {
                excluded_relative_prefixes.push(normalized);
            }
        }
        Ok(Self {
<<<<<<< HEAD
            state_dir,
            repo_state_dir,
=======
            state_paths,
>>>>>>> mcoda/task/ops-01-us-03-t02
            excluded_dir_names,
            excluded_relative_prefixes,
            symbols_enabled,
        })
    }

    pub fn state_dir(&self) -> &Path {
        self.state_paths.index_dir()
    }

    pub fn repo_state_dir(&self) -> &Path {
        self.state_paths.repo_root()
    }

    pub fn state_paths(&self) -> &StatePaths {
        &self.state_paths
    }

    pub fn repo_state_dir(&self) -> &Path {
        &self.repo_state_dir
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

<<<<<<< HEAD
pub fn clamp_run_summary_limit(limit: Option<usize>) -> usize {
    limit
        .unwrap_or(RUN_SUMMARY_DEFAULT_LIMIT)
        .clamp(1, RUN_SUMMARY_MAX_LIMIT)
=======
fn index_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(INDEX_STATE_FILENAME)
}

fn now_epoch_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}

fn read_index_state(state_dir: &Path) -> Result<Option<IndexStateFile>> {
    let path = index_state_path(state_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let parsed: IndexStateFile =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    Ok(Some(parsed))
}

fn write_index_state(state_dir: &Path, state: IndexStateFile) -> Result<()> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create {}", state_dir.display()))?;
    let path = index_state_path(state_dir);
    let bytes = serde_json::to_vec_pretty(&state).context("serialize index state")?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(&tmp, &path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn update_index_state(state_dir: &Path) -> Result<()> {
    let indexed_at_epoch_ms = now_epoch_ms()?;
    write_index_state(
        state_dir,
        IndexStateFile {
            version: INDEX_STATE_VERSION,
            indexed_at_epoch_ms,
        },
    )
}

fn latest_repo_modification_epoch_ms(repo_root: &Path, config: &IndexConfig) -> Option<u128> {
    let mut latest: Option<u128> = None;
    for entry in WalkDir::new(repo_root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !should_index(path, repo_root, config) {
            continue;
        }
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                    let millis = dur.as_millis();
                    if latest.map(|current| millis > current).unwrap_or(true) {
                        latest = Some(millis);
                    }
                }
            }
        }
    }
    latest
}

fn index_state_remediation_steps(repo_root: &Path) -> Vec<String> {
    let repo_display = repo_root.display();
    vec![
        format!(
            "Run `docdexd index --repo {repo_display}` to build the index."
        ),
        "For MCP clients: call `docdex_index` with no paths to rebuild the index.".to_string(),
    ]
}

fn index_state_error_details(
    repo_root: &Path,
    state_dir: &Path,
    hint: String,
    indexed_at_epoch_ms: Option<u128>,
    repo_last_modified_epoch_ms: Option<u128>,
    reason: Option<String>,
) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert(
        "repoRoot".to_string(),
        serde_json::Value::String(repo_root.display().to_string()),
    );
    details.insert(
        "stateDir".to_string(),
        serde_json::Value::String(state_dir.display().to_string()),
    );
    details.insert("hint".to_string(), serde_json::Value::String(hint));
    if let Some(indexed_at) = indexed_at_epoch_ms {
        details.insert("indexedAtEpochMs".to_string(), json!(indexed_at));
    }
    if let Some(repo_last_modified) = repo_last_modified_epoch_ms {
        details.insert(
            "repoLastModifiedEpochMs".to_string(),
            json!(repo_last_modified),
        );
    }
    if let Some(reason) = reason {
        details.insert("reason".to_string(), serde_json::Value::String(reason));
    }
    details.insert(
        "recoverySteps".to_string(),
        serde_json::Value::Array(
            index_state_remediation_steps(repo_root)
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
    serde_json::Value::Object(details)
}

fn missing_index_error(repo_root: &Path, state_dir: &Path) -> AppError {
    let hint = "Index is missing; build it before searching.".to_string();
    AppError::new(
        ERR_MISSING_INDEX,
        format!(
            "index not found at {}; run `docdexd index --repo {}`",
            state_dir.display(),
            repo_root.display()
        ),
    )
    .with_details(index_state_error_details(
        repo_root,
        state_dir,
        hint,
        None,
        None,
        None,
    ))
}

fn stale_index_error(
    repo_root: &Path,
    state_dir: &Path,
    indexed_at_epoch_ms: Option<u128>,
    repo_last_modified_epoch_ms: Option<u128>,
    reason: Option<String>,
) -> AppError {
    let hint = "Index is stale; re-run indexing before searching.".to_string();
    AppError::new(
        ERR_STALE_INDEX,
        format!(
            "index is stale; run `docdexd index --repo {}`",
            repo_root.display()
        ),
    )
    .with_details(index_state_error_details(
        repo_root,
        state_dir,
        hint,
        indexed_at_epoch_ms,
        repo_last_modified_epoch_ms,
        reason,
    ))
}

pub fn preflight_index_state(repo_root: &Path, config: &IndexConfig) -> Result<()> {
    let state_dir = config.state_dir();
    if !state_dir.exists() {
        return Err(missing_index_error(repo_root, state_dir).into());
    }
    let state = match read_index_state(state_dir) {
        Ok(Some(state)) => state,
        Ok(None) => return Err(missing_index_error(repo_root, state_dir).into()),
        Err(err) => {
            return Err(
                stale_index_error(
                    repo_root,
                    state_dir,
                    None,
                    None,
                    Some(err.to_string()),
                )
                .into(),
            );
        }
    };
    if state.version != INDEX_STATE_VERSION {
        return Err(
            stale_index_error(
                repo_root,
                state_dir,
                Some(state.indexed_at_epoch_ms),
                None,
                Some(format!(
                    "unsupported index state version {}; expected {}",
                    state.version, INDEX_STATE_VERSION
                )),
            )
            .into(),
        );
    }
    let repo_last_modified_epoch_ms = latest_repo_modification_epoch_ms(repo_root, config);
    if let Some(repo_last_modified) = repo_last_modified_epoch_ms {
        if repo_last_modified > state.indexed_at_epoch_ms {
            return Err(
                stale_index_error(
                    repo_root,
                    state_dir,
                    Some(state.indexed_at_epoch_ms),
                    Some(repo_last_modified),
                    None,
                )
                .into(),
            );
        }
    }
    Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t33
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
<<<<<<< HEAD
        ensure_state_dir_secure(config.repo_state_dir())?;
=======
        let state_dir_preexisting = state_dir_has_entries(config.state_dir());
>>>>>>> mcoda/task/bck-05-us-08-t11
        ensure_state_dir_secure(config.state_dir())?;
        let (schema, doc_id_field, path_field, body_field, summary_field, token_field) =
            build_schema();
        let index = Index::open_or_create(
            tantivy::directory::MmapDirectory::open(config.state_dir())?,
            schema.clone(),
        )?;
<<<<<<< HEAD
        let reader = Arc::new(
            index
                .reader_builder()
                .reload_policy(ReloadPolicy::Manual)
                .try_into()?,
        );
        let generation = Arc::new(AtomicU64::new(read_index_generation(config.state_dir())));
        let writer = index.writer(MAX_INDEX_RAM_BYTES)?;
=======
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        let writer = match index.writer(MAX_INDEX_RAM_BYTES) {
            Ok(writer) => writer,
            Err(err) => {
                if is_lock_busy(&err) {
                    return Err(index_writer_backoff_error().into());
                }
                return Err(err.into());
            }
        };
>>>>>>> mcoda/task/bck-05-us-09-t13
        let symbols_store = if config.symbols_enabled() {
            match SymbolsStore::new(&repo_root, config.repo_state_dir()) {
                Ok(store) => Some(store),
                Err(err) => {
                    warn!(target: "docdexd", error = ?err, "symbols store init failed; symbol extraction disabled for this run");
                    None
                }
            }
        } else {
            None
        };
        if let Err(err) = crate::repo_identity::record_repo_opened(&repo_root, config.state_dir()) {
            if let Some(identity) = err.downcast_ref::<crate::repo_identity::RepoIdentityError>() {
                return Err(repo_state_mismatch_error(&repo_root, Some(config.state_dir()), identity).into());
            }
            return Err(err).context("record repo identity metadata");
        }
        let indexer = Self {
            repo_root,
            config,
            index,
            reader: Arc::new(RwLock::new(reader)),
            doc_id_field,
            path_field,
            body_field,
            summary_field,
            token_field,
            index_state_preexisting: state_dir_preexisting,
            writer: Some(Arc::new(Mutex::new(writer))),
            symbols_store,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
            index_state_cache: Arc::new(Mutex::new(IndexStateCache::default())),
=======
            generation,
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
            write_gate: Arc::new(WriteGate::new(MAX_PENDING_WRITES)),
            state_lock: Arc::new(Mutex::new(())),
>>>>>>> mcoda/task/bck-05-us-08-t10
        })
=======
        };
        indexer.init_index_state()?;
        Ok(indexer)
>>>>>>> mcoda/task/bck-05-us-08-t11
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
<<<<<<< HEAD
<<<<<<< HEAD
=======
        let state_dir_preexisting = state_dir_has_entries(config.state_dir());
>>>>>>> mcoda/task/bck-05-us-08-t11
        if !config.state_dir().exists() {
<<<<<<< HEAD
<<<<<<< HEAD
            return Err(missing_index_error(
                &repo_root,
                config.state_dir(),
                &config.state_dir().join(INDEX_STATE_FILENAME),
                Some("state_dir_missing".to_string()),
            )
            .into());
=======
            return Err(missing_index_error(&repo_root, config.state_dir()).into());
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
            return Err(missing_index_error(&repo_root, config.state_dir()).into());
>>>>>>> mcoda/task/bck-05-us-08-t10
        }
=======
        ensure_index_state_ready(config.state_dir())?;
>>>>>>> mcoda/task/bck-05-us-08-t09
        let index = Index::open_in_dir(config.state_dir())?;
        let reader = Arc::new(
            index
                .reader_builder()
                .reload_policy(ReloadPolicy::Manual)
                .try_into()?,
        );
        let schema = index.schema();
        let doc_id_field = schema.get_field("doc_id").unwrap();
        let path_field = schema.get_field("rel_path").unwrap();
        let body_field = schema.get_field("body").unwrap();
        let summary_field = schema.get_field("summary").unwrap();
        let token_field = schema.get_field("token_estimate").unwrap();
        let symbols_store = if config.symbols_enabled() {
            SymbolsStore::new(&repo_root, config.repo_state_dir()).ok()
        } else {
            None
        };
        if let Err(err) = crate::repo_identity::validate_repo_state_dir(&repo_root, config.state_dir()) {
            if let Some(identity) = err.downcast_ref::<crate::repo_identity::RepoIdentityError>() {
                return Err(repo_state_mismatch_error(&repo_root, Some(config.state_dir()), identity).into());
            }
            return Err(err).context("validate repo identity metadata");
        }
        let generation = Arc::new(AtomicU64::new(read_index_generation(config.state_dir())));
        Ok(Self {
            repo_root,
            config,
            index,
            reader: Arc::new(RwLock::new(reader)),
            doc_id_field,
            path_field,
            body_field,
            summary_field,
            token_field,
            index_state_preexisting: state_dir_preexisting,
            writer: None,
            symbols_store,
<<<<<<< HEAD
<<<<<<< HEAD
            index_state_cache: Arc::new(Mutex::new(IndexStateCache::default())),
=======
            generation,
>>>>>>> mcoda/task/bck-05-us-08-t09
        })
    }

<<<<<<< HEAD
    async fn reindex_all_inner(&self, mut tracker: Option<&mut IndexRunTracker>) -> Result<()> {
=======
            write_gate: Arc::new(WriteGate::new(MAX_PENDING_WRITES)),
            state_lock: Arc::new(Mutex::new(())),
        })
    }

    pub async fn reindex_all(&self) -> Result<()> {
        let _write_guard = self.write_gate.acquire().await?;
>>>>>>> mcoda/task/bck-05-us-08-t10
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        writer.delete_all_documents()?;
        if let Some(store) = self.symbols_store.as_ref() {
            if let Err(err) = store.reset() {
                warn!(target: "docdexd", error = ?err, "failed to reset symbols store; continuing without clearing old symbols");
            }
        }
        let mut entries = Vec::new();
        for entry in WalkDir::new(&self.repo_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if let Some(tracker) = tracker.as_deref_mut() {
                tracker.record_seen();
            }
            let decision = decide_file(path, &self.repo_root, &self.config);
            if !decision.should_index() {
                if let Some(tracker) = tracker.as_deref_mut() {
                    tracker.record_skip(self.sample_path(path), decision.reason.clone());
                }
                continue;
            }
<<<<<<< HEAD
            let ingest = self.add_document(&mut writer, path)?;
            let outcome = self.maybe_update_symbols(&ingest);
            if let Some(tracker) = tracker.as_deref_mut() {
                tracker.record_indexed(&ingest);
                tracker.record_symbols(&ingest.rel_path, outcome);
            }
=======
            let rel = self.rel_path(path)?;
            entries.push((rel, path.to_path_buf()));
        }
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut symbols_budget = SymbolsBudget::new(symbols::MAX_SYMBOLS_PER_RUN);
        for (_rel, path) in entries {
            let ingest = self.add_document(&mut writer, &path)?;
            self.maybe_update_symbols(&ingest, Some(&mut symbols_budget));
>>>>>>> mcoda/task/bck-05-us-10-t05
        }
        writer.commit()?;
<<<<<<< HEAD
        self.reader.reload()?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.write_index_state(now_epoch_ms()?)?;
=======
        update_index_state(self.config.state_dir())?;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
        self.record_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
        self.write_index_state_now()?;
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
        self.commit_index_update()?;
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
        self.record_index_update(true);
>>>>>>> mcoda/task/bck-05-us-08-t10
=======
        self.record_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t06
        Ok(())
=======
    pub async fn reindex_all(&self) -> Result<()> {
        let result = (|| -> Result<()> {
            let writer_arc = self.writer()?;
            let mut writer = writer_arc.lock();
            writer.delete_all_documents()?;
            if let Some(store) = self.symbols_store.as_ref() {
                if let Err(err) = store.reset() {
                    warn!(target: "docdexd", error = ?err, "failed to reset symbols store; continuing without clearing old symbols");
                }
            }
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
        })();
        match result {
            Ok(()) => {
                if let Err(err) = self.record_index_success() {
                    warn!(target: "docdexd", error = ?err, "failed to record index success");
                }
                Ok(())
            }
            Err(err) => {
                self.record_index_failure(&err);
                Err(err)
            }
        }
>>>>>>> mcoda/task/bck-05-us-08-t11
    }

    pub async fn reindex_all(&self) -> Result<()> {
        self.reindex_all_inner(None).await
    }

    pub async fn reindex_all_with_summary(&self) -> Result<IndexRunSummary> {
        let mut tracker = IndexRunTracker::new(
            IndexRunType::Reindex,
            self.config.symbols_enabled(),
            self.symbols_store.is_some(),
        );
        self.reindex_all_inner(Some(&mut tracker)).await?;
        let summary = tracker.finish();
        if let Err(err) = record_run_summary(self.config.state_dir(), summary.clone()) {
            warn!(target: "docdexd", error = ?err, "failed to persist run summary");
        }
        Ok(summary)
    }

    pub async fn ingest_file(&self, file: PathBuf) -> Result<FileDecision> {
        let mut symbols_budget = SymbolsBudget::new(symbols::MAX_SYMBOLS_PER_RUN);
        self.ingest_file_with_budget(file, Some(&mut symbols_budget))
            .await
    }

    pub(crate) async fn ingest_file_with_budget(
        &self,
        file: PathBuf,
        budget: Option<&mut SymbolsBudget>,
    ) -> Result<FileDecision> {
        let path = file.canonicalize().context("resolve file")?;
        let decision = decide_file(&path, &self.repo_root, &self.config);
        if !decision.should_index() {
            return Ok(decision);
        }
<<<<<<< HEAD
<<<<<<< HEAD
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        let rel = self.rel_path(&path)?;
        let term = Term::from_field_text(self.doc_id_field, &rel);
        writer.delete_term(term);
        let ingest = self.add_document(&mut writer, &path)?;
<<<<<<< HEAD
        let _ = self.maybe_update_symbols(&ingest);
=======
        self.maybe_update_symbols(&ingest, budget);
>>>>>>> mcoda/task/bck-05-us-10-t05
        writer.commit()?;
<<<<<<< HEAD
        self.reader.reload()?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.write_index_state(now_epoch_ms()?)?;
=======
        update_index_state(self.config.state_dir())?;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
        self.record_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
        self.write_index_state_now()?;
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
        self.commit_index_update()?;
>>>>>>> mcoda/task/bck-05-us-08-t09
        Ok(decision)
    }

    pub async fn ingest_file_with_summary(
        &self,
        file: PathBuf,
    ) -> Result<(FileDecision, IndexRunSummary)> {
        let mut tracker = IndexRunTracker::new(
            IndexRunType::Ingest,
            self.config.symbols_enabled(),
            self.symbols_store.is_some(),
        );
        let path = file.canonicalize().context("resolve file")?;
        tracker.record_seen();
        let decision = decide_file(&path, &self.repo_root, &self.config);
        if !decision.should_index() {
            tracker.record_skip(self.sample_path(&path), decision.reason.clone());
            let summary = tracker.finish();
            if let Err(err) = record_run_summary(self.config.state_dir(), summary.clone()) {
                warn!(target: "docdexd", error = ?err, "failed to persist run summary");
            }
            return Ok((decision, summary));
        }
=======
        let _write_guard = self.write_gate.acquire().await?;
>>>>>>> mcoda/task/bck-05-us-08-t10
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        let rel = self.rel_path(&path)?;
        let term = Term::from_field_text(self.doc_id_field, &rel);
        writer.delete_term(term);
        let ingest = self.add_document(&mut writer, &path)?;
        let outcome = self.maybe_update_symbols(&ingest);
        tracker.record_indexed(&ingest);
        tracker.record_symbols(&ingest.rel_path, outcome);
        writer.commit()?;
        self.reader.reload()?;
<<<<<<< HEAD
<<<<<<< HEAD
        let summary = tracker.finish();
        if let Err(err) = record_run_summary(self.config.state_dir(), summary.clone()) {
            warn!(target: "docdexd", error = ?err, "failed to persist run summary");
        }
        Ok((decision, summary))
=======
        let result = (|| -> Result<FileDecision> {
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
        })();
        match result {
            Ok(decision) => {
                if let Err(err) = self.record_index_success() {
                    warn!(target: "docdexd", error = ?err, "failed to record index success");
                }
                Ok(decision)
            }
            Err(err) => {
                self.record_index_failure(&err);
                Err(err)
            }
        }
>>>>>>> mcoda/task/bck-05-us-08-t11
=======
        self.record_index_update(false);
=======
        self.record_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t06
        Ok(decision)
>>>>>>> mcoda/task/bck-05-us-08-t10
    }

    pub async fn delete_file(&self, file: PathBuf) -> Result<()> {
        let rel = match self.rel_path(&file) {
            Ok(rel) => rel,
            Err(_) => return Ok(()),
        };
<<<<<<< HEAD
<<<<<<< HEAD
=======
        let _write_guard = self.write_gate.acquire().await?;
>>>>>>> mcoda/task/bck-05-us-08-t10
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        let term = Term::from_field_text(self.doc_id_field, &rel);
        writer.delete_term(term);
        writer.commit()?;
<<<<<<< HEAD
        self.reader.reload()?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.write_index_state(now_epoch_ms()?)?;
=======
        update_index_state(self.config.state_dir())?;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
        self.record_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
        self.write_index_state_now()?;
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
        self.commit_index_update()?;
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
        self.record_index_update(false);
>>>>>>> mcoda/task/bck-05-us-08-t10
        if let Some(store) = self.symbols_store.as_ref() {
            if let Err(err) = store.delete_symbols(&rel) {
                warn!(target: "docdexd", error = ?err, rel_path = %rel, "failed to delete symbols record");
=======
        let result = (|| -> Result<()> {
            let writer_arc = self.writer()?;
            let mut writer = writer_arc.lock();
            let term = Term::from_field_text(self.doc_id_field, &rel);
            writer.delete_term(term);
            writer.commit()?;
            self.reader.reload()?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                if let Some(store) = self.symbols_store.as_ref() {
                    if let Err(err) = store.delete_symbols(&rel) {
                        warn!(target: "docdexd", error = ?err, rel_path = %rel, "failed to delete symbols record");
                    }
                }
                if let Err(err) = self.record_index_success() {
                    warn!(target: "docdexd", error = ?err, "failed to record index success");
                }
                Ok(())
            }
            Err(err) => {
                self.record_index_failure(&err);
                Err(err)
>>>>>>> mcoda/task/bck-05-us-08-t11
            }
        }
<<<<<<< HEAD
=======
        self.record_index_state()?;
        Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t06
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
        self.ensure_index_fresh()?;
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
<<<<<<< HEAD
        self.ensure_index_ready()?;
<<<<<<< HEAD
        let snapshot = self.snapshot();
        let searcher = &snapshot.searcher;
=======
=======
        self.ensure_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t06
        let searcher = self.reader.searcher();
>>>>>>> mcoda/task/bck-05-us-08-t10
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
            SnippetGenerator::create(searcher, tantivy_query.as_ref(), self.body_field).ok();
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

    fn fetch_document(&self, searcher: &Searcher, doc_id: &str) -> Result<Option<Document>> {
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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    pub fn repo_state_dir(&self) -> &Path {
        self.config.repo_state_dir()
=======
    fn index_state_path(&self) -> PathBuf {
        self.config.state_dir().join(INDEX_STATE_FILENAME)
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
    fn snapshot(&self) -> ReaderSnapshot {
        let reader = self.reader.read().clone();
        ReaderSnapshot::new(reader)
>>>>>>> mcoda/task/bck-05-us-08-t09
=======
=======
>>>>>>> mcoda/task/bck-05-us-08-t06
    fn index_state_path(&self) -> PathBuf {
        self.config.state_dir().join(INDEX_STATE_FILENAME)
    }

    fn load_index_state(&self) -> Option<IndexStateFile> {
<<<<<<< HEAD
        let path = self.index_state_path();
        let raw = match fs::read(&path) {
            Ok(raw) => raw,
            Err(err) => {
                if err.kind() != io::ErrorKind::NotFound {
                    warn!(target: "docdexd", error = ?err, path = %path.display(), "failed to read index state");
                }
                return None;
            }
        };
        match serde_json::from_slice::<IndexStateFile>(&raw) {
            Ok(state) => Some(state),
            Err(err) => {
                warn!(target: "docdexd", error = ?err, path = %path.display(), "failed to parse index state");
                None
            }
        }
    }

    fn write_index_state(&self, state: &IndexStateFile) -> Result<()> {
        let _guard = self.state_lock.lock();
        let path = self.index_state_path();
        let tmp_path = path.with_file_name(format!("{INDEX_STATE_FILENAME}.tmp"));
        let payload = serde_json::to_vec_pretty(state)?;
        fs::write(&tmp_path, payload)?;
        fs::rename(&tmp_path, &path)?;
        Ok(())
    }

    fn record_index_update(&self, clear_stale: bool) {
        let now = now_epoch_ms();
        let mut state = self
            .load_index_state()
            .unwrap_or_else(|| IndexStateFile::new(now));
        state.version = INDEX_STATE_VERSION;
        state.last_indexed_epoch_ms = Some(now);
        if clear_stale {
            state.stale = false;
            state.stale_reason = None;
            state.stale_since_epoch_ms = None;
            state.stale_events_dropped = None;
        }
        if let Err(err) = self.write_index_state(&state) {
            warn!(target: "docdexd", error = ?err, "failed to persist index state");
        }
    }

    pub(crate) fn mark_stale(&self, reason: &str, dropped: Option<u64>) -> Result<()> {
        let now = now_epoch_ms();
        let mut state = self
            .load_index_state()
            .unwrap_or_else(|| IndexStateFile::new(now));
        state.version = INDEX_STATE_VERSION;
        state.stale = true;
        state.stale_reason = Some(reason.to_string());
        state.stale_since_epoch_ms = Some(now);
        state.stale_events_dropped = dropped;
        self.write_index_state(&state)
    }

    fn ensure_index_ready(&self) -> Result<()> {
        let stats = self.stats_unchecked()?;
        let state = self.load_index_state();
        if state.is_none() && stats.num_docs == 0 {
            return Err(missing_index_error(&self.repo_root, self.config.state_dir()).into());
        }
        if let Some(state) = state.as_ref() {
            if state.stale {
                return Err(
                    stale_index_error(&self.repo_root, self.config.state_dir(), state).into(),
                );
            }
        }
        Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t10
=======
        let raw = fs::read_to_string(self.index_state_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn record_index_state(&self) -> Result<()> {
        let payload = IndexStateFile {
            version: INDEX_STATE_VERSION,
            last_indexed_epoch_ms: now_epoch_ms_u64()?,
        };
        let raw = serde_json::to_string_pretty(&payload)?;
        fs::write(self.index_state_path(), raw)?;
        Ok(())
    }

    fn latest_repo_modified_epoch_ms(&self) -> Result<Option<u64>> {
        let mut latest: Option<u64> = None;
        for entry in WalkDir::new(&self.repo_root).into_iter() {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !decide_file(path, &self.repo_root, &self.config).should_index() {
                continue;
            }
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            let modified = match meta.modified() {
                Ok(modified) => modified,
                Err(_) => continue,
            };
            let ms = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let ms_u64 = ms.min(u128::from(u64::MAX)) as u64;
            latest = Some(latest.map_or(ms_u64, |current| current.max(ms_u64)));
        }
        Ok(latest)
    }

    fn latest_state_dir_modified_epoch_ms(&self) -> Option<u64> {
        let mut latest: Option<u64> = None;
        for entry in walkdir::WalkDir::new(self.config.state_dir()).into_iter().flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    let ms = modified
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis();
                    let ms_u64 = ms.min(u128::from(u64::MAX)) as u64;
                    latest = Some(latest.map_or(ms_u64, |current| current.max(ms_u64)));
                }
            }
        }
        latest
    }

    fn index_has_docs(&self) -> bool {
        let searcher = self.reader.searcher();
        for segment_reader in searcher.segment_readers() {
            let live_docs = segment_reader
                .alive_bitset()
                .map(|bits| bits.num_alive_docs() as u64)
                .unwrap_or_else(|| segment_reader.max_doc() as u64);
            if live_docs > 0 {
                return true;
            }
        }
        false
    }

    pub fn ensure_index_state(&self) -> Result<()> {
        let state = match self.load_index_state() {
            Some(state) => state,
            None => {
                if !self.index_has_docs() {
                    return Err(AppError::new(
                        ERR_MISSING_INDEX,
                        format!(
                            "index not ready; run `docdexd index --repo {}` or MCP `docdex_index`",
                            self.repo_root.display()
                        ),
                    )
                    .into());
                }
                let last_indexed_epoch_ms = self
                    .latest_state_dir_modified_epoch_ms()
                    .unwrap_or(now_epoch_ms_u64()?);
                let payload = IndexStateFile {
                    version: INDEX_STATE_VERSION,
                    last_indexed_epoch_ms,
                };
                let raw = serde_json::to_string_pretty(&payload)?;
                fs::write(self.index_state_path(), raw)?;
                payload
            }
        };
        if let Some(repo_latest) = self.latest_repo_modified_epoch_ms()? {
            if repo_latest > state.last_indexed_epoch_ms {
                return Err(AppError::new(
                    ERR_STALE_INDEX,
                    format!(
                        "index is stale; run `docdexd index --repo {}` or MCP `docdex_index`",
                        self.repo_root.display()
                    ),
                )
                .into());
            }
        }
        Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t06
    }

    fn writer(&self) -> Result<Arc<Mutex<IndexWriter>>> {
        self.writer
            .clone()
<<<<<<< HEAD
            .ok_or_else(|| {
                BackoffRequired::new(
<<<<<<< HEAD
<<<<<<< HEAD
                    Duration::from_secs(1),
                    "index_writer".to_string(),
                    "repo".to_string(),
=======
                    Duration::from_millis(0),
                    "index_writer".to_string(),
                    "index".to_string(),
=======
                    "index writer unavailable (another docdexd may be indexing); retry later",
                    "index_writer",
                    "repo",
>>>>>>> mcoda/task/bck-05-us-09-t07
                )
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
                .with_message(
                    "index writer unavailable (another docdexd may be indexing); retry later",
>>>>>>> mcoda/task/bck-05-us-09-t22
                )
                .with_message("index writer unavailable (another docdexd may be indexing); retry later")
=======
                .with_details(retry_hint_details(
                    DEFAULT_BACKOFF_RETRY_AFTER_MS,
                    "index_writer",
                    "repo",
                ))
>>>>>>> mcoda/task/bck-05-us-09-t28
=======
                .with_details(backoff_retry_details(DEFAULT_BACKOFF_RETRY_AFTER_MS))
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
                .with_details(backoff_required_details("index_writer", "repo"))
>>>>>>> mcoda/task/bck-05-us-09-t37
                .into()
            })
=======
            .ok_or_else(|| index_writer_backoff_error().into())
>>>>>>> mcoda/task/bck-05-us-09-t13
    }

    pub fn config(&self) -> &IndexConfig {
        &self.config
    }

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    pub fn symbols_store_ready(&self) -> bool {
        self.symbols_store.is_some()
=======
    pub fn ensure_index_fresh(&self) -> Result<()> {
        let state_dir = self.config.state_dir();
        let state_path = self.index_state_path();
        if !state_dir.exists() {
            return Err(missing_index_error(
                &self.repo_root,
                state_dir,
                &state_path,
                Some("state_dir_missing".to_string()),
            )
            .into());
        }
        let raw = match fs::read_to_string(&state_path) {
            Ok(raw) => raw,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(missing_index_error(
                    &self.repo_root,
                    state_dir,
                    &state_path,
                    Some("index_state_missing".to_string()),
                )
                .into());
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("read {}", state_path.display()));
            }
        };
        let state: IndexStateV1 = match serde_json::from_str(&raw) {
            Ok(state) => state,
            Err(err) => {
                return Err(stale_index_error(
                    &self.repo_root,
                    state_dir,
                    &state_path,
                    None,
                    None,
                    Some(format!("invalid index_state.json: {err}")),
                )
                .into());
            }
        };
        if state.version != INDEX_STATE_VERSION || state.last_indexed_epoch_ms == 0 {
            return Err(stale_index_error(
                &self.repo_root,
                state_dir,
                &state_path,
                Some(state.last_indexed_epoch_ms),
                None,
                Some("index_state_version_mismatch".to_string()),
            )
            .into());
        }
        let latest_repo_mtime = self.latest_repo_mtime_epoch_ms_cached()?;
        if let Some(latest) = latest_repo_mtime {
            if latest > state.last_indexed_epoch_ms {
                return Err(stale_index_error(
                    &self.repo_root,
                    state_dir,
                    &state_path,
                    Some(state.last_indexed_epoch_ms),
                    Some(latest),
                    Some("repo_changed_since_index".to_string()),
=======
    pub fn ensure_index_fresh(&self) -> Result<()> {
        let manifest = match read_index_state_manifest(self.config.state_dir()) {
            Ok(Some(manifest)) => manifest,
            Ok(None) => {
                return Err(index_state_error(
                    IndexState::Missing,
                    &self.repo_root,
                    self.config.state_dir(),
                    None,
                    None,
                    None,
                )
                .into())
            }
            Err(err) => {
                return Err(index_state_error(
                    IndexState::Missing,
                    &self.repo_root,
                    self.config.state_dir(),
                    None,
                    None,
                    Some(format!(
                        "index state unreadable; re-run `docdex_index` ({err})"
                    )),
                )
                .into())
            }
        };

        let repo_last_modified_epoch_ms = repo_last_modified_epoch_ms(&self.repo_root, &self.config)?;
        if let Some(repo_last_modified_epoch_ms) = repo_last_modified_epoch_ms {
            if repo_last_modified_epoch_ms > manifest.index_last_updated_epoch_ms {
                return Err(index_state_error(
                    IndexState::Stale,
                    &self.repo_root,
                    self.config.state_dir(),
                    Some(manifest.index_last_updated_epoch_ms),
                    Some(repo_last_modified_epoch_ms),
                    None,
>>>>>>> mcoda/task/bck-05-us-08-t31
                )
                .into());
            }
        }
        Ok(())
<<<<<<< HEAD
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
    pub fn preflight_index_state(&self) -> Result<()> {
        preflight_index_state(&self.repo_root, &self.config)
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
    }

    fn record_index_state(&self) -> Result<()> {
        let manifest = IndexStateManifest {
            version: INDEX_STATE_VERSION,
            index_last_updated_epoch_ms: now_epoch_ms()?,
        };
        write_index_state_manifest(self.config.state_dir(), &manifest)?;
        Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
    fn ensure_index_ready(&self) -> Result<()> {
        ensure_index_state_ready(self.config.state_dir())
    }

    fn next_generation(&self) -> u64 {
        self.generation
            .fetch_add(1, AtomicOrdering::SeqCst)
            .saturating_add(1)
    }

    fn commit_index_update(&self) -> Result<()> {
        let reader = Arc::new(
            self.index
                .reader_builder()
                .reload_policy(ReloadPolicy::Manual)
                .try_into()?,
        );
        let generation = self.next_generation();
        write_index_state(self.config.state_dir(), IndexStateStatus::Ready, generation)?;
        *self.reader.write() = reader;
        Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t09
    }

    pub fn stats(&self) -> Result<IndexStats> {
<<<<<<< HEAD
        self.ensure_index_ready()?;
<<<<<<< HEAD
        let snapshot = self.snapshot();
        let searcher = &snapshot.searcher;
=======
    fn init_index_state(&self) -> Result<()> {
        let state_path = index_state_path(self.config.state_dir());
        if state_path.exists() {
            return Ok(());
        }
        let mut last_success = None;
        if self.index_state_preexisting {
            last_success = index_last_updated_epoch_ms(self.config.state_dir())
                .or_else(|| now_epoch_ms().ok());
        }
        let state = match (self.index_state_preexisting, last_success) {
            (true, Some(epoch)) => IndexState::fresh(epoch),
            _ => IndexState::missing(),
        };
        write_index_state(self.config.state_dir(), &state)?;
        Ok(())
    }

    fn load_index_state(&self) -> Result<IndexState> {
        match read_index_state(self.config.state_dir()) {
            Ok(Some(state)) => return Ok(state),
            Ok(None) => {}
            Err(err) => {
                warn!(target: "docdexd", error = ?err, "failed to read index state; inferring from disk");
            }
        }
        if self.index_state_preexisting {
            if let Some(epoch) = index_last_updated_epoch_ms(self.config.state_dir())
                .or_else(|| now_epoch_ms().ok())
            {
                return Ok(IndexState::fresh(epoch));
            }
        }
        Ok(IndexState::missing())
    }

    fn ensure_index_fresh(&self) -> Result<()> {
        let state = self.load_index_state()?;
        match state.status {
            IndexStateStatus::Fresh => Ok(()),
            IndexStateStatus::Missing | IndexStateStatus::Stale => {
                Err(index_state_error(&self.repo_root, &state).into())
            }
        }
    }

    fn record_index_success(&self) -> Result<()> {
        let now = now_epoch_ms()?;
        let state = IndexState::fresh(now);
        write_index_state(self.config.state_dir(), &state)
    }

    fn record_index_failure(&self, err: &anyhow::Error) {
        if let Some(app) = err.downcast_ref::<AppError>() {
            if app.code == ERR_BACKOFF_REQUIRED {
                return;
            }
        }
        let mut state = match self.load_index_state() {
            Ok(state) => state,
            Err(load_err) => {
                warn!(target: "docdexd", error = ?load_err, "failed to load index state after update failure");
                return;
            }
        };
        if let Ok(epoch) = now_epoch_ms() {
            state.last_attempt_epoch_ms = Some(epoch);
        }
        state.last_error = Some(truncate_state_error(&err.to_string()));
        if state.last_success_epoch_ms.is_some() {
            state.status = IndexStateStatus::Stale;
        } else {
            state.status = IndexStateStatus::Missing;
        }
        if let Err(write_err) = write_index_state(self.config.state_dir(), &state) {
            warn!(target: "docdexd", error = ?write_err, "failed to record index failure state");
        }
    }

    pub fn stats(&self) -> Result<IndexStats> {
        self.ensure_index_fresh()?;
=======
        self.stats_unchecked()
    }

    fn stats_unchecked(&self) -> Result<IndexStats> {
>>>>>>> mcoda/task/bck-05-us-08-t10
=======
        self.ensure_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t06
        let searcher = self.reader.searcher();
>>>>>>> mcoda/task/bck-05-us-08-t11
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
<<<<<<< HEAD
        let last_updated_epoch_ms = index_last_updated_epoch_ms(&state_dir);
=======
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
        let repo_snapshot = Self::scan_repo_indexable(&self.repo_root, &self.config);
        let index_status =
            Self::resolve_index_status(&state_dir, num_docs, last_updated_epoch_ms, &repo_snapshot);
>>>>>>> mcoda/task/bck-05-us-08-t12
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
            index_status,
        })
    }

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    pub fn run_summaries(&self, limit: Option<usize>) -> Result<RunSummaryResponse> {
        let limit = clamp_run_summary_limit(limit);
        let history = load_run_history(self.config.state_dir());
        let total = history.runs.len();
        let runs = history.runs.into_iter().take(limit).collect();
        Ok(RunSummaryResponse { total, limit, runs })
=======
    fn latest_repo_mtime_epoch_ms_cached(&self) -> Result<Option<u128>> {
        let now = now_epoch_ms()?;
        {
            let cache = self.index_state_cache.lock();
            if let Some(last_scan) = cache.last_scan_epoch_ms {
                if now.saturating_sub(last_scan) < INDEX_STATE_CACHE_TTL_MS {
                    return Ok(cache.last_repo_mtime_epoch_ms);
                }
            }
        }
        let latest = self.latest_repo_mtime_epoch_ms()?;
        let mut cache = self.index_state_cache.lock();
        cache.last_scan_epoch_ms = Some(now);
        cache.last_repo_mtime_epoch_ms = latest;
        Ok(latest)
    }

    fn latest_repo_mtime_epoch_ms(&self) -> Result<Option<u128>> {
        let mut latest: Option<u128> = None;
        for entry in WalkDir::new(&self.repo_root).into_iter().flatten() {
=======
    pub fn index_state_path(&self) -> PathBuf {
        self.config.state_dir().join(INDEX_STATE_FILENAME)
    }

    pub fn read_index_state(&self) -> Result<Option<IndexStateSnapshot>> {
        let path = self.index_state_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw =
            fs::read_to_string(&path).with_context(|| format!("read index state {}", path.display()))?;
        let parsed: IndexStateFile =
            serde_json::from_str(&raw).context("parse index state json")?;
        if parsed.version != INDEX_STATE_VERSION {
            return Ok(None);
        }
        Ok(Some(IndexStateSnapshot {
            indexed_at_epoch_ms: parsed.indexed_at_epoch_ms,
        }))
    }

    fn write_index_state(&self, indexed_at_epoch_ms: u64) -> Result<()> {
        let path = self.index_state_path();
        let payload = IndexStateFile {
            version: INDEX_STATE_VERSION,
            indexed_at_epoch_ms,
        };
        let serialized =
            serde_json::to_string_pretty(&payload).context("serialize index state json")?;
        fs::write(&path, serialized)
            .with_context(|| format!("write index state {}", path.display()))?;
        Ok(())
    }

    fn write_index_state_now(&self) -> Result<()> {
        let now = now_epoch_ms_u64()?;
        self.write_index_state(now)
    }

    pub fn latest_repo_mtime_epoch_ms(&self) -> Result<Option<u64>> {
        let mut latest: Option<u64> = None;
        for entry in WalkDir::new(&self.repo_root).into_iter().filter_map(|e| e.ok()) {
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
    fn scan_repo_indexable(repo_root: &Path, config: &IndexConfig) -> RepoIndexSnapshot {
        let mut snapshot = RepoIndexSnapshot::default();
        for entry in WalkDir::new(repo_root).into_iter().flatten() {
>>>>>>> mcoda/task/bck-05-us-08-t12
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
<<<<<<< HEAD
            if !should_index(path, &self.repo_root, &self.config) {
                continue;
            }
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let Ok(modified) = meta.modified() else {
                continue;
            };
<<<<<<< HEAD
            let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) else {
                continue;
            };
            let millis = dur.as_millis();
            if latest.map(|current| millis > current).unwrap_or(true) {
                latest = Some(millis);
            }
=======
            let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) else {
                continue;
            };
            let ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
            latest = Some(latest.map_or(ms, |current| current.max(ms)));
>>>>>>> mcoda/task/bck-05-us-08-t30
        }
        Ok(latest)
    }

<<<<<<< HEAD
    fn write_index_state(&self, last_indexed_epoch_ms: u128) -> Result<()> {
        let state = IndexStateV1 {
            version: INDEX_STATE_VERSION,
            last_indexed_epoch_ms,
        };
        let bytes = serde_json::to_vec_pretty(&state).context("serialize index state")?;
        let path = self.index_state_path();
        let tmp = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
        fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        fs::rename(&tmp, &path)
            .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
        Ok(())
>>>>>>> mcoda/task/bck-05-us-08-t32
    }

=======
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
            if !should_index(path, repo_root, config) {
                continue;
            }
            snapshot.indexable_files = snapshot.indexable_files.saturating_add(1);
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                        let millis = dur.as_millis();
                        if snapshot
                            .latest_mtime_ms
                            .map(|current| millis > current)
                            .unwrap_or(true)
                        {
                            snapshot.latest_mtime_ms = Some(millis);
                        }
                    }
                }
            }
        }
        snapshot
    }

    fn resolve_index_status(
        state_dir: &Path,
        num_docs: u64,
        last_updated_epoch_ms: Option<u128>,
        repo_snapshot: &RepoIndexSnapshot,
    ) -> IndexStatus {
        if !state_dir.exists() {
            return IndexStatus::Missing;
        }
        if repo_snapshot.indexable_files == 0 {
            return IndexStatus::Fresh;
        }
        if num_docs == 0 {
            return IndexStatus::NotStarted;
        }
        if num_docs != repo_snapshot.indexable_files {
            return IndexStatus::Stale;
        }
        if let Some(repo_latest) = repo_snapshot.latest_mtime_ms {
            if let Some(index_latest) = last_updated_epoch_ms {
                if repo_latest > index_latest {
                    return IndexStatus::Stale;
                }
            } else {
                return IndexStatus::Stale;
            }
        }
        IndexStatus::Fresh
    }

>>>>>>> mcoda/task/bck-05-us-08-t12
    pub fn snapshot_with_snippet(
        &self,
        doc_id: &str,
        query: Option<&str>,
        fallback_lines: usize,
    ) -> Result<Option<(DocSnapshot, Option<SnippetResult>)>> {
<<<<<<< HEAD
<<<<<<< HEAD
        self.ensure_index_ready()?;
        let snapshot = self.snapshot();
        let Some(doc) = self.fetch_document(&snapshot.searcher, doc_id)? else {
=======
        self.ensure_index_fresh()?;
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t10
        let Some(doc) = self.fetch_document(doc_id)? else {
>>>>>>> mcoda/task/bck-05-us-08-t11
            return Ok(None);
        };
        let snapshot = self.snapshot_from_document(doc_id, &doc);
        let snippet = self.snippet_from_document(
            &snapshot.searcher,
            &doc,
            Some(&snapshot.rel_path),
            query,
            fallback_lines,
        )?;
        Ok(Some((snapshot, snippet)))
    }

    pub fn list_docs(&self, offset: usize, limit: usize) -> Result<(Vec<DocSnapshot>, u64)> {
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.ensure_index_ready()?;
        let snapshot = self.snapshot();
        let searcher = &snapshot.searcher;
=======
        self.ensure_index_fresh()?;
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t10
=======
        self.ensure_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t06
        let searcher = self.reader.searcher();
>>>>>>> mcoda/task/bck-05-us-08-t11
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

<<<<<<< HEAD
    fn sample_path(&self, path: &Path) -> String {
        self.rel_path(path)
            .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
    }

    fn maybe_update_symbols(&self, ingest: &DocumentIngest) -> Option<SymbolOutcome> {
=======
    fn maybe_update_symbols(&self, ingest: &DocumentIngest, mut budget: Option<&mut SymbolsBudget>) {
>>>>>>> mcoda/task/bck-05-us-10-t05
        let Some(store) = self.symbols_store.as_ref() else {
            return None;
        };

        let Some(language) = symbols::language_for_path(&ingest.rel_path) else {
            let outcome = SymbolOutcome {
                status: SymbolOutcomeStatus::Skipped,
                reason: Some("unsupported_language".to_string()),
                error_summary: None,
            };
            let payload = symbols::build_symbols_payload(
                store.repo_id(),
                &ingest.rel_path,
                Vec::new(),
<<<<<<< HEAD
                outcome.clone(),
=======
                symbols::build_symbol_outcome(
                    SymbolOutcomeStatus::Skipped,
                    Some("unsupported_language".to_string()),
                    None,
                    None,
                ),
>>>>>>> mcoda/task/bck-05-us-10-t04
            );
            if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
            }
            return Some(outcome);
        };

        if let Some(err) = ingest.read_error.as_ref() {
            let outcome = SymbolOutcome {
                status: SymbolOutcomeStatus::Failed,
                reason: Some(format!("read_failed ({})", language.as_str())),
                error_summary: Some(truncate_error_summary(
                    err,
                    SYMBOL_ERROR_SUMMARY_MAX_CHARS,
                )),
            };
            let payload = symbols::build_symbols_payload(
                store.repo_id(),
                &ingest.rel_path,
                Vec::new(),
<<<<<<< HEAD
<<<<<<< HEAD
                outcome.clone(),
=======
                SymbolOutcome {
                    status: SymbolOutcomeStatus::Failed,
                    reason: Some(format!("read_failed ({})", language.as_str())),
                    error_summary: Some(symbols::clamp_error_summary(err)),
                },
>>>>>>> mcoda/task/bck-05-us-10-t05
=======
                symbols::build_symbol_outcome(
                    SymbolOutcomeStatus::Failed,
                    Some(format!("read_failed ({})", language.as_str())),
                    Some(err.clone()),
                    Some(language),
                ),
>>>>>>> mcoda/task/bck-05-us-10-t04
            );
            if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
            }
            return Some(outcome);
        }

        if let Some(ref mut budget) = budget {
            if budget.is_exhausted() {
                let payload = symbols::build_symbols_payload(
                    store.repo_id(),
                    &ingest.rel_path,
                    Vec::new(),
                    SymbolOutcome {
                        status: SymbolOutcomeStatus::Skipped,
                        reason: Some("symbols_budget_exhausted".to_string()),
                        error_summary: None,
                    },
                );
                if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                    warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
                }
                return;
            }
        }

        match symbols::extract_symbols_best_effort(
            store.repo_id(),
            &ingest.rel_path,
            &ingest.content,
            language,
        ) {
<<<<<<< HEAD
            Ok(symbols) => {
                let outcome = SymbolOutcome {
                    status: SymbolOutcomeStatus::Ok,
                    reason: None,
                    error_summary: None,
                };
=======
            Ok(mut symbols) => {
                if let Some(ref mut budget) = budget {
                    let allowed = budget.take(symbols.len());
                    if allowed < symbols.len() {
                        symbols.truncate(allowed);
                    }
                }
>>>>>>> mcoda/task/bck-05-us-10-t05
                let payload = symbols::build_symbols_payload(
                    store.repo_id(),
                    &ingest.rel_path,
                    symbols,
<<<<<<< HEAD
                    outcome.clone(),
=======
                    symbols::build_symbol_outcome(
                        SymbolOutcomeStatus::Ok,
                        None,
                        None,
                        Some(language),
                    ),
>>>>>>> mcoda/task/bck-05-us-10-t04
                );
                if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                    warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
                }
                Some(outcome)
            }
            Err(err) => {
                let outcome = SymbolOutcome {
                    status: SymbolOutcomeStatus::Failed,
                    reason: Some(format!("extract_failed ({})", language.as_str())),
                    error_summary: Some(truncate_error_summary(
                        &err.to_string(),
                        SYMBOL_ERROR_SUMMARY_MAX_CHARS,
                    )),
                };
                let payload = symbols::build_symbols_payload(
                    store.repo_id(),
                    &ingest.rel_path,
                    Vec::new(),
<<<<<<< HEAD
<<<<<<< HEAD
                    outcome.clone(),
=======
                    SymbolOutcome {
                        status: SymbolOutcomeStatus::Failed,
                        reason: Some(format!("extract_failed ({})", language.as_str())),
                        error_summary: Some(symbols::clamp_error_summary(&err.to_string())),
                    },
>>>>>>> mcoda/task/bck-05-us-10-t05
=======
                    symbols::build_symbol_outcome(
                        SymbolOutcomeStatus::Failed,
                        Some(format!("extract_failed ({})", language.as_str())),
                        Some(err.to_string()),
                        Some(language),
                    ),
>>>>>>> mcoda/task/bck-05-us-10-t04
                );
                if let Err(err) = store.upsert_symbols(&ingest.rel_path, &payload) {
                    warn!(target: "docdexd", error = ?err, rel_path = %ingest.rel_path, "failed to persist symbols outcome");
                }
                Some(outcome)
            }
        }
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
        searcher: &Searcher,
        doc: &Document,
        rel_path_hint: Option<&str>,
        query: Option<&str>,
        fallback_lines: usize,
    ) -> Result<Option<SnippetResult>> {
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
                    SnippetGenerator::create(searcher, parsed.as_ref(), self.body_field)
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

<<<<<<< HEAD
struct IndexRunTracker {
    run_type: IndexRunType,
    started_at_epoch_ms: u128,
    files_seen: usize,
    files_indexed: usize,
    files_skipped: usize,
    read_errors: usize,
    skipped_samples: Vec<IndexSkipSample>,
    skipped_truncated: bool,
    error_samples: Vec<IndexErrorSample>,
    errors_truncated: bool,
    symbols: SymbolsRunTracker,
}

impl IndexRunTracker {
    fn new(run_type: IndexRunType, symbols_enabled: bool, symbols_store_ready: bool) -> Self {
        Self {
            run_type,
            started_at_epoch_ms: now_epoch_ms(),
            files_seen: 0,
            files_indexed: 0,
            files_skipped: 0,
            read_errors: 0,
            skipped_samples: Vec::new(),
            skipped_truncated: false,
            error_samples: Vec::new(),
            errors_truncated: false,
            symbols: SymbolsRunTracker::new(symbols_enabled, symbols_store_ready),
        }
    }

    fn record_seen(&mut self) {
        self.files_seen = self.files_seen.saturating_add(1);
    }

    fn record_skip(&mut self, path: String, reason: FileDecisionReason) {
        self.files_skipped = self.files_skipped.saturating_add(1);
        let sample = IndexSkipSample { path, reason };
        push_bounded(
            &mut self.skipped_samples,
            sample,
            &mut self.skipped_truncated,
            RUN_SUMMARY_MAX_SKIP_SAMPLES,
        );
    }

    fn record_indexed(&mut self, ingest: &DocumentIngest) {
        self.files_indexed = self.files_indexed.saturating_add(1);
        if let Some(err) = ingest.read_error.as_ref() {
            self.read_errors = self.read_errors.saturating_add(1);
            let sample = IndexErrorSample {
                path: ingest.rel_path.clone(),
                error: truncate_error_summary(err, RUN_SUMMARY_MAX_ERROR_CHARS),
            };
            push_bounded(
                &mut self.error_samples,
                sample,
                &mut self.errors_truncated,
                RUN_SUMMARY_MAX_ERROR_SAMPLES,
            );
        }
    }

    fn record_symbols(&mut self, path: &str, outcome: Option<SymbolOutcome>) {
        self.symbols.record(path, outcome);
    }

    fn finish(self) -> IndexRunSummary {
        IndexRunSummary {
            run_type: self.run_type,
            started_at_epoch_ms: self.started_at_epoch_ms,
            finished_at_epoch_ms: now_epoch_ms(),
            files_seen: self.files_seen,
            files_indexed: self.files_indexed,
            files_skipped: self.files_skipped,
            read_errors: self.read_errors,
            skipped_samples: self.skipped_samples,
            skipped_truncated: self.skipped_truncated,
            error_samples: self.error_samples,
            errors_truncated: self.errors_truncated,
            symbols: self.symbols.finish(),
        }
    }
}

struct SymbolsRunTracker {
    enabled: bool,
    store_ready: bool,
    ok: usize,
    skipped: usize,
    failed: usize,
    skipped_samples: Vec<SymbolsSkipSample>,
    skipped_truncated: bool,
    error_samples: Vec<SymbolsErrorSample>,
    errors_truncated: bool,
}

impl SymbolsRunTracker {
    fn new(enabled: bool, store_ready: bool) -> Self {
        Self {
            enabled,
            store_ready,
            ok: 0,
            skipped: 0,
            failed: 0,
            skipped_samples: Vec::new(),
            skipped_truncated: false,
            error_samples: Vec::new(),
            errors_truncated: false,
        }
    }

    fn record(&mut self, path: &str, outcome: Option<SymbolOutcome>) {
        let Some(outcome) = outcome else {
            return;
        };
        let SymbolOutcome {
            status,
            reason,
            error_summary,
        } = outcome;
        match status {
            SymbolOutcomeStatus::Ok => {
                self.ok = self.ok.saturating_add(1);
            }
            SymbolOutcomeStatus::Skipped => {
                self.skipped = self.skipped.saturating_add(1);
                let sample = SymbolsSkipSample {
                    path: path.to_string(),
                    reason,
                };
                push_bounded(
                    &mut self.skipped_samples,
                    sample,
                    &mut self.skipped_truncated,
                    RUN_SUMMARY_MAX_SKIP_SAMPLES,
                );
            }
            SymbolOutcomeStatus::Failed => {
                self.failed = self.failed.saturating_add(1);
                let sample = SymbolsErrorSample {
                    path: path.to_string(),
                    reason,
                    error_summary: error_summary
                        .as_deref()
                        .map(|value| truncate_error_summary(value, RUN_SUMMARY_MAX_ERROR_CHARS)),
                };
                push_bounded(
                    &mut self.error_samples,
                    sample,
                    &mut self.errors_truncated,
                    RUN_SUMMARY_MAX_ERROR_SAMPLES,
                );
            }
        }
    }

    fn finish(self) -> SymbolsRunSummary {
        SymbolsRunSummary {
            enabled: self.enabled,
            store_ready: self.store_ready,
            ok: self.ok,
            skipped: self.skipped,
            failed: self.failed,
            skipped_samples: self.skipped_samples,
            skipped_truncated: self.skipped_truncated,
            error_samples: self.error_samples,
            errors_truncated: self.errors_truncated,
        }
    }
}

fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn push_bounded<T>(vec: &mut Vec<T>, value: T, truncated: &mut bool, max: usize) {
    if vec.len() < max {
        vec.push(value);
    } else {
        *truncated = true;
    }
}

fn truncate_error_summary(input: &str, max_chars: usize) -> String {
    let (truncated, _) = truncate_to_limit(input, max_chars);
    truncated
}

fn run_history_path(state_dir: &Path) -> PathBuf {
    state_dir.join(RUN_HISTORY_FILENAME)
}

fn load_run_history(state_dir: &Path) -> RunHistory {
    let path = run_history_path(state_dir);
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return RunHistory {
                version: RUN_HISTORY_SCHEMA_VERSION,
                runs: Vec::new(),
            }
        }
        Err(_) => {
            return RunHistory {
                version: RUN_HISTORY_SCHEMA_VERSION,
                runs: Vec::new(),
            }
        }
    };
    let mut history: RunHistory = serde_json::from_str(&data).unwrap_or_else(|_| RunHistory {
        version: RUN_HISTORY_SCHEMA_VERSION,
        runs: Vec::new(),
    });
    if history.version == 0 {
        history.version = RUN_HISTORY_SCHEMA_VERSION;
    }
    history
}

fn record_run_summary(state_dir: &Path, summary: IndexRunSummary) -> Result<()> {
    fs::create_dir_all(state_dir).with_context(|| format!("create {}", state_dir.display()))?;
    let mut history = load_run_history(state_dir);
    history.version = RUN_HISTORY_SCHEMA_VERSION;
    history.runs.insert(0, summary);
    if history.runs.len() > RUN_SUMMARY_MAX_LIMIT {
        history.runs.truncate(RUN_SUMMARY_MAX_LIMIT);
    }
    let payload = serde_json::to_string_pretty(&history).context("serialize run summary")?;
    fs::write(run_history_path(state_dir), payload)
        .with_context(|| format!("write {}", run_history_path(state_dir).display()))?;
    Ok(())
}

=======
#[derive(Debug)]
pub(crate) struct SymbolsBudget {
    remaining: usize,
}

impl SymbolsBudget {
    pub(crate) fn new(max_symbols: usize) -> Self {
        Self {
            remaining: max_symbols,
        }
    }

    fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }

    fn take(&mut self, requested: usize) -> usize {
        let allowed = self.remaining.min(requested);
        self.remaining = self.remaining.saturating_sub(allowed);
        allowed
    }
}

>>>>>>> mcoda/task/bck-05-us-10-t05
fn env_flag_enabled(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| matches!(v.trim().to_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false)
}

fn index_state_manifest_path(state_dir: &Path) -> PathBuf {
    state_dir.join(INDEX_STATE_FILENAME)
}

fn read_index_state_manifest(state_dir: &Path) -> Result<Option<IndexStateManifest>> {
    let path = index_state_manifest_path(state_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let manifest: IndexStateManifest =
        serde_json::from_str(&raw).context("parse index state manifest")?;
    Ok(Some(manifest))
}

fn write_index_state_manifest(state_dir: &Path, manifest: &IndexStateManifest) -> Result<()> {
    let path = index_state_manifest_path(state_dir);
    let payload = serde_json::to_vec(manifest).context("serialize index state manifest")?;
    fs::write(path, payload).context("write index state manifest")?;
    Ok(())
}

fn repo_last_modified_epoch_ms(
    repo_root: &Path,
    config: &IndexConfig,
) -> Result<Option<u128>> {
    let mut latest: Option<u128> = None;
    for entry in WalkDir::new(repo_root).into_iter().filter_map(|e| e.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !decide_file(path, repo_root, config).should_index() {
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        let Ok(modified) = meta.modified() else {
            continue;
        };
        let Ok(duration) = modified.duration_since(UNIX_EPOCH) else {
            continue;
        };
        let millis = duration.as_millis();
        if latest.map(|current| millis > current).unwrap_or(true) {
            latest = Some(millis);
        }
    }
    Ok(latest)
}

fn now_epoch_ms() -> Result<u128> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis())
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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "code")]
pub enum FileDecisionReason {
    OutsideRepo,
    StateDir,
    NotAFile,
    ExcludedPrefix { prefix: String },
    ExcludedDirName { name: String },
    MissingExtension,
    UnsupportedExtension { extension: String },
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
                return FileDecision::exclude(FileDecisionReason::ExcludedDirName { name: name_lower });
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

    FileDecision::include(FileDecisionReason::AllowedExtension { extension })
}

pub(crate) fn should_index(path: &Path, repo_root: &Path, config: &IndexConfig) -> bool {
    decide_file(path, repo_root, config).should_index()
}

fn now_epoch_ms_u64() -> Result<u64> {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    Ok(ms.min(u128::from(u64::MAX)) as u64)
}

#[cfg(test)]
mod file_decision_tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn decide_file_picks_longest_excluded_prefix() {
        let repo = TempDir::new().expect("temp repo");
        let state_root = TempDir::new().expect("temp state");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(state_root.path().to_path_buf()),
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
        let state_root = TempDir::new().expect("temp state");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
<<<<<<< HEAD
            Some(PathBuf::from(".docdex/index")),
=======
            Some(state_root.path().to_path_buf()),
>>>>>>> mcoda/task/ops-01-us-03-t02
            Vec::new(),
            Vec::new(),
            false,
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
        let state_root = TempDir::new().expect("temp state");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            false,
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
    fn decide_file_excludes_outside_repo() {
        let repo = TempDir::new().expect("temp repo");
        let state_root = TempDir::new().expect("temp state");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            false,
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
    fn decide_file_includes_supported_extensions() {
        let repo = TempDir::new().expect("temp repo");
        let state_root = TempDir::new().expect("temp state");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let config = IndexConfig::with_overrides(
            &repo_root,
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            false,
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
    }
}

<<<<<<< HEAD
#[cfg(test)]
mod state_path_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn resolve_state_paths_scopes_under_base_and_isolated() -> Result<()> {
        let base = TempDir::new()?;
        let shared_base = base.path().join("state");
        fs::create_dir_all(&shared_base)?;

        let repo_a = TempDir::new()?;
        let repo_b = TempDir::new()?;
        fs::create_dir_all(repo_a.path().join(".git"))?;
        fs::create_dir_all(repo_b.path().join(".git"))?;

        let paths_a = resolve_state_paths(repo_a.path(), Some(shared_base.clone()))?;
        let paths_b = resolve_state_paths(repo_b.path(), Some(shared_base.clone()))?;

        assert_ne!(paths_a.index_dir(), paths_b.index_dir());
        let expected_repos = shared_base.join("repos");
        assert!(paths_a.index_dir().starts_with(&expected_repos));
        assert!(paths_a.repo_state_dir().starts_with(&expected_repos));
        assert!(paths_b.index_dir().starts_with(&expected_repos));
        assert!(paths_b.repo_state_dir().starts_with(&expected_repos));
        Ok(())
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

<<<<<<< HEAD
fn state_dir_has_entries(path: &Path) -> bool {
    match fs::read_dir(path) {
        Ok(mut entries) => entries.next().is_some(),
        Err(_) => false,
    }
}

fn index_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(INDEX_STATE_FILENAME)
}

fn read_index_state(state_dir: &Path) -> Result<Option<IndexState>> {
    let path = index_state_path(state_dir);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };
    let state = serde_json::from_str(&raw)?;
    Ok(Some(state))
}

fn write_index_state(state_dir: &Path, state: &IndexState) -> Result<()> {
    let path = index_state_path(state_dir);
    let temp_path = path.with_extension("json.tmp");
    let payload = serde_json::to_vec_pretty(state)?;
    fs::write(&temp_path, payload)?;
    if let Err(err) = fs::rename(&temp_path, &path) {
        if path.exists() {
            let _ = fs::remove_file(&path);
        }
        fs::rename(&temp_path, &path).map_err(|_| err)?;
    }
    Ok(())
}

fn index_last_updated_epoch_ms(state_dir: &Path) -> Option<u128> {
    let mut last_updated_epoch_ms: Option<u128> = None;
    for entry in walkdir::WalkDir::new(state_dir).into_iter().flatten() {
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
    last_updated_epoch_ms
}

fn now_epoch_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}

fn truncate_state_error(message: &str) -> String {
    if message.len() <= MAX_INDEX_STATE_ERROR_BYTES {
        return message.to_string();
    }
    let mut end = MAX_INDEX_STATE_ERROR_BYTES;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = message[..end].to_string();
    out.push_str("…");
    out
=======
fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn json_u128(value: u128) -> serde_json::Value {
    serde_json::Value::Number(serde_json::Number::from(
        u64::try_from(value).unwrap_or(u64::MAX),
    ))
>>>>>>> mcoda/task/bck-05-us-08-t10
}

fn normalize_for_error(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
fn now_epoch_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}

fn index_state_recovery_steps() -> Vec<String> {
    vec![
        "Run: `docdexd index --repo <repo>` to build or refresh the index.".to_string(),
        "If using MCP, call `docdex_index` (or `docdex.index`) for a full reindex.".to_string(),
    ]
}

fn index_state_details(
    repo_root: &Path,
    state_dir: &Path,
    state_path: &Path,
    state: &str,
    last_indexed_epoch_ms: Option<u128>,
    latest_repo_mtime_epoch_ms: Option<u128>,
    reason: Option<String>,
) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert(
        "repoRoot".to_string(),
        serde_json::Value::String(normalize_for_error(repo_root)),
    );
    details.insert(
        "stateDir".to_string(),
        serde_json::Value::String(normalize_for_error(state_dir)),
    );
    details.insert(
        "indexStatePath".to_string(),
        serde_json::Value::String(normalize_for_error(state_path)),
    );
    details.insert(
        "state".to_string(),
        serde_json::Value::String(state.to_string()),
    );
    if let Some(last) = last_indexed_epoch_ms {
        details.insert(
            "lastIndexedEpochMs".to_string(),
            serde_json::Value::Number(serde_json::Number::from(last as u64)),
        );
    }
    if let Some(latest) = latest_repo_mtime_epoch_ms {
        details.insert(
            "latestRepoMtimeEpochMs".to_string(),
            serde_json::Value::Number(serde_json::Number::from(latest as u64)),
        );
    }
    if let Some(reason) = reason {
        details.insert("reason".to_string(), serde_json::Value::String(reason));
=======
fn index_recovery_steps(repo_root: &Path) -> Vec<String> {
    vec![format!("docdexd index --repo {}", repo_root.display())]
}

fn missing_index_error(repo_root: &Path, state_dir: &Path) -> AppError {
    AppError::new(
        ERR_MISSING_INDEX,
        "index missing; run `docdexd index --repo <repo>`",
    )
    .with_details(json!({
        "repo_root": normalize_for_error(repo_root),
        "state_dir": normalize_for_error(state_dir),
        "recoverySteps": index_recovery_steps(repo_root),
    }))
}

fn stale_index_error(repo_root: &Path, state_dir: &Path, state: &IndexStateFile) -> AppError {
    let mut details = serde_json::Map::new();
    details.insert(
        "repo_root".to_string(),
        serde_json::Value::String(normalize_for_error(repo_root)),
    );
    details.insert(
        "state_dir".to_string(),
        serde_json::Value::String(normalize_for_error(state_dir)),
    );
    if let Some(last) = state.last_indexed_epoch_ms {
        details.insert(
            "last_indexed_epoch_ms".to_string(),
            json_u128(last),
        );
    }
    if let Some(reason) = state.stale_reason.as_ref() {
        details.insert(
            "stale_reason".to_string(),
            serde_json::Value::String(reason.clone()),
        );
    }
    if let Some(since) = state.stale_since_epoch_ms {
        details.insert(
            "stale_since_epoch_ms".to_string(),
            json_u128(since),
        );
    }
    if let Some(dropped) = state.stale_events_dropped {
        details.insert(
            "stale_events_dropped".to_string(),
            serde_json::Value::Number(dropped.into()),
        );
>>>>>>> mcoda/task/bck-05-us-08-t10
    }
    details.insert(
        "recoverySteps".to_string(),
        serde_json::Value::Array(
<<<<<<< HEAD
            index_state_recovery_steps()
=======
            index_recovery_steps(repo_root)
>>>>>>> mcoda/task/bck-05-us-08-t10
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        ),
    );
<<<<<<< HEAD
    serde_json::Value::Object(details)
}

fn missing_index_error(
    repo_root: &Path,
    state_dir: &Path,
    state_path: &Path,
    reason: Option<String>,
) -> AppError {
    AppError::new(
        ERR_MISSING_INDEX,
        "index missing; run `docdexd index --repo <repo>` first",
    )
    .with_details(index_state_details(
        repo_root,
        state_dir,
        state_path,
        "missing",
        None,
        None,
        reason,
    ))
}

fn stale_index_error(
    repo_root: &Path,
    state_dir: &Path,
    state_path: &Path,
    last_indexed_epoch_ms: Option<u128>,
    latest_repo_mtime_epoch_ms: Option<u128>,
    reason: Option<String>,
) -> AppError {
    AppError::new(
        ERR_STALE_INDEX,
        "index is stale; re-run `docdexd index --repo <repo>`",
    )
    .with_details(index_state_details(
        repo_root,
        state_dir,
        state_path,
        "stale",
        last_indexed_epoch_ms,
        latest_repo_mtime_epoch_ms,
        reason,
    ))
=======
fn index_writer_backoff_details() -> serde_json::Value {
    json!({
        "retry_after_ms": INDEX_WRITER_BACKOFF_MS,
        "limit_key": "index_writer",
        "scope": "repo",
    })
}

fn index_writer_backoff_error() -> AppError {
    AppError::new(
        ERR_BACKOFF_REQUIRED,
        "index writer unavailable (another docdexd may be indexing); retry later",
    )
    .with_details(index_writer_backoff_details())
}

fn is_lock_busy(err: &TantivyError) -> bool {
    matches!(
        err,
        TantivyError::LockFailure(lock_err, _) if matches!(lock_err, LockError::LockBusy)
    )
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
fn index_state_error(repo_root: &Path, state: &IndexState) -> AppError {
    let remediation = match state.status {
        IndexStateStatus::Missing => "run `docdexd index --repo <repo>` to build a fresh index",
        IndexStateStatus::Stale => "run `docdexd index --repo <repo>` to refresh the index",
        IndexStateStatus::Fresh => "run `docdexd index --repo <repo>` to rebuild the index",
    };
    let message = match state.status {
        IndexStateStatus::Missing => format!("index missing; {remediation}"),
        IndexStateStatus::Stale => format!("index stale after failed update; {remediation}"),
        IndexStateStatus::Fresh => format!("index ready; {remediation}"),
    };
    let code = match state.status {
        IndexStateStatus::Missing => ERR_MISSING_INDEX,
        IndexStateStatus::Stale => ERR_STALE_INDEX,
        IndexStateStatus::Fresh => ERR_INTERNAL_ERROR,
    };
    let mut details = serde_json::Map::new();
    details.insert("indexState".to_string(), json!(state.status));
    details.insert(
        "repoRoot".to_string(),
        json!(normalize_for_error(repo_root)),
    );
    if let Some(value) = state.last_success_epoch_ms {
        details.insert("lastSuccessEpochMs".to_string(), json!(value));
    }
    if let Some(value) = state.last_attempt_epoch_ms {
        details.insert("lastAttemptEpochMs".to_string(), json!(value));
    }
    if let Some(value) = state.last_error.as_ref() {
        details.insert("lastError".to_string(), json!(value));
    }
    details.insert("remediation".to_string(), json!([remediation]));
    AppError::new(code, message).with_details(serde_json::Value::Object(details))
>>>>>>> mcoda/task/bck-05-us-08-t11
=======
    AppError::new(
        ERR_STALE_INDEX,
        "index stale; run `docdexd index --repo <repo>` to rebuild",
    )
    .with_details(serde_json::Value::Object(details))
>>>>>>> mcoda/task/bck-05-us-08-t10
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
    let meta_path = StatePaths::new(base_dir.to_path_buf()).repo_meta_path(&state_key);
    let raw = fs::read_to_string(&meta_path).ok()?;
    let parsed: serde_json::Value = serde_json::from_str(&raw).ok()?;
    parsed
        .get("canonical_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn index_state_details(state_dir: &Path, reason: Option<&str>) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert(
        "stateDir".to_string(),
        serde_json::Value::String(state_dir.display().to_string()),
    );
    if let Some(reason) = reason {
        details.insert(
            "reason".to_string(),
            serde_json::Value::String(reason.to_string()),
        );
    }
    details.insert(
        "recoverySteps".to_string(),
        serde_json::Value::Array(vec![
            serde_json::Value::String(
                "Run `docdexd index --repo <repo>` to build or refresh the index.".to_string(),
            ),
            serde_json::Value::String(
                "If you expect a different state directory, pass `--state-dir <path>` explicitly."
                    .to_string(),
            ),
        ]),
    );
    serde_json::Value::Object(details)
}

fn missing_index_error(state_dir: &Path) -> AppError {
    AppError::new(
        ERR_MISSING_INDEX,
        "index not initialized; run `docdexd index --repo <repo>` first",
    )
    .with_details(index_state_details(state_dir, None))
}

fn stale_index_error(state_dir: &Path, reason: String) -> AppError {
    AppError::new(
        ERR_STALE_INDEX,
        format!(
            "index is stale ({reason}); run `docdexd index --repo <repo>` to rebuild"
        ),
    )
    .with_details(index_state_details(state_dir, Some(&reason)))
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
    identity: &crate::repo_identity::RepoIdentityError,
) -> AppError {
    let attempted_fingerprint = crate::repo_identity::repo_fingerprint_sha256(repo_root).ok();
    let mut known_canonical_path = index_state_dir.and_then(known_canonical_path_from_repo_meta);
    if let crate::repo_identity::RepoIdentityError::CanonicalPathCollision { canonical_path, .. } = identity {
        known_canonical_path = Some(canonical_path.clone());
    }
    if let crate::repo_identity::RepoIdentityError::ReassociationRequired {
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

<<<<<<< HEAD
fn resolve_state_paths(repo_root: &Path, state_dir: Option<PathBuf>) -> Result<RepoStatePaths> {
=======
fn ensure_index_state_ready(state_dir: &Path) -> Result<()> {
    match read_index_state(state_dir) {
        IndexStateOutcome::Ready(_) => Ok(()),
        IndexStateOutcome::Missing => Err(missing_index_error(state_dir).into()),
        IndexStateOutcome::Stale { reason } => Err(stale_index_error(state_dir, reason).into()),
    }
}

fn read_index_generation(state_dir: &Path) -> u64 {
    match read_index_state(state_dir) {
        IndexStateOutcome::Ready(state) => state.generation,
        IndexStateOutcome::Stale { .. } => 0,
        IndexStateOutcome::Missing => 0,
    }
}

fn read_index_state(state_dir: &Path) -> IndexStateOutcome {
    if !state_dir.exists() {
        return IndexStateOutcome::Missing;
    }
    let path = state_dir.join(INDEX_STATE_FILENAME);
    if !path.exists() {
        return IndexStateOutcome::Missing;
    }
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) => {
            return IndexStateOutcome::Stale {
                reason: format!("failed to read index state: {err}"),
            }
        }
    };
    let parsed: IndexStateFile = match serde_json::from_str(&raw) {
        Ok(parsed) => parsed,
        Err(err) => {
            return IndexStateOutcome::Stale {
                reason: format!("invalid index state: {err}"),
            }
        }
    };
    if parsed.version != INDEX_STATE_VERSION {
        return IndexStateOutcome::Stale {
            reason: format!(
                "index state version mismatch (expected {INDEX_STATE_VERSION}, found {})",
                parsed.version
            ),
        };
    }
    if parsed.status != IndexStateStatus::Ready {
        return IndexStateOutcome::Stale {
            reason: format!("index state status {}", parsed.status.as_str()),
        };
    }
    IndexStateOutcome::Ready(parsed)
}

fn now_epoch_ms_u64() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

fn write_index_state(state_dir: &Path, status: IndexStateStatus, generation: u64) -> Result<()> {
    let state = IndexStateFile {
        version: INDEX_STATE_VERSION,
        status,
        generation,
        updated_at_epoch_ms: now_epoch_ms_u64(),
    };
    let payload = serde_json::to_string_pretty(&state)?;
    let path = state_dir.join(INDEX_STATE_FILENAME);
    write_atomic(&path, payload.as_bytes())
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("missing parent dir for {}", path.display()))?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("index_state.json");
    let tmp = parent.join(format!(".{}.{}.tmp", file_name, std::process::id()));
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

fn resolve_state_dir(repo_root: &Path, state_dir: Option<PathBuf>) -> Result<PathBuf> {
>>>>>>> mcoda/task/bck-05-us-08-t09
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
                return Ok(RepoStatePaths::legacy(custom));
            }
            let (base_dir, _, _) =
                crate::repo_identity::split_scoped_state_dir(&custom)
                    .unwrap_or_else(|| (custom.to_path_buf(), None, false));
            let index_dir = resolve_shared_index_dir(&repo_root, &custom)?;
            RepoStatePaths::scoped(base_dir, index_dir)
        }
        Some(custom) => Ok(RepoStatePaths::legacy(repo_root.join(custom))),
        None => {
            let base_dir = default_state_base_dir()?;
            let index_dir = resolve_shared_index_dir(repo_root, &base_dir)?;
            RepoStatePaths::scoped(base_dir, index_dir)
        }
    }
}

fn resolve_shared_index_dir(repo_root: &Path, custom_state_dir: &Path) -> Result<PathBuf> {
    let (base_dir, _, _) =
        crate::repo_identity::split_scoped_state_dir(custom_state_dir)
            .unwrap_or_else(|| (custom_state_dir.to_path_buf(), None, false));
    match crate::repo_identity::resolve_shared_index_state_dir(repo_root, custom_state_dir) {
        Ok(path) => Ok(path),
        Err(err) => {
            if let Some(identity) = err.downcast_ref::<crate::repo_identity::RepoIdentityError>() {
                let paths = StatePaths::new(base_dir.to_path_buf());
                let index_dir_hint = match identity {
                    crate::repo_identity::RepoIdentityError::StateMetaFingerprintMismatch { state_key, .. } => {
                        Some(paths.repo_index_dir(state_key))
                    }
                    crate::repo_identity::RepoIdentityError::StateKeyConflict {
                        existing_state_key,
                        ..
                    } => Some(paths.repo_index_dir(existing_state_key)),
                    _ => None,
                };
                return Err(
                    repo_state_mismatch_error(repo_root, index_dir_hint.as_deref(), identity).into(),
                );
            }
            Err(err)
        }
    }
}

=======
>>>>>>> mcoda/task/ops-01-us-03-t02
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

fn now_epoch_ms_u64() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64)
}

fn summarize(content: &str) -> String {
    let cleaned = strip_front_matter(content);
    let segments = collect_segments(cleaned, MAX_SUMMARY_SEGMENTS);
    if segments.is_empty() {
        let collapsed = collapse_whitespace(cleaned);
        let (truncated, was_truncated) = truncate_utf8_chars(&collapsed, MAX_SUMMARY_CHARS);
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
        let (truncated, was_truncated) = truncate_utf8_chars(&fallback, MAX_SUMMARY_CHARS);
        return if was_truncated { truncated } else { fallback };
    }
    let (truncated, was_truncated) = truncate_utf8_chars(&summary, MAX_SUMMARY_CHARS);
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
        let (truncated, _) = truncate_utf8_chars(&snippet, max_chars);
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
mod index_state_tests {
    use super::*;
    use crate::error::{AppError, ERR_MISSING_INDEX, ERR_STALE_INDEX};
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn search_errors_when_index_is_missing() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let file = repo_root.join("docs/readme.md");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "# Docdex\n").expect("write file");
        let config =
            IndexConfig::with_overrides(&repo_root, None, Vec::new(), Vec::new(), false).expect("config");
        let indexer = Indexer::with_config(repo_root, config).expect("indexer");

        let err = indexer
            .search_with_query_meta("docdex", 5)
            .expect_err("expected missing index error");
        let app = err.downcast_ref::<AppError>().expect("app error");
        assert_eq!(app.code, ERR_MISSING_INDEX);
    }

    #[test]
    fn search_errors_when_index_is_stale() {
        let repo = TempDir::new().expect("temp repo");
        let repo_root = repo.path().canonicalize().expect("canonical repo root");
        let file = repo_root.join("docs/readme.md");
        fs::create_dir_all(file.parent().expect("parent dir")).expect("mkdir");
        fs::write(&file, "# Docdex\n").expect("write file");
        let config =
            IndexConfig::with_overrides(&repo_root, None, Vec::new(), Vec::new(), false).expect("config");
        let indexer = Indexer::with_config(repo_root, config).expect("indexer");
        indexer
            .mark_stale("test_stale", Some(3))
            .expect("mark stale");

        let err = indexer
            .search_with_query_meta("docdex", 5)
            .expect_err("expected stale index error");
        let app = err.downcast_ref::<AppError>().expect("app error");
        assert_eq!(app.code, ERR_STALE_INDEX);
    }
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
