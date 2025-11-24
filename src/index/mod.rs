use anyhow::{anyhow, Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tantivy::collector::TopDocs;
use tantivy::query::{AllQuery, QueryParser};
use tantivy::schema::{Schema, FAST, STORED, STRING, TEXT};
use tantivy::{
    doc, Document, Index, IndexReader, IndexWriter, ReloadPolicy, SnippetGenerator, Term,
};
use tracing::warn;
use walkdir::WalkDir;

const MAX_INDEX_RAM_BYTES: usize = 50 * 1024 * 1024;
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
const MAX_SUMMARY_CHARS: usize = 360;
const MAX_SUMMARY_SEGMENTS: usize = 4;
const MAX_SNIPPET_CHARS: usize = 420;
const FALLBACK_PREVIEW_LINES: usize = 60;

#[derive(Clone)]
pub struct IndexConfig {
    state_dir: PathBuf,
    excluded_dir_names: Vec<String>,
    excluded_relative_prefixes: Vec<String>,
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
}

#[derive(Debug, serde::Serialize)]
pub struct Hit {
    pub doc_id: String,
    pub rel_path: String,
    pub score: f32,
    pub summary: String,
    pub snippet: String,
    pub token_estimate: u64,
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
}

#[derive(Debug, serde::Serialize)]
pub struct DocSnapshot {
    pub doc_id: String,
    pub rel_path: String,
    pub summary: String,
    pub token_estimate: u64,
}

impl IndexConfig {
    #[allow(dead_code)]
    pub fn for_repo(repo_root: &Path) -> Self {
        Self::with_overrides(repo_root, None, Vec::new(), Vec::new())
    }

    pub fn with_overrides(
        repo_root: &Path,
        state_dir: Option<PathBuf>,
        extra_excluded_dirs: Vec<String>,
        extra_excluded_prefixes: Vec<String>,
    ) -> Self {
        let state_dir = resolve_state_dir(repo_root, state_dir);
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
        Self {
            state_dir,
            excluded_dir_names,
            excluded_relative_prefixes,
        }
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
}

impl Indexer {
    #[allow(dead_code)]
    pub fn new(repo_root: PathBuf) -> Result<Self> {
        let repo_root = repo_root.canonicalize().context("resolve repo root")?;
        let config = IndexConfig::for_repo(&repo_root);
        Self::with_config(repo_root, config)
    }

    pub fn with_config(repo_root: PathBuf, config: IndexConfig) -> Result<Self> {
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
        })
    }

    pub fn with_config_read_only(repo_root: PathBuf, config: IndexConfig) -> Result<Self> {
        let repo_root = repo_root.canonicalize().context("resolve repo root")?;
        if !config.state_dir().exists() {
            return Err(anyhow!(
                "index not found at {}; run `docdexd index` first",
                config.state_dir().display()
            ));
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
        })
    }

    pub async fn reindex_all(&self) -> Result<()> {
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        writer.delete_all_documents()?;
        for entry in WalkDir::new(&self.repo_root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if !should_index(path, &self.repo_root, &self.config) {
                continue;
            }
            self.add_document(&mut writer, path)?;
        }
        writer.commit()?;
        self.reader.reload()?;
        Ok(())
    }

    pub async fn ingest_file(&self, file: PathBuf) -> Result<()> {
        let path = file.canonicalize().context("resolve file")?;
        if !should_index(&path, &self.repo_root, &self.config) {
            return Ok(());
        }
        let rel = self.rel_path(&path)?;
        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();
        let term = Term::from_field_text(self.doc_id_field, &rel);
        writer.delete_term(term);
        self.add_document(&mut writer, &path)?;
        writer.commit()?;
        self.reader.reload()?;
        Ok(())
    }

    pub fn search(&self, query: &str, limit: usize) -> Result<Vec<Hit>> {
        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(
            &self.index,
            vec![self.body_field, self.summary_field, self.path_field],
        );
        let tantivy_query = match parser.parse_query(query) {
            Ok(q) => q,
            Err(err) => {
                let sanitized = sanitize_query(query);
                if sanitized.trim().is_empty() {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        "query parse failed; using AllQuery fallback"
                    );
                    Box::new(AllQuery)
                } else {
                    match parser.parse_query(&sanitized) {
                        Ok(q) => {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                sanitized = %sanitized,
                                "query parse failed; using sanitized query"
                            );
                            q
                        }
                        Err(err2) => {
                            warn!(
                                target: "docdexd",
                                error = ?err2,
                                sanitized = %sanitized,
                                "sanitized query parse failed; using AllQuery fallback"
                            );
                            Box::new(AllQuery)
                        }
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
            let doc_id = retrieved
                .get_first(self.doc_id_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let rel_path = retrieved
                .get_first(self.path_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let summary = retrieved
                .get_first(self.summary_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let token_estimate = retrieved
                .get_first(self.token_field)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let snippet = snippet_generator
                .as_ref()
                .map(|gen| {
                    let snippet = gen.snippet_from_doc(&retrieved);
                    snippet.fragment().trim().to_string()
                })
                .filter(|snippet| !snippet.is_empty())
                .or_else(|| {
                    match self.preview_snippet(&rel_path, FALLBACK_PREVIEW_LINES) {
                        Ok(Some((text, _truncated))) => Some(text),
                        Ok(None) => None,
                        Err(err) => {
                            warn!(target: "docdexd", error = ?err, %rel_path, "failed to build fallback snippet");
                            None
                        }
                    }
                })
                .unwrap_or_else(|| summary.clone());
            results.push(Hit {
                doc_id,
                rel_path,
                score,
                summary,
                snippet,
                token_estimate,
            });
        }
        Ok(results)
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
    ) -> Result<Option<(String, bool)>> {
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
        let mut preview_lines = Vec::new();
        let mut truncated = false;
        for (idx, line_res) in reader.lines().enumerate() {
            if idx >= max_lines {
                truncated = true;
                break;
            }
            let line = line_res?;
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                preview_lines.push(trimmed.to_string());
            }
        }
        if preview_lines.is_empty() {
            return Ok(None);
        }
        let (snippet, snippet_truncated) = condense_snippet(&preview_lines, MAX_SNIPPET_CHARS);
        if snippet.is_empty() {
            return Ok(None);
        }
        Ok(Some((snippet, truncated || snippet_truncated)))
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    fn writer(&self) -> Result<Arc<Mutex<IndexWriter>>> {
        self.writer
            .clone()
            .ok_or_else(|| anyhow!("index opened in read-only mode; writer unavailable"))
    }

    pub fn config(&self) -> &IndexConfig {
        &self.config
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

    fn add_document(&self, writer: &mut IndexWriter, path: &Path) -> Result<()> {
        let rel = self.rel_path(path)?;
        let content = fs::read_to_string(path).unwrap_or_default();
        let summary = summarize(&content);
        let tokens = estimate_tokens(&content);
        writer.add_document(doc!(
            self.doc_id_field => rel.clone(),
            self.path_field => rel,
            self.body_field => content,
            self.summary_field => summary,
            self.token_field => tokens,
        ))?;
        Ok(())
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
            if let Some((text, truncated)) = self.preview_snippet(&rel_path, fallback_lines)? {
                return Ok(Some(SnippetResult {
                    text,
                    html: None,
                    truncated,
                    origin: SnippetOrigin::Preview,
                }));
            }
        }
        Ok(None)
    }
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

pub(crate) fn should_index(path: &Path, repo_root: &Path, config: &IndexConfig) -> bool {
    if path.starts_with(config.state_dir()) {
        return false;
    }
    if let (Ok(state_dir), Ok(canonical)) = (config.state_dir().canonicalize(), path.canonicalize())
    {
        if canonical.starts_with(state_dir) {
            return false;
        }
    }
    let relative = path.strip_prefix(repo_root).unwrap_or(path);
    let normalized = relative
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_string()
        .to_lowercase();
    if config
        .excluded_relative_prefixes()
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return false;
    }
    for component in relative.components() {
        if let Component::Normal(name) = component {
            let name_lower = name.to_string_lossy().to_lowercase();
            if config
                .excluded_dir_names()
                .iter()
                .any(|excluded| excluded == &name_lower)
            {
                return false;
            }
        }
    }
    let Some(ext) = path.extension().and_then(|e| e.to_str()) else {
        return false;
    };
    let lower = format!(".{}", ext.to_lowercase());
    DEFAULT_EXTENSIONS.contains(&lower.as_str())
}

fn ensure_state_dir_secure(path: &Path) -> Result<()> {
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
    Ok(())
}

fn resolve_state_dir(repo_root: &Path, state_dir: Option<PathBuf>) -> PathBuf {
    match state_dir {
        Some(custom) if custom.is_absolute() => custom,
        Some(custom) => repo_root.join(custom),
        None => {
            let default_dir = repo_root.join(".docdex").join("index");
            let legacy_dir = repo_root.join(".gpt-creator").join("docdex").join("index");
            if !default_dir.exists() && legacy_dir.exists() {
                warn!(
                    target: "docdexd",
                    legacy = %legacy_dir.display(),
                    default = %default_dir.display(),
                    "using legacy docdex index path; consider migrating to the new default"
                );
                legacy_dir
            } else {
                default_dir
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
