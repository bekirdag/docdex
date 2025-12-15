use crate::error::{AppError, ERR_BACKOFF_REQUIRED};
use crate::index::{
    DocSnapshot, Hit, QueryRewrite, SearchError, SearchQueryMeta, SearchSnippetOrigin,
    SnippetOrigin, SnippetResult,
};
use anyhow::{Context, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tantivy::collector::TopDocs;
use tantivy::query::QueryParser;
use tantivy::schema::{Schema, FAST, STORED, STRING, TEXT};
use tantivy::{doc, Document, Index, IndexReader, IndexWriter, ReloadPolicy, Term};
use tracing::warn;

const MAX_INDEX_RAM_BYTES: usize = 50 * 1024 * 1024;
const MAX_LIB_DOC_BYTES: u64 = 512 * 1024;
const MAX_LIB_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

pub(crate) fn libs_state_dir_from_index_state_dir(index_state_dir: &Path) -> PathBuf {
    index_state_dir
        .parent()
        .unwrap_or(index_state_dir)
        .join("libs_index")
}

#[derive(Debug, Clone, Deserialize)]
pub struct LibSource {
    pub library: String,
    #[serde(default)]
    pub version: Option<String>,
    pub source: String,
    pub path: PathBuf,
    #[serde(default)]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LibSourcesFile {
    pub sources: Vec<LibSource>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LibSourceStatus {
    Success,
    SkippedStale,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibSourceReport {
    pub library: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub source: String,
    pub path: String,
    pub status: LibSourceStatus,
    pub docs_ingested: usize,
    pub bytes_ingested: u64,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LibsIngestStatus {
    Success,
    PartialSuccess,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct LibsIngestReport {
    pub status: LibsIngestStatus,
    pub libs_state_dir: String,
    pub total_sources: usize,
    pub succeeded_sources: usize,
    pub failed_sources: usize,
    pub skipped_sources: usize,
    pub sources: Vec<LibSourceReport>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct LibsManifest {
    version: u32,
    sources: BTreeMap<String, LibsManifestEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LibsManifestEntry {
    fingerprint_sha256: String,
    doc_ids: Vec<String>,
    updated_at_epoch_ms: u128,
}

#[derive(Clone)]
pub struct LibsIndexer {
    libs_state_dir: PathBuf,
    index: Index,
    reader: IndexReader,
    doc_id_field: tantivy::schema::Field,
    rel_path_field: tantivy::schema::Field,
    body_field: tantivy::schema::Field,
    summary_field: tantivy::schema::Field,
    token_field: tantivy::schema::Field,
    library_field: tantivy::schema::Field,
    version_field: tantivy::schema::Field,
    source_field: tantivy::schema::Field,
    title_field: tantivy::schema::Field,
    writer: Option<Arc<Mutex<IndexWriter>>>,
}

impl LibsIndexer {
    pub fn open_or_create(libs_state_dir: PathBuf) -> Result<Self> {
        crate::index::ensure_state_dir_secure(&libs_state_dir)?;
        let (schema, fields) = build_schema();
        let index = Index::open_or_create(
            tantivy::directory::MmapDirectory::open(&libs_state_dir)?,
            schema.clone(),
        )?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        let writer = index.writer(MAX_INDEX_RAM_BYTES)?;
        Ok(Self {
            libs_state_dir,
            index,
            reader,
            doc_id_field: fields.doc_id,
            rel_path_field: fields.rel_path,
            body_field: fields.body,
            summary_field: fields.summary,
            token_field: fields.token,
            library_field: fields.library,
            version_field: fields.version,
            source_field: fields.source,
            title_field: fields.title,
            writer: Some(Arc::new(Mutex::new(writer))),
        })
    }

    pub fn open_read_only(libs_state_dir: PathBuf) -> Result<Option<Self>> {
        if !libs_state_dir.exists() {
            return Ok(None);
        }
        let index = Index::open_in_dir(&libs_state_dir)
            .with_context(|| format!("open libs index at {}", libs_state_dir.display()))?;
        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommit)
            .try_into()?;
        let schema = index.schema();
        let doc_id_field = schema.get_field("doc_id").unwrap();
        let rel_path_field = schema.get_field("rel_path").unwrap();
        let body_field = schema.get_field("body").unwrap();
        let summary_field = schema.get_field("summary").unwrap();
        let token_field = schema.get_field("token_estimate").unwrap();
        let library_field = schema.get_field("library").unwrap();
        let version_field = schema.get_field("version").unwrap();
        let source_field = schema.get_field("source").unwrap();
        let title_field = schema.get_field("title").unwrap();
        Ok(Some(Self {
            libs_state_dir,
            index,
            reader,
            doc_id_field,
            rel_path_field,
            body_field,
            summary_field,
            token_field,
            library_field,
            version_field,
            source_field,
            title_field,
            writer: None,
        }))
    }

    fn writer(&self) -> Result<Arc<Mutex<IndexWriter>>> {
        self.writer.clone().ok_or_else(|| {
            AppError::new(
                ERR_BACKOFF_REQUIRED,
                "libs index writer unavailable (another docdexd may be indexing); retry later",
            )
            .into()
        })
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
        if sanitize_query(raw).trim().is_empty() {
            return Err(SearchError::InvalidQuery {
                reason: "query contains no searchable terms".to_string(),
            }
            .into());
        }

        let searcher = self.reader.searcher();
        let parser = QueryParser::for_index(
            &self.index,
            vec![
                self.body_field,
                self.summary_field,
                self.title_field,
                self.library_field,
            ],
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
            tantivy::SnippetGenerator::create(&searcher, tantivy_query.as_ref(), self.body_field)
                .ok();
        if let Some(generator) = snippet_generator.as_mut() {
            generator.set_max_num_chars(420);
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
                .get_first(self.rel_path_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let path = rel_path.clone();
            let body = retrieved
                .get_first(self.body_field)
                .and_then(|v| v.as_text())
                .unwrap_or_default();
            let summary = retrieved
                .get_first(self.summary_field)
                .and_then(|v| v.as_text().map(|s| s.to_string()))
                .unwrap_or_default();
            let token_estimate = retrieved
                .get_first(self.token_field)
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            let (snippet, snippet_origin) = snippet_generator
                .as_ref()
                .and_then(|gen| {
                    let snippet = gen.snippet_from_doc(&retrieved);
                    let fragment = snippet.fragment().trim().to_string();
                    if fragment.is_empty() {
                        None
                    } else {
                        Some((fragment, SearchSnippetOrigin::Query))
                    }
                })
                .or_else(|| {
                    preview_snippet_from_body(body, 40).map(|text| (text, SearchSnippetOrigin::Preview))
                })
                .unwrap_or_else(|| (summary.clone(), SearchSnippetOrigin::Summary));

            results.push(Hit {
                doc_id,
                rel_path,
                path,
                score,
                summary,
                snippet,
                token_estimate,
                snippet_origin: Some(snippet_origin),
                snippet_truncated: Some(false),
                line_start: None,
                line_end: None,
            });
        }

        results.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.doc_id.cmp(&b.doc_id))
        });

        Ok((results, query_meta))
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
            self.snippet_from_document(&doc, query, fallback_lines)?;
        Ok(Some((snapshot, snippet)))
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

    fn snapshot_from_document(&self, doc_id: &str, doc: &Document) -> DocSnapshot {
        let rel_path = doc
            .get_first(self.rel_path_field)
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
        query: Option<&str>,
        fallback_lines: usize,
    ) -> Result<Option<SnippetResult>> {
        let searcher = self.reader.searcher();
        if let Some(query) = query.and_then(|q| {
            let trimmed = q.trim();
            if trimmed.is_empty() { None } else { Some(trimmed) }
        }) {
            let parser = QueryParser::for_index(&self.index, vec![self.body_field]);
            if let Ok(parsed) = parser.parse_query(query) {
                if let Ok(mut generator) =
                    tantivy::SnippetGenerator::create(&searcher, parsed.as_ref(), self.body_field)
                {
                    generator.set_max_num_chars(420);
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
        let body = doc
            .get_first(self.body_field)
            .and_then(|v| v.as_text())
            .unwrap_or_default();
        let preview = preview_snippet_from_body(body, fallback_lines).unwrap_or_default();
        if preview.trim().is_empty() {
            return Ok(None);
        }
        Ok(Some(SnippetResult {
            text: preview,
            html: None,
            truncated: false,
            origin: SnippetOrigin::Preview,
            line_start: None,
            line_end: None,
        }))
    }

    pub fn ingest_sources(&self, sources: &[LibSource]) -> Result<LibsIngestReport> {
        let mut warnings: Vec<String> = Vec::new();
        let manifest_path = self.libs_state_dir.join("libs_manifest.json");
        let mut manifest = load_manifest(&manifest_path).unwrap_or_else(|err| {
            warnings.push(format!(
                "failed to read libs manifest (will proceed without staleness checks): {err}"
            ));
            LibsManifest::default()
        });
        if manifest.version == 0 {
            manifest.version = 1;
        }

        let writer_arc = self.writer()?;
        let mut writer = writer_arc.lock();

        let mut reports: Vec<LibSourceReport> = Vec::new();
        let mut succeeded_sources = 0usize;
        let mut failed_sources = 0usize;
        let mut skipped_sources = 0usize;

        for source in sources {
            let report = ingest_one_source(&mut writer, self, &mut manifest, source);
            match report.status {
                LibSourceStatus::Success => succeeded_sources += 1,
                LibSourceStatus::Failed => failed_sources += 1,
                LibSourceStatus::SkippedStale => skipped_sources += 1,
            }
            reports.push(report);
        }

        writer.commit()?;
        self.reader.reload()?;

        if let Err(err) = save_manifest(&manifest_path, &manifest) {
            warnings.push(format!("failed to write libs manifest: {err}"));
        }

        let status = if failed_sources == 0 {
            LibsIngestStatus::Success
        } else if succeeded_sources > 0 || skipped_sources > 0 {
            LibsIngestStatus::PartialSuccess
        } else {
            LibsIngestStatus::Failed
        };

        Ok(LibsIngestReport {
            status,
            libs_state_dir: self.libs_state_dir.display().to_string(),
            total_sources: sources.len(),
            succeeded_sources,
            failed_sources,
            skipped_sources,
            sources: reports,
            warnings,
        })
    }
}

fn ingest_one_source(
    writer: &mut IndexWriter,
    indexer: &LibsIndexer,
    manifest: &mut LibsManifest,
    source: &LibSource,
) -> LibSourceReport {
    let library = source.library.trim().to_string();
    let version = source.version.as_ref().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let source_label = source.source.trim().to_string();
    let path = source.path.clone();
    let path_display = path.display().to_string();
    let title = source.title.clone().filter(|t| !t.trim().is_empty());

    if library.is_empty() {
        return LibSourceReport {
            library,
            version,
            source: source_label,
            path: path_display,
            status: LibSourceStatus::Failed,
            docs_ingested: 0,
            bytes_ingested: 0,
            truncated: false,
            error: Some("library must not be empty".to_string()),
            hint: Some("Ensure resolver emits a non-empty `library` field.".to_string()),
        };
    }
    if source_label.is_empty() {
        return LibSourceReport {
            library,
            version,
            source: source_label,
            path: path_display,
            status: LibSourceStatus::Failed,
            docs_ingested: 0,
            bytes_ingested: 0,
            truncated: false,
            error: Some("source must not be empty".to_string()),
            hint: Some("Ensure resolver emits a non-empty `source` field.".to_string()),
        };
    }

    let source_key = format!(
        "{}@{}|{}",
        library,
        version.clone().unwrap_or_else(|| "unknown".to_string()),
        source_label
    );

    let (body, bytes_ingested, truncated) = match read_text_limited(&path, MAX_LIB_DOC_BYTES) {
        Ok(value) => value,
        Err(err) => {
            let hint = if err.to_string().contains("No such file") {
                Some("Verify the resolver output path and ensure the library docs are present on disk.".to_string())
            } else {
                Some("Check file permissions and that the path points to a text/markdown document.".to_string())
            };
            return LibSourceReport {
                library,
                version,
                source: source_label,
                path: path_display,
                status: LibSourceStatus::Failed,
                docs_ingested: 0,
                bytes_ingested: 0,
                truncated: false,
                error: Some(err.to_string()),
                hint,
            };
        }
    };

    let fingerprint = sha256_hex(body.as_bytes());
    if let Some(entry) = manifest.sources.get(&source_key) {
        if entry.fingerprint_sha256 == fingerprint {
            return LibSourceReport {
                library,
                version,
                source: source_label,
                path: path_display,
                status: LibSourceStatus::SkippedStale,
                docs_ingested: 0,
                bytes_ingested,
                truncated,
                error: None,
                hint: None,
            };
        }
    }

    // Guardrail: cap per-source total bytes to avoid index bloat.
    let capped_body = if (body.as_bytes().len() as u64) > MAX_LIB_SOURCE_BYTES {
        let trimmed = &body.as_bytes()[..(MAX_LIB_SOURCE_BYTES as usize).min(body.len())];
        String::from_utf8_lossy(trimmed).to_string()
    } else {
        body
    };
    let summary = summarize_lib_doc(title.as_deref(), &capped_body);
    let tokens = estimate_tokens(&capped_body);
    let doc_id = format!(
        "libs:{}",
        sha256_hex(format!("{source_key}|{path_display}|{fingerprint}").as_bytes())
    );
    let rel_path = format!(
        "libs/{}/{}/{}",
        sanitize_path_component(&library),
        sanitize_path_component(version.as_deref().unwrap_or("unknown")),
        sanitize_path_component(&path.file_name().and_then(|s| s.to_str()).unwrap_or("doc"))
    );

    if let Err(err) = writer.add_document(doc!(
            indexer.doc_id_field => doc_id.clone(),
            indexer.rel_path_field => rel_path,
            indexer.body_field => capped_body,
            indexer.summary_field => summary,
            indexer.token_field => tokens,
            indexer.library_field => library.clone(),
            indexer.version_field => version.clone().unwrap_or_default(),
            indexer.source_field => source_label.clone(),
            indexer.title_field => title.unwrap_or_else(|| library.clone()),
        )) {
        warn!(target: "docdexd", error = ?err, source_key = %source_key, "failed to add libs doc to index");
        return LibSourceReport {
            library,
            version,
            source: source_label,
            path: path_display,
            status: LibSourceStatus::Failed,
            docs_ingested: 0,
            bytes_ingested,
            truncated,
            error: Some(err.to_string()),
            hint: Some("Ensure the libs index directory is writable and the Tantivy index is not corrupted.".to_string()),
        };
    }

    // Only delete old docs once we have the new content in hand.
    if let Some(previous) = manifest.sources.get(&source_key) {
        for old in previous.doc_ids.iter() {
            let term = Term::from_field_text(indexer.doc_id_field, old);
            writer.delete_term(term);
        }
    }

    manifest.sources.insert(
        source_key,
        LibsManifestEntry {
            fingerprint_sha256: fingerprint,
            doc_ids: vec![doc_id],
            updated_at_epoch_ms: now_epoch_ms().unwrap_or(0),
        },
    );

    LibSourceReport {
        library,
        version,
        source: source_label,
        path: path_display,
        status: LibSourceStatus::Success,
        docs_ingested: 1,
        bytes_ingested,
        truncated,
        error: None,
        hint: None,
    }
}

struct SchemaFields {
    doc_id: tantivy::schema::Field,
    rel_path: tantivy::schema::Field,
    title: tantivy::schema::Field,
    body: tantivy::schema::Field,
    summary: tantivy::schema::Field,
    token: tantivy::schema::Field,
    library: tantivy::schema::Field,
    version: tantivy::schema::Field,
    source: tantivy::schema::Field,
}

fn build_schema() -> (Schema, SchemaFields) {
    let mut builder = Schema::builder();
    let doc_id = builder.add_text_field("doc_id", STRING | STORED);
    let rel_path = builder.add_text_field("rel_path", STRING | STORED);
    let title = builder.add_text_field("title", TEXT | STORED);
    let body = builder.add_text_field("body", TEXT | STORED);
    let summary = builder.add_text_field("summary", TEXT | STORED);
    let token = builder.add_u64_field("token_estimate", FAST | STORED);
    let library = builder.add_text_field("library", STRING | STORED);
    let version = builder.add_text_field("version", STRING | STORED);
    let source = builder.add_text_field("source", STRING | STORED);
    (
        builder.build(),
        SchemaFields {
            doc_id,
            rel_path,
            title,
            body,
            summary,
            token,
            library,
            version,
            source,
        },
    )
}

fn load_manifest(path: &Path) -> Result<LibsManifest> {
    if !path.exists() {
        return Ok(LibsManifest::default());
    }
    let content = fs::read_to_string(path)
        .with_context(|| format!("read libs manifest {}", path.display()))?;
    let mut parsed: LibsManifest =
        serde_json::from_str(&content).context("parse libs manifest json")?;
    if parsed.version == 0 {
        parsed.version = 1;
    }
    Ok(parsed)
}

fn save_manifest(path: &Path, manifest: &LibsManifest) -> Result<()> {
    let serialized = serde_json::to_string_pretty(manifest).context("serialize libs manifest")?;
    fs::write(path, serialized).with_context(|| format!("write libs manifest {}", path.display()))
}

fn read_text_limited(path: &Path, max_bytes: u64) -> Result<(String, u64, bool)> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("stat {}", path.display()))?;
    let total = meta.len();
    let mut buf = Vec::new();
    file.take(max_bytes)
        .read_to_end(&mut buf)
        .with_context(|| format!("read {}", path.display()))?;
    let truncated = total > max_bytes;
    Ok((String::from_utf8_lossy(&buf).to_string(), buf.len() as u64, truncated))
}

fn sanitize_query(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c.is_whitespace() || c == '_' {
                c
            } else {
                ' '
            }
        })
        .collect::<String>()
        .split_whitespace()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn preview_snippet_from_body(body: &str, max_lines: usize) -> Option<String> {
    if max_lines == 0 {
        return None;
    }
    let mut lines = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        lines.push(trimmed.to_string());
        if lines.len() >= max_lines {
            break;
        }
    }
    if lines.is_empty() {
        return None;
    }
    let joined = lines.join(" ");
    let snippet = joined.chars().take(420).collect::<String>();
    Some(snippet)
}

fn estimate_tokens(text: &str) -> u64 {
    text.split_whitespace().count() as u64
}

fn summarize_lib_doc(title: Option<&str>, body: &str) -> String {
    let cleaned_title = title.unwrap_or("").trim();
    let body_first_line = body
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim();
    if !cleaned_title.is_empty() && !body_first_line.is_empty() {
        format!("{cleaned_title} — {body_first_line}")
    } else if !cleaned_title.is_empty() {
        cleaned_title.to_string()
    } else if !body_first_line.is_empty() {
        body_first_line.to_string()
    } else {
        String::new()
    }
}

fn sanitize_path_component(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }
    let mut out = String::with_capacity(trimmed.len());
    for c in trimmed.chars() {
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
            out.push(c);
        } else if c.is_whitespace() || c == '/' || c == '\\' || c == ':' {
            out.push('_');
        }
    }
    let cleaned = out.trim_matches('_').to_string();
    if cleaned.is_empty() {
        "unknown".to_string()
    } else {
        cleaned
    }
}

fn sha256_hex(input: &[u8]) -> String {
    hex::encode(Sha256::digest(input))
}

fn now_epoch_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("read system clock")?
        .as_millis())
}
