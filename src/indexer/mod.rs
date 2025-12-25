use crate::index::{FileDecision, IndexConfig, Indexer};
use crate::libs;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct IndexingOptions {
    pub libs_sources: Option<libs::LibSourcesFile>,
}

impl IndexingOptions {
    pub fn none() -> Self {
        Self { libs_sources: None }
    }

    pub fn with_libs_sources(libs_sources: libs::LibSourcesFile) -> Self {
        Self {
            libs_sources: Some(libs_sources),
        }
    }

    pub fn from_sources_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("read libs sources file {}", path.display()))?;
        let sources: libs::LibSourcesFile =
            serde_json::from_str(&raw).context("parse libs sources json")?;
        Ok(Self::with_libs_sources(sources))
    }
}

#[derive(Debug, Clone)]
pub struct IndexingReport {
    pub repo_root: PathBuf,
    pub state_dir: PathBuf,
    pub docs_indexed: Option<u64>,
    pub libs_report: Option<libs::LibsIngestReport>,
}

pub async fn reindex_repo(
    repo_root: PathBuf,
    index_config: IndexConfig,
    options: IndexingOptions,
) -> Result<IndexingReport> {
    let indexer = Indexer::with_config(repo_root, index_config)?;
    indexer.reindex_all().await?;

    let docs_indexed = indexer.stats().ok().map(|stats| stats.num_docs);
    let libs_report = match options.libs_sources {
        None => None,
        Some(sources) => {
            let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
            let libs_indexer = libs::LibsIndexer::open_or_create(libs_dir)?;
            Some(libs_indexer.ingest_sources(&sources.sources)?)
        }
    };

    Ok(IndexingReport {
        repo_root: indexer.repo_root().to_path_buf(),
        state_dir: indexer.state_dir().to_path_buf(),
        docs_indexed,
        libs_report,
    })
}

pub async fn ingest_file(
    repo_root: PathBuf,
    index_config: IndexConfig,
    file: PathBuf,
) -> Result<FileDecision> {
    let indexer = Indexer::with_config(repo_root, index_config)?;
    indexer.ingest_file(file).await
}
