use crate::config::RepoArgs;
use crate::index;
use crate::libs;
use crate::libs_source_resolver;
use crate::util;
use crate::{error, error::AppError};
use anyhow::Context;
use anyhow::Result;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

pub fn run_command(command: super::super::LibsCommand) -> Result<()> {
    match command {
        super::super::LibsCommand::Fetch { repo, sources } => run_fetch(repo, sources),
        super::super::LibsCommand::Discover { repo, sources } => run_discover(repo, sources),
    }
}

pub fn run_fetch(repo: RepoArgs, sources: Option<PathBuf>) -> Result<()> {
    let explicit = sources
        .as_ref()
        .map(read_sources_file)
        .transpose()?;
    let resolver = libs_source_resolver::LibsSourceResolver::new(repo.repo_root());
    let resolution = resolver.resolve(explicit.as_ref())?;
    let mut sources_file =
        libs_source_resolver::resolution_to_sources(&resolution, explicit.is_none());
    if let Some(explicit_file) = explicit {
        sources_file
            .sources
            .extend(explicit_file.sources.into_iter());
        sources_file.sources = dedupe_sources(sources_file.sources);
    }
    if sources_file.sources.is_empty() {
        return Err(AppError::new(
            error::ERR_INVALID_ARGUMENT,
            "no eligible libs sources discovered; run `docdex libs discover` or provide --sources",
        )
        .into());
    }
    ingest_sources_for_repo(&repo, &sources_file)
}

pub fn run_ingest(repo: RepoArgs, sources: PathBuf) -> Result<()> {
    let sources_file = read_sources_file(&sources)?;
    ingest_sources_for_repo(&repo, &sources_file)
}

pub fn run_discover(repo: RepoArgs, sources: Option<PathBuf>) -> Result<()> {
    let repo_root = repo.repo_root();
    util::init_logging("warn")?;
    let explicit = match sources {
        None => None,
        Some(path) => {
            let parsed = read_sources_file(&path)?;
            Some(parsed)
        }
    };
    let resolver = libs_source_resolver::LibsSourceResolver::new(repo_root);
    let resolution = resolver.resolve(explicit.as_ref())?;
    println!("{}", serde_json::to_string_pretty(&resolution)?);
    Ok(())
}

fn ingest_sources_for_repo(repo: &RepoArgs, sources_file: &libs::LibSourcesFile) -> Result<()> {
    util::init_logging("warn")?;
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    let libs_dir = libs::libs_state_dir_from_index_state_dir(index_config.state_dir());
    let indexer = libs::LibsIndexer::open_or_create(libs_dir)?;
    let report = indexer.ingest_sources(&repo_root, &sources_file.sources)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn read_sources_file(path: &PathBuf) -> Result<libs::LibSourcesFile> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read libs sources file {}", path.display()))?;
    serde_json::from_str(&raw).context("parse libs sources json")
}

fn dedupe_sources(sources: Vec<libs::LibSource>) -> Vec<libs::LibSource> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut deduped = Vec::new();
    for source in sources {
        let key = lib_source_key(&source);
        if seen.insert(key) {
            deduped.push(source);
        }
    }
    deduped
}

fn lib_source_key(source: &libs::LibSource) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        source.library.trim(),
        source.version.as_deref().unwrap_or("").trim(),
        source.source.trim(),
        source.path.to_string_lossy(),
        source.title.as_deref().unwrap_or("").trim()
    )
}
