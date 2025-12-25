use crate::config::RepoArgs;
use crate::index;
use crate::libs;
use crate::libs_source_resolver;
use crate::util;
use crate::{error, error::AppError};
use anyhow::Context;
use anyhow::Result;
use std::fs;
use std::path::PathBuf;

pub fn run_command(command: super::super::LibsCommand) -> Result<()> {
    match command {
        super::super::LibsCommand::Fetch { repo, sources } => run_fetch(repo, sources),
        super::super::LibsCommand::Discover { repo, sources } => run_discover(repo, sources),
    }
}

pub fn run_fetch(repo: RepoArgs, sources: Option<PathBuf>) -> Result<()> {
    let Some(sources) = sources else {
        return Err(AppError::new(
            error::ERR_INVALID_ARGUMENT,
            "libs fetch requires --sources until dependency fetch is wired",
        )
        .into());
    };
    run_ingest(repo, sources)
}

pub fn run_ingest(repo: RepoArgs, sources: PathBuf) -> Result<()> {
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let libs_dir = libs::libs_state_dir_from_index_state_dir(index_config.state_dir());
    let indexer = libs::LibsIndexer::open_or_create(libs_dir)?;
    let raw =
        fs::read_to_string(&sources).with_context(|| format!("read libs sources file {}", sources.display()))?;
    let sources_file: libs::LibSourcesFile =
        serde_json::from_str(&raw).context("parse libs sources json")?;
    let report = indexer.ingest_sources(&repo_root, &sources_file.sources)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub fn run_discover(repo: RepoArgs, sources: Option<PathBuf>) -> Result<()> {
    let repo_root = repo.repo_root();
    util::init_logging("warn")?;
    let explicit = match sources {
        None => None,
        Some(path) => {
            let raw = fs::read_to_string(&path)
                .with_context(|| format!("read libs sources file {}", path.display()))?;
            let parsed: libs::LibSourcesFile =
                serde_json::from_str(&raw).context("parse libs sources json")?;
            Some(parsed)
        }
    };
    let resolver = libs_source_resolver::LibsSourceResolver::new(repo_root);
    let resolution = resolver.resolve(explicit.as_ref())?;
    println!("{}", serde_json::to_string_pretty(&resolution)?);
    Ok(())
}
