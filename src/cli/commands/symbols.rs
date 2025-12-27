use crate::config::RepoArgs;
use crate::index;
use crate::symbols::SymbolsStore;
use crate::util;
use anyhow::Result;

pub fn run_status(repo: RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    index::ensure_state_dir_secure(index_config.state_dir())?;

    let store = SymbolsStore::new(&repo_root, index_config.state_dir())?;
    let status = store.parser_status()?;
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}
