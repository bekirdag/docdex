use crate::config::RepoArgs;
use crate::error::{AppError, ERR_INVALID_ARGUMENT};
use anyhow::Result;
use std::path::PathBuf;

pub fn run(_repo: RepoArgs, _target: Option<PathBuf>) -> Result<()> {
    Err(AppError::new(
        ERR_INVALID_ARGUMENT,
        "run-tests is not implemented in this build",
    )
    .into())
}
