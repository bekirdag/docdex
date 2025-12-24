use crate::error::{AppError, ERR_INVALID_ARGUMENT};
use anyhow::Result;
use std::path::PathBuf;

pub fn run(_repo: Option<PathBuf>) -> Result<()> {
    Err(AppError::new(
        ERR_INVALID_ARGUMENT,
        "tui is not implemented in this build",
    )
    .into())
}
