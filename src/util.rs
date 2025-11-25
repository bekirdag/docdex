use anyhow::Result;
use std::io;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // Write logs to stderr to avoid interfering with stdout protocols (e.g., MCP stdio).
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(io::stderr)
        .try_init();
    Ok(())
}
