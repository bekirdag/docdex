use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    let _ = fmt().with_env_filter(filter).try_init();
    Ok(())
}
