use anyhow::Result;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logging(level: &str) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));
    // Write logs to stderr to avoid interfering with stdout protocols (e.g., MCP stdio).
    if let Some(path) = resolve_state_log_path() {
        match OpenOptions::new().create(true).append(true).open(&path) {
            Ok(file) => {
                let file = Arc::new(Mutex::new(file));
                let make_writer = move || StateLogWriter {
                    file: Arc::clone(&file),
                    stderr: io::stderr(),
                };
                let _ = fmt().with_env_filter(filter).with_writer(make_writer).try_init();
                return Ok(());
            }
            Err(err) => {
                eprintln!("docdexd: failed to open log file {}: {err}", path.display());
            }
        }
    }
    let _ = fmt().with_env_filter(filter).with_writer(io::stderr).try_init();
    Ok(())
}

fn resolve_state_log_path() -> Option<PathBuf> {
    if !env_boolish("DOCDEX_LOG_TO_STATE").unwrap_or(false) {
        return None;
    }
    let base_dir = crate::state_paths::default_state_base_dir().ok()?;
    let logs_dir = base_dir.join("logs");
    if let Err(err) = crate::state_layout::ensure_state_dir_secure(&logs_dir) {
        eprintln!(
            "docdexd: failed to create logs dir {}: {err}",
            logs_dir.display()
        );
        return None;
    }
    Some(logs_dir.join(format!("docdexd-{}.log", std::process::id())))
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

struct StateLogWriter {
    file: Arc<Mutex<std::fs::File>>,
    stderr: io::Stderr,
}

impl Write for StateLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut file = self.file.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "state log file lock poisoned")
        })?;
        let _ = self.stderr.write_all(buf);
        file.write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut file = self.file.lock().map_err(|_| {
            io::Error::new(io::ErrorKind::Other, "state log file lock poisoned")
        })?;
        let _ = self.stderr.flush();
        file.flush()
    }
}
