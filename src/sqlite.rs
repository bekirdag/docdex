use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use std::path::Path;
use std::time::Duration;

pub(crate) const SQLITE_BUSY_TIMEOUT_SECS: u64 = 5;

pub(crate) fn open_rw_create_full_mutex(path: &Path, label: &str) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .with_context(|| format!("open {}", path.display()))?;
    set_busy_timeout(&conn, label)?;
    Ok(conn)
}

pub(crate) fn set_busy_timeout(conn: &Connection, label: &str) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(SQLITE_BUSY_TIMEOUT_SECS))
        .with_context(|| format!("set {label} database busy timeout"))
}

pub(crate) fn enable_wal_and_foreign_keys(conn: &Connection, label: &str) -> Result<()> {
    conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;")
        .with_context(|| format!("enable {label} database WAL mode"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn open_rw_create_full_mutex_sets_busy_timeout() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("test.db");
        let conn = open_rw_create_full_mutex(&path, "test")?;
        let busy_timeout_ms: i64 = conn.query_row("PRAGMA busy_timeout", [], |row| row.get(0))?;
        assert!(busy_timeout_ms >= (SQLITE_BUSY_TIMEOUT_SECS as i64) * 1000);
        Ok(())
    }
}
