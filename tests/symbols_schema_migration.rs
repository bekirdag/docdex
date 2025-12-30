use docdexd::symbols::SymbolsStore;
use rusqlite::{params, Connection};
use std::error::Error;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn init_symbols_db(path: &Path, schema_version: i64) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS symbols_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); \
         CREATE TABLE IF NOT EXISTS symbols_files ( \
             file_path TEXT PRIMARY KEY, \
             outcome_status TEXT, \
             outcome_reason TEXT, \
             outcome_error_summary TEXT, \
             file_lang TEXT \
         ); \
         CREATE TABLE IF NOT EXISTS symbols ( \
             id INTEGER PRIMARY KEY AUTOINCREMENT, \
             file_path TEXT NOT NULL, \
             symbol_id TEXT, \
             name TEXT NOT NULL, \
             kind TEXT NOT NULL, \
             line_start INTEGER NOT NULL, \
             start_col INTEGER NOT NULL, \
             line_end INTEGER NOT NULL, \
             end_col INTEGER NOT NULL, \
             signature TEXT \
         );",
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO symbols_meta (key, value) VALUES ('schema_version', ?1)",
        params![schema_version],
    )?;
    Ok(())
}

#[test]
fn symbols_schema_upgrades_from_v2() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let db_path = state_root.path().join("symbols.db");

    init_symbols_db(&db_path, 2)?;

    let _store = SymbolsStore::new(repo.path(), state_root.path())?;

    let conn = Connection::open(db_path)?;
    let version_raw: String = conn.query_row(
        "SELECT value FROM symbols_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    )?;
    let version: i64 = version_raw.parse()?;
    assert!(version > 2);
    Ok(())
}

#[test]
fn symbols_schema_rejects_newer_version() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let db_path = state_root.path().join("symbols.db");

    init_symbols_db(&db_path, 999)?;

    let err = match SymbolsStore::new(repo.path(), state_root.path()) {
        Ok(_) => return Err("expected newer schema version to fail".into()),
        Err(err) => err,
    };
    assert!(err.to_string().contains("newer than supported"));
    Ok(())
}
