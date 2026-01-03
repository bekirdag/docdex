use docdexd::symbols::SymbolsStore;
use rusqlite::{params, Connection, OptionalExtension};
use std::error::Error;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn init_symbols_db(path: &Path) -> Result<(), Box<dyn Error>> {
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
        "INSERT OR REPLACE INTO symbols_meta (key, value) VALUES ('schema_version', '2')",
        [],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO symbols_meta (key, value) VALUES ('parser_versions', ?1)",
        params![r#"{"tree_sitter":"0.0.0"}"#],
    )?;
    conn.execute(
        "INSERT OR REPLACE INTO symbols_files (file_path, outcome_status) VALUES (?1, 'ok')",
        params!["src/lib.rs"],
    )?;
    conn.execute(
        "INSERT INTO symbols (file_path, symbol_id, name, kind, line_start, start_col, line_end, end_col) \
         VALUES (?1, ?2, ?3, ?4, 1, 1, 1, 5)",
        params!["src/lib.rs", "id", "demo", "function"],
    )?;
    Ok(())
}

fn count_rows(conn: &Connection, table: &str) -> Result<i64, Box<dyn Error>> {
    let value: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    Ok(value)
}

fn read_meta(conn: &Connection, key: &str) -> Result<Option<String>, Box<dyn Error>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM symbols_meta WHERE key = ?1",
            params![key],
            |row| row.get(0),
        )
        .optional()?;
    Ok(value)
}

#[test]
fn symbols_invalidate_on_parser_version_change() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    fs::create_dir_all(repo.path().join("src"))?;
    fs::write(repo.path().join("src").join("lib.rs"), "pub fn demo() {}\n")?;
    let state_root = TempDir::new()?;
    let db_path = state_root.path().join("symbols.db");
    init_symbols_db(&db_path)?;

    let _store = SymbolsStore::new(repo.path(), state_root.path())?;

    let conn = Connection::open(db_path)?;
    assert_eq!(count_rows(&conn, "symbols")?, 0);
    assert_eq!(count_rows(&conn, "symbols_files")?, 0);
    assert_eq!(
        read_meta(&conn, "symbols_invalidation_reason")?.as_deref(),
        Some("parser_versions_changed")
    );
    assert!(read_meta(&conn, "parser_versions_previous")?.is_some());
    Ok(())
}
