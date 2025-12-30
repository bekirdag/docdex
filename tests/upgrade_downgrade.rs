use docdexd::memory::{memory_path, MemoryStore};
use docdexd::profiles::db::init_profile_db;
use rusqlite::{params, Connection};
use tempfile::tempdir;

#[test]
fn profile_schema_newer_is_rejected() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("profiles.db");
    let conn = Connection::open(&db_path).expect("open profile db");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS profile_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO profile_meta (key, value) VALUES (?1, ?2)",
        params!["schema_version", "99"],
    )
    .unwrap();

    let err = match init_profile_db(&db_path, None) {
        Ok(_) => panic!("expected schema version error"),
        Err(err) => err,
    };
    assert!(
        err.to_string()
            .contains("profile schema version 99 is newer than supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn profile_schema_zero_is_upgraded() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("profiles.db");
    let conn = Connection::open(&db_path).expect("open profile db");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS profile_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO profile_meta (key, value) VALUES (?1, ?2)",
        params!["schema_version", "0"],
    )
    .unwrap();

    let _ = init_profile_db(&db_path, None).expect("expected upgrade to succeed");
    let stored: String = conn
        .query_row(
            "SELECT value FROM profile_meta WHERE key = ?1",
            params!["schema_version"],
            |row| row.get(0),
        )
        .expect("read schema version");
    assert_eq!(stored, "1");
}

#[test]
fn memory_schema_newer_is_rejected() {
    let dir = tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("create state dir");
    let db_path = memory_path(&state_dir);
    let conn = Connection::open(&db_path).expect("open memory db");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS memory_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO memory_meta (key, value) VALUES (?1, ?2)",
        params!["schema_version", "99"],
    )
    .unwrap();

    let store = MemoryStore::new(&state_dir);
    let err = store.check_access().expect_err("expected schema version error");
    assert!(
        err.to_string()
            .contains("memory schema version 99 is newer than supported"),
        "unexpected error: {err}"
    );
}

#[test]
fn memory_schema_zero_is_upgraded() {
    let dir = tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(&state_dir).expect("create state dir");
    let db_path = memory_path(&state_dir);
    let conn = Connection::open(&db_path).expect("open memory db");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS memory_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT OR REPLACE INTO memory_meta (key, value) VALUES (?1, ?2)",
        params!["schema_version", "0"],
    )
    .unwrap();

    let store = MemoryStore::new(&state_dir);
    store.check_access().expect("expected upgrade to succeed");
    let stored: String = conn
        .query_row(
            "SELECT value FROM memory_meta WHERE key = ?1",
            params!["schema_version"],
            |row| row.get(0),
        )
        .expect("read schema version");
    assert_eq!(stored, "1");
}
