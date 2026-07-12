use super::*;

fn schema_objects(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut stmt = conn.prepare(
        "SELECT type, name
         FROM sqlite_master
         WHERE name NOT LIKE 'sqlite_%'
         ORDER BY type, name",
    )?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

#[test]
fn newer_schema_is_rejected_before_database_mutation() -> Result<()> {
    let state = TempDir::new()?;
    let db_path = state.path().join(DB_FILE);
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE;
         CREATE TABLE personal_preferences_meta(
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE future_only(value TEXT NOT NULL);",
    )?;
    conn.execute(
        "INSERT INTO personal_preferences_meta(key, value) VALUES ('schema_version', ?1)",
        params![(SCHEMA_VERSION + 1).to_string()],
    )?;
    let before_objects = schema_objects(&conn)?;
    let before_journal_mode =
        conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?;
    drop(conn);

    let err = match PersonalPreferencesStore::new(state.path()) {
        Ok(_) => return Err(anyhow!("expected newer schema version to be rejected")),
        Err(err) => err,
    };
    assert!(err.to_string().contains("newer than supported version"));

    let conn = Connection::open(&db_path)?;
    assert_eq!(schema_objects(&conn)?, before_objects);
    assert_eq!(
        conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0))?,
        before_journal_mode
    );
    assert!(!before_objects
        .iter()
        .any(|(_, name)| name == "captured_conversations"));
    Ok(())
}
