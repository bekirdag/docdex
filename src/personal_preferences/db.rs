use super::*;

pub(super) fn read_meta_i64(conn: &Connection, key: &str) -> Result<Option<i64>> {
    let value = conn
        .query_row(
            "SELECT value FROM personal_preferences_meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .and_then(|value| value.parse::<i64>().ok());
    Ok(value)
}

pub(super) fn write_meta_i64(db_path: &Path, key: &str, value: i64) -> Result<()> {
    let conn = open_db(db_path)?;
    conn.execute(
        "INSERT OR REPLACE INTO personal_preferences_meta(key, value) VALUES (?1, ?2)",
        params![key, value.to_string()],
    )?;
    Ok(())
}

pub(super) fn open_db(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .with_context(|| format!("open {}", path.display()))?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

pub(super) fn count_query(conn: &Connection, sql: &str) -> Result<usize> {
    Ok(conn.query_row(sql, [], |row| row.get::<_, i64>(0))? as usize)
}

pub(super) fn count_query_with_param<P>(conn: &Connection, sql: &str, params: P) -> Result<usize>
where
    P: rusqlite::Params,
{
    Ok(conn.query_row(sql, params, |row| row.get::<_, i64>(0))? as usize)
}
