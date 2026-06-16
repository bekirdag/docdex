use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use std::path::Path;
use std::sync::Once;

const PROFILE_META_EMBED_DIM: &str = "embedding_dim";
const PROFILE_META_SCHEMA_VERSION: &str = "schema_version";
const PROFILE_SCHEMA_VERSION: u32 = 1;

static SQLITE_VEC_INIT: Once = Once::new();

pub struct ProfileDbInit {
    pub conn: Connection,
    pub embedding_dim: Option<usize>,
    pub schema_version: u32,
}

pub fn init_profile_db(path: &Path, embedding_dim: Option<usize>) -> Result<ProfileDbInit> {
    ensure_vec_extension_loaded()?;
    let mut conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_FULL_MUTEX,
    )
    .with_context(|| format!("open {}", path.display()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")
        .context("enable WAL mode")?;
    let stored_dim = ensure_schema(&conn, embedding_dim)?;
    if let Some(dim) = stored_dim {
        seed_defaults(&mut conn, dim)?;
    }
    let schema_version = load_schema_version(&conn)?.unwrap_or(PROFILE_SCHEMA_VERSION);
    Ok(ProfileDbInit {
        conn,
        embedding_dim: stored_dim,
        schema_version,
    })
}

#[cfg(not(target_env = "musl"))]
fn ensure_vec_extension_loaded() -> Result<()> {
    SQLITE_VEC_INIT.call_once(|| unsafe {
        rusqlite::ffi::sqlite3_auto_extension(Some(std::mem::transmute(
            sqlite_vec::sqlite3_vec_init as *const (),
        )));
    });
    Ok(())
}

#[cfg(target_env = "musl")]
fn ensure_vec_extension_loaded() -> Result<()> {
    anyhow::bail!("sqlite-vec is not available on musl builds; profile vector search is disabled");
}

fn ensure_schema(conn: &Connection, embedding_dim: Option<usize>) -> Result<Option<usize>> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS agents(
            id TEXT PRIMARY KEY,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS preferences(
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            content TEXT NOT NULL,
            embedding BLOB NOT NULL,
            category TEXT NOT NULL,
            last_updated INTEGER NOT NULL,
            FOREIGN KEY(agent_id) REFERENCES agents(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS profile_meta(
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );",
    )
    .context("ensure profile schema")?;
    ensure_embedding_metadata_columns(conn)?;

    ensure_schema_version(conn)?;

    let stored_dim = load_embedding_dim(conn)?;
    if let (Some(stored), Some(requested)) = (stored_dim, embedding_dim) {
        if stored != requested {
            return Err(anyhow::anyhow!(
                "embedding dimension mismatch: stored {stored}, requested {requested}"
            ));
        }
    }

    let inferred = if stored_dim.is_some() {
        stored_dim
    } else if embedding_dim.is_some() {
        embedding_dim
    } else {
        infer_embedding_dim(conn)?
    };

    if let Some(dim) = inferred {
        ensure_vec_table(conn, dim)?;
        if stored_dim.is_none() {
            conn.execute(
                "INSERT OR REPLACE INTO profile_meta (key, value) VALUES (?1, ?2)",
                params![PROFILE_META_EMBED_DIM, dim.to_string()],
            )
            .context("store embedding dimension")?;
        }
        backfill_vec_table(conn, dim)?;
    }

    Ok(inferred)
}

fn ensure_embedding_metadata_columns(conn: &Connection) -> Result<()> {
    let mut stmt = conn
        .prepare("PRAGMA table_info(preferences)")
        .context("inspect preferences schema")?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .context("read preferences schema")?;
    let mut columns = Vec::new();
    for row in rows {
        columns.push(row.context("read preferences column")?);
    }
    if !columns.iter().any(|column| column == "embedding_provider") {
        conn.execute_batch("ALTER TABLE preferences ADD COLUMN embedding_provider TEXT;")
            .context("add preferences.embedding_provider")?;
    }
    if !columns.iter().any(|column| column == "embedding_model") {
        conn.execute_batch("ALTER TABLE preferences ADD COLUMN embedding_model TEXT;")
            .context("add preferences.embedding_model")?;
    }
    if !columns.iter().any(|column| column == "embedding_dim") {
        conn.execute_batch("ALTER TABLE preferences ADD COLUMN embedding_dim INTEGER;")
            .context("add preferences.embedding_dim")?;
    }
    Ok(())
}

fn ensure_schema_version(conn: &Connection) -> Result<()> {
    let stored = load_schema_version(conn)?;
    match stored {
        None | Some(0) => {
            store_schema_version(conn, PROFILE_SCHEMA_VERSION)?;
        }
        Some(version) if version == PROFILE_SCHEMA_VERSION => {}
        Some(version) if version > PROFILE_SCHEMA_VERSION => {
            return Err(anyhow::anyhow!(
                "profile schema version {version} is newer than supported {PROFILE_SCHEMA_VERSION}"
            ));
        }
        Some(version) => {
            migrate_schema(conn, version, PROFILE_SCHEMA_VERSION)?;
            store_schema_version(conn, PROFILE_SCHEMA_VERSION)?;
        }
    }
    Ok(())
}

pub(crate) fn load_schema_version(conn: &Connection) -> Result<Option<u32>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM profile_meta WHERE key = ?1",
            params![PROFILE_META_SCHEMA_VERSION],
            |row| row.get(0),
        )
        .optional()
        .context("read schema version")?;
    match raw {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse::<u32>()
            .map(Some)
            .context("parse schema version"),
    }
}

fn store_schema_version(conn: &Connection, version: u32) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO profile_meta (key, value) VALUES (?1, ?2)",
        params![PROFILE_META_SCHEMA_VERSION, version.to_string()],
    )
    .context("store schema version")?;
    Ok(())
}

fn migrate_schema(_conn: &Connection, from: u32, to: u32) -> Result<()> {
    Err(anyhow::anyhow!(
        "unsupported profile schema migration {from}->{to}"
    ))
}

fn load_embedding_dim(conn: &Connection) -> Result<Option<usize>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM profile_meta WHERE key = ?1",
            params![PROFILE_META_EMBED_DIM],
            |row| row.get(0),
        )
        .optional()
        .context("read embedding dimension")?;
    match raw {
        None => Ok(None),
        Some(value) => value
            .trim()
            .parse::<usize>()
            .map(Some)
            .context("parse embedding dimension"),
    }
}

fn infer_embedding_dim(conn: &Connection) -> Result<Option<usize>> {
    let maybe_blob: Option<Vec<u8>> = conn
        .query_row("SELECT embedding FROM preferences LIMIT 1", [], |row| {
            row.get(0)
        })
        .optional()
        .context("inspect existing embeddings")?;
    let Some(blob) = maybe_blob else {
        return Ok(None);
    };
    Ok(decode_embedding(&blob).map(|embedding| embedding.len()))
}

fn ensure_vec_table(conn: &Connection, embedding_dim: usize) -> Result<()> {
    let statement = format!(
        "CREATE VIRTUAL TABLE IF NOT EXISTS preferences_vec USING vec0(embedding float[{embedding_dim}])"
    );
    conn.execute_batch(&statement)
        .context("ensure preferences vector table")?;
    Ok(())
}

fn backfill_vec_table(conn: &Connection, embedding_dim: usize) -> Result<()> {
    let pref_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM preferences", [], |row| row.get(0))
        .unwrap_or(0);
    if pref_count == 0 {
        return Ok(());
    }
    let vec_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM preferences_vec", [], |row| row.get(0))
        .unwrap_or(0);
    if vec_count >= pref_count {
        return Ok(());
    }

    let mut stmt = conn
        .prepare(
            "SELECT rowid, embedding FROM preferences
             WHERE rowid NOT IN (SELECT rowid FROM preferences_vec)",
        )
        .context("prepare preferences vec backfill")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    for row in rows {
        let (rowid, blob) = match row {
            Ok(row) => row,
            Err(_) => continue,
        };
        let Some(embedding) = decode_embedding(&blob) else {
            continue;
        };
        if embedding.len() != embedding_dim {
            continue;
        }
        let embedding_json = embedding_to_json(&embedding).context("serialize embedding")?;
        conn.execute(
            "INSERT OR IGNORE INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid, embedding_json],
        )
        .context("backfill preferences vector")?;
    }
    Ok(())
}

pub(crate) fn embedding_to_json(embedding: &[f32]) -> Result<String> {
    serde_json::to_string(embedding).context("serialize embedding")
}

pub(crate) fn encode_embedding(embedding: &[f32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(embedding.len().saturating_mul(4));
    for value in embedding {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

pub(crate) fn decode_embedding(blob: &[u8]) -> Option<Vec<f32>> {
    if blob.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(blob.len() / 4);
    for chunk in blob.chunks_exact(4) {
        let bytes: [u8; 4] = chunk.try_into().ok()?;
        out.push(f32::from_le_bytes(bytes));
    }
    Some(out)
}

pub(crate) fn distance_to_score(distance: f64) -> f32 {
    let score = 1.0 / (1.0 + distance.max(0.0));
    score as f32
}

#[derive(Deserialize)]
struct SeedManifest {
    agents: Vec<SeedAgent>,
    preferences: Vec<SeedPreference>,
}

#[derive(Deserialize)]
struct SeedAgent {
    id: String,
    role: String,
}

#[derive(Deserialize)]
struct SeedPreference {
    id: String,
    agent_id: String,
    content: String,
    category: String,
}

fn seed_defaults(conn: &mut Connection, embedding_dim: usize) -> Result<()> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))
        .unwrap_or(0);
    if count > 0 {
        return Ok(());
    }

    let raw = include_str!("defaults.json");
    let manifest: SeedManifest =
        serde_json::from_str(raw).context("parse profile defaults.json")?;
    if manifest.agents.is_empty() {
        return Ok(());
    }

    let now_ms = now_epoch_ms();
    let embedding = vec![0.0_f32; embedding_dim.max(1)];
    let embedding_blob = encode_embedding(&embedding);
    let embedding_json = embedding_to_json(&embedding).context("serialize seed embedding")?;

    let tx = conn
        .transaction()
        .context("start profile seed transaction")?;
    for agent in &manifest.agents {
        tx.execute(
            "INSERT INTO agents (id, role, created_at) VALUES (?1, ?2, ?3)",
            params![agent.id, agent.role, now_ms],
        )
        .context("insert seed agent")?;
    }
    for pref in &manifest.preferences {
        tx.execute(
            "INSERT INTO preferences (id, agent_id, content, embedding, category, last_updated)\n             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                pref.id,
                pref.agent_id,
                pref.content,
                embedding_blob.as_slice(),
                pref.category,
                now_ms
            ],
        )
        .context("insert seed preference")?;
        let rowid = tx.last_insert_rowid();
        tx.execute(
            "INSERT INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid, embedding_json.as_str()],
        )
        .context("insert seed preference vector")?;
    }
    tx.commit().context("commit profile seed")?;
    Ok(())
}

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_creates_schema_and_meta() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("profile.db");
        let ProfileDbInit { conn, .. } = init_profile_db(&path, Some(4))?;

        let mut stmt = conn.prepare(
            "SELECT name FROM sqlite_master WHERE name IN ('agents','preferences','profile_meta','preferences_vec')",
        )?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut names = Vec::new();
        for row in rows {
            if let Ok(name) = row {
                names.push(name);
            }
        }
        assert!(names.contains(&"agents".to_string()));
        assert!(names.contains(&"preferences".to_string()));
        assert!(names.contains(&"profile_meta".to_string()));
        assert!(names.contains(&"preferences_vec".to_string()));

        let dim: String = conn.query_row(
            "SELECT value FROM profile_meta WHERE key = ?1",
            params![PROFILE_META_EMBED_DIM],
            |row| row.get(0),
        )?;
        assert_eq!(dim, "4");
        Ok(())
    }

    #[test]
    fn init_rejects_embedding_dim_mismatch() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("profile.db");
        let _ = init_profile_db(&path, Some(4))?;
        let err = init_profile_db(&path, Some(8)).err();
        assert!(err.is_some());
        Ok(())
    }

    #[test]
    fn seed_is_idempotent() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("profile.db");
        let ProfileDbInit { conn, .. } = init_profile_db(&path, Some(4))?;
        let agents_first: i64 =
            conn.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?;
        let prefs_first: i64 =
            conn.query_row("SELECT COUNT(*) FROM preferences", [], |row| row.get(0))?;
        drop(conn);

        let ProfileDbInit { conn, .. } = init_profile_db(&path, Some(4))?;
        let agents_second: i64 =
            conn.query_row("SELECT COUNT(*) FROM agents", [], |row| row.get(0))?;
        let prefs_second: i64 =
            conn.query_row("SELECT COUNT(*) FROM preferences", [], |row| row.get(0))?;

        assert_eq!(agents_first, agents_second);
        assert_eq!(prefs_first, prefs_second);
        Ok(())
    }

    #[test]
    fn vector_search_orders_by_distance() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("profile.db");
        let ProfileDbInit { conn, .. } = init_profile_db(&path, Some(2))?;

        conn.execute("DELETE FROM preferences_vec", [])?;
        conn.execute("DELETE FROM preferences", [])?;
        conn.execute("DELETE FROM agents", [])?;

        conn.execute(
            "INSERT INTO agents (id, role, created_at) VALUES (?1, ?2, ?3)",
            params!["agent", "test", 1i64],
        )?;

        let embedding_a = vec![0.0_f32, 0.0_f32];
        let embedding_b = vec![1.0_f32, 1.0_f32];
        let embedding_blob_a = encode_embedding(&embedding_a);
        let embedding_blob_b = encode_embedding(&embedding_b);
        let embedding_json_a = embedding_to_json(&embedding_a)?;
        let embedding_json_b = embedding_to_json(&embedding_b)?;

        conn.execute(
            "INSERT INTO preferences (id, agent_id, content, embedding, category, last_updated)\n             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "pref-a",
                "agent",
                "alpha",
                embedding_blob_a,
                "style",
                1i64
            ],
        )?;
        let rowid_a = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid_a, embedding_json_a],
        )?;

        conn.execute(
            "INSERT INTO preferences (id, agent_id, content, embedding, category, last_updated)\n             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                "pref-b",
                "agent",
                "beta",
                embedding_blob_b,
                "style",
                1i64
            ],
        )?;
        let rowid_b = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO preferences_vec (rowid, embedding) VALUES (?1, ?2)",
            params![rowid_b, embedding_json_b],
        )?;

        let query_json = embedding_to_json(&embedding_a)?;
        let mut stmt = conn.prepare(
            "SELECT p.id FROM preferences_vec v\n             JOIN preferences p ON p.rowid = v.rowid\n             WHERE v.embedding MATCH ?1 AND k = ?2\n             ORDER BY v.distance ASC",
        )?;
        let rows = stmt.query_map(params![query_json, 2i64], |row| row.get::<_, String>(0))?;
        let mut ids = Vec::new();
        for row in rows {
            if let Ok(id) = row {
                ids.push(id);
            }
        }
        assert_eq!(ids.first().map(String::as_str), Some("pref-a"));
        Ok(())
    }
}
