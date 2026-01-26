use crate::llm::delegation_rating::{compute_agent_update, AgentRatingState, AgentRatingUpdate};
use crate::mcoda::registry::default_db_path;
use anyhow::{anyhow, Context, Result};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::Path;
use tracing::warn;
use uuid::Uuid;

pub struct AgentRunRating {
    pub agent_id: String,
    pub command_name: String,
    pub discipline: Option<String>,
    pub complexity: i64,
    pub quality_score: f64,
    pub tokens_total: u64,
    pub duration_seconds: f64,
    pub iterations: i64,
    pub total_cost: f64,
    pub run_score: f64,
    pub rating_version: String,
    pub raw_review_json: Option<String>,
    pub created_at: String,
}

pub struct RatingResult {
    pub update: AgentRatingUpdate,
    pub run_id: Option<String>,
}

pub fn apply_agent_rating_default(
    agent_id: &str,
    run: &AgentRunRating,
    rating_window: u32,
    now: &str,
) -> Result<Option<RatingResult>> {
    let db_path = default_db_path()?;
    if !db_path.exists() {
        return Ok(None);
    }
    apply_agent_rating(&db_path, agent_id, run, rating_window, now)
}

pub fn apply_agent_rating(
    db_path: &Path,
    agent_id: &str,
    run: &AgentRunRating,
    rating_window: u32,
    now: &str,
) -> Result<Option<RatingResult>> {
    if !db_path.exists() {
        return Ok(None);
    }
    let conn = Connection::open(db_path)
        .with_context(|| format!("open mcoda db {}", db_path.display()))?;
    let agent_columns = table_columns(&conn, "agents")?;
    if agent_columns.is_empty() {
        return Ok(None);
    }
    let state = load_agent_state(&conn, agent_id, &agent_columns)?
        .ok_or_else(|| anyhow!("mcoda agent not found: {agent_id}"))?;
    let update = compute_agent_update(
        &state,
        run.run_score,
        run.quality_score,
        run.complexity,
        now,
        rating_window,
    );
    apply_agent_update(&conn, agent_id, &update, &agent_columns)?;
    let run_id = insert_run_rating(&conn, run).unwrap_or_else(|err| {
        warn!(
            target: "docdexd",
            error = ?err,
            "failed to insert mcoda agent run rating"
        );
        None
    });
    Ok(Some(RatingResult { update, run_id }))
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            params![table],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    Ok(exists)
}

fn table_columns(conn: &Connection, table: &str) -> Result<HashSet<String>> {
    if !table_exists(conn, table)? {
        return Ok(HashSet::new());
    }
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({})", table))?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = HashSet::new();
    for row in rows {
        columns.insert(row?);
    }
    Ok(columns)
}

fn load_agent_state(
    conn: &Connection,
    agent_id: &str,
    columns: &HashSet<String>,
) -> Result<Option<AgentRatingState>> {
    let rating_sql = if columns.contains("rating") {
        "rating"
    } else {
        "NULL"
    };
    let reasoning_sql = if columns.contains("reasoning_rating") {
        "reasoning_rating"
    } else {
        "NULL"
    };
    let samples_sql = if columns.contains("rating_samples") {
        "rating_samples"
    } else {
        "NULL"
    };
    let complexity_sql = if columns.contains("max_complexity") {
        "max_complexity"
    } else {
        "NULL"
    };
    let complexity_samples_sql = if columns.contains("complexity_samples") {
        "complexity_samples"
    } else {
        "NULL"
    };
    let complexity_updated_sql = if columns.contains("complexity_updated_at") {
        "complexity_updated_at"
    } else {
        "NULL"
    };
    let sql = format!(
        "SELECT {rating_sql} as rating,
                {reasoning_sql} as reasoning_rating,
                {samples_sql} as rating_samples,
                {complexity_sql} as max_complexity,
                {complexity_samples_sql} as complexity_samples,
                {complexity_updated_sql} as complexity_updated_at
         FROM agents
         WHERE id = ?1"
    );
    conn.query_row(&sql, params![agent_id], |row| {
        Ok(AgentRatingState {
            rating: row.get::<_, Option<f64>>(0)?,
            reasoning_rating: row.get::<_, Option<f64>>(1)?,
            rating_samples: row.get::<_, Option<i64>>(2)?,
            max_complexity: row.get::<_, Option<i64>>(3)?,
            complexity_samples: row.get::<_, Option<i64>>(4)?,
            complexity_updated_at: row.get::<_, Option<String>>(5)?,
        })
    })
    .optional()
    .map_err(|err| err.into())
}

fn apply_agent_update(
    conn: &Connection,
    agent_id: &str,
    update: &AgentRatingUpdate,
    columns: &HashSet<String>,
) -> Result<()> {
    let mut updates: Vec<&str> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();

    if columns.contains("rating") {
        updates.push("rating = ?");
        params.push(update.rating.into());
    }
    if columns.contains("reasoning_rating") {
        updates.push("reasoning_rating = ?");
        params.push(update.reasoning_rating.into());
    }
    if columns.contains("rating_samples") {
        updates.push("rating_samples = ?");
        params.push(update.rating_samples.into());
    }
    if columns.contains("rating_last_score") {
        updates.push("rating_last_score = ?");
        params.push(update.rating_last_score.into());
    }
    if columns.contains("rating_updated_at") {
        updates.push("rating_updated_at = ?");
        params.push(update.rating_updated_at.clone().into());
    }
    if columns.contains("max_complexity") {
        updates.push("max_complexity = ?");
        params.push(update.max_complexity.into());
    }
    if columns.contains("complexity_samples") {
        updates.push("complexity_samples = ?");
        params.push(update.complexity_samples.into());
    }
    if columns.contains("complexity_updated_at") {
        updates.push("complexity_updated_at = ?");
        match &update.complexity_updated_at {
            Some(value) => params.push(value.clone().into()),
            None => params.push(SqlValue::Null),
        }
    }

    if updates.is_empty() {
        return Ok(());
    }
    let sql = format!("UPDATE agents SET {} WHERE id = ?", updates.join(", "));
    params.push(agent_id.to_string().into());
    conn.execute(&sql, rusqlite::params_from_iter(params))?;
    Ok(())
}

fn insert_run_rating(conn: &Connection, run: &AgentRunRating) -> Result<Option<String>> {
    let columns = table_columns(conn, "agent_run_ratings")?;
    if columns.is_empty() {
        return Ok(None);
    }
    let required = [
        "id",
        "agent_id",
        "command_name",
        "complexity",
        "quality_score",
        "tokens_total",
        "duration_seconds",
        "iterations",
        "total_cost",
        "run_score",
        "rating_version",
        "raw_review_json",
        "created_at",
    ];
    if required.iter().any(|name| !columns.contains(*name)) {
        warn!(
            target: "docdexd",
            "agent_run_ratings missing required columns; skipping insert"
        );
        return Ok(None);
    }

    let id = Uuid::new_v4().to_string();
    let mut fields: Vec<&str> = Vec::new();
    let mut params: Vec<SqlValue> = Vec::new();
    let mut push_field = |name: &'static str, value: SqlValue| {
        if columns.contains(name) {
            fields.push(name);
            params.push(value);
        }
    };

    push_field("id", id.clone().into());
    push_field("agent_id", run.agent_id.clone().into());
    push_field("job_id", SqlValue::Null);
    push_field("command_run_id", SqlValue::Null);
    push_field("task_id", SqlValue::Null);
    push_field("task_key", SqlValue::Null);
    push_field("command_name", run.command_name.clone().into());
    match &run.discipline {
        Some(value) => push_field("discipline", value.clone().into()),
        None => push_field("discipline", SqlValue::Null),
    }
    push_field("complexity", run.complexity.into());
    push_field("quality_score", run.quality_score.into());
    push_field("tokens_total", (run.tokens_total as i64).into());
    push_field("duration_seconds", run.duration_seconds.into());
    push_field("iterations", run.iterations.into());
    push_field("total_cost", run.total_cost.into());
    push_field("run_score", run.run_score.into());
    push_field("rating_version", run.rating_version.clone().into());
    match &run.raw_review_json {
        Some(value) => push_field("raw_review_json", value.clone().into()),
        None => push_field("raw_review_json", SqlValue::Null),
    }
    push_field("created_at", run.created_at.clone().into());

    if fields.is_empty() {
        return Ok(None);
    }

    let placeholders = vec!["?"; fields.len()].join(", ");
    let sql = format!(
        "INSERT INTO agent_run_ratings ({}) VALUES ({})",
        fields.join(", "),
        placeholders
    );
    conn.execute(&sql, rusqlite::params_from_iter(params))?;
    Ok(Some(id))
}
