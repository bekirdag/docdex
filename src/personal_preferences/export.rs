use anyhow::Result;
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use rusqlite::{params_from_iter, types::ValueRef, Connection};
use serde_json::{json, Value};

use super::parse_json_value;

pub(super) fn payload_array_len(payload: &Value, key: &str) -> usize {
    payload
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

pub(super) fn export_row_ids(rows: &[Value]) -> Vec<String> {
    rows.iter()
        .filter_map(|row| row.get("id").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn export_table_json(
    conn: &Connection,
    table: &str,
    order_by: &str,
) -> Result<Vec<Value>> {
    let sql = format!("SELECT * FROM {table} ORDER BY {order_by}");
    export_query_json(conn, &sql, &[])
}

pub(super) fn export_table_json_where_any_in(
    conn: &Connection,
    table: &str,
    clauses: &[(&str, Vec<String>)],
    order_by: &str,
) -> Result<Vec<Value>> {
    let active = clauses
        .iter()
        .filter(|(_, values)| !values.is_empty())
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(Vec::new());
    }
    let mut params = Vec::new();
    let mut where_clauses = Vec::new();
    for (column, values) in active {
        let placeholders = std::iter::repeat("?")
            .take(values.len())
            .collect::<Vec<_>>()
            .join(", ");
        where_clauses.push(format!("{column} IN ({placeholders})"));
        params.extend(values.iter().cloned());
    }
    let sql = format!(
        "SELECT * FROM {table} WHERE ({}) ORDER BY {order_by}",
        where_clauses.join(" OR ")
    );
    export_query_json(conn, &sql, &params)
}

pub(super) fn export_table_json_where_like_any(
    conn: &Connection,
    table: &str,
    column: &str,
    needles: &[String],
    order_by: &str,
) -> Result<Vec<Value>> {
    if needles.is_empty() {
        return Ok(Vec::new());
    }
    let mut params = Vec::new();
    let mut clauses = Vec::new();
    for needle in needles {
        clauses.push(format!("{column} LIKE ?"));
        params.push(format!("%{needle}%"));
    }
    let sql = format!(
        "SELECT * FROM {table} WHERE ({}) ORDER BY {order_by}",
        clauses.join(" OR ")
    );
    export_query_json(conn, &sql, &params)
}

fn export_query_json(conn: &Connection, sql: &str, values: &[String]) -> Result<Vec<Value>> {
    let mut stmt = conn.prepare(sql)?;
    let columns = stmt
        .column_names()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let mut rows = stmt.query(params_from_iter(values.iter()))?;
    let mut output = Vec::new();
    while let Some(row) = rows.next()? {
        let mut object = serde_json::Map::new();
        for (idx, column) in columns.iter().enumerate() {
            let key = export_column_key(column);
            let value = export_sql_value(column, row.get_ref(idx)?);
            object.insert(key, value);
        }
        output.push(Value::Object(object));
    }
    Ok(output)
}

fn export_column_key(column: &str) -> String {
    match column {
        "metadata_json" => "metadata".to_string(),
        "change_json" => "change".to_string(),
        "explanation_json" => "explanation".to_string(),
        "trigger_terms_json" => "trigger_terms".to_string(),
        "evidence_claim_ids_json" => "evidence_claim_ids".to_string(),
        _ => column.to_string(),
    }
}

fn export_sql_value(column: &str, value: ValueRef<'_>) -> Value {
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(value) => json!(value),
        ValueRef::Real(value) => json!(value),
        ValueRef::Text(bytes) => {
            let text = String::from_utf8_lossy(bytes).to_string();
            if export_column_is_json(column) {
                parse_json_value(&text)
            } else {
                Value::String(text)
            }
        }
        ValueRef::Blob(bytes) => Value::String(Base64Engine.encode(bytes)),
    }
}

fn export_column_is_json(column: &str) -> bool {
    matches!(
        column,
        "metadata_json"
            | "change_json"
            | "explanation_json"
            | "trigger_terms_json"
            | "evidence_claim_ids_json"
    )
}
