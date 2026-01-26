use crate::cli::http_client::CliHttpClient;
use crate::config;
use crate::llm::local_library::{
    load_local_library, refresh_local_library_if_stale, LocalModelLibrary,
};
use anyhow::Result;
use reqwest::Method;

pub(crate) async fn run(command: crate::cli::DelegationCommand) -> Result<()> {
    match command {
        crate::cli::DelegationCommand::Savings { json } => run_savings(json).await,
        crate::cli::DelegationCommand::Agents { json } => run_agents(json).await,
    }
}

async fn run_savings(json: bool) -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::GET, "/v1/telemetry/delegation")
        .send()
        .await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd delegation savings failed ({}): {}", status, text);
    }
    if json {
        let value: serde_json::Value = serde_json::from_str(&text)?;
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        println!("{text}");
    }
    Ok(())
}

async fn run_agents(json: bool) -> Result<()> {
    let config = config::AppConfig::load_default().unwrap_or_default();
    let state_dir = config.core.global_state_dir.as_deref();
    let llm_config = config.llm;
    let library = match refresh_local_library_if_stale(state_dir, &llm_config, true).await {
        Ok(library) => library,
        Err(err) => {
            eprintln!("[docdex] local model library refresh failed: {err}");
            load_local_library(state_dir)?
        }
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&library)?);
        return Ok(());
    }
    println!("{}", render_delegation_table(&library));
    Ok(())
}

fn render_delegation_table(library: &LocalModelLibrary) -> String {
    let headers = [
        "TYPE",
        "ID/NAME",
        "SLUG",
        "SOURCE",
        "MODEL",
        "CAPABILITIES",
        "CLASS",
        "USAGE",
        "COMPLEXITY",
        "RATING",
        "REASON",
        "COST/$1M",
        "HEALTH",
    ];
    let mut rows: Vec<[String; 13]> = Vec::new();

    let mut agents = library.agents.clone();
    agents.sort_by(|a, b| {
        a.agent_slug
            .cmp(&b.agent_slug)
            .then_with(|| a.agent_id.cmp(&b.agent_id))
    });
    for agent in agents {
        rows.push([
            "agent".to_string(),
            agent.agent_id,
            agent.agent_slug,
            agent.adapter,
            agent.default_model.unwrap_or_else(|| "-".to_string()),
            format_caps(&agent.capabilities),
            normalize_cell(&agent.classification_method),
            format_opt_string(agent.usage.as_deref()),
            format_opt_i64(agent.max_complexity),
            format_opt_f64(agent.rating),
            format_opt_f64(agent.reasoning_rating),
            format_opt_f64(agent.cost_per_million),
            format_opt_string(agent.health_status.as_deref()),
        ]);
    }

    let mut models = library.models.clone();
    models.sort_by(|a, b| a.name.cmp(&b.name));
    for model in models {
        rows.push([
            "model".to_string(),
            model.name,
            "-".to_string(),
            normalize_cell(&model.source),
            "-".to_string(),
            format_caps(&model.capabilities),
            normalize_cell(&model.classification_method),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
        ]);
    }

    if rows.is_empty() {
        return "(no local delegation targets found)".to_string();
    }

    let mut widths = [0usize; 13];
    for (idx, header) in headers.iter().enumerate() {
        widths[idx] = header.len();
    }
    for row in &rows {
        for (idx, cell) in row.iter().enumerate() {
            widths[idx] = widths[idx].max(cell.len());
        }
    }

    let mut lines = Vec::new();
    let header_row: [String; 13] = headers.map(|value| value.to_string());
    lines.push(format_row(&header_row, &widths));
    lines.push(format_separator(&widths));
    for row in rows {
        lines.push(format_row(&row, &widths));
    }
    lines.join("\n")
}

fn format_row(row: &[String], widths: &[usize; 13]) -> String {
    let mut parts = Vec::with_capacity(row.len());
    for (value, width) in row.iter().zip(widths.iter()) {
        parts.push(format!("{:<width$}", value, width = *width));
    }
    parts.join(" | ")
}

fn format_separator(widths: &[usize; 13]) -> String {
    widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<String>>()
        .join("-+-")
}

fn format_caps(caps: &[String]) -> String {
    if caps.is_empty() {
        return "-".to_string();
    }
    let mut values: Vec<&str> = caps.iter().map(|cap| cap.as_str()).collect();
    values.sort_unstable();
    values.join(",")
}

fn normalize_cell(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        "-".to_string()
    } else {
        trimmed.to_string()
    }
}

fn format_opt_string(value: Option<&str>) -> String {
    match value {
        Some(value) => normalize_cell(value),
        None => "-".to_string(),
    }
}

fn format_opt_i64(value: Option<i64>) -> String {
    value
        .map(|number| number.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn format_opt_f64(value: Option<f64>) -> String {
    value.map(format_float).unwrap_or_else(|| "-".to_string())
}

fn format_float(value: f64) -> String {
    if !value.is_finite() {
        return "-".to_string();
    }
    let mut formatted = format!("{:.2}", value);
    while formatted.ends_with('0') {
        formatted.pop();
    }
    if formatted.ends_with('.') {
        formatted.pop();
    }
    formatted
}
