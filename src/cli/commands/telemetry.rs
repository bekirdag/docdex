use crate::cli::http_client::CliHttpClient;
use crate::config;
use crate::llm::local_library::{
    load_local_library, refresh_local_library_if_stale, LocalModelLibrary,
};
use anyhow::Result;
use chrono::{TimeZone, Utc};
use reqwest::Method;
use serde::Deserialize;

#[derive(Deserialize)]
struct DelegationSavingsPricing {
    configured_primary_usd_per_million_tokens: f64,
    configured_local_usd_per_million_tokens: f64,
    effective_avoided_primary_usd_per_million_tokens: Option<f64>,
    effective_local_usd_per_million_tokens: Option<f64>,
}

#[derive(Deserialize)]
struct DelegationSavingsResponse {
    generated_at_epoch_ms: i64,
    delegate_requests_total: u64,
    delegate_offloaded_total: u64,
    delegate_fallbacks_total: u64,
    delegate_token_estimate_total: u64,
    delegate_local_tokens_total: u64,
    delegate_primary_tokens_total: u64,
    delegate_tokens_total: u64,
    delegate_token_savings_total: u64,
    delegate_local_cost_micros_total: u64,
    delegate_primary_cost_micros_total: u64,
    delegate_avoided_primary_cost_micros_total: u64,
    delegate_avoided_primary_cost_usd: f64,
    delegate_cost_savings_micros_total: u64,
    delegate_cost_savings_usd: f64,
    pricing: DelegationSavingsPricing,
}

pub(crate) async fn run(command: crate::cli::DelegationCommand) -> Result<()> {
    match command {
        crate::cli::DelegationCommand::Savings { repo, all, json } => {
            run_savings(repo, all, json).await
        }
        crate::cli::DelegationCommand::Agents { json } => run_agents(json).await,
    }
}

async fn run_savings(repo: crate::config::RepoArgs, all: bool, json: bool) -> Result<()> {
    let client = CliHttpClient::new()?;
    let req = if all {
        client
            .request(Method::GET, "/v1/telemetry/delegation")
            .query(&[("all", "true")])
    } else {
        let repo_root = repo.repo_root();
        client.ensure_repo(&repo_root).await?;
        let req = client.request(Method::GET, "/v1/telemetry/delegation");
        client.with_repo(req, &repo_root)?
    };
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd delegation savings failed ({}): {}", status, text);
    }
    if json {
        let value: serde_json::Value = serde_json::from_str(&text)?;
        println!("{}", serde_json::to_string_pretty(&value)?);
    } else {
        let response: DelegationSavingsResponse = serde_json::from_str(&text)?;
        println!("{}", render_delegation_savings_table(&response));
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

fn render_delegation_savings_table(response: &DelegationSavingsResponse) -> String {
    let rows = vec![
        (
            "Requests".to_string(),
            format_u64(response.delegate_requests_total),
        ),
        (
            "Offloaded".to_string(),
            format_u64(response.delegate_offloaded_total),
        ),
        (
            "Fallbacks".to_string(),
            format_u64(response.delegate_fallbacks_total),
        ),
        (
            "Token Estimate".to_string(),
            format_u64(response.delegate_token_estimate_total),
        ),
        (
            "Local Tokens".to_string(),
            format_u64(response.delegate_local_tokens_total),
        ),
        (
            "Primary Tokens".to_string(),
            format_u64(response.delegate_primary_tokens_total),
        ),
        (
            "Total Tokens".to_string(),
            format_u64(response.delegate_tokens_total),
        ),
        (
            "Token Savings".to_string(),
            format_u64(response.delegate_token_savings_total),
        ),
        (
            "Local Cost".to_string(),
            format_cost(response.delegate_local_cost_micros_total),
        ),
        (
            "Primary Cost".to_string(),
            format_cost(response.delegate_primary_cost_micros_total),
        ),
        (
            "Avoided Primary Cost".to_string(),
            format!(
                "{} ({} micros)",
                format_usd(response.delegate_avoided_primary_cost_usd),
                format_u64(response.delegate_avoided_primary_cost_micros_total)
            ),
        ),
        (
            "Cost Savings".to_string(),
            format!(
                "{} ({} micros)",
                format_usd(response.delegate_cost_savings_usd),
                format_u64(response.delegate_cost_savings_micros_total)
            ),
        ),
        (
            "Effective Local Rate".to_string(),
            format_opt_rate(response.pricing.effective_local_usd_per_million_tokens),
        ),
        (
            "Effective Avoided Rate".to_string(),
            format_opt_rate(
                response
                    .pricing
                    .effective_avoided_primary_usd_per_million_tokens,
            ),
        ),
        (
            "Configured Local Rate".to_string(),
            format_rate(response.pricing.configured_local_usd_per_million_tokens),
        ),
        (
            "Configured Primary Rate".to_string(),
            format_rate(response.pricing.configured_primary_usd_per_million_tokens),
        ),
        (
            "Generated At".to_string(),
            format_generated_at(response.generated_at_epoch_ms),
        ),
    ];

    render_boxed_kv_table("METRIC", "VALUE", &rows)
}

fn render_boxed_kv_table(
    left_header: &str,
    right_header: &str,
    rows: &[(String, String)],
) -> String {
    let left_width = std::iter::once(left_header)
        .chain(rows.iter().map(|(label, _)| label.as_str()))
        .map(display_width)
        .max()
        .unwrap_or(0);
    let right_width = std::iter::once(right_header)
        .chain(rows.iter().map(|(_, value)| value.as_str()))
        .map(display_width)
        .max()
        .unwrap_or(0);

    let mut lines = Vec::with_capacity(rows.len() + 4);
    lines.push(format!(
        "╭{}┬{}╮",
        "─".repeat(left_width + 2),
        "─".repeat(right_width + 2)
    ));
    lines.push(format!(
        "│ {} │ {} │",
        pad_right(left_header, left_width),
        pad_right(right_header, right_width)
    ));
    lines.push(format!(
        "├{}┼{}┤",
        "─".repeat(left_width + 2),
        "─".repeat(right_width + 2)
    ));
    for (label, value) in rows {
        lines.push(format!(
            "│ {} │ {} │",
            pad_right(label, left_width),
            pad_left(value, right_width)
        ));
    }
    lines.push(format!(
        "╰{}┴{}╯",
        "─".repeat(left_width + 2),
        "─".repeat(right_width + 2)
    ));
    lines.join("\n")
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

fn display_width(value: &str) -> usize {
    value.chars().count()
}

fn pad_right(value: &str, width: usize) -> String {
    format!(
        "{}{}",
        value,
        " ".repeat(width.saturating_sub(display_width(value)))
    )
}

fn pad_left(value: &str, width: usize) -> String {
    format!(
        "{}{}",
        " ".repeat(width.saturating_sub(display_width(value))),
        value
    )
}

fn format_u64(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + (digits.len() / 3));
    for (idx, ch) in digits.chars().enumerate() {
        if idx > 0 && (digits.len() - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn format_cost(micros: u64) -> String {
    format!(
        "{} ({} micros)",
        format_usd(micros as f64 / 1_000_000.0),
        format_u64(micros)
    )
}

fn format_usd(value: f64) -> String {
    format!("${}", format_float_with_precision(value, 6))
}

fn format_rate(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        return "-".to_string();
    }
    format!("${}/1M", format_float_with_precision(value, 4))
}

fn format_opt_rate(value: Option<f64>) -> String {
    value.map(format_rate).unwrap_or_else(|| "-".to_string())
}

fn format_generated_at(epoch_ms: i64) -> String {
    match Utc.timestamp_millis_opt(epoch_ms).single() {
        Some(timestamp) => timestamp.to_rfc3339(),
        None => epoch_ms.to_string(),
    }
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
    format_float_with_precision(value, 2)
}

fn format_float_with_precision(value: f64, precision: usize) -> String {
    if !value.is_finite() {
        return "-".to_string();
    }
    let mut formatted = format!("{value:.precision$}");
    while formatted.ends_with('0') {
        formatted.pop();
    }
    if formatted.ends_with('.') {
        formatted.pop();
    }
    formatted
}

#[cfg(test)]
mod tests {
    use super::{
        render_delegation_savings_table, DelegationSavingsPricing, DelegationSavingsResponse,
    };

    #[test]
    fn render_delegation_savings_table_uses_box_drawing_output() {
        let response = DelegationSavingsResponse {
            generated_at_epoch_ms: 1_772_971_367_124,
            delegate_requests_total: 4,
            delegate_offloaded_total: 4,
            delegate_fallbacks_total: 0,
            delegate_token_estimate_total: 692,
            delegate_local_tokens_total: 610,
            delegate_primary_tokens_total: 0,
            delegate_tokens_total: 610,
            delegate_token_savings_total: 610,
            delegate_local_cost_micros_total: 426,
            delegate_primary_cost_micros_total: 0,
            delegate_avoided_primary_cost_micros_total: 1_646,
            delegate_avoided_primary_cost_usd: 0.001646,
            delegate_cost_savings_micros_total: 1_220,
            delegate_cost_savings_usd: 0.00122,
            pricing: DelegationSavingsPricing {
                configured_primary_usd_per_million_tokens: 0.0,
                configured_local_usd_per_million_tokens: 0.0,
                effective_avoided_primary_usd_per_million_tokens: Some(2.6983606557),
                effective_local_usd_per_million_tokens: Some(0.6983606557),
            },
        };

        let rendered = render_delegation_savings_table(&response);

        assert!(rendered.starts_with("╭"));
        assert!(rendered.contains("│ METRIC"));
        assert!(rendered.contains("Token Savings"));
        assert!(rendered.contains("Avoided Primary Cost"));
        assert!(rendered.contains("Effective Avoided Rate"));
        assert!(rendered.contains("610"));
        assert!(rendered.ends_with("╯"));
    }
}
