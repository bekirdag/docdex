use crate::audit;
use crate::hardware;
use crate::config::RepoArgs;
use crate::index;
use crate::search;
use crate::util;
use anyhow::anyhow;
use anyhow::Result;
use std::fs;

const DEFAULT_SELF_CHECK_TERMS: &[&str] = &[
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "API_KEY",
    "PRIVATE KEY",
    "-----BEGIN PRIVATE KEY-----",
];

pub async fn run(
    repo: RepoArgs,
    terms: Vec<String>,
    limit: usize,
    include_default_patterns: bool,
) -> Result<()> {
    let profile = hardware::detect_hardware();
    println!(
        "hardware summary: {}",
        hardware::format_hardware_summary(&profile)
    );
    println!(
        "hardware recommendation: {}",
        profile.recommended_tier()
    );
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let indexer = index::Indexer::with_config_read_only(repo_root.clone(), index_config.clone())?;
    let mut findings = Vec::new();
    let mut all_terms: Vec<String> = terms
        .into_iter()
        .filter(|t| !t.trim().is_empty())
        .map(|t| t.trim().to_string())
        .collect();
    if include_default_patterns {
        for default in DEFAULT_SELF_CHECK_TERMS {
            if !all_terms.iter().any(|t| t.eq_ignore_ascii_case(default)) {
                all_terms.push(default.to_string());
            }
        }
    }
    for term in all_terms {
        let search_limit = limit.saturating_add(1);
        let hits = search::run_query(&indexer, None, &term, search_limit).await?;
        if !hits.hits.is_empty() {
            let more = hits.hits.len() > limit;
            let sample: Vec<String> = hits
                .hits
                .iter()
                .take(limit)
                .map(|hit| hit.rel_path.clone())
                .collect();
            findings.push((term, sample, more));
        }
    }
    if findings.is_empty() {
        let report_path = index_config.state_dir().join("self_check_report.json");
        let empty: Vec<serde_json::Value> = Vec::new();
        let report = serde_json::json!({
            "repo": repo_root,
            "checked_at": chrono::Utc::now().to_rfc3339(),
            "findings": empty,
        });
        let _ = fs::write(&report_path, serde_json::to_string_pretty(&report)?);
        println!("no sensitive terms found (report: {})", report_path.display());
        let _ = audit::AuditLogger::new(index_config.state_dir().join("audit.log"), 5_000_000, 5)
            .map(|logger| logger.log("self_check", "pass", None, None, None, None, None, None));
        return Ok(());
    }
    let report_path = index_config.state_dir().join("self_check_report.json");
    let report = serde_json::json!({
        "repo": repo_root,
        "checked_at": chrono::Utc::now().to_rfc3339(),
        "findings": findings.iter().map(|(term, sample, more)| serde_json::json!({
            "term": term,
            "sample_paths": sample,
            "truncated": *more,
        })).collect::<Vec<_>>(),
    });
    let _ = fs::write(&report_path, serde_json::to_string_pretty(&report)?);
    eprintln!("sensitive terms found (report: {}):", report_path.display());
    for (term, sample, more) in findings {
        let count_hint = if more {
            format!("{}+", sample.len())
        } else {
            sample.len().to_string()
        };
        let mut line = format!(
            "- {term}: {count_hint} hits (sample: {})",
            sample.join(", ")
        );
        if more {
            line.push_str("; more matches exist");
        }
        eprintln!("{line}");
    }
    let _ = audit::AuditLogger::new(index_config.state_dir().join("audit.log"), 5_000_000, 5)
        .map(|logger| {
            logger.log(
                "self_check",
                "fail",
                None,
                None,
                None,
                None,
                None,
                Some("sensitive terms found"),
            )
        });
    Err(anyhow!("sensitive terms detected in index"))
}
