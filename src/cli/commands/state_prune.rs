use anyhow::{Context, Result};

use crate::state_prune::{analyze, apply, format_bytes, ReclaimReason};

pub fn run(apply_changes: bool, json: bool) -> Result<()> {
    let state_base =
        crate::state_paths::default_state_base_dir().context("resolve docdex state directory")?;
    let report = analyze(&state_base).context("analyze docdex state directory")?;

    if !apply_changes {
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
            return Ok(());
        }
        println!("State directory: {}", state_base.display());
        println!(
            "  in use       {:>4} repositories  {:>10}",
            report.live_repos,
            format_bytes(report.live_bytes)
        );
        println!(
            "  orphaned     {:>4} repositories  (repository path no longer exists)",
            report.orphaned()
        );
        println!(
            "  unregistered {:>4} directories   (no registry entry)",
            report.unregistered()
        );
        println!(
            "  reclaimable  {:>26}",
            format_bytes(report.reclaimable_bytes())
        );
        for candidate in report.candidates.iter().take(10) {
            let reason = match candidate.reason {
                ReclaimReason::Orphaned => "orphaned",
                ReclaimReason::Unregistered => "unregistered",
            };
            println!(
                "    {:>10}  {:<12}  {}",
                format_bytes(candidate.bytes),
                reason,
                candidate
                    .repo_path
                    .as_deref()
                    .unwrap_or(&candidate.state_key)
            );
        }
        if report.candidates.len() > 10 {
            println!("    ... and {} more", report.candidates.len() - 10);
        }
        if !report.candidates.is_empty() {
            println!("\nRe-run with --apply to remove them.");
        }
        return Ok(());
    }

    let outcome = apply(&state_base, &report).context("remove reclaimable docdex state")?;
    if json {
        println!("{}", serde_json::to_string_pretty(&outcome)?);
    } else {
        println!(
            "Removed {} directories, reclaimed {}.",
            outcome.removed,
            format_bytes(outcome.removed_bytes)
        );
        for failure in &outcome.failed {
            eprintln!("  failed: {failure}");
        }
    }
    Ok(())
}
