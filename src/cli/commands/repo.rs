use crate::cli::http_client::CliHttpClient;
use crate::error;
use crate::repo_manager;
use anyhow::{Context, Result};
use reqwest::Method;
use serde_json::json;
use std::path::Path;
use std::process::Command;

pub(crate) async fn run(command: super::super::RepoCommand) -> Result<()> {
    match command {
        super::super::RepoCommand::Init { repo } => {
            run_init(repo).await?;
        }
        super::super::RepoCommand::Id { repo } => {
            run_id(repo)?;
        }
        super::super::RepoCommand::Status { repo } => {
            run_status(repo)?;
        }
        super::super::RepoCommand::Dirty { repo, exit_code } => {
            run_dirty(repo, exit_code)?;
        }
        super::super::RepoCommand::Reassociate {
            repo,
            fingerprint,
            old_path,
        } => {
            let repo_root = repo.repo_root();
            let Some(state_dir) = repo.state_dir_override() else {
                return Err(error::AppError::new(
                    error::ERR_INVALID_ARGUMENT,
                    "`repo reassociate` requires an explicit shared --state-dir base directory",
                )
                .into());
            };
            let state_dir = if state_dir.is_absolute() {
                state_dir
            } else {
                repo_root.join(state_dir)
            };

            match repo_manager::reassociate_repo_path(
                &repo_root,
                &state_dir,
                fingerprint.as_deref(),
                old_path.as_deref(),
            ) {
                Ok(result) => println!("{}", serde_json::to_string_pretty(&result)?),
                Err(err) => {
                    if let Some(identity) = err.downcast_ref::<repo_manager::RepoIdentityError>() {
                        let normalized = repo_root.to_string_lossy().replace('\\', "/");
                        let attempted = repo_manager::repo_fingerprint_sha256(&repo_root).ok();
                        let mut known_canonical: Option<String> = None;
                        let mut code = error::ERR_REPO_STATE_MISMATCH;
                        let mut message = "repo re-association refused".to_string();
                        let mut extra_details: Option<serde_json::Value> = None;

                        match identity {
                            repo_manager::RepoIdentityError::AmbiguousOldPath {
                                old_path,
                                candidate_fingerprints,
                            } => {
                                code = error::ERR_INVALID_ARGUMENT;
                                message = "ambiguous old path; multiple candidates".to_string();
                                extra_details = Some(json!({
                                    "oldPath": old_path,
                                    "candidateFingerprints": candidate_fingerprints,
                                }));
                            }
                            repo_manager::RepoIdentityError::UnknownFingerprint { .. } => {
                                code = error::ERR_INVALID_ARGUMENT;
                                message =
                                    "unknown fingerprint; no registry entry found".to_string();
                            }
                            repo_manager::RepoIdentityError::ReassociationRequired {
                                registered_canonical_path,
                                ..
                            } => {
                                known_canonical = Some(registered_canonical_path.clone());
                            }
                            repo_manager::RepoIdentityError::CanonicalPathCollision {
                                canonical_path,
                                ..
                            } => {
                                known_canonical = Some(canonical_path.clone());
                            }
                            _ => {}
                        }

                        let mut steps = vec![
                            "Verify `--repo` points at the moved repo's current path.".to_string(),
                            "Verify `--state-dir` points at the same shared base directory used previously."
                                .to_string(),
                        ];
                        if matches!(
                            identity,
                            repo_manager::RepoIdentityError::AmbiguousOldPath { .. }
                        ) {
                            steps.push(
                                "Re-run with `--fingerprint <sha256>` to select the intended repo entry."
                                    .to_string(),
                            );
                        }

                        let mut details = error::repo_resolution_details(
                            normalized,
                            attempted,
                            known_canonical,
                            steps,
                        );
                        if let (Some(extra), Some(obj)) = (extra_details, details.as_object_mut()) {
                            if let Some(extra_obj) = extra.as_object() {
                                for (k, v) in extra_obj {
                                    obj.insert(k.clone(), v.clone());
                                }
                            }
                        }
                        return Err(error::AppError::new(code, message)
                            .with_details(details)
                            .into());
                    }
                    return Err(err);
                }
            }
        }
        super::super::RepoCommand::Inspect { repo } => {
            let repo_root = repo.repo_root();
            let state_dir = repo.state_dir_override();
            let report = repo_manager::inspect_repo(&repo_root, state_dir.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }
    Ok(())
}

fn run_id(repo: crate::config::RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let repo_id = repo_manager::repo_fingerprint_sha256(&repo_root)?;
    let payload = json!({
        "repo_id": repo_id,
        "repo_root": repo_root.to_string_lossy().replace('\\', "/"),
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn run_status(repo: crate::config::RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let output = git_status_porcelain(&repo_root)?;
    let files = parse_porcelain_paths(&output);
    let payload = json!({
        "dirty": !files.is_empty(),
        "files": files,
        "repo_root": repo_root.to_string_lossy().replace('\\', "/"),
    });
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn run_dirty(repo: crate::config::RepoArgs, exit_code: bool) -> Result<()> {
    let repo_root = repo.repo_root();
    let output = git_status_porcelain(&repo_root)?;
    let dirty = !parse_porcelain_paths(&output).is_empty();
    let status = if dirty { "dirty" } else { "clean" };
    println!("{status}");
    if dirty && exit_code {
        std::process::exit(1);
    }
    Ok(())
}

async fn run_init(repo: crate::config::RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    let root_uri = format!("file://{}", repo_root.display());
    let payload = json!({ "rootUri": root_uri });
    let mut req = client
        .request(Method::POST, "/v1/initialize")
        .json(&payload);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd initialize failed ({}): {}", status, body);
    }
    let value: serde_json::Value = serde_json::from_str(&body)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn git_status_porcelain(repo_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("status")
        .arg("--porcelain=v1")
        .current_dir(repo_root)
        .output()
        .context("run git status --porcelain=v1")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.trim();
        if message.is_empty() {
            anyhow::bail!("git status failed with exit {}", output.status);
        }
        anyhow::bail!("git status failed: {message}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn parse_porcelain_paths(output: &str) -> Vec<String> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                return None;
            }
            let rest = if trimmed.len() > 3 {
                &trimmed[3..]
            } else {
                trimmed
            };
            let path = rest.split(" -> ").last().unwrap_or(rest).trim();
            if path.is_empty() {
                None
            } else {
                Some(path.to_string())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::parse_porcelain_paths;
    use crate::repo_manager;
    use anyhow::Result;

    #[test]
    fn repo_id_is_non_empty_for_temp_dir() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo_id = repo_manager::repo_fingerprint_sha256(temp.path())?;
        assert!(!repo_id.trim().is_empty());
        Ok(())
    }

    #[test]
    fn parse_porcelain_paths_handles_basic_statuses() {
        let input = " M src/lib.rs\nA  Cargo.toml\n?? README.md\n";
        let parsed = parse_porcelain_paths(input);
        assert_eq!(parsed, vec!["src/lib.rs", "Cargo.toml", "README.md"]);
    }

    #[test]
    fn parse_porcelain_paths_handles_rename() {
        let input = "R  old/name.txt -> new/name.txt\n";
        let parsed = parse_porcelain_paths(input);
        assert_eq!(parsed, vec!["new/name.txt"]);
    }
}
