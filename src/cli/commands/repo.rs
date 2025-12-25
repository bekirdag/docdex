use crate::error;
use crate::repo_manager;
use anyhow::Result;
use serde_json::json;

pub(crate) fn run(command: super::super::RepoCommand) -> Result<()> {
    match command {
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
                        if let (Some(extra), Some(obj)) =
                            (extra_details, details.as_object_mut())
                        {
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
