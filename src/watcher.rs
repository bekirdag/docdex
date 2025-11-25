use crate::index::{self, Indexer};
use anyhow::Result;
use notify::event::{ModifyKind, RemoveKind};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Debug)]
enum WatchAction {
    Upsert(PathBuf),
    Delete(PathBuf),
}

pub fn spawn(indexer: Arc<Indexer>) -> Result<()> {
    let repo_root = indexer.repo_root().to_path_buf();
    let config = indexer.config().clone();
    let (tx, mut rx) = mpsc::unbounded_channel::<WatchAction>();
    start_blocking_watcher(repo_root.clone(), config, tx)?;
    info!(
        target: "docdexd",
        repo = %repo_root.display(),
        "docdex file watcher active"
    );
    tokio::spawn(async move {
        while let Some(action) = rx.recv().await {
            let idx = indexer.clone();
            match action {
                WatchAction::Upsert(path) => {
                    if let Err(err) = idx.ingest_file(path.clone()).await {
                        warn!(
                            target: "docdexd",
                            error = ?err,
                            file = %path.display(),
                            "failed to ingest file change"
                        );
                    } else {
                        debug!(
                            target: "docdexd",
                            file = %path.display(),
                            "indexed modified document"
                        );
                    }
                }
                WatchAction::Delete(path) => {
                    if let Err(err) = idx.delete_file(path.clone()).await {
                        warn!(
                            target: "docdexd",
                            error = ?err,
                            file = %path.display(),
                            "failed to remove deleted document from index"
                        );
                    } else {
                        debug!(
                            target: "docdexd",
                            file = %path.display(),
                            "removed deleted document from index"
                        );
                    }
                }
            }
        }
    });
    Ok(())
}

fn start_blocking_watcher(
    repo_root: PathBuf,
    config: index::IndexConfig,
    tx: mpsc::UnboundedSender<WatchAction>,
) -> Result<()> {
    std::thread::Builder::new()
        .name("docdexd-watcher".into())
        .spawn(move || {
            let (event_tx, event_rx) = std::sync::mpsc::channel();
            let watcher_builder = RecommendedWatcher::new(
                move |res| {
                    let _ = event_tx.send(res);
                },
                Config::default(),
            );
            let mut watcher = match watcher_builder {
                Ok(w) => w,
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        repo = %repo_root.display(),
                        "failed to initialise filesystem watcher"
                    );
                    return;
                }
            };
            let _ = watcher
                .configure(Config::default().with_poll_interval(std::time::Duration::from_secs(2)));
            if let Err(err) = watcher.watch(&repo_root, RecursiveMode::Recursive) {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    repo = %repo_root.display(),
                    "failed to watch repository"
                );
                return;
            }
            for res in event_rx {
                if let Err(err) = handle_event(&repo_root, &config, &tx, res) {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        repo = %repo_root.display(),
                        "filesystem watcher error"
                    );
                }
            }
        })?;
    Ok(())
}

fn handle_event(
    repo_root: &Path,
    config: &index::IndexConfig,
    tx: &mpsc::UnboundedSender<WatchAction>,
    result: Result<Event, notify::Error>,
) -> Result<(), notify::Error> {
    let event = result?;
    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any) => {
            for path in &event.paths {
                if !should_track_path(path, repo_root, config, false) {
                    continue;
                }
                if tx.send(WatchAction::Upsert(path.clone())).is_err() {
                    return Ok(());
                }
            }
        }
        EventKind::Modify(ModifyKind::Name(_)) => {
            if let Some(old) = event.paths.get(0) {
                if should_track_path(old, repo_root, config, true) {
                    let _ = tx.send(WatchAction::Delete(old.clone()));
                }
            }
            if let Some(new_path) = event.paths.get(1) {
                if should_track_path(new_path, repo_root, config, false) {
                    let _ = tx.send(WatchAction::Upsert(new_path.clone()));
                }
            }
        }
        EventKind::Remove(RemoveKind::Any | RemoveKind::File | RemoveKind::Folder) => {
            for path in &event.paths {
                if !should_track_path(path, repo_root, config, true) {
                    continue;
                }
                if tx.send(WatchAction::Delete(path.clone())).is_err() {
                    return Ok(());
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn should_track_path(
    path: &Path,
    repo_root: &Path,
    config: &index::IndexConfig,
    allow_missing: bool,
) -> bool {
    if !allow_missing && !path.exists() {
        return false;
    }
    if !path.starts_with(repo_root) {
        return false;
    }
    if !allow_missing && !path.is_file() {
        return false;
    }
    if !index::should_index(path, repo_root, config) {
        return false;
    }
    true
}
