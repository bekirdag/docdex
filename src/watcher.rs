use crate::index::{self, Indexer};
use anyhow::Result;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

pub fn spawn(indexer: Arc<Indexer>) -> Result<()> {
    let repo_root = indexer.repo_root().to_path_buf();
    let config = indexer.config().clone();
    let (tx, mut rx) = mpsc::unbounded_channel::<PathBuf>();
    start_blocking_watcher(repo_root.clone(), config, tx)?;
    info!(
        target: "docdexd",
        repo = %repo_root.display(),
        "docdex file watcher active"
    );
    tokio::spawn(async move {
        while let Some(path) = rx.recv().await {
            let idx = indexer.clone();
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
    });
    Ok(())
}

fn start_blocking_watcher(
    repo_root: PathBuf,
    config: index::IndexConfig,
    tx: mpsc::UnboundedSender<PathBuf>,
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
                match res {
                    Ok(event) => {
                        if !is_relevant_event(&event) {
                            continue;
                        }
                        for path in event.paths {
                            if !should_track_path(&path, &repo_root, &config) {
                                continue;
                            }
                            if tx.send(path.clone()).is_err() {
                                warn!(
                                    target: "docdexd",
                                    file = %path.display(),
                                    "dropping fs event; channel closed"
                                );
                                return;
                            }
                        }
                    }
                    Err(err) => warn!(
                        target: "docdexd",
                        error = ?err,
                        repo = %repo_root.display(),
                        "filesystem watcher error"
                    ),
                }
            }
        })?;
    Ok(())
}

fn is_relevant_event(event: &Event) -> bool {
    matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
}

fn should_track_path(path: &Path, repo_root: &Path, config: &index::IndexConfig) -> bool {
    if !path.exists() {
        return false;
    }
    if !path.starts_with(repo_root) {
        return false;
    }
    if !path.is_file() {
        return false;
    }
    if !index::should_index(path, repo_root, config) {
        return false;
    }
    true
}
