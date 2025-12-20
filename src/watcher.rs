use crate::index::{self, Indexer};
use anyhow::Result;
use notify::event::{ModifyKind, RemoveKind};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const WATCH_QUEUE_LIMIT: usize = 512;
const WATCH_BACKPRESSURE_REASON: &str = "watcher_backpressure";

#[derive(Debug)]
enum WatchAction {
    Upsert(PathBuf),
    Delete(PathBuf),
}

#[derive(Default)]
struct WatchBackpressure {
    dropped: AtomicUsize,
}

impl WatchBackpressure {
    fn record_drop(&self) -> bool {
        let previous = self.dropped.fetch_add(1, Ordering::SeqCst);
        previous == 0
    }

    fn take_dropped(&self) -> usize {
        self.dropped.swap(0, Ordering::SeqCst)
    }
}

pub fn spawn(indexer: Arc<Indexer>) -> Result<()> {
    let repo_root = indexer.repo_root().to_path_buf();
    let config = indexer.config().clone();
    let backpressure = Arc::new(WatchBackpressure::default());
    let (tx, mut rx) = mpsc::channel::<WatchAction>(WATCH_QUEUE_LIMIT);
    start_blocking_watcher(repo_root.clone(), config, tx, backpressure.clone())?;
    info!(
        target: "docdexd",
        repo = %repo_root.display(),
        "docdex file watcher active"
    );
    tokio::spawn(async move {
        while let Some(action) = rx.recv().await {
            let dropped = backpressure.take_dropped();
            if dropped > 0 {
                if let Err(err) = indexer.mark_stale(WATCH_BACKPRESSURE_REASON, Some(dropped as u64)) {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        dropped,
                        "failed to mark index stale after watcher overflow"
                    );
                }
            }
            let idx = indexer.clone();
            match action {
                WatchAction::Upsert(path) => {
                    match idx.ingest_file(path.clone()).await {
                        Ok(decision) => {
                            if decision.should_index() {
                                debug!(
                                    target: "docdexd",
                                    file = %path.display(),
                                    "indexed modified document"
                                );
                            } else {
                                debug!(
                                    target: "docdexd",
                                    file = %path.display(),
                                    reason = ?decision.reason,
                                    "skipped file change"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                file = %path.display(),
                                "failed to ingest file change"
                            );
                        }
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
    tx: mpsc::Sender<WatchAction>,
    backpressure: Arc<WatchBackpressure>,
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
                if let Err(err) = handle_event(&repo_root, &config, &tx, &backpressure, res) {
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
    tx: &mpsc::Sender<WatchAction>,
    backpressure: &WatchBackpressure,
    result: Result<Event, notify::Error>,
) -> Result<(), notify::Error> {
    let event = result?;
    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any) => {
            for path in &event.paths {
                if !should_track_path(path, repo_root, config, false) {
                    continue;
                }
                if let Err(err) = tx.try_send(WatchAction::Upsert(path.clone())) {
                    if err.is_full() && backpressure.record_drop() {
                        warn!(
                            target: "docdexd",
                            queue_limit = WATCH_QUEUE_LIMIT,
                            "watcher queue full; marking index stale until reindex"
                        );
                    }
                    if err.is_closed() {
                        return Ok(());
                    }
                }
            }
        }
        EventKind::Modify(ModifyKind::Name(_)) => {
            if let Some(old) = event.paths.get(0) {
                if should_track_path(old, repo_root, config, true) {
                    if let Err(err) = tx.try_send(WatchAction::Delete(old.clone())) {
                        if err.is_full() && backpressure.record_drop() {
                            warn!(
                                target: "docdexd",
                                queue_limit = WATCH_QUEUE_LIMIT,
                                "watcher queue full; marking index stale until reindex"
                            );
                        }
                    }
                }
            }
            if let Some(new_path) = event.paths.get(1) {
                if should_track_path(new_path, repo_root, config, false) {
                    if let Err(err) = tx.try_send(WatchAction::Upsert(new_path.clone())) {
                        if err.is_full() && backpressure.record_drop() {
                            warn!(
                                target: "docdexd",
                                queue_limit = WATCH_QUEUE_LIMIT,
                                "watcher queue full; marking index stale until reindex"
                            );
                        }
                    }
                }
            }
        }
        EventKind::Remove(RemoveKind::Any | RemoveKind::File | RemoveKind::Folder) => {
            for path in &event.paths {
                if !should_track_path(path, repo_root, config, true) {
                    continue;
                }
                if let Err(err) = tx.try_send(WatchAction::Delete(path.clone())) {
                    if err.is_full() && backpressure.record_drop() {
                        warn!(
                            target: "docdexd",
                            queue_limit = WATCH_QUEUE_LIMIT,
                            "watcher queue full; marking index stale until reindex"
                        );
                    }
                    if err.is_closed() {
                        return Ok(());
                    }
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
