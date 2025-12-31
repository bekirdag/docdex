use crate::index::{self, Indexer};
use anyhow::Result;
use notify::event::{CreateKind, ModifyKind, RemoveKind};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

#[derive(Debug)]
enum WatchAction {
    Upsert(PathBuf),
    Delete(PathBuf),
}

pub struct WatcherHandle {
    stop_flag: Arc<AtomicBool>,
    watcher_thread: Option<std::thread::JoinHandle<()>>,
    worker_task: Option<tokio::task::JoinHandle<()>>,
}

impl WatcherHandle {
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(task) = self.worker_task.take() {
            task.abort();
        }
        if let Some(join) = self.watcher_thread.take() {
            std::thread::spawn(move || {
                let _ = join.join();
            });
        }
    }
}

pub fn spawn(indexer: Arc<Indexer>) -> Result<WatcherHandle> {
    let repo_root = indexer.repo_root().to_path_buf();
    let config = indexer.config().clone();
    let stop_flag = Arc::new(AtomicBool::new(false));
    let (tx, mut rx) = mpsc::unbounded_channel::<WatchAction>();
    let watcher_thread = start_blocking_watcher(
        repo_root.clone(),
        config,
        tx,
        stop_flag.clone(),
    )?;
    info!(
        target: "docdexd",
        repo = %repo_root.display(),
        "docdex file watcher active"
    );
    let worker_task = tokio::spawn(async move {
        while let Some(action) = rx.recv().await {
            let idx = indexer.clone();
            match action {
                WatchAction::Upsert(path) => match idx.ingest_file(path.clone()).await {
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
                },
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
    Ok(WatcherHandle {
        stop_flag,
        watcher_thread: Some(watcher_thread),
        worker_task: Some(worker_task),
    })
}

fn start_blocking_watcher(
    repo_root: PathBuf,
    config: index::IndexConfig,
    tx: mpsc::UnboundedSender<WatchAction>,
    stop_flag: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>> {
    let handle = std::thread::Builder::new()
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
            loop {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                match event_rx.recv_timeout(std::time::Duration::from_millis(250)) {
                    Ok(res) => {
                        if let Err(err) = handle_event(&repo_root, &config, &tx, res) {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                repo = %repo_root.display(),
                                "filesystem watcher error"
                            );
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })?;
    Ok(handle)
}

fn handle_event(
    repo_root: &Path,
    config: &index::IndexConfig,
    tx: &mpsc::UnboundedSender<WatchAction>,
    result: Result<Event, notify::Error>,
) -> Result<(), notify::Error> {
    let event = result?;
    let invalidate_map = match &event.kind {
        EventKind::Create(CreateKind::Folder)
        | EventKind::Remove(RemoveKind::Folder)
        | EventKind::Remove(RemoveKind::Any) => true,
        EventKind::Modify(ModifyKind::Name(_)) => event.paths.iter().any(|path| path.is_dir()),
        _ => false,
    };
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
    if invalidate_map {
        if let Err(err) = crate::project_map::invalidate_project_map_cache(config.state_dir()) {
            warn!(
                target: "docdexd",
                error = ?err,
                repo = %repo_root.display(),
                "project map cache invalidation failed"
            );
        }
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
