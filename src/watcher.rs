use crate::index::{self, Indexer};
use anyhow::{anyhow, Result};
use notify::event::{CreateKind, ModifyKind, RemoveKind, RenameMode};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const WATCH_EVENT_CAPACITY: usize = 256;
const WATCH_ACTION_CAPACITY: usize = 256;
const WATCH_BATCH_MAX_ACTIONS: usize = 256;
const WATCH_BATCH_WINDOW: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq)]
enum WatchAction {
    Upsert(PathBuf),
    Delete(PathBuf),
    Rescan,
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
            let _ = join.join();
        }
    }
}

impl Drop for WatcherHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn spawn(indexer: Arc<Indexer>) -> Result<WatcherHandle> {
    let repo_root = indexer.repo_root().to_path_buf();
    let config = indexer.config().clone();
    let stop_flag = Arc::new(AtomicBool::new(false));
    if config.repo_encryption().is_enabled() {
        info!(
            target: "docdexd",
            repo = %repo_root.display(),
            "docdex file watcher disabled for encrypted repository"
        );
        return Ok(WatcherHandle {
            stop_flag,
            watcher_thread: None,
            worker_task: None,
        });
    }
    let (tx, mut rx) = mpsc::channel::<WatchAction>(WATCH_ACTION_CAPACITY);
    let action_overflowed = Arc::new(AtomicBool::new(false));
    let watcher_thread = start_blocking_watcher(
        repo_root.clone(),
        config,
        tx,
        stop_flag.clone(),
        Arc::clone(&action_overflowed),
    )?;
    info!(
        target: "docdexd",
        repo = %repo_root.display(),
        "docdex file watcher active"
    );
    let worker_task = tokio::spawn(async move {
        while let Some(actions) = next_action_batch(&mut rx, &action_overflowed).await {
            process_action_batch(&indexer, actions).await;
        }
    });
    Ok(WatcherHandle {
        stop_flag,
        watcher_thread: Some(watcher_thread),
        worker_task: Some(worker_task),
    })
}

async fn next_action_batch(
    rx: &mut mpsc::Receiver<WatchAction>,
    overflowed: &AtomicBool,
) -> Option<Vec<WatchAction>> {
    if overflowed.swap(false, Ordering::AcqRel) {
        warn!(
            target: "docdexd",
            "watcher action queue overflowed; reconciling the full index"
        );
        for _ in 0..WATCH_ACTION_CAPACITY {
            if rx.try_recv().is_err() {
                break;
            }
        }
        return Some(vec![WatchAction::Rescan]);
    }

    let first = rx.recv().await?;
    let mut actions = Vec::with_capacity(WATCH_BATCH_MAX_ACTIONS.min(16));
    actions.push(first);
    let deadline = tokio::time::Instant::now() + WATCH_BATCH_WINDOW;
    while actions.len() < WATCH_BATCH_MAX_ACTIONS {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(action)) => actions.push(action),
            Ok(None) | Err(_) => break,
        }
    }
    if overflowed.swap(false, Ordering::AcqRel) {
        warn!(
            target: "docdexd",
            "watcher action queue overflowed while batching; reconciling the full index"
        );
        actions.push(WatchAction::Rescan);
    }
    if actions
        .iter()
        .any(|action| matches!(action, WatchAction::Rescan))
    {
        for _ in 0..WATCH_ACTION_CAPACITY {
            if rx.try_recv().is_err() {
                break;
            }
        }
    }
    Some(coalesce_actions(actions))
}

fn coalesce_actions(actions: Vec<WatchAction>) -> Vec<WatchAction> {
    if actions
        .iter()
        .any(|action| matches!(action, WatchAction::Rescan))
    {
        return vec![WatchAction::Rescan];
    }

    let mut by_path = BTreeMap::new();
    for action in actions {
        let path = match &action {
            WatchAction::Upsert(path) | WatchAction::Delete(path) => path.clone(),
            WatchAction::Rescan => unreachable!("rescan actions returned above"),
        };
        by_path.insert(path, action);
    }

    let mut coalesced = Vec::with_capacity(by_path.len());
    coalesced.extend(
        by_path
            .values()
            .filter(|action| matches!(action, WatchAction::Delete(_)))
            .cloned(),
    );
    coalesced.extend(
        by_path
            .values()
            .filter(|action| matches!(action, WatchAction::Upsert(_)))
            .cloned(),
    );
    coalesced
}

async fn process_action_batch(indexer: &Arc<Indexer>, actions: Vec<WatchAction>) {
    for action in actions {
        let idx = Arc::clone(indexer);
        match action {
            WatchAction::Rescan => {
                if let Err(err) = idx.reindex_all().await {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        repo = %idx.repo_root().display(),
                        "failed to reconcile index after a directory change or watcher overflow"
                    );
                } else {
                    debug!(
                        target: "docdexd",
                        repo = %idx.repo_root().display(),
                        "reconciled index after a directory change or watcher overflow"
                    );
                }
            }
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
}

fn start_blocking_watcher(
    repo_root: PathBuf,
    config: index::IndexConfig,
    tx: mpsc::Sender<WatchAction>,
    stop_flag: Arc<AtomicBool>,
    action_overflowed: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let wait_repo_root = repo_root.clone();
    let watcher_stop_flag = Arc::clone(&stop_flag);
    let handle = std::thread::Builder::new()
        .name("docdexd-watcher".into())
        .spawn(move || {
            let (event_tx, event_rx) = std::sync::mpsc::sync_channel(WATCH_EVENT_CAPACITY);
            let event_overflowed = Arc::new(AtomicBool::new(false));
            let callback_overflowed = Arc::clone(&event_overflowed);
            let watcher_builder = RecommendedWatcher::new(
                move |res| match event_tx.try_send(res) {
                    Ok(()) => {}
                    Err(std::sync::mpsc::TrySendError::Full(_)) => {
                        callback_overflowed.store(true, Ordering::Release);
                    }
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
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
                    let _ = ready_tx.send(Err(format!(
                        "failed to initialise filesystem watcher for {}: {err}",
                        repo_root.display()
                    )));
                    return;
                }
            };
            let _ = watcher.configure(Config::default().with_poll_interval(Duration::from_secs(2)));
            if let Err(err) = watcher.watch(&repo_root, RecursiveMode::Recursive) {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    repo = %repo_root.display(),
                    "failed to watch repository"
                );
                let _ = ready_tx.send(Err(format!(
                    "failed to watch repository {}: {err}",
                    repo_root.display()
                )));
                return;
            }
            let _ = ready_tx.send(Ok(()));
            loop {
                if watcher_stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                if event_overflowed.swap(false, Ordering::AcqRel) {
                    warn!(
                        target: "docdexd",
                        repo = %repo_root.display(),
                        "filesystem event queue overflowed; scheduling a full index reconciliation"
                    );
                    for _ in 0..WATCH_EVENT_CAPACITY {
                        if event_rx.try_recv().is_err() {
                            break;
                        }
                    }
                    if !enqueue_action(&tx, &action_overflowed, WatchAction::Rescan) {
                        break;
                    }
                }
                match event_rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(res) => {
                        if let Err(err) =
                            handle_event(&repo_root, &config, &tx, &action_overflowed, res)
                        {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                repo = %repo_root.display(),
                                "filesystem watcher error"
                            );
                            if !enqueue_action(&tx, &action_overflowed, WatchAction::Rescan) {
                                break;
                            }
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        })?;
    match ready_rx.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(message)) => {
            stop_flag.store(true, Ordering::Relaxed);
            let _ = handle.join();
            Err(anyhow!(message))
        }
        Err(err) => {
            stop_flag.store(true, Ordering::Relaxed);
            if handle.is_finished() {
                let _ = handle.join();
            }
            Err(anyhow!(
                "filesystem watcher for {} did not become ready: {err}",
                wait_repo_root.display()
            ))
        }
    }
}

fn handle_event(
    repo_root: &Path,
    config: &index::IndexConfig,
    tx: &mpsc::Sender<WatchAction>,
    action_overflowed: &AtomicBool,
    result: Result<Event, notify::Error>,
) -> Result<(), notify::Error> {
    let event = result?;
    let reconcile_all = event_requires_full_reconcile(&event, repo_root, config);
    let invalidate_map = reconcile_all;
    if reconcile_all {
        let _ = enqueue_action(tx, action_overflowed, WatchAction::Rescan);
    }
    match &event.kind {
        _ if reconcile_all => {}
        EventKind::Create(_) | EventKind::Modify(ModifyKind::Data(_) | ModifyKind::Any) => {
            for path in &event.paths {
                if !should_track_path(path, repo_root, config, false) {
                    continue;
                }
                if !enqueue_action(tx, action_overflowed, WatchAction::Upsert(path.clone())) {
                    return Ok(());
                }
            }
        }
        EventKind::Modify(ModifyKind::Name(mode)) => {
            if !matches!(mode, RenameMode::To) {
                if let Some(old) = event.paths.first() {
                    if should_track_path(old, repo_root, config, true) {
                        let _ =
                            enqueue_action(tx, action_overflowed, WatchAction::Delete(old.clone()));
                    }
                }
            }
            let new_path = if matches!(mode, RenameMode::To) {
                event.paths.first()
            } else {
                event.paths.get(1)
            };
            if let Some(new_path) = new_path {
                if should_track_path(new_path, repo_root, config, false) {
                    let _ = enqueue_action(
                        tx,
                        action_overflowed,
                        WatchAction::Upsert(new_path.clone()),
                    );
                }
            }
        }
        EventKind::Remove(RemoveKind::File) => {
            for path in &event.paths {
                if should_track_path(path, repo_root, config, true)
                    && !enqueue_action(tx, action_overflowed, WatchAction::Delete(path.clone()))
                {
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

fn enqueue_action(
    tx: &mpsc::Sender<WatchAction>,
    overflowed: &AtomicBool,
    action: WatchAction,
) -> bool {
    match tx.try_send(action) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(_)) => {
            overflowed.store(true, Ordering::Release);
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn event_requires_full_reconcile(
    event: &Event,
    repo_root: &Path,
    config: &index::IndexConfig,
) -> bool {
    if event.need_rescan() {
        return true;
    }

    let touches_tracked_tree = event
        .paths
        .iter()
        .any(|path| should_track_subtree(path, repo_root, config));
    if matches!(event.kind, EventKind::Any) {
        return event.paths.is_empty() || touches_tracked_tree;
    }
    if !touches_tracked_tree {
        return false;
    }

    match event.kind {
        EventKind::Create(CreateKind::Folder) => true,
        EventKind::Create(_) => event.paths.iter().any(|path| path.is_dir()),
        EventKind::Modify(ModifyKind::Any) => {
            event.paths.iter().any(|path| path.is_dir())
                || event.paths.iter().any(|path| !path.exists())
        }
        EventKind::Modify(ModifyKind::Name(mode)) => rename_requires_full_reconcile(event, mode),
        EventKind::Remove(RemoveKind::Any | RemoveKind::Folder | RemoveKind::Other) => true,
        _ => false,
    }
}

fn rename_requires_full_reconcile(event: &Event, mode: RenameMode) -> bool {
    if event.paths.iter().any(|path| path.is_dir()) {
        return true;
    }

    match mode {
        RenameMode::Both | RenameMode::Any | RenameMode::Other if event.paths.len() >= 2 => {
            !event.paths[1].is_file()
        }
        RenameMode::To => event
            .paths
            .first()
            .map(|path| !path.is_file())
            .unwrap_or(true),
        RenameMode::From | RenameMode::Any | RenameMode::Other | RenameMode::Both => true,
    }
}

fn should_track_subtree(path: &Path, repo_root: &Path, config: &index::IndexConfig) -> bool {
    if path.starts_with(config.state_dir()) || !path.starts_with(repo_root) {
        return false;
    }
    let Ok(relative) = path.strip_prefix(repo_root) else {
        return false;
    };
    if let Some(matcher) = config.ignore_matcher() {
        if matcher.is_ignored(path, true) {
            return false;
        }
    }
    let normalized = relative
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_lowercase();
    if config
        .excluded_relative_prefixes()
        .iter()
        .any(|prefix| normalized.starts_with(prefix))
    {
        return false;
    }
    !relative.components().any(|component| match component {
        Component::Normal(name) => {
            let name = name.to_string_lossy().to_lowercase();
            config
                .excluded_dir_names()
                .iter()
                .any(|excluded| excluded == &name)
        }
        _ => false,
    })
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

#[cfg(test)]
mod tests {
    use super::{
        coalesce_actions, enqueue_action, handle_event, next_action_batch, process_action_batch,
        spawn, WatchAction,
    };
    use crate::index::{IndexConfig, Indexer};
    use crate::repo_encryption::{
        RepoEncryptionConfig, RepoEncryptionMode, DEFAULT_REPO_ENCRYPTION_KEY_ENV,
    };
    use anyhow::Result;
    use notify::event::{Flag, ModifyKind, RemoveKind, RenameMode};
    use notify::{Event, EventKind};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    const TEST_KEY: &str = "01234567890123456789012345678901";

    #[test]
    fn encrypted_repos_do_not_start_filesystem_watcher() -> Result<()> {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV, TEST_KEY);
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let mut repo_encryption = RepoEncryptionConfig {
            encryption_mode: RepoEncryptionMode::ApplicationManagedEncryption,
            ..RepoEncryptionConfig::default()
        };
        repo_encryption.apply_defaults();
        let config = IndexConfig::with_overrides(
            repo.path(),
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )?
        .with_repo_encryption(repo_encryption);
        let indexer = std::sync::Arc::new(Indexer::with_config(repo.path().to_path_buf(), config)?);

        let mut handle = spawn(indexer)?;

        assert!(handle.watcher_thread.is_none());
        assert!(handle.worker_task.is_none());
        handle.stop();
        std::env::remove_var(DEFAULT_REPO_ENCRYPTION_KEY_ENV);
        Ok(())
    }

    #[test]
    fn watcher_startup_reports_watch_registration_failure() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let config = test_index_config(&repo, &state_root)?;
        let missing_repo = repo.path().to_path_buf();
        drop(repo);
        let (tx, _rx) = mpsc::channel(1);

        let error = super::start_blocking_watcher(
            missing_repo,
            config,
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
        .expect_err("missing repository must fail watcher startup");

        assert!(error.to_string().contains("failed to watch repository"));
        Ok(())
    }

    #[test]
    fn bounded_action_overflow_requests_reconciliation() {
        let (tx, _rx) = mpsc::channel(1);
        let overflowed = AtomicBool::new(false);
        let first = PathBuf::from("first.md");
        let second = PathBuf::from("second.md");

        assert!(enqueue_action(&tx, &overflowed, WatchAction::Upsert(first)));
        assert!(enqueue_action(
            &tx,
            &overflowed,
            WatchAction::Upsert(second)
        ));
        assert!(overflowed.load(Ordering::Acquire));
    }

    #[test]
    fn coalescing_keeps_the_last_action_per_path() {
        let first = PathBuf::from("first.md");
        let second = PathBuf::from("second.md");
        let actions = vec![
            WatchAction::Upsert(first.clone()),
            WatchAction::Delete(second.clone()),
            WatchAction::Delete(first.clone()),
            WatchAction::Upsert(second.clone()),
        ];

        assert_eq!(
            coalesce_actions(actions),
            vec![WatchAction::Delete(first), WatchAction::Upsert(second)]
        );
    }

    #[test]
    fn reconciliation_supersedes_incremental_actions() {
        let actions = vec![
            WatchAction::Upsert(PathBuf::from("first.md")),
            WatchAction::Rescan,
            WatchAction::Delete(PathBuf::from("second.md")),
        ];

        assert_eq!(coalesce_actions(actions), vec![WatchAction::Rescan]);
    }

    #[test]
    fn directory_remove_enqueues_full_reconciliation() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let removed = repo.path().join("docs");
        fs::create_dir_all(&removed)?;
        let config = test_index_config(&repo, &state_root)?;
        fs::remove_dir_all(&removed)?;
        let (tx, mut rx) = mpsc::channel(4);
        let overflowed = AtomicBool::new(false);
        let event = Event::new(EventKind::Remove(RemoveKind::Folder)).add_path(removed);

        handle_event(repo.path(), &config, &tx, &overflowed, Ok(event))?;

        assert_eq!(rx.try_recv()?, WatchAction::Rescan);
        Ok(())
    }

    #[test]
    fn directory_rename_enqueues_full_reconciliation() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let old = repo.path().join("old-docs");
        let new = repo.path().join("new-docs");
        fs::create_dir_all(&old)?;
        let config = test_index_config(&repo, &state_root)?;
        fs::rename(&old, &new)?;
        let (tx, mut rx) = mpsc::channel(4);
        let overflowed = AtomicBool::new(false);
        let event = Event::new(EventKind::Modify(ModifyKind::Name(RenameMode::Both)))
            .add_path(old)
            .add_path(new);

        handle_event(repo.path(), &config, &tx, &overflowed, Ok(event))?;

        assert_eq!(rx.try_recv()?, WatchAction::Rescan);
        Ok(())
    }

    #[test]
    fn notify_rescan_flag_enqueues_full_reconciliation() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let config = test_index_config(&repo, &state_root)?;
        let (tx, mut rx) = mpsc::channel(4);
        let overflowed = AtomicBool::new(false);
        let event = Event::new(EventKind::Other).set_flag(Flag::Rescan);

        handle_event(repo.path(), &config, &tx, &overflowed, Ok(event))?;

        assert_eq!(rx.try_recv()?, WatchAction::Rescan);
        Ok(())
    }

    #[test]
    fn excluded_directory_remove_does_not_reconcile() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let config = test_index_config(&repo, &state_root)?;
        let (tx, mut rx) = mpsc::channel(4);
        let overflowed = AtomicBool::new(false);
        let event =
            Event::new(EventKind::Remove(RemoveKind::Folder)).add_path(repo.path().join(".git"));

        handle_event(repo.path(), &config, &tx, &overflowed, Ok(event))?;

        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn closed_action_channel_stops_batch_worker() {
        let (tx, mut rx) = mpsc::channel(1);
        let overflowed = AtomicBool::new(false);
        drop(tx);

        assert!(next_action_batch(&mut rx, &overflowed).await.is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overflow_reconciliation_discards_stale_queued_actions() {
        let (tx, mut rx) = mpsc::channel(2);
        tx.try_send(WatchAction::Upsert(PathBuf::from("first.md")))
            .expect("first action should fit");
        tx.try_send(WatchAction::Delete(PathBuf::from("second.md")))
            .expect("second action should fit");
        let overflowed = AtomicBool::new(true);

        assert_eq!(
            next_action_batch(&mut rx, &overflowed).await,
            Some(vec![WatchAction::Rescan])
        );
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn imprecise_notify_event_enqueues_full_reconciliation() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let config = test_index_config(&repo, &state_root)?;
        let (tx, mut rx) = mpsc::channel(4);
        let overflowed = AtomicBool::new(false);

        handle_event(
            repo.path(),
            &config,
            &tx,
            &overflowed,
            Ok(Event::new(EventKind::Any)),
        )?;

        assert_eq!(rx.try_recv()?, WatchAction::Rescan);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn full_reconciliation_removes_descendant_documents() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let docs = repo.path().join("docs");
        let nested = docs.join("nested.md");
        fs::create_dir_all(&docs)?;
        fs::write(&nested, "# Nested\nWATCHER_DIRECTORY_RECONCILE\n")?;
        let config = test_index_config(&repo, &state_root)?;
        let indexer = Arc::new(Indexer::with_config(repo.path().to_path_buf(), config)?);
        indexer.reindex_all().await?;
        let (before, _) = indexer.list_docs(0, 100)?;
        assert!(before.iter().any(|doc| doc.rel_path == "docs/nested.md"));
        fs::remove_dir_all(&docs)?;

        process_action_batch(&indexer, vec![WatchAction::Rescan]).await;

        let (after, _) = indexer.list_docs(0, 100)?;
        assert!(!after.iter().any(|doc| doc.rel_path == "docs/nested.md"));
        Ok(())
    }

    fn test_index_config(repo: &TempDir, state_root: &TempDir) -> Result<IndexConfig> {
        IndexConfig::with_overrides(
            repo.path(),
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )
    }
}
