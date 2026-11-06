//! Bounded background admission and explicitly scoped resource diagnostics.
use once_cell::sync::Lazy;
use parking_lot::{Condvar, Mutex};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub fn parse_limit(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

pub fn effective_headroom(current: u64, high: Option<u64>, max: Option<u64>) -> Option<u64> {
    high.into_iter()
        .chain(max)
        .min()
        .map(|ceiling| ceiling.saturating_sub(current))
}

#[derive(Default, Clone, Serialize)]
pub struct MemoryPressure {
    pub cgroup: Option<PathBuf>,
    pub current_bytes: Option<u64>,
    pub high_bytes: Option<u64>,
    pub max_bytes: Option<u64>,
    pub headroom_bytes: Option<u64>,
    pub pressured: bool,
    pub events: BTreeMap<String, u64>,
    pub memory_stat: BTreeMap<String, u64>,
}

fn number(path: &Path) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

pub fn counters(path: &Path) -> BTreeMap<String, u64> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.trim_end_matches(':').to_string(),
                fields.next()?.parse().ok()?,
            ))
        })
        .collect()
}

pub fn memory_pressure() -> MemoryPressure {
    let membership = fs::read_to_string("/proc/self/cgroup").unwrap_or_default();
    let Some(relative) = membership.lines().find_map(|line| line.strip_prefix("0::")) else {
        return MemoryPressure::default();
    };
    pressure_at(
        &Path::new("/sys/fs/cgroup").join(relative.trim_start_matches('/')),
        Path::new("/sys/fs/cgroup"),
    )
}

fn pressure_at(leaf: &Path, root: &Path) -> MemoryPressure {
    let mut result = MemoryPressure {
        cgroup: Some(leaf.to_path_buf()),
        current_bytes: number(&leaf.join("memory.current")),
        events: counters(&leaf.join("memory.events")),
        memory_stat: counters(&leaf.join("memory.stat")),
        ..MemoryPressure::default()
    };
    // Ancestors can constrain a unit even when its own limits say `max`.
    for dir in leaf.ancestors().take_while(|dir| dir.starts_with(root)) {
        let high = fs::read_to_string(dir.join("memory.high"))
            .ok()
            .and_then(|v| parse_limit(&v));
        let max = fs::read_to_string(dir.join("memory.max"))
            .ok()
            .and_then(|v| parse_limit(&v));
        result.high_bytes = result.high_bytes.into_iter().chain(high).min();
        result.max_bytes = result.max_bytes.into_iter().chain(max).min();
        if let Some(current) = number(&dir.join("memory.current")) {
            if let Some(headroom) = effective_headroom(current, high, max) {
                result.headroom_bytes = result
                    .headroom_bytes
                    .into_iter()
                    .chain(Some(headroom))
                    .min();
                let ceiling = high.into_iter().chain(max).min().unwrap();
                result.pressured |= headroom < (ceiling / 10).max(64 * 1024 * 1024);
            }
        }
    }
    result
}

static INTERACTIVE: AtomicUsize = AtomicUsize::new(0);
static BACKGROUND: Lazy<(Mutex<usize>, Condvar)> = Lazy::new(|| (Mutex::new(0), Condvar::new()));

pub struct Interactive;
impl Interactive {
    pub fn enter() -> Self {
        INTERACTIVE.fetch_add(1, Ordering::Relaxed);
        Self
    }
}
impl Drop for Interactive {
    fn drop(&mut self) {
        INTERACTIVE.fetch_sub(1, Ordering::Relaxed);
        BACKGROUND.1.notify_all();
    }
}

pub struct Background;
impl Background {
    /// Called only on blocking workers. Bound heavyweight work across repositories.
    /// Interactive work gets a head start; eventual indexing progress is retained.
    pub fn enter() -> Self {
        let started = Instant::now();
        let mut active = BACKGROUND.0.lock();
        loop {
            let pressure = memory_pressure().pressured;
            let limit = if pressure { 1 } else { 2 };
            let interactive = INTERACTIVE.load(Ordering::Relaxed) > 0;
            if *active < limit && (!interactive || started.elapsed() >= Duration::from_millis(250))
            {
                *active += 1;
                return Self;
            }
            BACKGROUND
                .1
                .wait_for(&mut active, Duration::from_millis(50));
        }
    }

    pub fn try_maintenance() -> Option<Self> {
        if INTERACTIVE.load(Ordering::Relaxed) > 0 || memory_pressure().pressured {
            return None;
        }
        let mut active = BACKGROUND.0.lock();
        if *active > 0 {
            return None;
        }
        *active += 1;
        Some(Self)
    }
}
impl Drop for Background {
    fn drop(&mut self) {
        *BACKGROUND.0.lock() -= 1;
        BACKGROUND.1.notify_all();
    }
}

#[derive(Default, Clone, Serialize)]
struct OperationStats {
    calls: u64,
    active: u64,
    elapsed_us: u64,
    max_elapsed_us: u64,
    thread_read_bytes: u64,
    thread_write_bytes: u64,
    thread_rchar: u64,
}

static OPERATIONS: Lazy<Mutex<BTreeMap<String, OperationStats>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Synchronous scopes only: /proc/thread-self/io deltas belong to the same
/// blocking thread, unlike overlapping process deltas from concurrent requests.
pub struct Operation {
    key: String,
    start: Instant,
    io: Option<BTreeMap<String, u64>>,
}
impl Operation {
    pub fn enter(repo: &Path, operation: &str) -> Self {
        Self::start(repo, operation, true)
    }

    /// Async tasks can migrate threads; record time and counts, never thread I/O.
    pub fn asynchronous(scope: &Path, operation: &str) -> Self {
        Self::start(scope, operation, false)
    }

    fn start(repo: &Path, operation: &str, synchronous: bool) -> Self {
        let mut key = format!("{}:{operation}", repo.display());
        let mut stats = OPERATIONS.lock();
        if stats.len() >= 512 && !stats.contains_key(&key) {
            key = "overflow".into();
        }
        let stat = stats.entry(key.clone()).or_default();
        stat.calls += 1;
        stat.active += 1;
        drop(stats);
        Self {
            key,
            start: Instant::now(),
            io: synchronous.then(|| counters(Path::new("/proc/thread-self/io"))),
        }
    }
}
impl Drop for Operation {
    fn drop(&mut self) {
        let end = self
            .io
            .as_ref()
            .map(|_| counters(Path::new("/proc/thread-self/io")))
            .unwrap_or_default();
        let elapsed = self.start.elapsed().as_micros() as u64;
        let mut stats = OPERATIONS.lock();
        let stat = stats.get_mut(&self.key).unwrap();
        stat.active -= 1;
        stat.elapsed_us += elapsed;
        stat.max_elapsed_us = stat.max_elapsed_us.max(elapsed);
        let delta = |key: &str| {
            end.get(key).copied().unwrap_or(0).saturating_sub(
                self.io
                    .as_ref()
                    .and_then(|io| io.get(key))
                    .copied()
                    .unwrap_or(0),
            )
        };
        stat.thread_read_bytes += delta("read_bytes");
        stat.thread_write_bytes += delta("write_bytes");
        stat.thread_rchar += delta("rchar");
    }
}

pub fn diagnostics() -> serde_json::Value {
    serde_json::json!({
        "memory": memory_pressure(),
        "process_io": counters(Path::new("/proc/self/io")),
        "process_memory_kib": counters(Path::new("/proc/self/smaps_rollup")),
        "interactive_requests": INTERACTIVE.load(Ordering::Relaxed),
        "background_operations": *BACKGROUND.0.lock(),
        "operations": OPERATIONS.lock().clone(),
        "io_scope": "operation counters are synchronous calling-thread I/O; nested scopes overlap; Tantivy worker I/O is included only in process totals; no per-repo anonymous heap attribution is inferred"
    })
}

/// Release free glibc arenas after lifecycle cleanup under pressure. This does
/// not evict indexes or live allocations, and is intentionally not per request.
pub fn release_free_memory_under_pressure() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    if memory_pressure().pressured {
        extern "C" {
            fn malloc_trim(pad: usize) -> i32;
        }
        // SAFETY: glibc's allocator maintenance API is thread-safe and takes no pointers.
        unsafe {
            malloc_trim(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_limits_and_over_limit_headroom() {
        assert_eq!(parse_limit(" max\n"), None);
        assert_eq!(parse_limit("0"), Some(0));
        assert_eq!(parse_limit("bad"), None);
        assert_eq!(parse_limit(" 1024\n"), Some(1024));
        assert_eq!(effective_headroom(150, Some(100), Some(200)), Some(0));
        assert_eq!(effective_headroom(50, Some(200), Some(100)), Some(50));
        assert_eq!(effective_headroom(50, None, None), None);
    }
    #[test]
    fn parent_pressure_applies_to_unlimited_child() {
        let temp = tempfile::TempDir::new().unwrap();
        let child = temp.path().join("child");
        fs::create_dir(&child).unwrap();
        for (dir, current, high, max) in [
            (temp.path(), "950000000", "1000000000", "2000000000"),
            (child.as_path(), "100000000", "max", "max"),
        ] {
            fs::write(dir.join("memory.current"), current).unwrap();
            fs::write(dir.join("memory.high"), high).unwrap();
            fs::write(dir.join("memory.max"), max).unwrap();
        }
        let result = pressure_at(&child, temp.path());
        assert!(result.pressured);
        assert_eq!(result.headroom_bytes, Some(50_000_000));
        assert_eq!(result.high_bytes, Some(1_000_000_000));
    }
}
