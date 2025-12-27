use docdexd::memory::MemoryStore;
use serde_json::json;
use std::error::Error;
use std::time::Instant;
use tempfile::TempDir;

fn percentile(sorted: &[u128], p: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let p = p.clamp(0.0, 1.0);
    let idx = ((p * ((sorted.len() - 1) as f64)).ceil() as usize).min(sorted.len() - 1);
    sorted[idx]
}

fn summarize(mut samples_us: Vec<u128>) -> (u128, u128, u128) {
    samples_us.sort_unstable();
    let p50 = percentile(&samples_us, 0.50);
    let p95 = percentile(&samples_us, 0.95);
    let max = *samples_us.last().unwrap_or(&0);
    (p50, p95, max)
}

fn embedding_for(idx: usize, dims: usize) -> Vec<f32> {
    (0..dims)
        .map(|offset| (idx as f32 + offset as f32) * 0.001)
        .collect()
}

/// NFR check: memory recall p95 should remain under 50ms.
/// See `docs/sds/sds.md` (latency: local search p95 < 50ms; memory recall should align).
#[test]
#[ignore]
fn memory_recall_p95_under_50ms() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let store = MemoryStore::new(state_root.path());

    let dims = 8usize;
    let total_items = 400usize;
    for idx in 0..total_items {
        let embedding = embedding_for(idx, dims);
        let content = format!("memory item {}", idx);
        store.store(&content, &embedding, json!({}), idx as i64)?;
    }

    let query_embedding = embedding_for(0, dims);
    for _ in 0..20usize {
        let _ = store.recall(&query_embedding, 5)?;
    }

    let iterations = 200usize;
    let mut samples_us = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = store.recall(&query_embedding, 5)?;
        samples_us.push(start.elapsed().as_micros());
    }

    let (p50, p95, max) = summarize(samples_us);
    eprintln!(
        "memory recall latency: p50={}us p95={}us max={}us ({} items)",
        p50, p95, max, total_items
    );

    if cfg!(debug_assertions) {
        eprintln!(
            "note: perf assertions are enforced in release builds; re-run with `cargo test --release ... -- --ignored --nocapture`"
        );
        return Ok(());
    }

    assert!(
        p95 < 50_000,
        "memory recall p95 {}us exceeds 50ms (see docs/sds/sds.md)",
        p95
    );
    Ok(())
}
