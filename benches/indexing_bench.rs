use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use docdexd::index::{IndexConfig, Indexer};
use std::fs;
use std::time::Duration;
use tempfile::TempDir;

fn build_large_repo(file_count: usize) -> TempDir {
    let repo = TempDir::new().expect("create repo tempdir");
    let src_root = repo.path().join("src");
    fs::create_dir_all(&src_root).expect("create src dir");
    fs::create_dir_all(repo.path().join(".git")).expect("create .git dir");
    for idx in 0..file_count {
        let bucket = idx % 25;
        let dir = src_root.join(format!("mod_{bucket}"));
        fs::create_dir_all(&dir).expect("create module dir");
        let path = dir.join(format!("file_{idx}.rs"));
        fs::write(
            path,
            format!(
                "pub fn f_{idx}() -> usize {{ {idx} }}\nconst TOKEN: &str = \"INDEX_BENCH_TOKEN\";\n"
            ),
        )
        .expect("write file");
    }
    repo
}

fn bench_indexing(c: &mut Criterion) {
    let repo = build_large_repo(1000);
    let repo_root = repo.path().to_path_buf();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");

    let mut group = c.benchmark_group("indexing");
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);
    group.bench_function("reindex_large_repo_1k", |b| {
        b.iter_batched(
            || TempDir::new().expect("create state tempdir"),
            |state_dir| {
                let config = IndexConfig::with_overrides(
                    &repo_root,
                    Some(state_dir.path().to_path_buf()),
                    Vec::new(),
                    Vec::new(),
                    true,
                )
                .expect("index config");
                let indexer =
                    Indexer::with_config(repo_root.clone(), config).expect("indexer");
                rt.block_on(indexer.reindex_all())
                    .expect("reindex");
            },
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(indexing_benches, bench_indexing);
criterion_main!(indexing_benches);
