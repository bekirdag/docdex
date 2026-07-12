fn main() {
    let result = if cfg!(windows) {
        let runner = std::thread::Builder::new()
            .name("docdexd-main".to_string())
            .stack_size(8 * 1024 * 1024)
            .spawn(run_with_runtime);
        match runner {
            Ok(handle) => match handle.join() {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("docdexd main thread panicked")),
            },
            Err(_) => run_with_runtime(),
        }
    } else {
        run_with_runtime()
    };

    if let Err(err) = result {
        docdexd::cli::render_error_and_exit(err);
    }
}

fn run_with_runtime() -> Result<(), anyhow::Error> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(anyhow::Error::from)?;
    let result = runtime.block_on(docdexd::cli::run());
    // Detached blocking work must not keep a terminating daemon resident
    // indefinitely after its bounded HTTP drain and resource cleanup complete.
    runtime.shutdown_timeout(std::time::Duration::from_secs(2));
    result
}
