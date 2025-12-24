#[tokio::main]
async fn main() {
    if let Err(err) = docdexd::cli::run().await {
        docdexd::cli::render_error_and_exit(err);
    }
}
