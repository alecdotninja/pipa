//! Binary entrypoint for the jump server.

/// Starts the jump server binary.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    pipa::run().await
}
