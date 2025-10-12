//! Tachyon CLI binary

use anyhow::Result;
use cli::run;
use tracing::error;

#[tokio::main]
async fn main() -> Result<()> {
    if let Err(e) = run().await {
        // Map internal errors to a concise user-facing message
        error!(target: "cli", "error: {}", e);
        eprintln!("error: {}", e);
        return Err(e);
    }
    Ok(())
}
