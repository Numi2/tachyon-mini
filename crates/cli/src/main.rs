//! Tachyon CLI binary

use anyhow::Result;
use cli::run;

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}
