//! noirpass process entry point.

use std::process::ExitCode;

mod cli;

#[tokio::main]
async fn main() -> Result<ExitCode, Box<dyn std::error::Error>> {
    cli::run().await
}
