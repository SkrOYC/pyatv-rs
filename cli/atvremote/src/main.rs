//! `atvremote` — command line remote control for Apple TV and AirPlay devices.
//!
//! A thin shell over the `pyatv` crate, mirroring the subcommand surface of pyatv's own
//! `atvremote`. All protocol logic lives in the library crates; this binary only parses arguments,
//! sets up tracing and formats output.

mod cli;
mod commands;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cli.log_level())),
        )
        .with_writer(std::io::stderr)
        .init();

    commands::run(cli).await
}
