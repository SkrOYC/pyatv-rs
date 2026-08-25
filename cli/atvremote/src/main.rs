//! `atvremote` — command line remote control for Apple TV and AirPlay devices.
//!
//! A thin shell over the `pyatv` crate, mirroring the subcommand surface of pyatv's own
//! `atvremote`. All protocol logic lives in the library crates; this binary only parses arguments,
//! sets up tracing and formats output.

mod cli;
mod commands;

use std::process::ExitCode;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::Cli;

/// Exit status for a command that ran but could not do what was asked.
///
/// `_handle_device_command` returns `1` for both the "not supported by device" and the
/// authentication branches (`pyatv/scripts/atvremote.py:975-979`), and every other failure path in
/// that script does the same.
const FAILURE: u8 = 1;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(cli.log_level())),
        )
        .with_writer(std::io::stderr)
        .init();

    match commands::run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::from(FAILURE)
        }
    }
}

/// Print a failure the way a command-line tool should.
///
/// Returning the `anyhow::Error` from `main` would print it with `Debug`, which decorates the
/// message with `Error:` and a `Caused by:` block. The two failures a user meets routinely — a
/// capability no connected protocol serves, and credentials the device refused — deserve one plain
/// line each instead, matching what upstream logs (`atvremote.py:975-979`). Everything else keeps
/// the full chain, because for an unexpected failure that chain is the diagnosis.
fn report(error: &anyhow::Error) {
    match error.downcast_ref::<pyatv::Error>() {
        Some(pyatv::Error::NotSupported(what)) => {
            eprintln!("Command is not supported by device: {what}");
        }
        Some(pyatv::Error::Authentication(reason)) => {
            eprintln!("Authentication error: {reason}");
        }
        _ => eprintln!("{error:?}"),
    }
}
