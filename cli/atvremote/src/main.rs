//! `atvremote` — command line remote control for Apple TV and AirPlay devices.
//!
//! A thin shell over the `pyatv` crate, mirroring the subcommand surface of pyatv's own
//! `atvremote` and, under `--json`, the output schema of its `atvscript`. All protocol logic lives
//! in the library crates; this binary only parses arguments, sets up tracing and formats output.

mod cli;
mod commands;
mod json;
mod report;

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
        // Always stderr. Upstream's `atvremote` logs to stdout (`atvremote.py:697-702`) and its
        // `atvscript` refuses to log anywhere but a file, "to make sure output always has the
        // specified format" (`atvscript.py:385-392`). One stream for results and one for
        // diagnostics gives both guarantees without a mode switch.
        .with_writer(std::io::stderr)
        .init();

    match commands::run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            report(&cli, &error);
            ExitCode::from(FAILURE)
        }
    }
}

/// Print a failure the way a command-line tool should.
///
/// Under `--json` it is one more envelope on stdout, so a supervising process gets a parseable line
/// for a failure as well as for a success — which is the whole point of `atvscript`'s `result`
/// key, and what its top-level `except` emits (`atvscript.py:416-417`).
///
/// In text mode, returning the `anyhow::Error` from `main` would print it with `Debug`, which
/// decorates the message with `Error:` and a `Caused by:` block. The two failures a user meets
/// routinely — a capability no connected protocol serves, and credentials the device refused —
/// deserve one plain line each instead, matching what upstream logs (`atvremote.py:975-979`).
/// Everything else keeps the full chain, because for an unexpected failure that chain is the
/// diagnosis.
fn report(cli: &Cli, error: &anyhow::Error) {
    if cli.is_json() {
        json::emit(failure_envelope(error));
        return;
    }

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

/// The JSON form of a failure.
///
/// The two `error` strings upstream defines are the closed vocabulary
/// (`docs/documentation/atvscript.md:31`): `device_not_found` when nothing answered the scan
/// (`atvscript.py:289`) and `unsupported_command` when the capability is absent
/// (`atvscript.py:336`). Anything else is an `exception`, as it is upstream.
fn failure_envelope(error: &anyhow::Error) -> json::Envelope {
    let envelope = json::Envelope::failure();

    if matches!(
        error.downcast_ref::<pyatv::Error>(),
        Some(pyatv::Error::NotSupported(_))
    ) {
        return envelope.error("unsupported_command").exception(error);
    }
    if error.chain().any(|cause| {
        let message = cause.to_string();
        message.contains("no device found") || message.contains("devices, use --id")
    }) {
        return envelope.error("device_not_found").exception(error);
    }

    envelope.exception(error)
}
