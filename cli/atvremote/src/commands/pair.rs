//! The `pair` subcommand.
//!
//! Follows `AtvRemote.pair` and `_perform_pairing` (`pyatv/scripts/atvremote.py:162-238`) step for
//! step, including the prompt wording and the two lines printed on success, so that anyone moving
//! between the two tools sees the same thing.

use anyhow::{Context, Result, bail};
use pyatv::Protocol;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::cli::Cli;
use crate::commands::{open_storage, resolve_device};

/// The prompt upstream shows when the device displays the PIN
/// (`pyatv/scripts/atvremote.py:214`).
const PIN_PROMPT: &str = "Enter PIN on screen: ";

/// Pair one protocol on one device.
///
/// # Errors
///
/// Fails if no single device matches, if the device does not advertise the protocol, or if the
/// device rejects the PIN.
pub async fn run(cli: &Cli, protocol: Protocol) -> Result<()> {
    let config = resolve_device(cli).await?;
    let storage = std::sync::Arc::new(open_storage(cli)?);

    let handler = pyatv::pair(&config, protocol, storage).await?;

    // The connection is closed either way, exactly as upstream's `finally` does
    // (`pyatv/scripts/atvremote.py:203-205`).
    let outcome = perform(cli, handler.as_ref()).await;
    handler.close().await?;
    outcome
}

/// Drive the handler through the PIN exchange and report the result.
async fn perform(cli: &Cli, handler: &dyn pyatv::PairingHandler) -> Result<()> {
    // `begin` is what puts the PIN on the device's screen, so nothing may be read from stdin
    // before it returns.
    handler.begin().await?;

    if !handler.device_provides_pin() {
        // No pyatv pairing handler reports `false` today, so this is unreachable in practice; it
        // exists because the trait allows it and silently doing nothing would be worse.
        bail!("this protocol expects the controller to display a PIN, which is not implemented");
    }

    let pin = read_pin(PIN_PROMPT).await?;
    handler.pin(pin)?;
    handler.finish().await?;

    if handler.has_paired() {
        println!("Pairing seems to have succeeded, yey!");
        let credentials = handler
            .service()
            .credentials
            .unwrap_or_else(|| "None".to_owned());
        println!("You may now use these credentials: {credentials}");
        if cli.verbose > 0 {
            eprintln!("Credentials were saved to the settings file.");
        }
    } else {
        println!("Pairing failed!");
    }

    Ok(())
}

/// Prompt on stderr and read a PIN from stdin.
///
/// The prompt goes to stderr so that `atvremote … pair > file` still shows it, while the two
/// success lines stay on stdout where they can be captured.
async fn read_pin(prompt: &str) -> Result<u32> {
    use std::io::Write as _;

    eprint!("{prompt}");
    // `eprint!` does not flush, and the prompt has no trailing newline to trigger one.
    std::io::stderr().flush().ok();

    let mut line = String::new();
    let read = BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await
        .context("could not read the PIN from stdin")?;

    if read == 0 {
        bail!("no PIN was entered");
    }

    line.trim()
        .parse()
        .with_context(|| format!("{:?} is not a numeric PIN", line.trim()))
}
