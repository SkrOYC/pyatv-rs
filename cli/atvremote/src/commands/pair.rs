//! The `pair` subcommand.
//!
//! Follows `AtvRemote.pair` and `_perform_pairing` (`pyatv/scripts/atvremote.py:162-238`) step for
//! step, including the prompt wording and the two lines printed on success, so that anyone moving
//! between the two tools sees the same thing.

use anyhow::{Context, Result, bail};
use pyatv::Protocol;
use tokio::io::{AsyncBufReadExt, BufReader};

use crate::cli::Cli;
use crate::commands::{apply_overrides, open_storage, resolve_device};
use crate::report::Reporter;

/// The prompt upstream shows when the device displays the PIN
/// (`pyatv/scripts/atvremote.py:214`).
const PIN_PROMPT: &str = "Enter PIN on screen: ";

/// Pair one protocol on one device.
///
/// The protocol comes from the global `--protocol`, which upstream reads the same way
/// (`atvremote.py:164-166`) and refuses to run without.
///
/// # Errors
///
/// Fails if `--protocol` is missing, if no single device matches, if the device does not advertise
/// the protocol, or if the device rejects the PIN.
pub async fn run(cli: &Cli, reporter: Reporter) -> Result<()> {
    let Some(protocol) = cli.protocol else {
        // `_LOGGER.error("No protocol specified")` (`atvremote.py:164-166`).
        bail!("no protocol specified: pass --protocol");
    };
    let protocol = Protocol::from(protocol);

    let storage = open_storage(cli)?;
    let mut config = resolve_device(cli, storage.as_ref()).await?;
    // A device paired over one protocol while credentials for another are supplied on the command
    // line should still see those; `_autodiscover_device` applies them before pairing too
    // (`atvremote.py:746-783`).
    apply_overrides(cli, &mut config);

    let handler = pyatv::pair(&config, protocol, storage).await?;

    // The connection is closed either way, exactly as upstream's `finally` does
    // (`pyatv/scripts/atvremote.py:203-205`).
    let outcome = perform(cli, handler.as_ref(), reporter).await;
    handler.close().await?;
    outcome
}

/// Drive the handler through the PIN exchange and report the result.
async fn perform(cli: &Cli, handler: &dyn pyatv::PairingHandler, reporter: Reporter) -> Result<()> {
    // `begin` is what puts the PIN on the device's screen, so nothing may be read from stdin
    // before it returns.
    handler.begin().await?;

    if !handler.device_provides_pin() {
        // No pyatv pairing handler reports `false` today, so this is unreachable in practice; it
        // exists because the trait allows it and silently doing nothing would be worse.
        bail!("this protocol expects the controller to display a PIN, which is not implemented");
    }

    // `-p/--pin` (`atvremote.py:617-625`) makes pairing scriptable; without it the prompt is what a
    // user gets, as before.
    let pin = match cli.pin {
        Some(pin) => pin,
        None => read_pin(PIN_PROMPT).await?,
    };
    handler.pin(pin)?;
    handler.finish().await?;

    if handler.has_paired() {
        let credentials = handler.service().credentials;
        if reporter.is_json() {
            // Not an `atvscript` command upstream — it has no `pair` at all — so the two keys are
            // this tool's own, named after the lines the text arm prints.
            crate::json::emit(
                crate::json::Envelope::success()
                    .value("paired", true)
                    .value("credentials", credentials.clone()),
            );
        } else {
            println!("Pairing seems to have succeeded, yey!");
            println!(
                "You may now use these credentials: {}",
                crate::report::optional(credentials.as_deref())
            );
        }

        if cli.is_verbose() {
            eprintln!("Credentials were saved to the settings file.");
        }
    } else if reporter.is_json() {
        crate::json::emit(crate::json::Envelope::failure().value("paired", false));
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
    let _ = std::io::stderr().flush();

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
