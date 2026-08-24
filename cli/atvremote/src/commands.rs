//! Subcommand dispatch.
//!
//! Each arm resolves a device, connects, calls one library method and formats the result. Keeping
//! the formatting here rather than in the library is deliberate: `pyatv` returns typed values, and
//! only the CLI should be deciding how they look on a terminal.

mod pair;

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use pyatv::{BaseConfig, ScanOptions};

use crate::cli::{Cli, Command};

/// Run whichever subcommand was requested.
///
/// # Errors
///
/// Propagates any library error, plus "no matching device found" when `--id` does not resolve.
pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Scan => scan(&cli).await,
        Command::Pair { protocol } => pair::run(&cli, (*protocol).into()).await,
        // TODO(step-1): implement the remaining subcommands once `pyatv::connect` returns a live
        // facade. Each is: resolve device -> connect -> call one trait method -> print.
        _ => bail!("subcommand not implemented yet"),
    }
}

/// Scan options built from the global flags, shared by every subcommand that needs a device.
fn scan_options(cli: &Cli) -> ScanOptions {
    ScanOptions {
        timeout: Duration::from_secs(cli.scan_timeout),
        identifiers: cli.id.iter().cloned().collect::<HashSet<_>>(),
        protocols: HashSet::new(),
        hosts: cli.scan_hosts.clone(),
    }
}

/// Discover devices and print each one.
///
/// `BaseConfig`'s `Display` is `pyatv/interface.py:1448-1463` verbatim, which is exactly what
/// upstream's `atvremote scan` prints — so the formatting belongs there, not here.
async fn scan(cli: &Cli) -> Result<()> {
    for device in pyatv::scan(scan_options(cli)).await? {
        println!("{device}");
    }

    Ok(())
}

/// Find the one device a command should act on.
///
/// Mirrors `_scan_for_device` (`pyatv/scripts/atvremote.py:399-424`): scan, then require exactly
/// one match. Upstream errors out when `--id` is absent and more than one device answered, rather
/// than picking arbitrarily, and so does this.
pub async fn resolve_device(cli: &Cli) -> Result<BaseConfig> {
    let mut devices = pyatv::scan(scan_options(cli)).await?;

    match devices.len() {
        0 => bail!("no device found"),
        1 => Ok(devices.remove(0)),
        _ => {
            let identifiers: Vec<&str> = devices
                .iter()
                .filter_map(pyatv::BaseConfig::identifier)
                .collect();
            bail!(
                "found {} devices, use --id to pick one: {}",
                devices.len(),
                identifiers.join(", ")
            )
        }
    }
}

/// Open the credential store the global flags point at.
///
/// Defaults to `$HOME/.pyatv.conf`, the same path pyatv's own `FileStorage` uses, so a file written
/// by either implementation is readable by the other.
pub fn open_storage(cli: &Cli) -> Result<pyatv::FileStorage> {
    let path = match &cli.storage_filename {
        Some(path) => path.clone(),
        None => pyatv::FileStorage::default_path()
            .context("could not determine the default settings file path")?,
    };

    Ok(pyatv::FileStorage::new(path))
}
