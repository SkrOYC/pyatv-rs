//! Subcommand dispatch.
//!
//! Each arm resolves a device, connects, calls one library method and formats the result. Keeping
//! the formatting here rather than in the library is deliberate: `pyatv` returns typed values, and
//! only the CLI should be deciding how they look on a terminal.

mod device;
mod output;
mod pair;

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use pyatv::{BaseConfig, ScanOptions, Storage as _};

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
        // Everything else needs a live connection; `device` handles the connect/close lifecycle.
        _ => device::run(&cli).await,
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
    let storage = open_storage(cli)?;
    let mut devices = pyatv::scan(scan_options(cli)).await?;
    apply_settings(&storage, &mut devices)?;

    for device in &devices {
        println!("{device}");
    }

    // Discovery may have filed identifiers for devices the settings file had not seen, which
    // upstream persists on the way out (`pyatv/scripts/atvremote.py:736`). A scan that learned
    // nothing new writes nothing.
    storage.save()?;
    Ok(())
}

/// Apply stored credentials to freshly discovered devices.
///
/// `pyatv.scan()` does this itself (`pyatv/__init__.py:94-97`); this port's `scan()` takes no
/// storage argument, so the CLI does it instead. Devices without an identifier are skipped rather
/// than failing the whole scan — upstream never reaches them because it filters on `ready` first.
fn apply_settings(storage: &dyn pyatv::Storage, devices: &mut [BaseConfig]) -> Result<()> {
    for device in devices.iter_mut().filter(|device| device.ready()) {
        let settings = storage
            .get_settings(device)
            .with_context(|| format!("could not read the settings for {}", device.name))?;
        device.apply(&settings);
    }

    Ok(())
}

/// Find the one device a command should act on.
///
/// Mirrors `_scan_for_device` (`pyatv/scripts/atvremote.py:399-424`): scan, then require exactly
/// one match. Upstream errors out when `--id` is absent and more than one device answered, rather
/// than picking arbitrarily, and so does this.
pub async fn resolve_device(cli: &Cli) -> Result<BaseConfig> {
    let storage = open_storage(cli)?;
    let mut devices = pyatv::scan(scan_options(cli)).await?;
    apply_settings(&storage, &mut devices)?;

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

/// Open the credential store the global flags point at, already loaded.
///
/// Defaults to `$HOME/.pyatv.conf`, the same path pyatv's own `FileStorage` uses, and the same
/// bytes, so a file written by either implementation is readable by the other.
///
/// The load happens here rather than at the call site because it is not optional: a `FileStorage`
/// that is saved without having been loaded writes an empty document over the user's credentials.
/// Upstream loads at the same point (`pyatv/scripts/atvremote.py:715-716`).
///
/// # Errors
///
/// Fails if no settings path could be determined, or if the file exists but could not be read or
/// parsed.
pub fn open_storage(cli: &Cli) -> Result<pyatv::FileStorage> {
    let path = match &cli.storage_filename {
        Some(path) => path.clone(),
        None => pyatv::FileStorage::default_path()
            .context("could not determine the default settings file path")?,
    };

    let storage = pyatv::FileStorage::new(path);
    storage
        .load()
        .with_context(|| format!("could not read {}", storage.path().display()))?;

    Ok(storage)
}
