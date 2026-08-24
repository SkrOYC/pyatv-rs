//! Subcommand dispatch.
//!
//! Each arm resolves a device, connects, calls one library method and formats the result. Keeping
//! the formatting here rather than in the library is deliberate: `pyatv` returns typed values, and
//! only the CLI should be deciding how they look on a terminal.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{Result, bail};
use pyatv::ScanOptions;

use crate::cli::{Cli, Command};

/// Run whichever subcommand was requested.
///
/// # Errors
///
/// Propagates any library error, plus "no matching device found" when `--id` does not resolve.
pub async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::Scan => scan(&cli).await,
        // TODO(step-1): implement the remaining subcommands once `pyatv::connect` returns a live
        // facade. Each is: resolve device -> connect -> call one trait method -> print.
        _ => bail!("subcommand not implemented yet"),
    }
}

/// Discover devices and print one line per device, then one per service.
async fn scan(cli: &Cli) -> Result<()> {
    let options = ScanOptions {
        timeout: Duration::from_secs(cli.scan_timeout),
        identifiers: cli.id.iter().cloned().collect::<HashSet<_>>(),
        protocols: HashSet::new(),
        hosts: cli.scan_hosts.clone(),
    };

    for device in pyatv::scan(options).await? {
        println!("{}: {}", device.name, device.address);
        for service in &device.services {
            println!("  {:?} port {}", service.protocol, service.port);
        }
    }

    Ok(())
}
