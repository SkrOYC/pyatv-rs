//! The subcommands that need a live connection.
//!
//! Each one is the same four steps upstream's `_handle_device_command` performs
//! (`pyatv/scripts/atvremote.py:889-951`): resolve a device, connect, call one interface method,
//! print the result — and then close, which upstream does in its own `finally`
//! (`atvremote.py:880-883`).
//!
//! [`run`] owns the connection; [`dispatch`] owns the routing, and is re-entered by the `cli` REPL
//! for each line it reads, which is why the two are separate.

use std::sync::Arc;

use anyhow::{Context, Result};
use pyatv::AppleTV;

use crate::cli::{Cli, Command};
use crate::commands::{apply_overrides, open_storage, resolve_device};
use crate::commands::{apps, audio, buttons, media, repl, settings};
use crate::report::Reporter;

/// Connect and run whichever connection-requiring subcommand was asked for.
///
/// The close is unconditional and its failure is reported separately from the command's, so a
/// device that will not shut down cleanly cannot swallow the answer the user asked for.
///
/// # Errors
///
/// Propagates connection failures, plus [`pyatv::Error::NotSupported`] when no connected protocol
/// implements the capability the subcommand needs.
pub async fn run(cli: &Cli, reporter: Reporter) -> Result<()> {
    let storage = open_storage(cli)?;
    let mut config = resolve_device(cli, storage.as_ref()).await?;
    apply_overrides(cli, &mut config);

    // `connect(config, loop, protocol=args.protocol, ...)` (`atvremote.py:866`) — the global
    // `--protocol` restricts the connection to one protocol rather than setting all of them up.
    let protocol = cli.protocol.map(Into::into);
    let atv = pyatv::connect(&config, protocol, Arc::clone(&storage))
        .await
        .with_context(|| format!("could not connect to {}", config.name))?;

    let outcome = dispatch(cli, &cli.command, atv.as_ref(), reporter).await;

    if let Err(error) = atv.close().await {
        tracing::debug!(%error, "the device did not close cleanly");
    }
    // Credentials learned during the session, and any identifier the connection filled in, are
    // written out the way upstream's `finally` does (`atvremote.py:735-736`).
    if let Err(error) = storage.save() {
        tracing::warn!(%error, "the settings file could not be written");
    }
    outcome
}

/// Route one command to the module that implements it.
///
/// The grouping is upstream's priority order (`atvremote.py:889-951`), with one consequence worth
/// naming: `volume_up` and `volume_down` reach [`pyatv::Audio`], not [`pyatv::RemoteControl`],
/// because `audio` is tested before `ctrl` upstream and the comment there says why
/// (`atvremote.py:914-915`).
pub async fn dispatch(
    cli: &Cli,
    command: &Command,
    atv: &dyn AppleTV,
    reporter: Reporter,
) -> Result<()> {
    match command {
        // Device-level facts.
        Command::DeviceInfo => {
            reporter.device_info(atv.device_info());
            Ok(())
        }
        Command::Features { all } => {
            reporter.features(&atv.features().all_features(*all));
            Ok(())
        }

        // Buttons and gestures.
        Command::Remote { button, args } => buttons::run(atv, button, args, reporter).await,

        // Power.
        Command::TurnOn | Command::TurnOff | Command::PowerState => {
            apps::power(atv, command, reporter).await
        }

        // Apps, accounts and the on-screen keyboard.
        Command::AppList
        | Command::LaunchApp { .. }
        | Command::AccountList
        | Command::SwitchAccount { .. }
        | Command::TextFocusState
        | Command::TextGet
        | Command::TextSet { .. }
        | Command::TextAppend { .. }
        | Command::TextClear => apps::run(atv, command, reporter).await,

        // Volume and output devices.
        Command::Volume
        | Command::SetVolume { .. }
        | Command::OutputDevices
        | Command::AddOutputDevices { .. }
        | Command::RemoveOutputDevices { .. }
        | Command::SetOutputDevices { .. } => audio::run(atv, command, reporter).await,

        // Metadata, artwork, push updates and streaming.
        Command::Playing
        | Command::App
        | Command::DeviceId
        | Command::Artwork { .. }
        | Command::ArtworkId
        | Command::PushUpdates { .. }
        | Command::PlayUrl { .. }
        | Command::StreamFile { .. } => media::run(atv, command, reporter).await,

        // Settings, reachable from inside the REPL as well as from the command line.
        Command::PrintSettings
        | Command::ChangeSetting { .. }
        | Command::UnsetSetting { .. }
        | Command::RemoveSettings => settings::run_connected(cli, command, reporter),

        Command::Delay { milliseconds } => {
            // `asyncio.sleep(float(delay_time) / 1000.0)` (`atvremote.py:467-470`).
            tokio::time::sleep(std::time::Duration::from_millis(*milliseconds)).await;
            reporter.acknowledge("delay");
            Ok(())
        }

        // Boxed because the REPL re-enters this function for every line it reads, and a recursive
        // `async fn` has no finite size without indirection. It is also the one command that
        // cannot legitimately appear here — the REPL refuses to re-enter itself
        // (`atvremote.py:402-404`) — but the recursion is through `dispatch`, not through this arm.
        Command::Cli => Box::pin(repl::run(cli, atv, reporter)).await,

        Command::Scan | Command::Pair | Command::Commands => {
            unreachable!("dispatched before a connection is needed")
        }
    }
}
