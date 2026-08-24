//! The subcommands that need a live connection.
//!
//! Each one is the same four steps upstream's `_handle_device_command` performs
//! (`pyatv/scripts/atvremote.py:889-951`): resolve a device, connect, call one interface method,
//! print the result — and then close, which upstream does in its own `finally`
//! (`atvremote.py:867-871`).
//!
//! Output formatting is [`super::output`]. It is not in the library on purpose: `pyatv` returns
//! typed values and only the CLI should decide how they look on a terminal.

use std::sync::Arc;

use anyhow::{Context, Result, bail};
use pyatv::{AppleTV, BaseConfig, Protocol};

use crate::cli::{Cli, Command};
use crate::commands::output;
use crate::commands::{open_storage, resolve_device};

/// Connect, run `body`, then close whatever happened.
///
/// The close is unconditional and its failure is reported separately from the command's, so a
/// device that will not shut down cleanly cannot swallow the answer the user asked for.
async fn with_device<F>(cli: &Cli, body: F) -> Result<()>
where
    F: AsyncFnOnce(&dyn AppleTV) -> Result<()>,
{
    let mut config = resolve_device(cli).await?;
    apply_credential_overrides(cli, &mut config);

    let storage = Arc::new(open_storage(cli)?);
    let atv = pyatv::connect(&config, None, storage)
        .await
        .with_context(|| format!("could not connect to {}", config.name))?;

    let outcome = body(atv.as_ref()).await;

    if let Err(error) = atv.close().await {
        tracing::debug!(%error, "the device did not close cleanly");
    }
    outcome
}

/// Apply `--companion-credentials` over whatever storage supplied.
///
/// `_set_credentials` (`atvremote.py:753-776`): a command-line value wins over the stored one, and
/// an explicitly empty string *unsets* the stored credentials rather than being treated as absent.
fn apply_credential_overrides(cli: &Cli, config: &mut BaseConfig) {
    let Some(credentials) = cli.companion_credentials.as_deref() else {
        return;
    };

    let Some(service) = config.get_service_mut(Protocol::Companion) else {
        tracing::debug!("ignoring --companion-credentials: the device has no Companion service");
        return;
    };

    service.credentials = if credentials.is_empty() {
        None
    } else {
        Some(credentials.to_owned())
    };
}

/// Dispatch one connection-requiring subcommand.
///
/// # Errors
///
/// Propagates connection failures, plus [`pyatv::Error::NotSupported`] when no connected protocol
/// implements the capability the subcommand needs.
pub async fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::DeviceInfo => device_info(cli).await,
        Command::Features => features(cli).await,
        Command::AppList => app_list(cli).await,
        Command::LaunchApp { target } => launch_app(cli, target).await,
        Command::Remote { button } => remote(cli, button).await,
        Command::TurnOn => power(cli, true).await,
        Command::TurnOff => power(cli, false).await,
        Command::PowerState => power_state(cli).await,
        Command::Volume { level } => volume(cli, *level).await,
        Command::Playing => playing(cli).await,
        Command::PlayUrl { .. } | Command::StreamFile { .. } | Command::PushUpdates => {
            bail!("this subcommand needs AirPlay, RAOP or MRP, which this build cannot connect yet")
        }
        Command::Scan | Command::Pair { .. } => {
            unreachable!("dispatched before a connection is needed")
        }
    }
}

/// `Model/SW:` and `MAC:`, exactly as `DeviceCommands.device_info` prints them
/// (`atvremote.py:436-441`).
async fn device_info(cli: &Cli) -> Result<()> {
    with_device(cli, async |atv| {
        let info = atv.device_info();
        println!("Model/SW: {info}");
        println!("     MAC: {}", output::optional(info.mac()));
        Ok(())
    })
    .await
}

/// The feature list plus its legend (`atvremote.py:443-465`).
async fn features(cli: &Cli) -> Result<()> {
    with_device(cli, async |atv| {
        output::print_features(&atv.features().all_features(false));
        Ok(())
    })
    .await
}

/// Every launchable app, comma-separated — `_pretty_print`'s list branch
/// (`atvremote.py:987-988`) over `App.__str__` (`pyatv/interface.py:721-723`).
async fn app_list(cli: &Cli) -> Result<()> {
    with_device(cli, async |atv| {
        let apps = atv
            .apps()
            .ok_or_else(|| output::unsupported("app_list", "Companion"))?
            .app_list()
            .await?;

        println!("{}", output::join_apps(&apps));
        Ok(())
    })
    .await
}

/// Launch an app. Prints nothing on success, as upstream's `None` return does.
async fn launch_app(cli: &Cli, target: &str) -> Result<()> {
    with_device(cli, async |atv| {
        atv.apps()
            .ok_or_else(|| output::unsupported("launch_app", "Companion"))?
            .launch_app(target)
            .await?;
        Ok(())
    })
    .await
}

/// One button press. Prints nothing on success.
async fn remote(cli: &Cli, button: &str) -> Result<()> {
    let button = button.to_owned();
    with_device(cli, async |atv| {
        let remote = atv
            .remote_control()
            .ok_or_else(|| output::unsupported("remote control", "MRP, DMAP or Companion"))?;
        output::press(remote.as_ref(), &button).await
    })
    .await
}

/// Wake or sleep the device. Prints nothing on success.
async fn power(cli: &Cli, on: bool) -> Result<()> {
    with_device(cli, async |atv| {
        let power = atv
            .power()
            .ok_or_else(|| output::unsupported("power control", "Companion or MRP"))?;

        // `await_new_state` defaults to false upstream (`pyatv/interface.py::Power.turn_on`), and
        // the CLI has no flag for it, so the command returns as soon as the device acknowledges.
        if on {
            power.turn_on(false).await?;
        } else {
            power.turn_off(false).await?;
        }
        Ok(())
    })
    .await
}

/// The current power state, rendered as Python prints the enum: `PowerState.On`.
async fn power_state(cli: &Cli) -> Result<()> {
    with_device(cli, async |atv| {
        let power = atv
            .power()
            .ok_or_else(|| output::unsupported("power control", "Companion or MRP"))?;
        println!("{}", output::power_state(power.power_state()));
        Ok(())
    })
    .await
}

/// Read or set the volume.
///
/// Upstream splits these into two commands, `volume` (a property) and `set_volume=<n>`
/// (`atvremote.py:916-917` dispatching into `interface.Audio`); this CLI folds them into one
/// subcommand with an optional argument.
async fn volume(cli: &Cli, level: Option<f32>) -> Result<()> {
    with_device(cli, async |atv| {
        let audio = atv
            .audio()
            .ok_or_else(|| output::unsupported("volume", "RAOP, Companion or MRP"))?;

        if let Some(level) = level {
            audio.set_volume(level).await.map_err(Into::into)
        } else {
            println!("{}", output::float(audio.volume()));
            Ok(())
        }
    })
    .await
}

/// Now-playing metadata.
///
/// No protocol this build connects reports metadata, so this reports the same
/// [`pyatv::Error::NotSupported`] the facade would rather than pretending.
async fn playing(cli: &Cli) -> Result<()> {
    with_device(cli, async |atv| {
        let metadata = atv
            .metadata()
            .ok_or_else(|| output::unsupported("playing", "MRP, DMAP or RAOP"))?;
        println!("{:#?}", metadata.playing().await?);
        Ok(())
    })
    .await
}
