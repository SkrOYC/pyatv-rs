//! The subcommands that need a live connection.
//!
//! Each one is the same four steps upstream's `_handle_device_command` performs
//! (`pyatv/scripts/atvremote.py:889-951`): resolve a device, connect, call one interface method,
//! print the result — and then close, which upstream does in its own `finally`
//! (`atvremote.py:867-871`).
//!
//! Output formatting is [`super::output`]. It is not in the library on purpose: `pyatv` returns
//! typed values and only the CLI should decide how they look on a terminal.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use pyatv::{
    AppleTV, BaseConfig, FeatureName, FeatureState, MediaSource, PlaybackListener, Protocol,
};

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

/// Apply the `--<protocol>-credentials` flags over whatever storage supplied.
///
/// `_set_credentials` (`atvremote.py:753-776`): a command-line value wins over the stored one, and
/// an explicitly empty string *unsets* the stored credentials rather than being treated as absent.
fn apply_credential_overrides(cli: &Cli, config: &mut BaseConfig) {
    for (protocol, flag, value) in [
        (
            Protocol::Companion,
            "--companion-credentials",
            cli.companion_credentials.as_deref(),
        ),
        (
            Protocol::AirPlay,
            "--airplay-credentials",
            cli.airplay_credentials.as_deref(),
        ),
    ] {
        let Some(credentials) = value else { continue };

        let Some(service) = config.get_service_mut(protocol) else {
            tracing::debug!(
                flag,
                ?protocol,
                "ignoring an override for an absent service"
            );
            continue;
        };

        service.credentials = if credentials.is_empty() {
            None
        } else {
            Some(credentials.to_owned())
        };
    }
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
        Command::PushUpdates { timeout } => push_updates(cli, *timeout).await,
        Command::Artwork {
            output,
            width,
            height,
        } => artwork(cli, output, *width, *height).await,
        Command::PlayUrl { url } => play_url(cli, url).await,
        Command::StreamFile { path } => stream_file(cli, path).await,
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
            audio.set_volume(level, None).await.map_err(Into::into)
        } else {
            println!("{}", output::float(audio.volume()));
            Ok(())
        }
    })
    .await
}

/// Now-playing metadata, printed as `Playing.__str__` renders it
/// (`pyatv/interface.py:540-589`, ported as that type's `Display`).
async fn playing(cli: &Cli) -> Result<()> {
    with_device(cli, async |atv| {
        let metadata = atv
            .metadata()
            .ok_or_else(|| output::unsupported("playing", "MRP, DMAP or RAOP"))?;
        println!("{}", metadata.playing().await?);
        Ok(())
    })
    .await
}

/// Follow now-playing updates until Ctrl-C, or until `timeout` seconds have passed.
///
/// `PushUpdatesCommand.push_updates` (`atvremote.py:421-433`) plus `PushListener`
/// (`atvremote.py:504-513`): the availability check comes first and refuses with a message rather
/// than an error, each update prints the same block `playing` does followed by a twenty-dash rule,
/// and an error prints a line and lets the updater carry on.
async fn push_updates(cli: &Cli, timeout: Option<u64>) -> Result<()> {
    with_device(cli, async |atv| {
        // `atv.features.in_state(Available, PushUpdates)` (`atvremote.py:423-428`).
        if atv.features().get_feature(FeatureName::PushUpdates).state != FeatureState::Available {
            println!("Push updates are not supported (no protocol supports it)");
            return Ok(());
        }

        let updater = atv
            .push_updater()
            .ok_or_else(|| output::unsupported("push_updates", "MRP or DMAP"))?;

        // Held for as long as updates are wanted: the updater keeps only a weak reference, so
        // dropping this is what unsubscribes.
        let listener: Arc<dyn PlaybackListener> = Arc::new(output::PrintingListener);
        updater.set_listener(&listener);

        match timeout {
            Some(seconds) => println!("Following updates for {seconds}s"),
            None => println!("Press Ctrl-C to stop"),
        }
        updater.start(0).await?;

        match timeout {
            Some(seconds) => {
                let deadline = tokio::time::sleep(std::time::Duration::from_secs(seconds));
                tokio::select! {
                    () = deadline => {}
                    result = tokio::signal::ctrl_c() => result?,
                }
            }
            None => tokio::signal::ctrl_c().await?,
        }

        updater.stop();
        Ok(())
    })
    .await
}

/// Play a video URL and block until the device stops playing it.
///
/// `atvremote play_url=<url>` upstream, which goes through the generic command dispatcher and so
/// prints nothing at all — `play_url` returns `None` and `_pretty_print` has nothing to show
/// (`atvremote.py:889-951,980-990`). The two lines here are this CLI's own addition: the call does
/// not return until the media ends, which can be an hour, and a command that prints nothing for an
/// hour looks hung.
///
/// Ctrl-C stops the playback the way `atv.remote_control.stop()` would, rather than killing the
/// process with the connection still open.
async fn play_url(cli: &Cli, url: &str) -> Result<()> {
    let url = url.to_owned();
    with_device(cli, async |atv| {
        let stream = atv
            .stream()
            .ok_or_else(|| output::unsupported("play_url", "AirPlay"))?;

        // `atv.features.in_state(Available, PlayUrl)` is what upstream's own docs tell a caller to
        // check; the device answers `Unavailable` when it advertises neither video bit.
        if atv.features().get_feature(FeatureName::PlayUrl).state != FeatureState::Available {
            bail!("this device does not support play_url");
        }

        println!("Playing {url}");
        let playing = stream.play_url(&url);
        tokio::pin!(playing);

        tokio::select! {
            outcome = &mut playing => outcome?,
            result = tokio::signal::ctrl_c() => {
                result?;
                println!("Stopping");
                // `close()` raises the stop signal; awaiting the call again lets it unwind and
                // shut the connection down cleanly.
                stream.close();
                playing.await?;
            }
        }

        println!("Playback finished");
        Ok(())
    })
    .await
}

/// Stream an audio file, or a `http://` URL, over RAOP.
///
/// `stream_file` (`atvremote.py:953-966`), which like `play_url` returns nothing and prints
/// nothing. The two progress lines and the Ctrl-C handling are this CLI's own, for the same reason
/// they are on `play_url`: the call does not return until the whole file has been paced out in real
/// time, and a command that prints nothing for the length of an album looks hung.
///
/// The path is passed through whole. A string that spells a URL is fetched rather than opened, and
/// that decision belongs to the protocol crate — `_is_url` (`audio_source.py:731-735`) is what
/// makes it upstream too. A single `-` means standard input, exactly as upstream's dispatcher
/// special-cases it (`atvremote.py:961-964`).
async fn stream_file(cli: &Cli, path: &Path) -> Result<()> {
    let path = path.to_owned();
    with_device(cli, async |atv| {
        let stream = atv
            .stream()
            .ok_or_else(|| output::unsupported("stream_file", "RAOP"))?;

        if atv.features().get_feature(FeatureName::StreamFile).state != FeatureState::Available {
            bail!("this device does not support stream_file");
        }

        let (source, label) = read_source(&path)?;
        println!("Streaming {label}");
        let streaming = stream.stream_file(&source, None, false);
        tokio::pin!(streaming);

        tokio::select! {
            outcome = &mut streaming => outcome?,
            result = tokio::signal::ctrl_c() => {
                result?;
                println!("Stopping");
                // `close()` raises the stop flag the pacing loop polls; awaiting the call again
                // lets it unwind through `TEARDOWN` rather than dropping the sockets.
                stream.close();
                streaming.await?;
            }
        }

        println!("Streaming finished");
        Ok(())
    })
    .await
}

/// Turn the `stream_file` argument into a source, reading standard input for `-`.
///
/// `if command == "stream_file" and args[0] == "-": args = [sys.stdin.buffer, ...]`
/// (`atvremote.py:961-964`). Upstream hands the file object straight to the decoder and reads it
/// lazily; here standard input is drained into memory first, because
/// [`pyatv::MediaSource`](pyatv::MediaSource) is a value rather than a reader — and because the
/// decoder needs the whole stream anyway to work out its duration.
///
/// The second element is what to print, since `-` has no path to show.
fn read_source(path: &Path) -> Result<(MediaSource, String)> {
    if path == Path::new("-") {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin().lock(), &mut bytes)
            .context("reading audio from standard input")?;
        return Ok((MediaSource::Bytes(bytes), "standard input".to_owned()));
    }

    let label = path.display().to_string();
    // A `Path` that spells a URL is classified the way upstream classifies the string.
    let source = path.to_str().map_or_else(
        || MediaSource::from_path(path),
        MediaSource::from_str_source,
    );
    Ok((source, label))
}

/// Save the current artwork.
///
/// `artwork_save` (`atvremote.py:410-418`), except that the file name is taken whole rather than
/// having `.png` appended: the bytes a device sends are not always PNG, and silently mislabelling
/// them helps nobody. The "no artwork" message is upstream's, verbatim.
async fn artwork(
    cli: &Cli,
    output_path: &Path,
    width: Option<u32>,
    height: Option<u32>,
) -> Result<()> {
    with_device(cli, async |atv| {
        let metadata = atv
            .metadata()
            .ok_or_else(|| output::unsupported("artwork", "MRP, DMAP or RAOP"))?;

        let Some(artwork) = metadata.artwork(width, height).await? else {
            println!("No artwork is currently available.");
            return Ok(());
        };

        std::fs::write(output_path, &artwork.bytes)
            .with_context(|| format!("could not write {}", output_path.display()))?;
        println!(
            "Wrote {} bytes of {} to {}",
            artwork.bytes.len(),
            artwork.mimetype,
            output_path.display()
        );
        Ok(())
    })
    .await
}
