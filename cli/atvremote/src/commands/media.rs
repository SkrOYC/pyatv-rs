//! Now-playing metadata, artwork, push updates and streaming.
//!
//! `interface.Metadata` (`atvremote.py:922-923`), `interface.Stream` (`:932-933`) and the
//! atvremote-only `push_updates` (`:421-434`).

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use pyatv::{AppleTV, FeatureName, FeatureState, MediaMetadata, MediaSource, Metadata};

use crate::cli::Command;
use crate::report::listeners::Listeners;
use crate::report::{Reporter, unsupported};

/// Run a metadata, artwork, push-update or streaming command.
///
/// # Errors
///
/// Returns [`pyatv::Error::NotSupported`] when no connected protocol serves the capability, and
/// whatever the device reports otherwise.
pub async fn run(atv: &dyn AppleTV, command: &Command, reporter: Reporter) -> Result<()> {
    match command {
        Command::Playing => playing(atv, reporter).await,
        Command::App => {
            reporter.app(requires_metadata(atv, "app")?.app().as_ref());
            Ok(())
        }
        Command::DeviceId => {
            let device_id = requires_metadata(atv, "device_id")?.device_id();
            reporter.optional_value("device_id", device_id.as_deref());
            Ok(())
        }
        Command::ArtworkId => {
            let artwork_id = requires_metadata(atv, "artwork_id")?.artwork_id();
            reporter.optional_value("artwork_id", artwork_id.as_deref());
            Ok(())
        }
        Command::Artwork {
            output,
            width,
            height,
        } => artwork(atv, output, *width, *height, reporter).await,
        Command::PushUpdates { timeout } => push_updates(atv, *timeout, reporter).await,
        Command::PlayUrl { url } => play_url(atv, url, reporter).await,
        Command::StreamFile { .. } => stream_file(atv, command, reporter).await,
        other => unreachable!("{other:?} is not a media command"),
    }
}

fn requires_metadata(atv: &dyn AppleTV, what: &str) -> Result<Arc<dyn Metadata>> {
    atv.metadata()
        .ok_or_else(|| unsupported(what, "MRP, DMAP or RAOP"))
}

/// Now-playing metadata, printed as `Playing.__str__` renders it
/// (`pyatv/interface.py:540-589`, ported as that type's `Display`).
///
/// The app goes with it in JSON mode, which is what `output_playing` does
/// (`atvscript.py:300-307`); it is read only when `FeatureName::App` is available, because
/// upstream guards the same read with `features.in_state(Available, App)`.
async fn playing(atv: &dyn AppleTV, reporter: Reporter) -> Result<()> {
    let metadata = requires_metadata(atv, "playing")?;
    let state = metadata.playing().await?;

    let app = (atv.features().get_feature(FeatureName::App).state == FeatureState::Available)
        .then(|| metadata.app())
        .flatten();

    reporter.playing(&state, app.as_ref());
    Ok(())
}

/// Save the current artwork.
///
/// `artwork_save` (`atvremote.py:410-419`), except that the file name is taken whole rather than
/// having `.png` appended: the bytes a device sends are not always PNG, and silently mislabelling
/// them helps nobody. The "no artwork" message is upstream's, verbatim.
async fn artwork(
    atv: &dyn AppleTV,
    output_path: &Path,
    width: Option<u32>,
    height: Option<u32>,
    reporter: Reporter,
) -> Result<()> {
    let metadata = requires_metadata(atv, "artwork")?;

    let Some(artwork) = metadata.artwork(width, height).await? else {
        reporter.no_artwork();
        return Ok(());
    };

    std::fs::write(output_path, &artwork.bytes)
        .with_context(|| format!("could not write {}", output_path.display()))?;
    reporter.artwork_saved(&artwork, output_path);
    Ok(())
}

/// Follow now-playing updates until Ctrl-C, until the device goes away, or until `timeout` seconds
/// have passed.
///
/// `PushUpdatesCommand.push_updates` (`atvremote.py:421-433`) plus `PushListener`
/// (`atvremote.py:504-513`) in text mode, and `atvscript`'s five printers (`atvscript.py:309-330`)
/// in JSON mode. The availability check comes first and refuses with a message rather than an
/// error, exactly as upstream's does.
async fn push_updates(atv: &dyn AppleTV, timeout: Option<u64>, reporter: Reporter) -> Result<()> {
    // `atv.features.in_state(Available, PushUpdates)` (`atvremote.py:423-428`).
    if atv.features().get_feature(FeatureName::PushUpdates).state != FeatureState::Available {
        reporter.notice("Push updates are not supported (no protocol supports it)");
        return Ok(());
    }

    let updater = atv
        .push_updater()
        .ok_or_else(|| unsupported("push_updates", "MRP or DMAP"))?;

    // Held for as long as updates are wanted: everything registers weakly, so dropping this is
    // what unsubscribes.
    let listeners = Listeners::register(reporter, atv);
    updater.set_listener(listeners.playback());

    match timeout {
        Some(seconds) => reporter.notice(&format!("Following updates for {seconds}s")),
        None => reporter.notice("Press Ctrl-C to stop"),
    }
    updater.start(0).await?;
    listeners.emit_initial_state(atv);

    let aborted = Arc::clone(&listeners.aborted);
    let stop = async {
        tokio::select! {
            () = aborted.notified() => Ok(()),
            result = tokio::signal::ctrl_c() => result,
        }
    };

    match timeout {
        Some(seconds) => {
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(seconds)) => {}
                result = stop => result?,
            }
        }
        None => stop.await?,
    }

    updater.stop();
    // `return output(True, values={"push_updates": "finished"})` (`atvscript.py:330`).
    reporter.push_finished();
    Ok(())
}

/// Play a video URL and block until the device stops playing it.
///
/// `atvremote play_url=<url>` upstream, which goes through the generic command dispatcher and so
/// prints nothing at all — `play_url` returns `None` and `_pretty_print` has nothing to show
/// (`atvremote.py:889-951,982-990`). The progress lines here are this CLI's own addition: the call
/// does not return until the media ends, which can be an hour, and a command that prints nothing
/// for an hour looks hung. They go to stderr under `--json` so stdout stays parseable.
///
/// Ctrl-C stops the playback the way `atv.remote_control.stop()` would, rather than killing the
/// process with the connection still open.
async fn play_url(atv: &dyn AppleTV, url: &str, reporter: Reporter) -> Result<()> {
    let stream = atv
        .stream()
        .ok_or_else(|| unsupported("play_url", "AirPlay"))?;

    // `atv.features.in_state(Available, PlayUrl)` is what upstream's own docs tell a caller to
    // check; the device answers `Unavailable` when it advertises neither video bit.
    if atv.features().get_feature(FeatureName::PlayUrl).state != FeatureState::Available {
        bail!("this device does not support play_url");
    }

    reporter.notice(&format!("Playing {url}"));
    let playing = stream.play_url(url);
    tokio::pin!(playing);

    tokio::select! {
        outcome = &mut playing => outcome?,
        result = tokio::signal::ctrl_c() => {
            result?;
            reporter.notice("Stopping");
            // `close()` raises the stop signal; awaiting the call again lets it unwind and shut
            // the connection down cleanly.
            stream.close();
            playing.await?;
        }
    }

    reporter.notice("Playback finished");
    reporter.acknowledge("play_url");
    Ok(())
}

/// Stream an audio file, or a `http://` URL, over RAOP.
///
/// `stream_file` (`atvremote.py:953-966`), which like `play_url` returns nothing and prints
/// nothing; the progress lines are this CLI's own for the same reason.
///
/// The path is passed through whole. A string that spells a URL is fetched rather than opened, and
/// that decision belongs to the protocol crate — `_is_url` (`audio_source.py:731-735`) is what
/// makes it upstream too. A single `-` means standard input, exactly as upstream's dispatcher
/// special-cases it (`atvremote.py:961-964`).
async fn stream_file(atv: &dyn AppleTV, command: &Command, reporter: Reporter) -> Result<()> {
    let Command::StreamFile {
        path,
        title,
        artist,
        album,
        override_missing_metadata,
    } = command
    else {
        unreachable!("only stream_file reaches here");
    };

    let stream = atv
        .stream()
        .ok_or_else(|| unsupported("stream_file", "RAOP"))?;

    if atv.features().get_feature(FeatureName::StreamFile).state != FeatureState::Available {
        bail!("this device does not support stream_file");
    }

    let (source, label) = read_source(path)?;
    let metadata = MediaMetadata {
        title: title.clone(),
        artist: artist.clone(),
        album: album.clone(),
        ..MediaMetadata::default()
    };
    // `metadata=None` when nothing was supplied, so the source's own tags are used untouched
    // (`pyatv/interface.py:886-901`).
    let metadata = (!metadata.is_empty()).then_some(metadata);

    reporter.notice(&format!("Streaming {label}"));
    let streaming = stream.stream_file(&source, metadata.as_ref(), *override_missing_metadata);
    tokio::pin!(streaming);

    tokio::select! {
        outcome = &mut streaming => outcome?,
        result = tokio::signal::ctrl_c() => {
            result?;
            reporter.notice("Stopping");
            // `close()` raises the stop flag the pacing loop polls; awaiting the call again lets
            // it unwind through `TEARDOWN` rather than dropping the sockets.
            stream.close();
            streaming.await?;
        }
    }

    reporter.notice("Streaming finished");
    reporter.acknowledge("stream_file");
    Ok(())
}

/// Turn the `stream_file` argument into a source, reading standard input for `-`.
///
/// `if command == "stream_file" and args[0] == "-": args = [sys.stdin.buffer, ...]`
/// (`atvremote.py:961-964`). Upstream hands the file object straight to the decoder and reads it
/// lazily; here standard input is drained into memory first, because [`pyatv::MediaSource`] is a
/// value rather than a reader — and because the decoder needs the whole stream anyway to work out
/// its duration.
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
