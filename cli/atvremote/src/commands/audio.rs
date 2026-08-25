//! Volume and `AirPlay` 2 output devices.
//!
//! `interface.Audio` (`pyatv/interface.py:1162-1233`), which upstream dispatches *before*
//! `RemoteControl` so that `volume_up` and `volume_down` resolve here (`atvremote.py:914-917`).
//! Those two are reached through `remote` rather than as subcommands, so they live in
//! [`super::buttons`]; everything else is here.

use anyhow::Result;
use pyatv::{Audio, OutputDevice};

use crate::cli::Command;
use crate::report::{Reporter, unsupported};

/// Run a volume or output-device command.
///
/// # Errors
///
/// Returns [`pyatv::Error::NotSupported`] when no connected protocol reports volume, and whatever
/// the device reports otherwise.
pub async fn run(atv: &dyn pyatv::AppleTV, command: &Command, reporter: Reporter) -> Result<()> {
    let audio = atv
        .audio()
        .ok_or_else(|| unsupported("audio", "RAOP, Companion or MRP"))?;

    match command {
        // A property upstream, so it prints rather than acknowledges
        // (`pyatv/interface.py:1170-1178`).
        Command::Volume => reporter.volume(audio.volume()),

        Command::SetVolume {
            level,
            output_device,
        } => {
            set_volume(audio.as_ref(), *level, output_device.as_deref()).await?;
            reporter.acknowledge("set_volume");
        }

        Command::OutputDevices => reporter.output_devices(&audio.output_devices()),

        Command::AddOutputDevices { identifiers } => {
            audio.add_output_devices(identifiers).await?;
            reporter.acknowledge("add_output_devices");
        }
        Command::RemoveOutputDevices { identifiers } => {
            audio.remove_output_devices(identifiers).await?;
            reporter.acknowledge("remove_output_devices");
        }
        Command::SetOutputDevices { identifiers } => {
            audio.set_output_devices(identifiers).await?;
            reporter.acknowledge("set_output_devices");
        }

        other => unreachable!("{other:?} is not an audio command"),
    }

    Ok(())
}

/// `set_volume(level, output_device=None)` (`pyatv/interface.py:1180-1188`).
///
/// `--output-device` names one speaker in the playback group. The device is looked up in the group
/// so that its current name and volume travel with the request; a name the group does not hold is
/// still sent, as an identifier-only device, because upstream builds exactly that fallback when the
/// facade meets an unknown speaker (`pyatv/core/facade.py:487`).
async fn set_volume(audio: &dyn Audio, level: f32, output_device: Option<&str>) -> Result<()> {
    let Some(identifier) = output_device else {
        return audio.set_volume(level, None).await.map_err(Into::into);
    };

    let known = audio
        .output_devices()
        .into_iter()
        .find(|device| device.identifier == identifier);
    let target = known.unwrap_or_else(|| OutputDevice::new(identifier));

    audio
        .set_volume(level, Some(&target))
        .await
        .map_err(Into::into)
}
