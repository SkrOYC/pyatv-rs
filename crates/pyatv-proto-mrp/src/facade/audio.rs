//! `Audio`: volume and `AirPlay` 2 speaker-group management.
//!
//! Port of `MrpAudio`'s command half (`pyatv/protocols/mrp/__init__.py:746-948`); the state it
//! reads lives in [`crate::state::volume`].
//!
//! # There is no response to a volume change
//!
//! `SET_VOLUME_MESSAGE` is answered by nothing. The only confirmation is the next
//! `VOLUME_DID_CHANGE_MESSAGE` push, which is why every method here arms a waiter *before* sending
//! and then waits on it with a five-second deadline (`__init__.py:868-885`).

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::interface::{Audio, BoxFuture};
use pyatv_core::models::OutputDevice;
use pyatv_core::{Error as CoreError, Result as CoreResult};

use crate::facade::remote::send_hid_key;
use crate::hid;
use crate::messages::OutputDeviceChange;
use crate::protocol::MrpProtocol;
use crate::{Error, Result, messages};

/// How long to wait for the device to confirm a change (`asyncio.wait_for(..., timeout=5.0)`).
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(5);

/// The step `volume_up`/`volume_down` use when only absolute control is available
/// (`min(self.volume + 5, 100.0)`, `__init__.py:898-911`).
pub const ABSOLUTE_STEP: f32 = 5.0;

/// MRP's volume control.
#[derive(Debug)]
pub struct MrpAudio {
    protocol: Arc<MrpProtocol>,
}

impl MrpAudio {
    /// Wrap a connected protocol.
    #[must_use]
    pub const fn new(protocol: Arc<MrpProtocol>) -> Self {
        Self { protocol }
    }

    /// `set_volume` against this device's own output UID (`__init__.py:868-879`).
    ///
    /// The wait is skipped when the device only supports relative control, or when the cached level
    /// already matches — upstream's `if self.is_volume_absolute and self._volume != level`.
    async fn set_level(&self, level: f32) -> Result<()> {
        let state = self.protocol.state();
        let uid = state
            .device_uid()
            .ok_or(Error::InvalidState("no output device"))?;
        let volume = state.volume();

        let confirmed = state.volume_changed();
        self.protocol
            .send(messages::set_volume(&uid, level / 100.0)?)
            .await?;

        if volume.absolute && (volume.level - level).abs() > f32::EPSILON {
            tokio::time::timeout(CONFIRM_TIMEOUT, confirmed)
                .await
                .map_err(|_| Error::Timeout("SET_VOLUME_MESSAGE".to_owned()))?;
        }
        Ok(())
    }

    /// `set_volume` against one speaker in the group (`__init__.py:880-885`).
    ///
    /// The `else` branch of upstream's `set_volume`: the message is addressed to the caller's
    /// device rather than to ours, and the confirmation wait is gated on *that* device's last known
    /// level — with no `is_volume_absolute` check, because the capability flags describe this
    /// device and say nothing about someone else's speaker.
    async fn set_device_level(&self, device: &OutputDevice, level: f32) -> Result<()> {
        let state = self.protocol.state();

        let confirmed = state.volume_changed();
        self.protocol
            .send(messages::set_volume(&device.identifier, level / 100.0)?)
            .await?;

        if (device.volume - level).abs() > f32::EPSILON {
            tokio::time::timeout(CONFIRM_TIMEOUT, confirmed)
                .await
                .map_err(|_| Error::Timeout("SET_VOLUME_MESSAGE".to_owned()))?;
        }
        Ok(())
    }

    /// One relative or absolute volume step (`volume_up`/`volume_down`, `__init__.py:887-911`).
    ///
    /// Relative stepping is preferred when the device offers it, and the HID press deliberately
    /// skips the `GENERIC_MESSAGE` flush because this path waits on the volume push instead.
    async fn step(&self, up: bool) -> Result<()> {
        let state = self.protocol.state();
        let volume = state.volume();
        let boundary = if up { 100.0 } else { 0.0 };

        if volume.absolute && (volume.level - boundary).abs() < f32::EPSILON {
            return Ok(());
        }

        if volume.relative {
            let key = if up { hid::VOLUME_UP } else { hid::VOLUME_DOWN };
            let confirmed = state.volume_changed();

            send_hid_key(
                &self.protocol,
                key,
                pyatv_core::consts::InputAction::SingleTap,
                false,
            )
            .await?;

            if volume.absolute {
                tokio::time::timeout(CONFIRM_TIMEOUT, confirmed)
                    .await
                    .map_err(|_| Error::Timeout("VOLUME_DID_CHANGE_MESSAGE".to_owned()))?;
            }
            return Ok(());
        }

        if volume.absolute {
            let target = if up {
                (volume.level + ABSOLUTE_STEP).min(100.0)
            } else {
                (volume.level - ABSOLUTE_STEP).max(0.0)
            };
            return self.set_level(target).await;
        }

        Ok(())
    }

    /// One speaker-group change, waiting for the device-info refresh that follows.
    ///
    /// `add_output_devices` and friends (`__init__.py:933-948`) suppress the timeout: a device that
    /// never re-reports its group is not a failure, just an unconfirmed change.
    async fn modify_group(
        &self,
        change: OutputDeviceChange,
        identifiers: &[String],
    ) -> CoreResult<()> {
        let refreshed = self.protocol.state().output_devices_changed();
        self.protocol
            .send(messages::modify_output_context(change, identifiers)?)
            .await
            .map_err(CoreError::from)?;

        if tokio::time::timeout(CONFIRM_TIMEOUT, refreshed)
            .await
            .is_err()
        {
            tracing::debug!("the device did not re-report its output devices in time");
        }
        Ok(())
    }
}

impl Audio for MrpAudio {
    fn volume(&self) -> f32 {
        self.protocol.state().volume().level
    }

    fn set_volume(
        &self,
        level: f32,
        output_device: Option<&OutputDevice>,
    ) -> BoxFuture<'_, CoreResult<()>> {
        let output_device = output_device.cloned();
        Box::pin(async move {
            match output_device {
                Some(device) => self.set_device_level(&device, level).await,
                None => self.set_level(level).await,
            }
            .map_err(Into::into)
        })
    }

    fn volume_up(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move { self.step(true).await.map_err(Into::into) })
    }

    fn volume_down(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move { self.step(false).await.map_err(Into::into) })
    }

    fn output_devices(&self) -> Vec<OutputDevice> {
        self.protocol.state().volume().output_devices
    }

    fn add_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, CoreResult<()>> {
        let identifiers = identifiers.to_vec();
        Box::pin(async move {
            self.modify_group(OutputDeviceChange::Add, &identifiers)
                .await
        })
    }

    fn remove_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, CoreResult<()>> {
        let identifiers = identifiers.to_vec();
        Box::pin(async move {
            self.modify_group(OutputDeviceChange::Remove, &identifiers)
                .await
        })
    }

    fn set_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, CoreResult<()>> {
        let identifiers = identifiers.to_vec();
        Box::pin(async move {
            self.modify_group(OutputDeviceChange::Set, &identifiers)
                .await
        })
    }
}
