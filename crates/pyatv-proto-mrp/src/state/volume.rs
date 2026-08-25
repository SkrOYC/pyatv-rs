//! Volume and output-device tracking.
//!
//! Port of `MrpAudio` (`pyatv/protocols/mrp/__init__.py:746-948`), minus the commands, which live
//! in [`crate::facade::audio`]. Three device pushes feed it — `VOLUME_CONTROL_AVAILABILITY`,
//! `VOLUME_CONTROL_CAPABILITIES_DID_CHANGE` and `VOLUME_DID_CHANGE` — plus every `DeviceInfoMessage`,
//! which is where the output-device list and this device's own UID come from.

use pyatv_core::interface::BoxFuture;

use crate::Result;
use crate::message::MrpMessage;
use crate::protobuf::{
    DeviceInfoMessage, VolumeControlAvailabilityMessage, extensions, volume_capabilities,
};
use crate::state::MrpState;

/// One member of the playback group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputDevice {
    /// Display name.
    pub name: String,
    /// Stable identifier, which is what [`pyatv_core::interface::Audio`] exposes.
    pub identifier: String,
}

/// Everything `MrpAudio` tracks.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VolumeState {
    /// `volumeControlAvailable` from the last availability message.
    pub available: bool,
    /// Whether the device accepts an absolute level.
    pub absolute: bool,
    /// Whether the device accepts relative stepping, i.e. the HID volume keys.
    pub relative: bool,
    /// Current level as a percentage in `0.0..=100.0`.
    pub level: f32,
    /// The playback group, most recently derived from a `DeviceInfoMessage`.
    pub output_devices: Vec<OutputDevice>,
}

impl VolumeState {
    /// Identifiers only, which is the shape [`pyatv_core::interface::Audio`] wants.
    #[must_use]
    pub fn identifiers(&self) -> Vec<String> {
        self.output_devices
            .iter()
            .map(|device| device.identifier.clone())
            .collect()
    }
}

impl MrpState {
    /// A snapshot of the volume and output-device state.
    #[must_use]
    pub fn volume(&self) -> VolumeState {
        self.volume
            .lock()
            .map_or_else(|_| VolumeState::default(), |volume| volume.clone())
    }

    /// This device's own output-device UID (`MrpAudio.device_uid`, `__init__.py:764-770`).
    ///
    /// `clusterID or deviceUID`: the cluster identifier when the device is part of one, otherwise
    /// its own. `None` only while no `DeviceInfoMessage` has arrived at all — an *empty* UID is
    /// `Some("")` here, matching upstream, whose `is_available` check is `device_uid is not None`
    /// and so treats an empty string as present.
    #[must_use]
    pub fn device_uid(&self) -> Option<String> {
        let info = self.device_info()?;
        Some(match info.cluster_id.filter(|it| !it.is_empty()) {
            Some(cluster) => cluster,
            None => info.device_uid.unwrap_or_default(),
        })
    }

    /// Whether volume control is usable (`MrpAudio.is_available`, `__init__.py:772-775`).
    #[must_use]
    pub fn volume_available(&self) -> bool {
        self.volume().available && self.device_uid().is_some()
    }

    /// Wait for the next `VOLUME_DID_CHANGE_MESSAGE`.
    ///
    /// The returned future must be created **before** the change is requested, or the push can
    /// arrive in the gap and be missed. Upstream has the same requirement and the same
    /// wake-everyone behaviour when two callers wait at once, which its own comment documents as
    /// an accepted limitation (`__init__.py:853-859`).
    pub fn volume_changed(&self) -> BoxFuture<'_, ()> {
        let notified = self.volume_changed.notified();
        Box::pin(notified)
    }

    /// Wait for the next output-device list refresh.
    pub fn output_devices_changed(&self) -> BoxFuture<'_, ()> {
        let notified = self.output_devices_changed.notified();
        Box::pin(notified)
    }

    /// `VOLUME_CONTROL_AVAILABILITY_MESSAGE` (`__init__.py:806-808`).
    pub(super) fn handle_volume_availability(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::VOLUME_CONTROL_AVAILABILITY_MESSAGE)?;
        self.apply_volume_capabilities(&inner);
        Ok(())
    }

    /// `VOLUME_CONTROL_CAPABILITIES_DID_CHANGE_MESSAGE` (`__init__.py:810-816`).
    ///
    /// Gated on `outputDeviceUID == device_uid`: a capability change for someone else's speaker
    /// must not silently reconfigure ours.
    pub(super) fn handle_volume_capabilities(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::VOLUME_CONTROL_CAPABILITIES_DID_CHANGE_MESSAGE)?;
        if inner.output_device_uid.unwrap_or_default() != self.device_uid().unwrap_or_default() {
            return Ok(());
        }
        self.apply_volume_capabilities(&inner.capabilities.unwrap_or_default());
        Ok(())
    }

    /// `VOLUME_DID_CHANGE_MESSAGE` (`__init__.py:832-861`).
    ///
    /// A change for a *different* output device updates nothing but still releases the waiters,
    /// exactly as upstream does: the event is set unconditionally at the end of the handler.
    pub(super) fn handle_volume_changed(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::VOLUME_DID_CHANGE_MESSAGE)?;
        let level = round_to_tenth(inner.volume.unwrap_or_default() * 100.0);

        if inner.output_device_uid.unwrap_or_default() == self.device_uid().unwrap_or_default() {
            if let Ok(mut volume) = self.volume.lock() {
                volume.level = level;
            }
            tracing::debug!(level, "MRP volume changed");
        } else {
            tracing::debug!(level, "MRP volume changed for another output device");
        }

        self.volume_changed.notify_waiters();
        Ok(())
    }

    /// `DEVICE_INFO_MESSAGE`/`DEVICE_INFO_UPDATE_MESSAGE`.
    ///
    /// Feeds three consumers at once: the cached message (for the device UID and build number),
    /// the output-device list and the power state.
    pub(super) fn handle_device_info(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::DEVICE_INFO_MESSAGE)?;

        // The identity every downstream reader depends on — the power state, the output-device
        // group, the build number the facade reports — all comes out of this one message, and on a
        // tunnelled connection it is the *only* place any of it appears. Logging the fields once
        // per update is what makes a wrong power state or a missing group diagnosable from a log
        // rather than from a packet capture.
        tracing::debug!(
            name = ?inner.name,
            model = ?inner.model_id,
            build = ?inner.system_build_version,
            device_uid = ?inner.device_uid,
            cluster_id = ?inner.cluster_id,
            logical_device_count = ?inner.logical_device_count,
            is_group_leader = ?inner.is_group_leader,
            is_proxy_group_player = ?inner.is_proxy_group_player,
            grouped_devices = inner.grouped_devices.len(),
            "MRP device information"
        );

        if let Ok(mut slot) = self.device_info.lock() {
            *slot = Some(inner.clone());
        }
        self.update_output_devices(&inner);
        self.update_power(super::power::from_device_info(&inner));
        Ok(())
    }

    /// Rebuild the playback group from a `DeviceInfoMessage` (`_update_output_devices`,
    /// `__init__.py:913-926`).
    ///
    /// This device is a member only when it leads the group and is not a proxy player; the rest
    /// come from `groupedDevices`, whose entries are keyed by `deviceUID` rather than by the
    /// `uniqueIdentifier` the leader uses for itself.
    fn update_output_devices(&self, info: &DeviceInfoMessage) {
        let mut devices = Vec::new();

        if info.is_group_leader.unwrap_or_default()
            && !info.is_proxy_group_player.unwrap_or_default()
        {
            devices.push(OutputDevice {
                name: info.name.clone(),
                identifier: info.unique_identifier.clone().unwrap_or_default(),
            });
        }
        for device in &info.grouped_devices {
            devices.push(OutputDevice {
                name: device.name.clone(),
                identifier: device.device_uid.clone().unwrap_or_default(),
            });
        }

        if let Ok(mut volume) = self.volume.lock() {
            volume.output_devices = devices;
        }
        self.output_devices_changed.notify_waiters();
    }

    /// Shared by both capability messages (`_update_volume_controls`, `__init__.py:818-830`).
    fn apply_volume_capabilities(&self, message: &VolumeControlAvailabilityMessage) {
        let capabilities = message.volume_capabilities;
        let is = |wanted: volume_capabilities::Enum| capabilities == Some(wanted as i32);

        if let Ok(mut volume) = self.volume.lock() {
            volume.available = message.volume_control_available.unwrap_or_default();
            volume.absolute =
                is(volume_capabilities::Enum::Absolute) || is(volume_capabilities::Enum::Both);
            volume.relative =
                is(volume_capabilities::Enum::Relative) || is(volume_capabilities::Enum::Both);
            tracing::debug!(
                available = volume.available,
                absolute = volume.absolute,
                relative = volume.relative,
                "MRP volume control availability changed"
            );
        }
    }
}

/// `round(value, 1)` — the precision upstream stores volume at (`__init__.py:838`).
fn round_to_tenth(value: f32) -> f32 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::round_to_tenth;

    #[test]
    fn volume_is_rounded_to_one_decimal() {
        assert!((round_to_tenth(0.5 * 100.0) - 50.0).abs() < f32::EPSILON);
        assert!((round_to_tenth(0.3333 * 100.0) - 33.3).abs() < 0.001);
    }
}
