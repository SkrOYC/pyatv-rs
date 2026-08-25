//! Device-level traits: power, apps, audio, user accounts and feature reporting.

use crate::Result;
use crate::consts::PowerState;
use crate::features::{FeatureInfo, FeatureName};
use crate::interface::BoxFuture;
use crate::models::{App, OutputDevice, UserAccount};

/// Power control.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] when no connected protocol can change power
/// state, and [`crate::Error::Timeout`] when `await_new_state` is set and the device never reports
/// the requested state.
pub trait Power: Send + Sync + std::fmt::Debug {
    /// Last known power state.
    fn power_state(&self) -> PowerState;
    /// Wake the device. When `await_new_state` is set, resolve only once the device confirms.
    fn turn_on(&self, await_new_state: bool) -> BoxFuture<'_, Result<()>>;
    /// Put the device to sleep. When `await_new_state` is set, resolve only once the device
    /// confirms.
    fn turn_off(&self, await_new_state: bool) -> BoxFuture<'_, Result<()>>;
}

/// Installed application management.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] unless a Companion connection is active.
pub trait Apps: Send + Sync + std::fmt::Debug {
    /// Enumerate installed apps.
    fn app_list(&self) -> BoxFuture<'_, Result<Vec<App>>>;
    /// Launch an app by bundle identifier or by URL.
    fn launch_app(&self, bundle_id_or_url: &str) -> BoxFuture<'_, Result<()>>;
}

/// Volume control and `AirPlay` 2 output device management.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] when no connected protocol reports volume, and
/// [`crate::Error::Command`] if the device rejects a volume change.
pub trait Audio: Send + Sync + std::fmt::Debug {
    /// Current volume as a percentage in `0.0..=100.0`.
    fn volume(&self) -> f32;

    /// Set the volume as a percentage in `0.0..=100.0`.
    ///
    /// `set_volume(level, output_device=None)` (`pyatv/interface.py:1180-1188`). With
    /// `output_device` set the level is applied to that one speaker in the playback group rather
    /// than to the group as a whole; only MRP implements the targeted form
    /// (`pyatv/protocols/mrp/__init__.py:868-885`), and every other protocol ignores the argument
    /// the way upstream's do.
    fn set_volume(
        &self,
        level: f32,
        output_device: Option<&OutputDevice>,
    ) -> BoxFuture<'_, Result<()>>;

    /// Step the volume up by the device's own increment.
    fn volume_up(&self) -> BoxFuture<'_, Result<()>>;
    /// Step the volume down by the device's own increment.
    fn volume_down(&self) -> BoxFuture<'_, Result<()>>;

    /// The output devices currently in the playback group.
    ///
    /// `output_devices` (`interface.py:1214-1218`) returns `List[OutputDevice]`, so a caller sees
    /// each speaker's display name and last known volume rather than an identifier alone.
    fn output_devices(&self) -> Vec<OutputDevice>;
    /// Add devices to the playback group.
    fn add_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>>;
    /// Remove devices from the playback group.
    fn remove_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>>;
    /// Replace the playback group membership outright.
    fn set_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>>;
}

/// Notified when the volume or the playback group changes.
///
/// Ports `pyatv.interface.AudioListener` (`pyatv/interface.py:1139-1159`). Registered through
/// [`crate::interface::AppleTV::add_audio_listener`] and held weakly, as every other listener here
/// is.
///
/// Every method has a default no-op body so a caller that only cares about one of the three does
/// not have to write the others; upstream's are `@abstractmethod`, but Python callers routinely
/// subclass and override one, and there is no equivalent of that in Rust without defaults.
pub trait AudioListener: Send + Sync + std::fmt::Debug {
    /// The device's own volume changed.
    fn volume_update(&self, old_level: f32, new_level: f32) {
        let _ = (old_level, new_level);
    }

    /// One output device's volume changed.
    fn volume_device_update(&self, output_device: &OutputDevice, old_level: f32, new_level: f32) {
        let _ = (output_device, old_level, new_level);
    }

    /// The playback group's membership changed.
    fn outputdevices_update(&self, old_devices: &[OutputDevice], new_devices: &[OutputDevice]) {
        let _ = (old_devices, new_devices);
    }
}

/// User account enumeration and switching.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] unless a Companion connection is active.
pub trait UserAccounts: Send + Sync + std::fmt::Debug {
    /// Enumerate accounts configured on the device.
    fn account_list(&self) -> BoxFuture<'_, Result<Vec<UserAccount>>>;
    /// Switch the active account.
    fn switch_account(&self, account_id: &str) -> BoxFuture<'_, Result<()>>;
}

/// Reports which capabilities are usable on the connected device.
///
/// The facade builds this by unioning the feature set each connected protocol declared, then asking
/// the owning protocol for live availability.
pub trait Features: Send + Sync + std::fmt::Debug {
    /// Availability of a single feature.
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo;
    /// Availability of every feature the facade knows about.
    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)>;
}
