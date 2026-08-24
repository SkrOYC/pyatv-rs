//! Device-level traits: power, apps, audio, user accounts and feature reporting.

use crate::Result;
use crate::consts::PowerState;
use crate::features::{FeatureInfo, FeatureName};
use crate::interface::BoxFuture;
use crate::models::{App, UserAccount};

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
    fn set_volume(&self, level: f32) -> BoxFuture<'_, Result<()>>;
    /// Step the volume up by the device's own increment.
    fn volume_up(&self) -> BoxFuture<'_, Result<()>>;
    /// Step the volume down by the device's own increment.
    fn volume_down(&self) -> BoxFuture<'_, Result<()>>;

    /// Identifiers of the output devices currently in the playback group.
    fn output_devices(&self) -> Vec<String>;
    /// Add devices to the playback group.
    fn add_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>>;
    /// Remove devices from the playback group.
    fn remove_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>>;
    /// Replace the playback group membership outright.
    fn set_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>>;
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
