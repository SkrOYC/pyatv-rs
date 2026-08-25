//! The constant enums that appear in the public API.
//!
//! Discriminants are reproduced verbatim from `pyatv/const.py` (confirmed in
//! `docs/research/pyatv-architecture.md` §5) because they are part of pyatv's public contract:
//! credential files, `atvscript` JSON output and user scripts all round-trip these integers.
//! Changing a discriminant is a breaking change even though Rust would not notice.

use serde::{Deserialize, Serialize};

/// A wire protocol a device can be reached over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum Protocol {
    /// Legacy DMAP/DAAP, Apple TV generations 1-3.
    Dmap = 1,
    /// `MediaRemote` Protocol, Apple TV generation 4 and later.
    Mrp = 2,
    /// `AirPlay` 1 and 2.
    AirPlay = 3,
    /// Companion link.
    Companion = 4,
    /// Remote Audio Output Protocol.
    Raop = 5,
}

impl Protocol {
    /// Every protocol, in the order pyatv prioritises them for discovery.
    pub const ALL: [Self; 5] = [
        Self::Dmap,
        Self::Mrp,
        Self::AirPlay,
        Self::Companion,
        Self::Raop,
    ];
}

/// What kind of media is currently loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum MediaType {
    /// Nothing known.
    #[default]
    Unknown = 0,
    /// Generic video.
    Video = 1,
    /// Music.
    Music = 2,
    /// A TV show episode.
    Tv = 3,
}

/// Transport state of the current playback session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeviceState {
    /// Nothing is loaded.
    #[default]
    Idle = 0,
    /// Media is buffering.
    Loading = 1,
    /// Playback is paused.
    Paused = 2,
    /// Playback is running.
    Playing = 3,
    /// Playback was stopped.
    Stopped = 4,
    /// The user is scrubbing.
    Seeking = 5,
}

/// Repeat mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum RepeatState {
    /// No repeat.
    #[default]
    Off = 0,
    /// Repeat the current track.
    Track = 1,
    /// Repeat the whole queue.
    All = 2,
}

/// Shuffle mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum ShuffleState {
    /// No shuffle.
    #[default]
    Off = 0,
    /// Shuffle albums.
    Albums = 1,
    /// Shuffle songs.
    Songs = 2,
}

/// Power state of the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum PowerState {
    /// Not reported by any connected protocol.
    #[default]
    Unknown = 0,
    /// Device is asleep or off.
    Off = 1,
    /// Device is awake.
    On = 2,
}

/// Whether the on-screen keyboard currently has focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum KeyboardFocusState {
    /// Not reported.
    #[default]
    Unknown = 0,
    /// No text field is focused.
    Unfocused = 1,
    /// A text field is focused and accepting input.
    Focused = 2,
}

/// Operating system family reported by a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum OperatingSystem {
    /// Could not be determined.
    #[default]
    Unknown = 0,
    /// Apple TV Software (generations 1-3).
    Legacy = 1,
    /// tvOS.
    TvOs = 2,
    /// `AirPort` base station firmware.
    AirPortOs = 3,
    /// macOS.
    MacOs = 4,
}

/// Hardware model reported by a device.
///
/// Discriminants are deliberately non-contiguous: pyatv appended `Music`, `AppleTV4KGen2`,
/// `AppleTV4KGen3`, `HomePodGen2` and `AppleTVGen1` over several releases and the numbers are
/// load-bearing, so they are reproduced exactly rather than renumbered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeviceModel {
    /// Could not be determined.
    #[default]
    Unknown = 0,
    /// Apple TV (2nd generation).
    Gen2 = 1,
    /// Apple TV (3rd generation).
    Gen3 = 2,
    /// Apple TV (4th generation).
    Gen4 = 3,
    /// Apple TV 4K (1st generation).
    Gen4K = 4,
    /// `HomePod`.
    HomePod = 5,
    /// `HomePod` mini.
    HomePodMini = 6,
    /// `AirPort` Express.
    AirPortExpress = 7,
    /// `AirPort` Express (2nd generation).
    AirPortExpressGen2 = 8,
    /// Apple TV 4K (2nd generation).
    AppleTv4KGen2 = 9,
    /// The Music/iTunes desktop application.
    Music = 10,
    /// Apple TV 4K (3rd generation).
    AppleTv4KGen3 = 11,
    /// `HomePod` (2nd generation).
    HomePodGen2 = 12,
    /// Apple TV (1st generation).
    AppleTvGen1 = 13,
}

/// How a directional or select button press should be delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum InputAction {
    /// A single press and release.
    #[default]
    SingleTap = 0,
    /// Two presses in quick succession.
    DoubleTap = 1,
    /// Press and hold.
    Hold = 2,
}

/// Whether a service must be paired before it can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PairingRequirement {
    /// The protocol does not support pairing at all.
    Unsupported = 1,
    /// Pairing is supported but disabled on the device.
    Disabled = 2,
    /// The service works without pairing.
    NotNeeded = 3,
    /// Pairing unlocks extra functionality but is not required.
    Optional = 4,
    /// The service is unusable until paired.
    Mandatory = 5,
}

/// A low-level trackpad gesture phase.
///
/// Note the gap at `2`: pyatv's `TouchAction` has no value for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TouchAction {
    /// Finger down.
    Press = 1,
    /// Finger held in place.
    Hold = 3,
    /// Finger lifted.
    Release = 4,
    /// A complete press-and-release.
    Click = 5,
}

impl Protocol {
    /// The protocol's display name, exactly as `pyatv/convert.py:54-62` (`protocol_str`) renders
    /// it. The string appears in `atvremote scan` output and in the display form of
    /// [`crate::models::BaseService`], so it is part of the observable contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mrp => "MRP",
            Self::Dmap => "DMAP",
            Self::AirPlay => "AirPlay",
            Self::Companion => "Companion",
            Self::Raop => "RAOP",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl MediaType {
    /// `media_type_str` (`pyatv/convert.py:26-33`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Video => "Video",
            Self::Music => "Music",
            Self::Tv => "TV",
        }
    }
}

impl std::fmt::Display for MediaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DeviceState {
    /// `device_state_str` (`pyatv/convert.py:13-23`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::Loading => "Loading",
            Self::Stopped => "Stopped",
            Self::Paused => "Paused",
            Self::Playing => "Playing",
            Self::Seeking => "Seeking",
        }
    }
}

impl std::fmt::Display for DeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RepeatState {
    /// `repeat_str` (`pyatv/convert.py:36-42`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Track => "Track",
            Self::All => "All",
        }
    }
}

impl std::fmt::Display for RepeatState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ShuffleState {
    /// `shuffle_str` (`pyatv/convert.py:45-51`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Albums => "Albums",
            Self::Songs => "Songs",
        }
    }
}

impl std::fmt::Display for ShuffleState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl DeviceModel {
    /// The model's display name, exactly as `pyatv/convert.py:65-81` (`model_str`) renders it.
    ///
    /// [`DeviceModel::Unknown`] renders as the literal `"Unknown"` because upstream looks the model
    /// up with `dict.get(device_model, "Unknown")` and has no entry for it. Callers that want the
    /// raw advertised model string to win instead should use
    /// [`crate::device_info::DeviceInfo::model_str`].
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AppleTvGen1 => "Apple TV 1",
            Self::Gen2 => "Apple TV 2",
            Self::Gen3 => "Apple TV 3",
            Self::Gen4 => "Apple TV 4",
            Self::Gen4K => "Apple TV 4K",
            Self::HomePod => "HomePod",
            Self::HomePodMini => "HomePod Mini",
            Self::AirPortExpress => "AirPort Express (gen 1)",
            Self::AirPortExpressGen2 => "AirPort Express (gen 2)",
            Self::AppleTv4KGen2 => "Apple TV 4K (gen 2)",
            Self::Music => "Music/iTunes",
            Self::AppleTv4KGen3 => "Apple TV 4K (gen 3)",
            Self::HomePodGen2 => "HomePod (gen 2)",
            Self::Unknown => "Unknown",
        }
    }
}

impl std::fmt::Display for DeviceModel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceModel, Protocol, TouchAction};

    /// The `Protocol` discriminants are part of pyatv's persisted credential/settings format, so
    /// they are pinned by this test rather than left to declaration order.
    #[test]
    fn protocol_discriminants_match_pyatv() {
        assert_eq!(Protocol::Dmap as u8, 1);
        assert_eq!(Protocol::Mrp as u8, 2);
        assert_eq!(Protocol::AirPlay as u8, 3);
        assert_eq!(Protocol::Companion as u8, 4);
        assert_eq!(Protocol::Raop as u8, 5);
    }

    /// `DeviceModel` was extended out of order upstream; guard the non-contiguous values.
    #[test]
    fn device_model_keeps_pyatv_numbering() {
        assert_eq!(DeviceModel::AppleTv4KGen2 as u8, 9);
        assert_eq!(DeviceModel::Music as u8, 10);
        assert_eq!(DeviceModel::AppleTv4KGen3 as u8, 11);
        assert_eq!(DeviceModel::HomePodGen2 as u8, 12);
        assert_eq!(DeviceModel::AppleTvGen1 as u8, 13);
    }

    /// `TouchAction` skips 2 upstream.
    #[test]
    fn touch_action_skips_two() {
        assert_eq!(TouchAction::Press as u8, 1);
        assert_eq!(TouchAction::Hold as u8, 3);
        assert_eq!(TouchAction::Release as u8, 4);
        assert_eq!(TouchAction::Click as u8, 5);
    }

    /// `atvremote scan` prints these strings verbatim, so they are pinned against
    /// `pyatv/convert.py::protocol_str`.
    #[test]
    fn protocol_display_matches_convert_protocol_str() {
        assert_eq!(Protocol::Mrp.to_string(), "MRP");
        assert_eq!(Protocol::Dmap.to_string(), "DMAP");
        assert_eq!(Protocol::AirPlay.to_string(), "AirPlay");
        assert_eq!(Protocol::Companion.to_string(), "Companion");
        assert_eq!(Protocol::Raop.to_string(), "RAOP");
    }

    /// Pinned against `pyatv/convert.py::model_str`.
    #[test]
    fn device_model_display_matches_convert_model_str() {
        assert_eq!(DeviceModel::AppleTvGen1.to_string(), "Apple TV 1");
        assert_eq!(DeviceModel::Gen2.to_string(), "Apple TV 2");
        assert_eq!(DeviceModel::Gen3.to_string(), "Apple TV 3");
        assert_eq!(DeviceModel::Gen4.to_string(), "Apple TV 4");
        assert_eq!(DeviceModel::Gen4K.to_string(), "Apple TV 4K");
        assert_eq!(DeviceModel::HomePod.to_string(), "HomePod");
        assert_eq!(DeviceModel::HomePodMini.to_string(), "HomePod Mini");
        assert_eq!(
            DeviceModel::AirPortExpress.to_string(),
            "AirPort Express (gen 1)"
        );
        assert_eq!(
            DeviceModel::AirPortExpressGen2.to_string(),
            "AirPort Express (gen 2)"
        );
        assert_eq!(
            DeviceModel::AppleTv4KGen2.to_string(),
            "Apple TV 4K (gen 2)"
        );
        assert_eq!(DeviceModel::Music.to_string(), "Music/iTunes");
        assert_eq!(
            DeviceModel::AppleTv4KGen3.to_string(),
            "Apple TV 4K (gen 3)"
        );
        assert_eq!(DeviceModel::HomePodGen2.to_string(), "HomePod (gen 2)");
        assert_eq!(DeviceModel::Unknown.to_string(), "Unknown");
    }
}
