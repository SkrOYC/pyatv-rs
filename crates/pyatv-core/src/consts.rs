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
}
