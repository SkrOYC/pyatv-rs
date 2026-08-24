//! The Companion command vocabulary: HID buttons, media control and system status.
//!
//! The three enums are copied value-for-value from `pyatv/protocols/companion/api.py:35-85`
//! (`docs/research/companion-port-spec.md` §3.7, §3.8, §3.11). Every value is modelled even where
//! pyatv's own facade can never send it — `Siri` and `PageUp` have zero call sites upstream, and
//! four of the [`MediaControlCommand`] variants are likewise unreachable — because a raw-API caller
//! may want them and because a device could answer with one.

/// A HID button, sent as the `_hidC` content key of the same name (`api.py:35-56`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HidCommand {
    /// D-pad up.
    Up = 1,
    /// D-pad down.
    Down = 2,
    /// D-pad left.
    Left = 3,
    /// D-pad right.
    Right = 4,
    /// Menu / back.
    Menu = 5,
    /// Select / centre click.
    Select = 6,
    /// Home.
    Home = 7,
    /// Hardware volume up.
    VolumeUp = 8,
    /// Hardware volume down.
    VolumeDown = 9,
    /// Siri. Defined upstream but never sent by pyatv's own client.
    Siri = 10,
    /// Start the screensaver.
    Screensaver = 11,
    /// Put the device to sleep.
    Sleep = 12,
    /// Wake the device.
    Wake = 13,
    /// Toggle play/pause.
    PlayPause = 14,
    /// Next channel.
    ChannelIncrement = 15,
    /// Previous channel.
    ChannelDecrement = 16,
    /// Open the programme guide.
    Guide = 17,
    /// Page up. Defined upstream but never sent by pyatv's own client.
    PageUp = 18,
    /// Page down — which is what pyatv's `control_center()` actually sends, despite the name
    /// (`__init__.py:398-400`).
    PageDown = 19,
}

impl HidCommand {
    /// The number that goes on the wire under `_hidC`.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }
}

/// Button state under `_hBtS`: an integer with exactly two values, not a boolean
/// (`api.py:305-309`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ButtonState {
    /// Button pressed.
    Down = 1,
    /// Button released.
    Up = 2,
}

impl ButtonState {
    /// The number that goes on the wire under `_hBtS`.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// `1 if down else 2` (`api.py:308`).
    #[must_use]
    pub const fn from_down(down: bool) -> Self {
        if down { Self::Down } else { Self::Up }
    }
}

/// A media-control command, sent as the `_mcc` content key of the same name (`api.py:59-74`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MediaControlCommand {
    /// Start playback.
    Play = 1,
    /// Pause playback.
    Pause = 2,
    /// Skip to the next track.
    NextTrack = 3,
    /// Skip to the previous track.
    PreviousTrack = 4,
    /// Read the current volume.
    GetVolume = 5,
    /// Set the volume, as a `0.0..=1.0` fraction under `_vol`.
    SetVolume = 6,
    /// Seek by a relative number of seconds under `_skpS`.
    SkipBy = 7,
    /// Begin fast-forwarding. Never sent by pyatv's own facade.
    FastForwardBegin = 8,
    /// Stop fast-forwarding. Never sent by pyatv's own facade.
    FastForwardEnd = 9,
    /// Begin rewinding. Never sent by pyatv's own facade.
    RewindBegin = 10,
    /// Stop rewinding. Never sent by pyatv's own facade.
    RewindEnd = 11,
    /// Read caption settings. Never sent by pyatv's own facade.
    GetCaptionSettings = 12,
    /// Write caption settings. Never sent by pyatv's own facade.
    SetCaptionSettings = 13,
}

impl MediaControlCommand {
    /// The number that goes on the wire under `_mcc`.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }
}

/// What the device reports under `FetchAttentionState`'s `state` key (`api.py:77-85`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum SystemStatus {
    /// Client-side sentinel only. pyatv's own comment marks it "Not a valid protocol entry", so
    /// [`SystemStatus::from_code`] never produces it from wire bytes.
    #[default]
    Unknown = 0x00,
    /// Asleep.
    Asleep = 0x01,
    /// Showing the screensaver.
    Screensaver = 0x02,
    /// Awake.
    Awake = 0x03,
    /// Idle. pyatv marks this one "NB: Not verified" — believed but unconfirmed.
    Idle = 0x04,
}

impl SystemStatus {
    /// Map a wire value, refusing `0x00` and anything above `0x04`.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            0x01 => Some(Self::Asleep),
            0x02 => Some(Self::Screensaver),
            0x03 => Some(Self::Awake),
            0x04 => Some(Self::Idle),
            _ => None,
        }
    }

    /// The power state this status implies.
    ///
    /// `_system_status_to_power_state` (`__init__.py:263-273`): only `Asleep` means off, and
    /// screensaver, awake and idle all mean on.
    #[must_use]
    pub const fn to_power_state(self) -> pyatv_core::PowerState {
        use pyatv_core::PowerState;

        match self {
            Self::Asleep => PowerState::Off,
            Self::Screensaver | Self::Awake | Self::Idle => PowerState::On,
            Self::Unknown => PowerState::Unknown,
        }
    }
}

/// Whether a launch target should be sent as `_urlS` rather than `_bundleID`.
///
/// Mirrors `is_url_or_scheme` (`pyatv/support/url.py:12-15`), which is `bool(urlparse(x).scheme)`
/// — deliberately *not* the stricter `is_url`, and deliberately not the `url` crate: `Url::parse`
/// rejects a bare `"myapp:"` that Python's `urlparse` happily reports a scheme for
/// (`docs/research/companion-port-spec.md` §12 finding 9).
///
/// Python's scheme grammar is `[A-Za-z][A-Za-z0-9+.-]*` followed by `:`, and `urlparse` requires
/// the first character to be a letter — which is what keeps a bundle identifier such as
/// `com.apple.TVMusic` (no colon at all) on the `_bundleID` path.
#[must_use]
pub fn is_url_or_scheme(target: &str) -> bool {
    let Some((scheme, _)) = target.split_once(':') else {
        return false;
    };

    let mut characters = scheme.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic())
        && characters.all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '+' | '.' | '-')
        })
}

#[cfg(test)]
mod tests {
    use super::{ButtonState, HidCommand, MediaControlCommand, SystemStatus, is_url_or_scheme};
    use pyatv_core::PowerState;

    #[test]
    fn hid_and_media_control_codes_match_upstream() {
        assert_eq!(HidCommand::Up.code(), 1);
        assert_eq!(HidCommand::Select.code(), 6);
        assert_eq!(HidCommand::Sleep.code(), 12);
        assert_eq!(HidCommand::Wake.code(), 13);
        assert_eq!(HidCommand::PageDown.code(), 19);

        assert_eq!(MediaControlCommand::Play.code(), 1);
        assert_eq!(MediaControlCommand::SkipBy.code(), 7);
        assert_eq!(MediaControlCommand::SetCaptionSettings.code(), 13);
    }

    #[test]
    fn button_state_is_one_or_two_not_a_boolean() {
        assert_eq!(ButtonState::from_down(true).code(), 1);
        assert_eq!(ButtonState::from_down(false).code(), 2);
    }

    #[test]
    fn the_unknown_system_status_never_comes_off_the_wire() {
        assert_eq!(SystemStatus::from_code(0x00), None);
        assert_eq!(SystemStatus::from_code(0x05), None);
        assert_eq!(SystemStatus::from_code(0x01), Some(SystemStatus::Asleep));
        assert_eq!(SystemStatus::from_code(0x04), Some(SystemStatus::Idle));
    }

    #[test]
    fn only_asleep_maps_to_power_off() {
        assert_eq!(SystemStatus::Asleep.to_power_state(), PowerState::Off);
        assert_eq!(SystemStatus::Screensaver.to_power_state(), PowerState::On);
        assert_eq!(SystemStatus::Awake.to_power_state(), PowerState::On);
        assert_eq!(SystemStatus::Idle.to_power_state(), PowerState::On);
        assert_eq!(SystemStatus::Unknown.to_power_state(), PowerState::Unknown);
    }

    /// The classification table `docs/research/companion-port-spec.md` §12 finding 9 asks for.
    #[test]
    fn bundle_identifiers_and_urls_route_to_different_keys() {
        assert!(!is_url_or_scheme("com.apple.TVMusic"));
        assert!(!is_url_or_scheme("com.netflix.Netflix"));
        assert!(!is_url_or_scheme(""));
        // A bare scheme with no authority: Python's `urlparse` accepts it, `Url::parse` would not.
        assert!(is_url_or_scheme("myapp:"));
        assert!(is_url_or_scheme("https://example.com/x"));
        assert!(is_url_or_scheme("tv+:show"));
        // A scheme must start with a letter, so a leading digit is not one.
        assert!(!is_url_or_scheme("1nvalid:x"));
        // …and must not contain characters outside the scheme alphabet.
        assert!(!is_url_or_scheme("has space:x"));
    }
}
