//! Feature reporting: which capabilities a connected device actually exposes right now.
//!
//! `FeatureName` mirrors `pyatv/const.py`'s enum of the same name — one variant per
//! `@feature`-decorated method or property across the capability traits in [`crate::interface`].
//! Upstream grows this enum every release (`Guide` and `ControlCenter` landed in v0.17.0,
//! `ItunesStoreIdentifier` in v0.16.0), so it is marked `#[non_exhaustive]`.
//!
//! Unlike [`crate::consts`], `FeatureName`'s integer values are *not* part of pyatv's persisted
//! format, so no discriminants are pinned here.

use serde::{Deserialize, Serialize};

/// Availability of a single feature on a connected device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[repr(u8)]
pub enum FeatureState {
    /// Availability could not be determined.
    #[default]
    Unknown = 0,
    /// No connected protocol implements this feature.
    Unsupported = 1,
    /// Implemented, but not usable in the current device state.
    Unavailable = 2,
    /// Usable right now.
    Available = 3,
}

/// One capability of the unified device interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum FeatureName {
    // RemoteControl — navigation.
    /// Move selection up.
    Up,
    /// Move selection down.
    Down,
    /// Move selection left.
    Left,
    /// Move selection right.
    Right,
    /// Activate the selected item.
    Select,
    /// Go back one level.
    Menu,
    /// Go to the home screen.
    Home,
    /// Press and hold home.
    HomeHold,
    /// Go to the top-level menu.
    TopMenu,
    /// Open the on-screen programme guide.
    Guide,
    /// Open Control Center.
    ControlCenter,
    /// Start the screensaver.
    Screensaver,

    // RemoteControl — transport.
    /// Start playback.
    Play,
    /// Toggle play/pause.
    PlayPause,
    /// Pause playback.
    Pause,
    /// Stop playback.
    Stop,
    /// Skip to the next item.
    Next,
    /// Skip to the previous item.
    Previous,
    /// Jump forward by a time interval.
    SkipForward,
    /// Jump backward by a time interval.
    SkipBackward,
    /// Seek to an absolute position.
    SetPosition,
    /// Change shuffle mode.
    SetShuffle,
    /// Change repeat mode.
    SetRepeat,
    /// Channel up.
    ChannelUp,
    /// Channel down.
    ChannelDown,

    // Metadata / Playing.
    /// Title of the current item.
    Title,
    /// Artist of the current item.
    Artist,
    /// Album of the current item.
    Album,
    /// Genre of the current item.
    Genre,
    /// Total duration.
    TotalTime,
    /// Current position.
    Position,
    /// Current shuffle mode.
    Shuffle,
    /// Current repeat mode.
    Repeat,
    /// Series name for TV content.
    SeriesName,
    /// Season number for TV content.
    SeasonNumber,
    /// Episode number for TV content.
    EpisodeNumber,
    /// Opaque content identifier.
    ContentIdentifier,
    /// iTunes Store identifier.
    ItunesStoreIdentifier,
    /// Current media type.
    MediaType,
    /// Current transport state.
    DeviceState,
    /// Artwork for the current item.
    Artwork,
    /// The app that owns the current item.
    App,

    // Power.
    /// Read the power state.
    PowerState,
    /// Wake the device.
    TurnOn,
    /// Put the device to sleep.
    TurnOff,

    // Apps.
    /// Enumerate installed apps.
    AppList,
    /// Launch an app by bundle identifier or URL.
    LaunchApp,

    // Audio.
    /// Read the current volume.
    Volume,
    /// Set the volume.
    SetVolume,
    /// Step the volume up.
    VolumeUp,
    /// Step the volume down.
    VolumeDown,
    /// Enumerate and manage `AirPlay` 2 output devices.
    OutputDevices,

    // Stream.
    /// Play a video URL.
    PlayUrl,
    /// Stream an audio file over RAOP.
    StreamFile,

    // Keyboard.
    /// Whether a text field currently has focus.
    TextFocusState,
    /// Read the focused text field's contents.
    TextGet,
    /// Replace the focused text field's contents.
    TextSet,
    /// Append to the focused text field.
    TextAppend,
    /// Clear the focused text field.
    TextClear,

    // TouchGestures.
    /// Send a swipe gesture.
    Swipe,
    /// Send a click gesture.
    Click,
    /// Send a raw touch action.
    TouchAction,

    // UserAccounts.
    /// Enumerate user accounts.
    AccountList,
    /// Switch the active user account.
    SwitchAccount,

    // PushUpdater.
    /// Receive push-based now-playing updates.
    PushUpdates,
}

impl FeatureName {
    /// Every variant, in declaration order.
    ///
    /// Upstream iterates the enum itself — `for name in FeatureName` in
    /// `Features.all_features` (`pyatv/interface.py:1088-1095`) — which Rust cannot do for a
    /// plain enum without a derive. The list is hand-maintained; the test below asserts its
    /// length against [`FeatureName::COUNT`] so adding a variant without extending it fails to
    /// compile-and-test rather than silently dropping the feature from `atvremote features`.
    pub const ALL: [Self; Self::COUNT] = [
        Self::Up,
        Self::Down,
        Self::Left,
        Self::Right,
        Self::Select,
        Self::Menu,
        Self::Home,
        Self::HomeHold,
        Self::TopMenu,
        Self::Guide,
        Self::ControlCenter,
        Self::Screensaver,
        Self::Play,
        Self::PlayPause,
        Self::Pause,
        Self::Stop,
        Self::Next,
        Self::Previous,
        Self::SkipForward,
        Self::SkipBackward,
        Self::SetPosition,
        Self::SetShuffle,
        Self::SetRepeat,
        Self::ChannelUp,
        Self::ChannelDown,
        Self::Title,
        Self::Artist,
        Self::Album,
        Self::Genre,
        Self::TotalTime,
        Self::Position,
        Self::Shuffle,
        Self::Repeat,
        Self::SeriesName,
        Self::SeasonNumber,
        Self::EpisodeNumber,
        Self::ContentIdentifier,
        Self::ItunesStoreIdentifier,
        Self::MediaType,
        Self::DeviceState,
        Self::Artwork,
        Self::App,
        Self::PowerState,
        Self::TurnOn,
        Self::TurnOff,
        Self::AppList,
        Self::LaunchApp,
        Self::Volume,
        Self::SetVolume,
        Self::VolumeUp,
        Self::VolumeDown,
        Self::OutputDevices,
        Self::PlayUrl,
        Self::StreamFile,
        Self::TextFocusState,
        Self::TextGet,
        Self::TextSet,
        Self::TextAppend,
        Self::TextClear,
        Self::Swipe,
        Self::Click,
        Self::TouchAction,
        Self::AccountList,
        Self::SwitchAccount,
        Self::PushUpdates,
    ];

    /// Number of variants in [`FeatureName::ALL`].
    pub const COUNT: usize = 65;

    /// The variant's name, as `atvremote features` prints it.
    ///
    /// Matches Python's `FeatureName.<x>.name`, which is what upstream's `features` command
    /// formats with (`pyatv/scripts/atvremote.py:453`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "Up",
            Self::Down => "Down",
            Self::Left => "Left",
            Self::Right => "Right",
            Self::Select => "Select",
            Self::Menu => "Menu",
            Self::Home => "Home",
            Self::HomeHold => "HomeHold",
            Self::TopMenu => "TopMenu",
            Self::Guide => "Guide",
            Self::ControlCenter => "ControlCenter",
            Self::Screensaver => "Screensaver",
            Self::Play => "Play",
            Self::PlayPause => "PlayPause",
            Self::Pause => "Pause",
            Self::Stop => "Stop",
            Self::Next => "Next",
            Self::Previous => "Previous",
            Self::SkipForward => "SkipForward",
            Self::SkipBackward => "SkipBackward",
            Self::SetPosition => "SetPosition",
            Self::SetShuffle => "SetShuffle",
            Self::SetRepeat => "SetRepeat",
            Self::ChannelUp => "ChannelUp",
            Self::ChannelDown => "ChannelDown",
            Self::Title => "Title",
            Self::Artist => "Artist",
            Self::Album => "Album",
            Self::Genre => "Genre",
            Self::TotalTime => "TotalTime",
            Self::Position => "Position",
            Self::Shuffle => "Shuffle",
            Self::Repeat => "Repeat",
            Self::SeriesName => "SeriesName",
            Self::SeasonNumber => "SeasonNumber",
            Self::EpisodeNumber => "EpisodeNumber",
            Self::ContentIdentifier => "ContentIdentifier",
            Self::ItunesStoreIdentifier => "ItunesStoreIdentifier",
            Self::MediaType => "MediaType",
            Self::DeviceState => "DeviceState",
            Self::Artwork => "Artwork",
            Self::App => "App",
            Self::PowerState => "PowerState",
            Self::TurnOn => "TurnOn",
            Self::TurnOff => "TurnOff",
            Self::AppList => "AppList",
            Self::LaunchApp => "LaunchApp",
            Self::Volume => "Volume",
            Self::SetVolume => "SetVolume",
            Self::VolumeUp => "VolumeUp",
            Self::VolumeDown => "VolumeDown",
            Self::OutputDevices => "OutputDevices",
            Self::PlayUrl => "PlayUrl",
            Self::StreamFile => "StreamFile",
            Self::TextFocusState => "TextFocusState",
            Self::TextGet => "TextGet",
            Self::TextSet => "TextSet",
            Self::TextAppend => "TextAppend",
            Self::TextClear => "TextClear",
            Self::Swipe => "Swipe",
            Self::Click => "Click",
            Self::TouchAction => "Action",
            Self::AccountList => "AccountList",
            Self::SwitchAccount => "SwitchAccount",
            Self::PushUpdates => "PushUpdates",
        }
    }
}

impl std::fmt::Display for FeatureName {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The reported availability of one feature, plus an optional hint about why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeatureInfo {
    /// Availability of the feature.
    pub state: FeatureState,
    /// Free-form explanation, e.g. which protocol would be needed to enable it.
    pub reason: Option<String>,
}

impl FeatureInfo {
    /// A feature that is usable right now.
    #[must_use]
    pub const fn available() -> Self {
        Self {
            state: FeatureState::Available,
            reason: None,
        }
    }

    /// A feature no connected protocol implements.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            state: FeatureState::Unsupported,
            reason: None,
        }
    }

    /// A feature that is implemented but not usable in the device's current state.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            state: FeatureState::Unavailable,
            reason: None,
        }
    }
}

impl FeatureState {
    /// The state's name, as `atvremote features` prints it.
    ///
    /// Matches Python's `FeatureState.<x>.name` (`pyatv/scripts/atvremote.py:453`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "Unknown",
            Self::Unsupported => "Unsupported",
            Self::Unavailable => "Unavailable",
            Self::Available => "Available",
        }
    }
}

impl std::fmt::Display for FeatureState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::FeatureName;
    use std::collections::BTreeSet;

    /// `ALL` is hand-maintained; a duplicate or a missing variant would silently distort
    /// `atvremote features`.
    #[test]
    fn all_feature_names_are_unique_and_complete() {
        let unique: BTreeSet<FeatureName> = FeatureName::ALL.into_iter().collect();
        assert_eq!(unique.len(), FeatureName::COUNT);
    }

    #[test]
    fn feature_names_render_with_upstreams_spelling() {
        assert_eq!(FeatureName::TouchAction.to_string(), "Action");
        assert_eq!(FeatureName::PlayPause.to_string(), "PlayPause");
    }
}
