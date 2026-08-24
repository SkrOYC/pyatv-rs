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
}
