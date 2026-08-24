//! Feature reporting: which capabilities a connected device actually exposes right now.
//!
//! `FeatureName` mirrors `pyatv/const.py`'s enum of the same name — one variant per
//! `@feature`-decorated method or property across the capability traits in [`crate::interface`].
//! Upstream grows this enum every release (`Guide` and `ControlCenter` landed in v0.17.0,
//! `iTunesStoreIdentifier` in v0.16.0), so it is marked `#[non_exhaustive]`.
//!
//! The variants are declared in **upstream's order**, not in a tidier one, because
//! [`FeatureName::ALL`] is what `atvremote features` iterates and pyatv's `for name in FeatureName`
//! walks the enum in definition order. `tests::the_feature_names_match_const_py` pins the whole
//! ordered list against a fixture copied out of `const.py`.
//!
//! Two variants are spelled differently in Rust than in Python — `iTunesStoreIdentifier` is not a
//! legal Rust variant name, and `Action` reads badly next to the [`crate::TouchAction`] enum it
//! takes — so [`FeatureName::as_str`] rather than the variant name is what matches upstream.
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
    /// Move selection up.
    Up,
    /// Move selection down.
    Down,
    /// Move selection left.
    Left,
    /// Move selection right.
    Right,
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
    /// Activate the selected item.
    Select,
    /// Go back one level.
    Menu,
    /// Step the volume up.
    VolumeUp,
    /// Step the volume down.
    VolumeDown,
    /// Go to the home screen.
    Home,
    /// Press and hold home.
    ///
    /// Deprecated upstream in favour of `RemoteControl.home` with an `InputAction`
    /// (`const.py:300-301`); kept because upstream still emits it.
    HomeHold,
    /// Go to the top-level menu.
    TopMenu,
    /// Suspend the device.
    ///
    /// Deprecated upstream in favour of [`FeatureName::TurnOff`] (`const.py:306-307`). No protocol
    /// in this workspace declares it; it exists so the enum matches upstream's, which is what the
    /// facade iterates when reporting every feature.
    Suspend,
    /// Wake the device up.
    ///
    /// Deprecated upstream in favour of [`FeatureName::TurnOn`] (`const.py:309-310`); see
    /// [`FeatureName::Suspend`].
    WakeUp,
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
    ///
    /// Spelled `iTunesStoreIdentifier` upstream, which is not a legal Rust variant name under
    /// `non_camel_case_types`; [`FeatureName::as_str`] reports upstream's spelling.
    ItunesStoreIdentifier,
    /// Enumerate installed apps.
    AppList,
    /// Launch an app by bundle identifier or URL.
    LaunchApp,
    /// Enumerate user accounts.
    AccountList,
    /// Switch the active user account.
    SwitchAccount,
    /// Artwork for the current item.
    Artwork,
    /// The app that owns the current item.
    App,
    /// Receive push-based now-playing updates.
    PushUpdates,
    /// Play a video URL.
    PlayUrl,
    /// Stream an audio file over RAOP.
    StreamFile,
    /// Read the power state.
    PowerState,
    /// Start the screensaver.
    Screensaver,
    /// Wake the device.
    TurnOn,
    /// Put the device to sleep.
    TurnOff,
    /// Read the current volume.
    Volume,
    /// Set the volume.
    SetVolume,
    /// Enumerate `AirPlay` 2 output devices.
    OutputDevices,
    /// Add `AirPlay` 2 output devices.
    AddOutputDevices,
    /// Remove `AirPlay` 2 output devices.
    RemoveOutputDevices,
    /// Replace the set of `AirPlay` 2 output devices.
    SetOutputDevices,
    /// Whether a text field currently has focus.
    TextFocusState,
    /// Read the focused text field's contents.
    TextGet,
    /// Clear the focused text field.
    TextClear,
    /// Append to the focused text field.
    TextAppend,
    /// Replace the focused text field's contents.
    TextSet,
    /// Send a swipe gesture.
    Swipe,
    /// Send a raw touch action.
    ///
    /// Named `Action` upstream (`const.py:447`); the Rust variant is `TouchAction` so it does not
    /// read as a bare verb next to the [`crate::TouchAction`] enum it takes.
    TouchAction,
    /// Send a click gesture.
    Click,
    /// Open the on-screen programme guide.
    Guide,
    /// Open Control Center.
    ControlCenter,
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
        Self::Play,
        Self::PlayPause,
        Self::Pause,
        Self::Stop,
        Self::Next,
        Self::Previous,
        Self::Select,
        Self::Menu,
        Self::VolumeUp,
        Self::VolumeDown,
        Self::Home,
        Self::HomeHold,
        Self::TopMenu,
        Self::Suspend,
        Self::WakeUp,
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
        Self::AppList,
        Self::LaunchApp,
        Self::AccountList,
        Self::SwitchAccount,
        Self::Artwork,
        Self::App,
        Self::PushUpdates,
        Self::PlayUrl,
        Self::StreamFile,
        Self::PowerState,
        Self::Screensaver,
        Self::TurnOn,
        Self::TurnOff,
        Self::Volume,
        Self::SetVolume,
        Self::OutputDevices,
        Self::AddOutputDevices,
        Self::RemoveOutputDevices,
        Self::SetOutputDevices,
        Self::TextFocusState,
        Self::TextGet,
        Self::TextClear,
        Self::TextAppend,
        Self::TextSet,
        Self::Swipe,
        Self::TouchAction,
        Self::Click,
        Self::Guide,
        Self::ControlCenter,
    ];

    /// Number of variants in [`FeatureName::ALL`].
    pub const COUNT: usize = 68;

    /// The variant's name, as `atvremote features` prints it.
    ///
    /// Matches Python's `FeatureName.<x>.name`, which is what upstream's `features` command
    /// formats with (`pyatv/scripts/atvremote.py:453`). Note that this is the **enum member name**
    /// and not the string passed to upstream's `@feature` decorator: the two disagree for
    /// `Action`, which `interface.py:1301` decorates as `"TouchAction"` while `const.py:447` names
    /// `Action`. `atvremote` prints the member name, so that is what is reproduced here.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Up => "Up",
            Self::Down => "Down",
            Self::Left => "Left",
            Self::Right => "Right",
            Self::Play => "Play",
            Self::PlayPause => "PlayPause",
            Self::Pause => "Pause",
            Self::Stop => "Stop",
            Self::Next => "Next",
            Self::Previous => "Previous",
            Self::Select => "Select",
            Self::Menu => "Menu",
            Self::VolumeUp => "VolumeUp",
            Self::VolumeDown => "VolumeDown",
            Self::Home => "Home",
            Self::HomeHold => "HomeHold",
            Self::TopMenu => "TopMenu",
            Self::Suspend => "Suspend",
            Self::WakeUp => "WakeUp",
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
            Self::ItunesStoreIdentifier => "iTunesStoreIdentifier",
            Self::AppList => "AppList",
            Self::LaunchApp => "LaunchApp",
            Self::AccountList => "AccountList",
            Self::SwitchAccount => "SwitchAccount",
            Self::Artwork => "Artwork",
            Self::App => "App",
            Self::PushUpdates => "PushUpdates",
            Self::PlayUrl => "PlayUrl",
            Self::StreamFile => "StreamFile",
            Self::PowerState => "PowerState",
            Self::Screensaver => "Screensaver",
            Self::TurnOn => "TurnOn",
            Self::TurnOff => "TurnOff",
            Self::Volume => "Volume",
            Self::SetVolume => "SetVolume",
            Self::OutputDevices => "OutputDevices",
            Self::AddOutputDevices => "AddOutputDevices",
            Self::RemoveOutputDevices => "RemoveOutputDevices",
            Self::SetOutputDevices => "SetOutputDevices",
            Self::TextFocusState => "TextFocusState",
            Self::TextGet => "TextGet",
            Self::TextClear => "TextClear",
            Self::TextAppend => "TextAppend",
            Self::TextSet => "TextSet",
            Self::Swipe => "Swipe",
            Self::TouchAction => "Action",
            Self::Click => "Click",
            Self::Guide => "Guide",
            Self::ControlCenter => "ControlCenter",
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

    /// Every member name in `pyatv/const.py:252-457`, in declaration order.
    ///
    /// Copied out of `class FeatureName(Enum)` at pyatv b277a4c (release 0.18.0) with
    /// `[f.name for f in FeatureName]`. Python's `Enum` iterates in definition order and
    /// `Features.all_features` iterates the enum (`interface.py:1091`), so this is both the
    /// membership *and* the order `atvremote features` prints.
    const UPSTREAM: [&str; 68] = [
        "Up",
        "Down",
        "Left",
        "Right",
        "Play",
        "PlayPause",
        "Pause",
        "Stop",
        "Next",
        "Previous",
        "Select",
        "Menu",
        "VolumeUp",
        "VolumeDown",
        "Home",
        "HomeHold",
        "TopMenu",
        "Suspend",
        "WakeUp",
        "SkipForward",
        "SkipBackward",
        "SetPosition",
        "SetShuffle",
        "SetRepeat",
        "ChannelUp",
        "ChannelDown",
        "Title",
        "Artist",
        "Album",
        "Genre",
        "TotalTime",
        "Position",
        "Shuffle",
        "Repeat",
        "SeriesName",
        "SeasonNumber",
        "EpisodeNumber",
        "ContentIdentifier",
        "iTunesStoreIdentifier",
        "AppList",
        "LaunchApp",
        "AccountList",
        "SwitchAccount",
        "Artwork",
        "App",
        "PushUpdates",
        "PlayUrl",
        "StreamFile",
        "PowerState",
        "Screensaver",
        "TurnOn",
        "TurnOff",
        "Volume",
        "SetVolume",
        "OutputDevices",
        "AddOutputDevices",
        "RemoveOutputDevices",
        "SetOutputDevices",
        "TextFocusState",
        "TextGet",
        "TextClear",
        "TextAppend",
        "TextSet",
        "Swipe",
        "Action",
        "Click",
        "Guide",
        "ControlCenter",
    ];

    /// The whole enum, name for name and in order, against upstream.
    ///
    /// This is the test that would have caught the three drifts it was written for: `MediaType`
    /// and `DeviceState` were invented here and are not `FeatureName`s upstream at all (they are
    /// the `MediaType`/`DeviceState` enums), the three `*OutputDevices` members were missing, and
    /// the deprecated `Suspend`/`WakeUp` pair was dropped even though upstream still iterates them.
    #[test]
    fn the_feature_names_match_const_py() {
        let ours: Vec<&str> = FeatureName::ALL.iter().map(|name| name.as_str()).collect();
        assert_eq!(ours, UPSTREAM.to_vec());
    }

    /// `ALL` is hand-maintained; a duplicate or a missing variant would silently distort
    /// `atvremote features`.
    #[test]
    fn all_feature_names_are_unique_and_complete() {
        let unique: BTreeSet<FeatureName> = FeatureName::ALL.into_iter().collect();
        assert_eq!(unique.len(), FeatureName::COUNT);
    }

    /// The two variants whose Rust spelling deliberately differs from upstream's.
    #[test]
    fn feature_names_render_with_upstreams_spelling() {
        assert_eq!(FeatureName::TouchAction.to_string(), "Action");
        assert_eq!(
            FeatureName::ItunesStoreIdentifier.to_string(),
            "iTunesStoreIdentifier"
        );
        assert_eq!(FeatureName::PlayPause.to_string(), "PlayPause");
    }
}
