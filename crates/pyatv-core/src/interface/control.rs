//! Input traits: buttons, on-screen keyboard and trackpad gestures.

use crate::Result;
use crate::consts::{InputAction, KeyboardFocusState, RepeatState, ShuffleState, TouchAction};
use crate::interface::BoxFuture;

/// Navigation and media transport control.
///
/// Mirrors `pyatv.interface.RemoteControl`. Every method maps to a
/// [`crate::features::FeatureName`] so [`super::Features`] can report availability per method.
///
/// # Errors
///
/// Every method returns [`crate::Error::NotSupported`] when no connected protocol implements it,
/// [`crate::Error::Command`] when the device rejects it, and [`crate::Error::ConnectionLost`] if
/// the transport dropped.
pub trait RemoteControl: Send + Sync + std::fmt::Debug {
    /// Move the selection up.
    fn up(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Move the selection down.
    fn down(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Move the selection left.
    fn left(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Move the selection right.
    fn right(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Activate the selected item.
    fn select(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Go back one level.
    fn menu(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Go to the home screen.
    fn home(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
    /// Press and hold home, opening the app switcher.
    fn home_hold(&self) -> BoxFuture<'_, Result<()>>;
    /// Go to the top-level menu.
    fn top_menu(&self) -> BoxFuture<'_, Result<()>>;
    /// Open the on-screen programme guide.
    fn guide(&self) -> BoxFuture<'_, Result<()>>;
    /// Open Control Center.
    fn control_center(&self) -> BoxFuture<'_, Result<()>>;
    /// Start the screensaver.
    fn screensaver(&self) -> BoxFuture<'_, Result<()>>;

    /// Start playback.
    fn play(&self) -> BoxFuture<'_, Result<()>>;
    /// Toggle between play and pause.
    fn play_pause(&self) -> BoxFuture<'_, Result<()>>;
    /// Pause playback.
    fn pause(&self) -> BoxFuture<'_, Result<()>>;
    /// Stop playback.
    fn stop(&self) -> BoxFuture<'_, Result<()>>;
    /// Skip to the next item.
    fn next(&self) -> BoxFuture<'_, Result<()>>;
    /// Skip to the previous item.
    fn previous(&self) -> BoxFuture<'_, Result<()>>;

    /// Jump forward by `interval` seconds.
    fn skip_forward(&self, interval: f32) -> BoxFuture<'_, Result<()>>;
    /// Jump backward by `interval` seconds.
    fn skip_backward(&self, interval: f32) -> BoxFuture<'_, Result<()>>;
    /// Seek to an absolute position, in seconds.
    fn set_position(&self, position: f32) -> BoxFuture<'_, Result<()>>;
    /// Change the shuffle mode.
    fn set_shuffle(&self, state: ShuffleState) -> BoxFuture<'_, Result<()>>;
    /// Change the repeat mode.
    fn set_repeat(&self, state: RepeatState) -> BoxFuture<'_, Result<()>>;

    /// Step to the next channel.
    fn channel_up(&self) -> BoxFuture<'_, Result<()>>;
    /// Step to the previous channel.
    fn channel_down(&self) -> BoxFuture<'_, Result<()>>;
}

/// On-screen keyboard text entry. Companion-only in pyatv.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] unless a Companion connection is active, and
/// [`crate::Error::Command`] if no text field currently has focus.
pub trait Keyboard: Send + Sync + std::fmt::Debug {
    /// Whether a text field is currently accepting input.
    fn text_focus_state(&self) -> KeyboardFocusState;
    /// Read the focused field's contents.
    fn text_get(&self) -> BoxFuture<'_, Result<Option<String>>>;
    /// Replace the focused field's contents.
    fn text_set(&self, text: &str) -> BoxFuture<'_, Result<()>>;
    /// Append to the focused field.
    fn text_append(&self, text: &str) -> BoxFuture<'_, Result<()>>;
    /// Clear the focused field.
    fn text_clear(&self) -> BoxFuture<'_, Result<()>>;
}

/// Trackpad-style gestures for the virtual remote surface.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] unless a protocol implementing gestures is
/// connected.
pub trait TouchGestures: Send + Sync + std::fmt::Debug {
    /// Send a raw touch phase at a point on the virtual trackpad.
    fn action(&self, x: i32, y: i32, action: TouchAction) -> BoxFuture<'_, Result<()>>;
    /// Swipe from one point to another over `duration_ms` milliseconds.
    fn swipe(
        &self,
        start_x: i32,
        start_y: i32,
        end_x: i32,
        end_y: i32,
        duration_ms: u32,
    ) -> BoxFuture<'_, Result<()>>;
    /// Send a complete press-and-release.
    ///
    /// Takes an [`InputAction`], not a [`TouchAction`]: upstream's signature is
    /// `click(self, action: InputAction)` (`pyatv/interface.py:1312-1318`), and the three
    /// [`InputAction`] variants are exactly the three shapes a click can have — one tap, two taps,
    /// or one held for a second. [`TouchGestures::action`] is the one that takes a touch *phase*.
    fn click(&self, action: InputAction) -> BoxFuture<'_, Result<()>>;
}
