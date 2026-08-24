//! [`RemoteControl`] over Companion.
//!
//! Port of `CompanionRemoteControl` (`pyatv/protocols/companion/__init__.py:295-425`). Navigation,
//! volume buttons, play/pause, channel, screensaver, guide and control-center go out as `_hidC`
//! button presses; play, pause, next, previous and the two skips go out as `_mcc` media-control
//! commands instead. The split is upstream's, not this port's.
//!
//! Six [`RemoteControl`] methods have no Companion implementation at all — `home_hold`, `top_menu`,
//! `stop`, `set_position`, `set_shuffle` and `set_repeat`. pyatv expresses that by simply not
//! defining them, which makes its relayer raise `NotSupportedError`; Rust's traits have no such
//! thing as a partially implemented trait, so each returns [`pyatv_core::Error::NotSupported`] and
//! the facade's relayer falls through to another protocol when one is connected.

use std::sync::Arc;

use pyatv_core::interface::{BoxFuture, RemoteControl, not_supported};
use pyatv_core::{InputAction, RepeatState, Result, ShuffleState};

use crate::api::commands::{HidCommand, MediaControlCommand};
use crate::api::{CompanionApi, DEFAULT_SKIP_TIME};

/// Companion's remote control.
#[derive(Debug)]
pub struct CompanionRemoteControl {
    api: Arc<CompanionApi>,
}

impl CompanionRemoteControl {
    /// Wrap a connected session.
    #[must_use]
    pub const fn new(api: Arc<CompanionApi>) -> Self {
        Self { api }
    }

    /// One `_hidC` press, shaped by `action`.
    fn press(&self, command: HidCommand, action: InputAction) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.api
                .press_button(command, action)
                .await
                .map_err(Into::into)
        })
    }

    /// One `_mcc` command with no arguments.
    fn media(&self, command: MediaControlCommand) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.api
                .mediacontrol_command(command)
                .await
                .map(|_| ())
                .map_err(Into::into)
        })
    }

    /// `_mcc` `SkipBy` with the sign the caller asked for.
    ///
    /// `skip_forward`/`skip_backward` (`__init__.py:359-380`): a non-positive interval means "use
    /// the default", which upstream hardcodes at ten seconds "as seen in the TV Remote App".
    fn skip(&self, interval: f32, forward: bool) -> BoxFuture<'_, Result<()>> {
        let magnitude = if interval > 0.0 {
            interval
        } else {
            DEFAULT_SKIP_TIME
        };
        let seconds = if forward { magnitude } else { -magnitude };

        Box::pin(async move { self.api.skip_by(seconds).await.map_err(Into::into) })
    }
}

impl RemoteControl for CompanionRemoteControl {
    fn up(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Up, action)
    }

    fn down(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Down, action)
    }

    fn left(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Left, action)
    }

    fn right(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Right, action)
    }

    fn select(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Select, action)
    }

    fn menu(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Menu, action)
    }

    fn home(&self, action: InputAction) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Home, action)
    }

    /// Not implemented by Companion. pyatv's own `home_hold` is DMAP- and MRP-only.
    fn home_hold(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("home_hold over Companion")) })
    }

    /// Not implemented by Companion.
    fn top_menu(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("top_menu over Companion")) })
    }

    fn guide(&self) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Guide, InputAction::SingleTap)
    }

    /// Control Center, which upstream sends as `HidCommand::PageDown`.
    ///
    /// The name mismatch is real and deliberate (`__init__.py:398-400`): there is no
    /// control-centre-specific HID code, and page-down is what tvOS acts on.
    fn control_center(&self) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::PageDown, InputAction::SingleTap)
    }

    fn screensaver(&self) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::Screensaver, InputAction::SingleTap)
    }

    fn play(&self) -> BoxFuture<'_, Result<()>> {
        self.media(MediaControlCommand::Play)
    }

    /// A single `_hidC` button, not a play plus a pause.
    fn play_pause(&self) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::PlayPause, InputAction::SingleTap)
    }

    fn pause(&self) -> BoxFuture<'_, Result<()>> {
        self.media(MediaControlCommand::Pause)
    }

    /// Not implemented by Companion. `MediaControlCommand` has no stop.
    fn stop(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("stop over Companion")) })
    }

    fn next(&self) -> BoxFuture<'_, Result<()>> {
        self.media(MediaControlCommand::NextTrack)
    }

    fn previous(&self) -> BoxFuture<'_, Result<()>> {
        self.media(MediaControlCommand::PreviousTrack)
    }

    fn skip_forward(&self, interval: f32) -> BoxFuture<'_, Result<()>> {
        self.skip(interval, true)
    }

    fn skip_backward(&self, interval: f32) -> BoxFuture<'_, Result<()>> {
        self.skip(interval, false)
    }

    /// Not implemented by Companion: there is no absolute-seek command.
    fn set_position(&self, _position: f32) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("set_position over Companion")) })
    }

    /// Not implemented by Companion.
    fn set_shuffle(&self, _state: ShuffleState) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("set_shuffle over Companion")) })
    }

    /// Not implemented by Companion.
    fn set_repeat(&self, _state: RepeatState) -> BoxFuture<'_, Result<()>> {
        Box::pin(async { Err(not_supported("set_repeat over Companion")) })
    }

    fn channel_up(&self) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::ChannelIncrement, InputAction::SingleTap)
    }

    fn channel_down(&self) -> BoxFuture<'_, Result<()>> {
        self.press(HidCommand::ChannelDecrement, InputAction::SingleTap)
    }
}
