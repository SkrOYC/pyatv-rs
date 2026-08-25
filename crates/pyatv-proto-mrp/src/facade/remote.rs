//! `RemoteControl`: HID presses for navigation, `SEND_COMMAND_MESSAGE` for transport.
//!
//! Port of `MrpRemoteControl` (`pyatv/protocols/mrp/__init__.py:328-479`) and the free function
//! `_send_hid_key` (`__init__.py:296-324`). Which of the two paths a button takes is not a detail:
//! only the `SEND_COMMAND_MESSAGE` path has device-side error reporting, and only the HID path has
//! the flush round trip.

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::consts::{InputAction, RepeatState, ShuffleState};
use pyatv_core::interface::{BoxFuture, RemoteControl};
use pyatv_core::{Error as CoreError, Result as CoreResult};

use crate::hid::{self, Key};
use crate::protobuf::playback_state::Enum::{Paused, Playing};
use crate::protobuf::{Command, extensions, protocol_message::Type, send_error};
use crate::protocol::MrpProtocol;
use crate::{Result, messages};

/// How long `InputAction::Hold` keeps a key down (`asyncio.sleep(1)`, `__init__.py:303-304`).
pub const HOLD_DURATION: Duration = Duration::from_secs(1);

/// Delay between the two halves of `Power::turn_off` (`DELAY_BETWEEN_COMMANDS`,
/// `__init__.py:149`).
pub const DELAY_BETWEEN_COMMANDS: Duration = Duration::from_millis(100);

/// Send one HID key with the press pattern `action` describes.
///
/// `_send_hid_key` (`__init__.py:296-324`). After every press/release pair a bare `GENERIC_MESSAGE`
/// is sent **and waited for**, which upstream's own comment calls "some kind of flush mechanism" —
/// not a documented protocol requirement, just an empirically necessary round trip. `flush` is
/// false only for the volume keys, which wait on a `VOLUME_DID_CHANGE_MESSAGE` push instead
/// (`__init__.py:892-897`).
///
/// # Errors
///
/// Returns [`crate::Error::Timeout`] if the flush round trip goes unanswered, or
/// [`crate::Error::Closed`] if the connection dropped mid-press.
pub async fn send_hid_key(
    protocol: &MrpProtocol,
    key: Key,
    action: InputAction,
    flush: bool,
) -> Result<()> {
    let (presses, hold) = hid::presses_for(action);

    for _ in 0..presses {
        protocol
            .send(messages::send_hid_event(key.usage_page, key.usage, true)?)
            .await?;

        if hold {
            tokio::time::sleep(HOLD_DURATION).await;
        }

        protocol
            .send(messages::send_hid_event(key.usage_page, key.usage, false)?)
            .await?;

        if flush {
            protocol
                .send_and_receive(messages::create(Type::GenericMessage))
                .await?;
        }
    }

    Ok(())
}

/// Send a `SEND_COMMAND_MESSAGE` and fail on the device's own error report.
///
/// `_send_command` (`__init__.py:342-354`). This is the one MRP command path with real device-side
/// error reporting; a HID press has no response payload to fail on.
///
/// # Errors
///
/// Returns [`crate::Error::Command`] quoting the device's `SendError` and `HandlerReturnStatus`.
pub async fn send_command(
    protocol: &MrpProtocol,
    command: Command,
    options: Option<crate::protobuf::CommandOptions>,
) -> Result<()> {
    let response = protocol
        .send_and_receive(messages::command_with(command, options)?)
        .await?;
    let inner = response.inner(&extensions::SEND_COMMAND_RESULT_MESSAGE)?;

    let error = inner.send_error.unwrap_or_default();
    if error == send_error::Enum::NoError as i32 {
        return Ok(());
    }

    Err(messages::command_error(
        command,
        error,
        inner.handler_return_status.unwrap_or_default(),
    ))
}

/// `CommandInfo.preferredIntervals` is `double` but `CommandOptions.skipInterval` is `float`, so
/// the device's own preferred value has to be narrowed before it can be sent back.
#[allow(
    clippy::cast_possible_truncation,
    reason = "the two protobuf fields genuinely have different widths; upstream does the same \
              narrowing implicitly through Python's untyped float, and a skip interval is a small \
              number of seconds where f32 precision is ample"
)]
fn narrow(value: f64) -> f32 {
    value as f32
}

/// MRP's navigation and transport control.
#[derive(Debug)]
pub struct MrpRemoteControl {
    protocol: Arc<MrpProtocol>,
}

impl MrpRemoteControl {
    /// Wrap a connected protocol.
    #[must_use]
    pub const fn new(protocol: Arc<MrpProtocol>) -> Self {
        Self { protocol }
    }

    /// One HID button press, as the trait's `&self`-returning-a-future shape needs it.
    fn press(&self, key: Key, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            send_hid_key(&self.protocol, key, action, true)
                .await
                .map_err(Into::into)
        })
    }

    /// One transport command with no options.
    fn command(&self, command: Command) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            send_command(&self.protocol, command, None)
                .await
                .map_err(Into::into)
        })
    }

    /// `SkipForward`/`SkipBackward` with the interval resolution upstream uses.
    ///
    /// `_skip_command` (`__init__.py:455-467`): an explicit positive interval wins, else the
    /// *first* of the device's `preferredIntervals`, else 15 seconds.
    async fn skip(&self, command: Command, interval: f32) -> Result<()> {
        let preferred = self.protocol.state().with_playing(|playing| {
            playing
                .command_info(command)
                .and_then(|info| info.preferred_intervals.first().copied())
        });

        let resolved = if interval > 0.0 {
            interval.trunc()
        } else {
            preferred.map_or(messages::DEFAULT_SKIP_TIME, narrow)
        };

        send_command(
            &self.protocol,
            command,
            Some(crate::protobuf::CommandOptions {
                skip_interval: Some(resolved),
                ..crate::protobuf::CommandOptions::default()
            }),
        )
        .await
    }

    /// Hold home, then select — the whole of `Power::turn_off` (`__init__.py:664-669`).
    ///
    /// Lives here rather than in the power facade because it is entirely a pair of button presses:
    /// MRP has no power-off message at all.
    ///
    /// # Errors
    ///
    /// As [`send_hid_key`].
    pub async fn home_hold_then_select(&self) -> Result<()> {
        send_hid_key(&self.protocol, hid::HOME, InputAction::Hold, true).await?;
        tokio::time::sleep(DELAY_BETWEEN_COMMANDS).await;
        send_hid_key(&self.protocol, hid::SELECT, InputAction::SingleTap, true).await
    }
}

impl RemoteControl for MrpRemoteControl {
    fn up(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::UP, action)
    }

    fn down(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::DOWN, action)
    }

    fn left(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::LEFT, action)
    }

    fn right(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::RIGHT, action)
    }

    fn select(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::SELECT, action)
    }

    fn menu(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::MENU, action)
    }

    fn home(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::HOME, action)
    }

    /// `home_hold` is `home(Hold)`; upstream keeps both because the feature name is deprecated but
    /// still reported (`__init__.py:424-426`).
    fn home_hold(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::HOME, InputAction::Hold)
    }

    fn top_menu(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.press(hid::TOP_MENU, InputAction::SingleTap)
    }

    /// Not an MRP capability: nothing upstream maps `Guide` to an MRP message.
    fn guide(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async {
            Err(CoreError::NotSupported(
                "MRP has no guide button".to_owned(),
            ))
        })
    }

    /// Not an MRP capability; Companion implements it.
    fn control_center(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async {
            Err(CoreError::NotSupported(
                "MRP has no Control Center".to_owned(),
            ))
        })
    }

    /// Not an MRP capability; Companion implements it.
    fn screensaver(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async { Err(CoreError::NotSupported("MRP has no screensaver".to_owned())) })
    }

    fn play(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.command(Command::Play)
    }

    /// `TogglePlayPause` when the app supports it, otherwise the opposite of the current state.
    ///
    /// `play_pause` (`__init__.py:376-387`). The fallback exists because a feature check would
    /// report the toggle as available through emulation; upstream reads the raw `CommandInfo`
    /// instead, and its comment says so explicitly.
    fn play_pause(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            let toggles = self.protocol.state().with_playing(|playing| {
                playing
                    .command_info(Command::TogglePlayPause)
                    .is_some_and(|info| info.enabled.unwrap_or_default())
            });
            if toggles {
                return self.command(Command::TogglePlayPause).await;
            }

            match self.protocol.state().playback_state() {
                Some(Playing) => self.command(Command::Pause).await,
                Some(Paused) => self.command(Command::Play).await,
                _ => Ok(()),
            }
        })
    }

    fn pause(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.command(Command::Pause)
    }

    fn stop(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.command(Command::Stop)
    }

    fn next(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.command(Command::NextTrack)
    }

    fn previous(&self) -> BoxFuture<'_, CoreResult<()>> {
        self.command(Command::PreviousTrack)
    }

    fn skip_forward(&self, interval: f32) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.skip(Command::SkipForward, interval)
                .await
                .map_err(Into::into)
        })
    }

    fn skip_backward(&self, interval: f32) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.skip(Command::SkipBackward, interval)
                .await
                .map_err(Into::into)
        })
    }

    /// Seek, sent as a plain round trip.
    ///
    /// Upstream calls `send_and_receive` directly here rather than `_send_command`
    /// (`__init__.py:469-471`), so a device-side `sendError` on a seek is **not** reported. That
    /// asymmetry is preserved.
    fn set_position(&self, position: f32) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.protocol
                .send_and_receive(messages::seek_to_position(f64::from(position))?)
                .await
                .map(drop)
                .map_err(Into::into)
        })
    }

    /// As [`RemoteControl::set_position`], a plain round trip with no error check.
    fn set_shuffle(&self, state: ShuffleState) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.protocol
                .send_and_receive(messages::shuffle(state)?)
                .await
                .map(drop)
                .map_err(Into::into)
        })
    }

    /// As [`RemoteControl::set_position`], a plain round trip with no error check.
    fn set_repeat(&self, state: RepeatState) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.protocol
                .send_and_receive(messages::repeat(state)?)
                .await
                .map(drop)
                .map_err(Into::into)
        })
    }

    /// Not an MRP capability; Companion implements it.
    fn channel_up(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async { Err(CoreError::NotSupported("MRP has no channel up".to_owned())) })
    }

    /// Not an MRP capability; Companion implements it.
    fn channel_down(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async {
            Err(CoreError::NotSupported(
                "MRP has no channel down".to_owned(),
            ))
        })
    }
}
