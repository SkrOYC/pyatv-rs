//! HID input: buttons over `_hidC` and touch phases over `_hidT`.
//!
//! Port of `api.py:305-393` (`docs/research/companion-port-spec.md` §3.7, §3.9). Split out of
//! [`crate::api`] purely to keep both files inside the workspace's module-size rule; every method
//! here is an inherent method on [`CompanionApi`] exactly as upstream has them on `CompanionAPI`.

use std::time::{Duration, Instant};

use pyatv_core::{InputAction, TouchAction};
use pyatv_opack::opack;

use crate::Result;
use crate::api::commands::{ButtonState, HidCommand};
use crate::api::{CLICK_TAP_DELAY, CompanionApi, HOLD_DELAY, TOUCHPAD_DELAY};
use crate::session::{TOUCHPAD_HEIGHT, TOUCHPAD_WIDTH};

impl CompanionApi {
    /// `_hidC`: one half of a button press.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn hid_command(&self, down: bool, command: HidCommand) -> Result<()> {
        self.send_command(
            "_hidC",
            opack! {
                "_hBtS" => ButtonState::from_down(down).code(),
                "_hidC" => command.code(),
            },
        )
        .await
        .map(|_| ())
    }

    /// A full button press, shaped by `action`.
    ///
    /// `_press_button` (`__init__.py:402-425`). A double tap is two down/up pairs back to back
    /// with **no** delay between them; a hold is one pair a second apart.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn press_button(&self, command: HidCommand, action: InputAction) -> Result<()> {
        match action {
            InputAction::SingleTap => {
                self.hid_command(true, command).await?;
                self.hid_command(false, command).await
            }
            InputAction::Hold => {
                self.hid_command(true, command).await?;
                tokio::time::sleep(HOLD_DELAY).await;
                self.hid_command(false, command).await
            }
            InputAction::DoubleTap => {
                for _ in 0..2 {
                    self.hid_command(true, command).await?;
                    self.hid_command(false, command).await?;
                }
                Ok(())
            }
        }
    }

    /// `_hidT`: a touch phase at a point, sent as an event and never answered.
    ///
    /// `hid_event` (`api.py:311-326`), including its clamp to the touchpad's bounds and the `_ns`
    /// field measured from `_touchStart` rather than from any absolute epoch.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_event`].
    pub async fn hid_event(&self, x: i32, y: i32, mode: TouchAction) -> Result<()> {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "both bounds are literal 1000.0 and the value is clamped into 0..=1000 first"
        )]
        let clamp = |value: i32, bound: f64| -> u64 { value.clamp(0, bound as i32) as u64 };

        let elapsed = u64::try_from(self.touch_base.elapsed().as_nanos()).unwrap_or(u64::MAX);

        self.send_event(
            "_hidT",
            opack! {
                "_ns" => elapsed,
                "_tFg" => 1u64,
                "_cx" => clamp(x, TOUCHPAD_WIDTH),
                "_tPh" => u64::from(mode as u8),
                "_cy" => clamp(y, TOUCHPAD_HEIGHT),
            },
        )
        .await
    }

    /// Interpolate a swipe from one point to another over `duration_ms`.
    ///
    /// `swipe` (`api.py:328-362`). The step is **recomputed every tick** against the time
    /// remaining, so it grows as the end approaches; that is an artefact of upstream's formula
    /// rather than an easing curve, and it is reproduced exactly because the intermediate
    /// coordinates are what reach the device. The final `Release` uses the caller's raw end point,
    /// not the interpolated one.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_event`].
    pub async fn swipe(
        &self,
        start_x: i32,
        start_y: i32,
        end_x: i32,
        end_y: i32,
        duration_ms: u32,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(duration_ms));
        let mut x = f64::from(start_x);
        let mut y = f64::from(start_y);

        self.hid_event(start_x, start_y, TouchAction::Press).await?;

        #[expect(
            clippy::cast_possible_truncation,
            reason = "the coordinates are clamped to 0..=1000 before the cast, as upstream does"
        )]
        while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
            if remaining.is_zero() {
                break;
            }

            let step = TOUCHPAD_DELAY.as_secs_f64() / remaining.as_secs_f64();
            x = (x + (f64::from(end_x) - x) * step).clamp(0.0, TOUCHPAD_WIDTH);
            y = (y + (f64::from(end_y) - y) * step).clamp(0.0, TOUCHPAD_HEIGHT);

            self.hid_event(x as i32, y as i32, TouchAction::Hold)
                .await?;
            tokio::time::sleep(TOUCHPAD_DELAY).await;
        }

        self.hid_event(end_x, end_y, TouchAction::Release).await
    }

    /// A select click, optionally doubled or held.
    ///
    /// `click` (`api.py:373-393`). Every branch follows the `_hidC` pair with one `_hidT` `Click`
    /// at the fixed corner `(1000, 1000)` — a sentinel upstream always sends, not a real location.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn click(&self, action: InputAction) -> Result<()> {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "TOUCHPAD_WIDTH/HEIGHT are the literal 1000.0 upstream casts to int here"
        )]
        let corner = (TOUCHPAD_WIDTH as i32, TOUCHPAD_HEIGHT as i32);

        let (repeats, gap) = match action {
            InputAction::SingleTap => (1, CLICK_TAP_DELAY),
            InputAction::DoubleTap => (2, CLICK_TAP_DELAY),
            InputAction::Hold => (1, HOLD_DELAY),
        };

        for _ in 0..repeats {
            self.hid_command(true, HidCommand::Select).await?;
            tokio::time::sleep(gap).await;
            self.hid_command(false, HidCommand::Select).await?;
            self.hid_event(corner.0, corner.1, TouchAction::Click)
                .await?;
        }
        Ok(())
    }
}
