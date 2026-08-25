//! `DmapRemoteControl`: buttons, and the D-pad's synthetic trackpad drag.
//!
//! Port of `pyatv/protocols/dmap/__init__.py:247-392`.

use std::sync::Arc;

use pyatv_core::consts::{InputAction, RepeatState, ShuffleState};
use pyatv_core::interface::{BoxFuture, RemoteControl};
use pyatv_core::{Error as CoreError, Result as CoreResult};

use crate::Result;
use crate::client::BaseDmapAppleTV;
use crate::tags::{string_tag, uint8_tag};

/// The seek offset used when a caller asks to skip without saying how far.
///
/// `_DEFAULT_SKIP_TIME = 10` (`__init__.py:59`). DMAP has no seek-relative command at all, so
/// skipping is read-position-then-seek-absolute, and the interval is this client's choice rather
/// than the app's.
pub const DEFAULT_SKIP_TIME: i64 = 10;

/// The `cmcc` value that marks a control-prompt body as a trackpad event (`__init__.py:306`).
pub const GESTURE_MARKER: u8 = 0x30;

/// One step of a drag: phase, timestamp, and the point touched.
type Step = (&'static str, u32, u32, u32);

/// `up()` (`__init__.py:255-265`): drag from `20,275` up to `20,250` in five-pixel steps.
const UP: [Step; 7] = [
    ("Down", 0, 20, 275),
    ("Move", 1, 20, 270),
    ("Move", 2, 20, 265),
    ("Move", 3, 20, 260),
    ("Move", 4, 20, 255),
    ("Move", 5, 20, 250),
    ("Up", 6, 20, 250),
];

/// `down()` (`__init__.py:267-277`).
const DOWN: [Step; 7] = [
    ("Down", 0, 20, 250),
    ("Move", 1, 20, 255),
    ("Move", 2, 20, 260),
    ("Move", 3, 20, 265),
    ("Move", 4, 20, 270),
    ("Move", 5, 20, 275),
    ("Up", 6, 20, 275),
];

/// `left()` (`__init__.py:279-289`).
///
/// The timestamps run `0, 1, 3, 4, 5, 6, 7` — **`2` is skipped**. That is what the source literally
/// contains, and the fake device keys its gesture recognition off the final `time=7`
/// (`tests/fake_device/dmap.py:186-193`), so it is reproduced rather than tidied up.
const LEFT: [Step; 7] = [
    ("Down", 0, 75, 100),
    ("Move", 1, 70, 100),
    ("Move", 3, 65, 100),
    ("Move", 4, 60, 100),
    ("Move", 5, 55, 100),
    ("Move", 6, 50, 100),
    ("Up", 7, 50, 100),
];

/// `right()` (`__init__.py:291-301`), with the same skipped `time=2` as [`LEFT`].
const RIGHT: [Step; 7] = [
    ("Down", 0, 50, 100),
    ("Move", 1, 55, 100),
    ("Move", 3, 60, 100),
    ("Move", 4, 65, 100),
    ("Move", 5, 70, 100),
    ("Move", 6, 75, 100),
    ("Up", 7, 75, 100),
];

/// One gesture step's POST body.
///
/// `_move` (`__init__.py:303-306`). Note the tag order: `cmcc` first and `cmbe` second, the
/// *opposite* of [`BaseDmapAppleTV::controlprompt_cmd`], and `cmcc` is `0x30` rather than `0x00`.
#[must_use]
pub fn move_body(direction: &str, time: u32, x: u32, y: u32) -> Vec<u8> {
    [
        uint8_tag("cmcc", GESTURE_MARKER),
        string_tag(
            "cmbe",
            &format!("touch{direction}&time={time}&point={x},{y}"),
        ),
    ]
    .concat()
}

/// Navigation and transport control over DAAP.
#[derive(Debug)]
pub struct DmapRemoteControl {
    apple_tv: Arc<BaseDmapAppleTV>,
}

impl DmapRemoteControl {
    /// Control the device `apple_tv` is connected to.
    #[must_use]
    pub const fn new(apple_tv: Arc<BaseDmapAppleTV>) -> Self {
        Self { apple_tv }
    }

    /// Send all seven steps of one drag, in order.
    ///
    /// The fake device only recognises the gesture from its **final** event
    /// (`tests/fake_device/dmap.py:181-195`), but a real Apple TV is tracking the whole drag, so
    /// every step goes out — sending only the last one would be fitting the test rather than the
    /// device.
    async fn drag(&self, steps: &[Step]) -> Result<()> {
        for (direction, time, x, y) in steps {
            self.apple_tv
                .controlprompt_data(&move_body(direction, *time, *x, *y))
                .await?;
        }
        Ok(())
    }

    /// `skip_forward`/`skip_backward` (`__init__.py:356-378`).
    ///
    /// There is no relative-seek command in DMAP, so this reads the current position and seeks to
    /// an absolute one. When the current position is unknown or zero the whole thing is a **no-op**
    /// — upstream's `if current_position:` guards the entire body, so nothing is sent at all.
    async fn skip(&self, interval: f32, forward: bool) -> Result<()> {
        let Some(position) = self
            .apple_tv
            .playstatus(false)
            .await?
            .position
            .filter(|it| *it > 0)
        else {
            return Ok(());
        };

        // `int(time_interval) if time_interval > 0 else _DEFAULT_SKIP_TIME`: truncation, not
        // rounding, and any non-positive interval falls back to ten seconds.
        let step = if interval > 0.0 {
            truncate_toward_zero(interval)
        } else {
            DEFAULT_SKIP_TIME
        };
        let position = i64::from(position);
        let target = if forward {
            position + step
        } else {
            position - step
        };

        self.set_position_inner(target).await
    }

    /// `set_position` (`__init__.py:380-383`): seconds in, milliseconds on the wire.
    async fn set_position_inner(&self, position: i64) -> Result<()> {
        self.apple_tv
            .set_property("dacp.playingtime", position * 1000)
            .await
    }
}

/// Python's `int(x)` on a float: drop the fraction, keeping the sign.
///
/// Rust's `as` cast truncates toward zero and saturates at the integer bounds rather than being
/// undefined, which is exactly `int()`'s behaviour for every value a seek interval or a seek target
/// can take. The lint fires on the part that is deliberate.
#[expect(
    clippy::cast_possible_truncation,
    reason = "truncation is the ported behaviour — `int(time_interval)`, not a rounding"
)]
fn truncate_toward_zero(value: f32) -> i64 {
    value as i64
}

/// The answer for every method DMAP has no command for.
///
/// pyatv does not override these at all, so they inherit `interface.RemoteControl`'s base
/// implementation, which raises `NotSupportedError` — confirmed end to end by
/// `test_button_unsupported_raises` (`tests/protocols/dmap/test_dmap_functional.py:153-157`).
fn unsupported(name: &'static str) -> BoxFuture<'static, CoreResult<()>> {
    Box::pin(async move {
        Err(CoreError::NotSupported(format!(
            "DMAP does not implement {name}"
        )))
    })
}

macro_rules! dmap_unsupported {
    ($($method:ident($($argument:ident : $type:ty),*)),* $(,)?) => {
        $(
            fn $method(&self $(, $argument: $type)*) -> BoxFuture<'_, CoreResult<()>> {
                $(let _ = $argument;)*
                unsupported(stringify!($method))
            }
        )*
    };
}

impl RemoteControl for DmapRemoteControl {
    /// The four directions are drags, not key presses; `action` has no DMAP representation and is
    /// ignored, exactly as upstream ignores its own `action` parameter.
    fn up(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        let _ = action;
        Box::pin(async move { self.drag(&UP).await.map_err(Into::into) })
    }

    fn down(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        let _ = action;
        Box::pin(async move { self.drag(&DOWN).await.map_err(Into::into) })
    }

    fn left(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        let _ = action;
        Box::pin(async move { self.drag(&LEFT).await.map_err(Into::into) })
    }

    fn right(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        let _ = action;
        Box::pin(async move { self.drag(&RIGHT).await.map_err(Into::into) })
    }

    fn select(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        let _ = action;
        Box::pin(async move {
            self.apple_tv
                .controlprompt_cmd("select")
                .await
                .map_err(Into::into)
        })
    }

    fn menu(&self, action: InputAction) -> BoxFuture<'_, CoreResult<()>> {
        let _ = action;
        Box::pin(async move {
            self.apple_tv
                .controlprompt_cmd("menu")
                .await
                .map_err(Into::into)
        })
    }

    fn top_menu(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .controlprompt_cmd("topmenu")
                .await
                .map_err(Into::into)
        })
    }

    fn play(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move { self.apple_tv.ctrl_int_cmd("play").await.map_err(Into::into) })
    }

    fn play_pause(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .ctrl_int_cmd("playpause")
                .await
                .map_err(Into::into)
        })
    }

    fn pause(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .ctrl_int_cmd("pause")
                .await
                .map_err(Into::into)
        })
    }

    fn stop(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move { self.apple_tv.ctrl_int_cmd("stop").await.map_err(Into::into) })
    }

    fn next(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .ctrl_int_cmd("nextitem")
                .await
                .map_err(Into::into)
        })
    }

    fn previous(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .ctrl_int_cmd("previtem")
                .await
                .map_err(Into::into)
        })
    }

    fn skip_forward(&self, interval: f32) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move { self.skip(interval, true).await.map_err(Into::into) })
    }

    fn skip_backward(&self, interval: f32) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move { self.skip(interval, false).await.map_err(Into::into) })
    }

    /// `int(pos) * 1000` (`__init__.py:380-383`): a fractional second is truncated, not rounded.
    fn set_position(&self, position: f32) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.set_position_inner(truncate_toward_zero(position))
                .await
                .map_err(Into::into)
        })
    }

    /// `set_shuffle` (`__init__.py:385-388`): off is `0` and **everything else is `1`**.
    ///
    /// [`ShuffleState::Albums`] has no DMAP representation, so it is sent as plain shuffle and
    /// reads back as [`ShuffleState::Songs`] — see [`crate::playing`].
    fn set_shuffle(&self, state: ShuffleState) -> BoxFuture<'_, CoreResult<()>> {
        let wire = i64::from(state != ShuffleState::Off);
        Box::pin(async move {
            self.apple_tv
                .set_property("dacp.shufflestate", wire)
                .await
                .map_err(Into::into)
        })
    }

    /// `set_repeat` (`__init__.py:390-392`): the enum's own value is the wire value.
    fn set_repeat(&self, state: RepeatState) -> BoxFuture<'_, CoreResult<()>> {
        let wire = state as i64;
        Box::pin(async move {
            self.apple_tv
                .set_property("dacp.repeatstate", wire)
                .await
                .map_err(Into::into)
        })
    }

    dmap_unsupported!(
        home(action: InputAction),
        home_hold(),
        guide(),
        control_center(),
        screensaver(),
        channel_up(),
        channel_down(),
    );
}

#[cfg(test)]
mod tests {
    use super::{DOWN, GESTURE_MARKER, LEFT, RIGHT, UP, move_body};
    use crate::parser::{first_str, parse};

    /// The exact body of one gesture step (`__init__.py:303-306`), tag order included.
    #[test]
    fn a_gesture_step_is_cmcc_then_cmbe() {
        let body = move_body("Down", 0, 20, 275);

        assert_eq!(
            body,
            b"cmcc\x00\x00\x00\x01\x30cmbe\x00\x00\x00\x1dtouchDown&time=0&point=20,275"
        );

        let parsed = parse(&body).expect("well formed");
        assert_eq!(parsed[0].key, "cmcc", "cmcc comes first in a gesture");
        assert_eq!(
            first_str(&parsed, &["cmbe"]),
            Some("touchDown&time=0&point=20,275")
        );

        // `cmcc` is *written* with `uint8_tag` and *read* as a string: the tag table types it
        // `read_str` (`tag_definitions.py:114`). The single byte `0x30` is therefore the character
        // `"0"` on the way back, not the number 48 — a round-trip asymmetry that is upstream's and
        // that nothing depends on, since no pyatv code ever reads `cmcc`.
        assert_eq!(GESTURE_MARKER, b'0');
        assert_eq!(first_str(&parsed, &["cmcc"]), Some("0"));
    }

    /// The final event of each direction is what the fake device pattern-matches on
    /// (`tests/fake_device/dmap.py:186-193`), so those four strings are load-bearing.
    #[test]
    fn each_direction_ends_with_the_event_the_device_recognises() {
        for (steps, expected) in [
            (UP, "touchUp&time=6&point=20,250"),
            (DOWN, "touchUp&time=6&point=20,275"),
            (LEFT, "touchUp&time=7&point=50,100"),
            (RIGHT, "touchUp&time=7&point=75,100"),
        ] {
            let (direction, time, x, y) = steps[6];
            let body = move_body(direction, time, x, y);
            let parsed = parse(&body).expect("well formed");
            assert_eq!(first_str(&parsed, &["cmbe"]), Some(expected));
        }
    }

    /// Seven POSTs per press, starting with a `Down` and ending with an `Up`.
    #[test]
    fn every_direction_is_seven_steps_of_one_drag() {
        for steps in [UP, DOWN, LEFT, RIGHT] {
            assert_eq!(steps.len(), 7);
            assert_eq!(steps[0].0, "Down");
            assert_eq!(steps[6].0, "Up");
            for step in &steps[1..6] {
                assert_eq!(step.0, "Move");
            }
        }
    }

    /// `left`/`right` skip `time=2`; `up`/`down` do not. Verified against the source, not tidied.
    #[test]
    fn the_horizontal_drags_skip_a_timestamp() {
        let times = |steps: [super::Step; 7]| steps.map(|(_, time, _, _)| time);

        assert_eq!(times(UP), [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(times(DOWN), [0, 1, 2, 3, 4, 5, 6]);
        assert_eq!(times(LEFT), [0, 1, 3, 4, 5, 6, 7]);
        assert_eq!(times(RIGHT), [0, 1, 3, 4, 5, 6, 7]);
    }

    /// A drag ends where the previous step left off, or the device sees a jump.
    #[test]
    fn each_drag_is_continuous() {
        for steps in [UP, DOWN, LEFT, RIGHT] {
            let last_move = steps[5];
            let release = steps[6];
            assert_eq!((last_move.2, last_move.3), (release.2, release.3));
        }
    }
}
