//! The `remote` subcommand: one flat vocabulary of button names.
//!
//! The names are upstream's own command names, which are its interface method names verbatim
//! (`retrieve_commands(interface.RemoteControl)`, `atvremote.py:892`). Argument parsing is
//! [`args`]; the list a user can discover them from is [`vocabulary`].
//!
//! Two names route away from [`pyatv::RemoteControl`] and three route to
//! [`pyatv::TouchGestures`]:
//!
//! * `volume_up` and `volume_down` go to [`pyatv::Audio`], because upstream tests `audio` before
//!   `ctrl` precisely so that these two resolve there (`atvremote.py:914-917`). pyatv's
//!   `RemoteControl` versions are deprecated and this port never had them.
//! * `swipe`, `action` and `click` go to [`pyatv::TouchGestures`] (`atvremote.py:947-948`).

mod args;
mod vocabulary;

use anyhow::{Result, bail};
use pyatv::AppleTV;

use crate::report::{Reporter, unsupported};
use args::Args;

pub use vocabulary::print as print_vocabulary;

/// Press one button.
///
/// `button` may carry its arguments in upstream's `name=a,b` form as well as having them supplied
/// separately, so `remote up 1` and `remote up=1` do the same thing.
///
/// # Errors
///
/// Fails on an unknown button name, on a missing or unparseable argument, and on whatever the
/// device reports.
pub async fn run(
    atv: &dyn AppleTV,
    button: &str,
    supplied: &[String],
    reporter: Reporter,
) -> Result<()> {
    let (button, values) = args::split(button, supplied);
    let args = Args {
        button: &button,
        values: &values,
    };

    match button.as_str() {
        "volume_up" | "volume_down" => volume(atv, &button).await?,
        "swipe" | "action" | "click" => gesture(atv, &button, &args).await?,
        _ => press(atv, &button, &args).await?,
    }

    reporter.acknowledge(&button);
    Ok(())
}

/// `volume_up` / `volume_down`, which resolve on [`pyatv::Audio`].
async fn volume(atv: &dyn AppleTV, button: &str) -> Result<()> {
    let audio = atv
        .audio()
        .ok_or_else(|| unsupported(button, "RAOP, Companion or MRP"))?;

    if button == "volume_up" {
        audio.volume_up().await
    } else {
        audio.volume_down().await
    }
    .map_err(Into::into)
}

/// `swipe`, `action` and `click`, which resolve on [`pyatv::TouchGestures`].
async fn gesture(atv: &dyn AppleTV, button: &str, args: &Args<'_>) -> Result<()> {
    let touch = atv
        .touch_gestures()
        .ok_or_else(|| unsupported(button, "Companion"))?;

    match button {
        // `swipe(start_x, start_y, end_x, end_y, duration_ms)` (`pyatv/interface.py:1287-1292`).
        "swipe" => {
            touch
                .swipe(
                    args.parse(0)?,
                    args.parse(1)?,
                    args.parse(2)?,
                    args.parse(3)?,
                    args.parse(4)?,
                )
                .await
        }
        "action" => {
            touch
                .action(args.parse(0)?, args.parse(1)?, args.touch_action()?)
                .await
        }
        // `click(action: InputAction)` (`pyatv/interface.py:1312-1318`) — an input action, not a
        // touch phase.
        _ => touch.click(args.input_action()?).await,
    }
    .map_err(Into::into)
}

/// Everything that resolves on [`pyatv::RemoteControl`].
async fn press(atv: &dyn AppleTV, button: &str, args: &Args<'_>) -> Result<()> {
    let remote = atv
        .remote_control()
        .ok_or_else(|| unsupported("remote control", "MRP, DMAP or Companion"))?;

    match button {
        // The seven that take an `InputAction` (`atvremote.py:836-846`, minus `click`, which is a
        // touch gesture).
        "up" => remote.up(args.input_action()?).await,
        "down" => remote.down(args.input_action()?).await,
        "left" => remote.left(args.input_action()?).await,
        "right" => remote.right(args.input_action()?).await,
        "select" => remote.select(args.input_action()?).await,
        "menu" => remote.menu(args.input_action()?).await,
        "home" => remote.home(args.input_action()?).await,

        "home_hold" => remote.home_hold().await,
        "top_menu" => remote.top_menu().await,
        "guide" => remote.guide().await,
        "control_center" => remote.control_center().await,
        "screensaver" => remote.screensaver().await,

        "play" => remote.play().await,
        "play_pause" => remote.play_pause().await,
        "pause" => remote.pause().await,
        "stop" => remote.stop().await,
        "next" => remote.next().await,
        "previous" => remote.previous().await,

        // The interval defaults to zero, which every protocol reads as "the device's own step".
        "skip_forward" => remote.skip_forward(args.parse_or(0, 0.0)?).await,
        "skip_backward" => remote.skip_backward(args.parse_or(0, 0.0)?).await,
        "set_position" => remote.set_position(args.parse(0)?).await,
        "set_shuffle" => remote.set_shuffle(args.shuffle_state()?).await,
        "set_repeat" => remote.set_repeat(args.repeat_state()?).await,

        "channel_up" => remote.channel_up().await,
        "channel_down" => remote.channel_down().await,

        // `_LOGGER.error("Unknown command: %s", cmd)` (`atvremote.py:950`).
        other => bail!("unknown command: {other}"),
    }
    .map_err(Into::into)
}
