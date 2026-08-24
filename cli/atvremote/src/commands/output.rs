//! Rendering typed library values the way pyatv's `atvremote` prints them.
//!
//! Everything here exists so that someone moving between the two tools sees the same bytes. Where
//! upstream leans on a Python built-in — `print(float)`, `print(Enum)`, `", ".join(...)` — the
//! formatting is reproduced explicitly rather than left to Rust's defaults, which differ.

use anyhow::Result;
use pyatv::{App, FeatureInfo, FeatureName, InputAction, PowerState, RemoteControl};

/// What `_pretty_print` shows for a `None`: Python's own spelling.
pub fn optional(value: Option<&str>) -> &str {
    value.unwrap_or("None")
}

/// A float as Python's `print()` renders it: always with a decimal point.
///
/// `print(10.0)` is `10.0`, not `10`. Rust's `Display` for `f32` drops the trailing `.0`, so
/// `Debug` is used, which keeps it.
#[must_use]
pub fn float(value: f32) -> String {
    format!("{value:?}")
}

/// An enum member as Python's `print()` renders it: `PowerState.On`.
#[must_use]
pub fn power_state(state: PowerState) -> &'static str {
    match state {
        PowerState::Unknown => "PowerState.Unknown",
        PowerState::Off => "PowerState.Off",
        PowerState::On => "PowerState.On",
    }
}

/// A list of apps, comma-separated.
///
/// `_pretty_print`'s list branch, `", ".join([str(item) for item in data])`
/// (`atvremote.py:987-988`), over `App.__str__`, `f"App: {name} ({identifier})"`
/// (`pyatv/interface.py:721-723`).
#[must_use]
pub fn join_apps(apps: &[App]) -> String {
    apps.iter()
        .map(|app| format!("App: {} ({})", app.name, app.identifier))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The `features` subcommand's whole output, legend included (`atvremote.py:443-465`).
pub fn print_features(features: &[(FeatureName, FeatureInfo)]) {
    println!("Feature list:");
    println!("-------------");
    for (name, info) in features {
        println!("{name}: {}", info.state);
    }

    println!();
    println!("Legend:");
    println!("-------");
    println!("Available: Supported by device and usable now");
    println!("Unavailable: Supported by device but not usable now");
    println!("Unknown: Supported by the device but availability not known");
    println!("Unsupported: Not supported by this device (or by pyatv)");
}

/// The error a subcommand reports when no connected protocol serves it.
///
/// Upstream has no equivalent: its facade hands back an object for every capability and raises
/// `NotSupportedError` on first use. Here the capability is absent from the type, so the message
/// has to say which protocol would have supplied it.
#[must_use]
pub fn unsupported(what: &str, protocols: &str) -> anyhow::Error {
    anyhow::anyhow!("{what} is not supported by any connected protocol (needs {protocols})")
}

/// Map a button name onto a [`RemoteControl`] method.
///
/// The names are upstream's own command names, which are its `RemoteControl` method names verbatim
/// (`retrieve_commands(interface.RemoteControl)`, `atvremote.py:892`). Directional and select
/// presses take an [`InputAction`]; upstream exposes that as a `command=action` suffix, which this
/// CLI does not have yet, so every press is a single tap.
///
/// # Errors
///
/// Fails on an unknown button name, listing nothing — the name set is documented by `--help` and
/// upstream answers the same way (`_LOGGER.error("Unknown command: %s")`).
pub async fn press(remote: &dyn RemoteControl, button: &str) -> Result<()> {
    let tap = InputAction::SingleTap;

    match button {
        "up" => remote.up(tap).await,
        "down" => remote.down(tap).await,
        "left" => remote.left(tap).await,
        "right" => remote.right(tap).await,
        "select" => remote.select(tap).await,
        "menu" => remote.menu(tap).await,
        "home" => remote.home(tap).await,
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
        "skip_forward" => remote.skip_forward(0.0).await,
        "skip_backward" => remote.skip_backward(0.0).await,
        "channel_up" => remote.channel_up().await,
        "channel_down" => remote.channel_down().await,
        other => anyhow::bail!("unknown button: {other}"),
    }
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::{float, join_apps, optional, power_state};
    use pyatv::{App, PowerState};

    #[test]
    fn floats_keep_pythons_trailing_decimal() {
        assert_eq!(float(10.0), "10.0");
        assert_eq!(float(12.5), "12.5");
        assert_eq!(float(0.0), "0.0");
    }

    #[test]
    fn a_missing_value_prints_pythons_none() {
        assert_eq!(optional(None), "None");
        assert_eq!(optional(Some("aa:bb")), "aa:bb");
    }

    #[test]
    fn power_states_print_as_python_enum_members() {
        assert_eq!(power_state(PowerState::On), "PowerState.On");
        assert_eq!(power_state(PowerState::Off), "PowerState.Off");
        assert_eq!(power_state(PowerState::Unknown), "PowerState.Unknown");
    }

    #[test]
    fn apps_join_the_way_pretty_print_does() {
        let apps = [
            App {
                name: "Music".to_owned(),
                identifier: "com.apple.TVMusic".to_owned(),
            },
            App {
                name: "Netflix".to_owned(),
                identifier: "com.netflix.Netflix".to_owned(),
            },
        ];

        assert_eq!(
            join_apps(&apps),
            "App: Music (com.apple.TVMusic), App: Netflix (com.netflix.Netflix)"
        );
        assert_eq!(join_apps(&[]), "");
    }
}
