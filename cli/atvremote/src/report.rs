//! Rendering results, in text or in JSON.
//!
//! Every subcommand hands its result here rather than printing for itself, so that `--json` costs
//! one arm per result shape instead of a second copy of every command. The text arm reproduces
//! what pyatv's `atvremote` prints (`_pretty_print`, `pyatv/scripts/atvremote.py:982-990`, over the
//! interface types' `__str__`); the JSON arm reproduces `atvscript`'s envelope (see [`crate::json`]).
//!
//! Where upstream leans on a Python built-in — `print(float)`, `print(Enum)`, `", ".join(...)` —
//! the formatting is reproduced explicitly rather than left to Rust's defaults, which differ.

pub mod listeners;

use pyatv::{
    App, ArtworkInfo, BaseConfig, DeviceInfo, FeatureInfo, FeatureName, KeyboardFocusState,
    OutputDevice, Playing, PowerState, UserAccount,
};
use serde_json::{Map, Value};

use crate::json::{self, Envelope};

/// Decides how results are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reporter {
    json: bool,
}

impl Reporter {
    /// A reporter in the mode `--json` selected.
    #[must_use]
    pub const fn new(json: bool) -> Self {
        Self { json }
    }

    /// Whether results are rendered as JSON.
    #[must_use]
    pub const fn is_json(self) -> bool {
        self.json
    }

    /// Print a line of human-readable text, or nothing at all in JSON mode.
    fn line(self, text: &str) {
        if !self.json {
            println!("{text}");
        }
    }

    /// Emit a JSON envelope, or nothing at all in text mode.
    fn envelope(self, build: impl FnOnce(Envelope) -> Envelope) {
        if self.json {
            json::emit(build(Envelope::success()));
        }
    }

    /// Progress or guidance that is not a result.
    ///
    /// Goes to stdout in text mode and to **stderr** in JSON mode, because a `--json` caller parses
    /// stdout line by line and a stray sentence would break it. Upstream keeps the same guarantee
    /// by refusing to log anywhere but a file when scripting (`atvscript.py:385-392`).
    pub fn notice(self, text: &str) {
        if self.json {
            eprintln!("{text}");
        } else {
            println!("{text}");
        }
    }

    /// A command that produced no value: a button press, a launch, a setting change.
    ///
    /// Text prints nothing, exactly as `_pretty_print(None)` does (`atvremote.py:983-984`). JSON
    /// echoes the command name, which is what `atvscript` returns for a `RemoteControl` call
    /// (`atvscript.py:332-334`).
    pub fn acknowledge(self, command: &str) {
        self.envelope(|envelope| envelope.value("command", command));
    }

    /// The closing line of `push_updates`.
    ///
    /// `output(True, values={"push_updates": "finished"})` (`atvscript.py:330`) — a key of its own
    /// rather than the `command` [`Reporter::acknowledge`] would emit.
    pub fn push_finished(self) {
        self.envelope(|envelope| envelope.value("push_updates", "finished"));
    }

    /// The `scan` result.
    ///
    /// Text is `_print_found_apple_tvs` (`atvremote.py:739-743`): a banner, then each device
    /// followed by a blank line. `BaseConfig`'s `Display` is `pyatv/interface.py:1448-1463`
    /// verbatim, so the per-device body belongs to the library rather than here.
    pub fn devices(self, devices: &[BaseConfig]) {
        if self.json {
            let values: Vec<Value> = devices.iter().map(json::device_value).collect();
            json::emit(Envelope::success().value("devices", Value::Array(values)));
            return;
        }

        println!("Scan Results");
        println!("{}", "=".repeat(40));
        for device in devices {
            println!("{device}\n");
        }
    }

    /// What is playing, plus the app that owns it.
    ///
    /// Text is `Playing.__str__` (`pyatv/interface.py:540-589`), which does not mention the app;
    /// JSON is `output_playing` (`atvscript.py:210-226`), which does.
    pub fn playing(self, playing: &Playing, app: Option<&App>) {
        if self.json {
            json::emit(Envelope::success().values(json::playing_values(playing, app)));
        } else {
            println!("{playing}");
        }
    }

    /// The `features` list and its legend (`atvremote.py:443-465`).
    pub fn features(self, features: &[(FeatureName, FeatureInfo)]) {
        if self.json {
            let map: Map<String, Value> = features
                .iter()
                .map(|(name, info)| {
                    (
                        name.to_string(),
                        Value::String(info.state.to_string().to_ascii_lowercase()),
                    )
                })
                .collect();
            json::emit(Envelope::success().value("features", Value::Object(map)));
            return;
        }

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

    /// `Model/SW:` and `MAC:`, exactly as `DeviceCommands.device_info` prints them
    /// (`atvremote.py:436-441`).
    pub fn device_info(self, info: &DeviceInfo) {
        if self.json {
            json::emit(Envelope::success().value("device_info", json::device_info_value(info)));
            return;
        }

        println!("Model/SW: {info}");
        println!("     MAC: {}", optional(info.mac()));
    }

    /// A value that may be absent, printed as Python prints a `None`.
    ///
    /// `_pretty_print` returns early on `None` and prints nothing at all
    /// (`atvremote.py:983-984`), but these three commands — `device_id`, `artwork_id`, `text_get`
    /// — are properties whose absence is worth showing, and Python's `print(None)` is what a user
    /// coming from `atvremote device_id` on an unsupported protocol sees.
    pub fn optional_value(self, key: &str, value: Option<&str>) {
        self.line(optional(value));
        self.envelope(|envelope| {
            envelope.value(
                key,
                value.map_or(Value::Null, |text| Value::String(text.to_owned())),
            )
        });
    }

    /// The current power state, rendered as Python prints the enum: `PowerState.On`.
    pub fn power_state(self, state: PowerState) {
        self.line(power_state(state));
        self.envelope(|envelope| envelope.value("power_state", json::power_state_name(state)));
    }

    /// The keyboard focus state, rendered as Python prints the enum.
    pub fn focus_state(self, state: KeyboardFocusState) {
        self.line(focus_state(state));
        self.envelope(|envelope| envelope.value("focus_state", json::focus_state_name(state)));
    }

    /// The current volume.
    pub fn volume(self, level: f32) {
        self.line(&float(level));
        self.envelope(|envelope| envelope.value("volume", f64::from(level)));
    }

    /// Every launchable app, comma-separated — `_pretty_print`'s list branch
    /// (`atvremote.py:987-988`) over `App.__str__` (`pyatv/interface.py:721-723`).
    pub fn apps(self, apps: &[App]) {
        self.line(&join(apps, |app| {
            format!("App: {} ({})", app.name, app.identifier)
        }));
        self.envelope(|envelope| {
            let values: Vec<Value> = apps
                .iter()
                .map(|app| pair_value(Some(app.name.as_str()), &app.identifier))
                .collect();
            envelope.value("app_list", Value::Array(values))
        });
    }

    /// The app that owns what is playing.
    ///
    /// JSON carries `app` and `app_id` separately, matching the two keys `output_playing` adds
    /// (`atvscript.py:220-225`).
    pub fn app(self, app: Option<&App>) {
        if let Some(app) = app {
            self.line(&format!("App: {} ({})", app.name, app.identifier));
        } else {
            self.line("None");
        }

        self.envelope(|envelope| {
            envelope
                .value(
                    "app",
                    app.map_or(Value::Null, |app| Value::String(app.name.clone())),
                )
                .value(
                    "app_id",
                    app.map_or(Value::Null, |app| Value::String(app.identifier.clone())),
                )
        });
    }

    /// Every switchable account — `UserAccount.__str__` (`pyatv/interface.py:764-766`).
    pub fn accounts(self, accounts: &[UserAccount]) {
        self.line(&join(accounts, |account| {
            format!("Account: {} ({})", account.name, account.identifier)
        }));
        self.envelope(|envelope| {
            let values: Vec<Value> = accounts
                .iter()
                .map(|account| pair_value(Some(account.name.as_str()), &account.identifier))
                .collect();
            envelope.value("account_list", Value::Array(values))
        });
    }

    /// The speakers in the playback group — `OutputDevice.__str__`
    /// (`pyatv/interface.py:1124-1126`).
    pub fn output_devices(self, devices: &[OutputDevice]) {
        self.line(&join(devices, ToString::to_string));
        self.envelope(|envelope| {
            let values: Vec<Value> = devices.iter().map(json::output_device_value).collect();
            envelope.value("output_devices", Value::Array(values))
        });
    }

    /// Artwork written to disk.
    ///
    /// Text is this tool's own line rather than upstream's silence: `artwork_save` prints nothing
    /// on success (`atvremote.py:410-419`), which makes a command whose whole purpose is a side
    /// effect look like it did nothing.
    pub fn artwork_saved(self, artwork: &ArtworkInfo, path: &std::path::Path) {
        self.line(&format!(
            "Wrote {} bytes of {} to {}",
            artwork.bytes.len(),
            artwork.mimetype,
            path.display()
        ));
        self.envelope(|envelope| {
            envelope.value(
                "artwork",
                Value::Object(Map::from_iter([
                    ("path".to_owned(), Value::String(path.display().to_string())),
                    ("bytes".to_owned(), Value::from(artwork.bytes.len())),
                    (
                        "mimetype".to_owned(),
                        Value::String(artwork.mimetype.clone()),
                    ),
                ])),
            )
        });
    }

    /// The device has no artwork to give. Upstream's wording, verbatim
    /// (`atvremote.py:417`).
    pub fn no_artwork(self) {
        self.line("No artwork is currently available.");
        self.envelope(|envelope| envelope.value("artwork", Value::Null));
    }

    /// Every stored setting as `path = value`, one per line
    /// (`stringify_model`, `pyatv/support/__init__.py:173-200`).
    pub fn settings(self, settings: &[(String, Option<String>)]) {
        if self.json {
            let map: Map<String, Value> = settings
                .iter()
                .map(|(path, value)| {
                    (
                        path.clone(),
                        value
                            .as_ref()
                            .map_or(Value::Null, |it| Value::String(it.clone())),
                    )
                })
                .collect();
            json::emit(Envelope::success().value("settings", Value::Object(map)));
            return;
        }

        for (path, value) in settings {
            println!("{path} = {}", optional(value.as_deref()));
        }
    }
}

/// What `_pretty_print` shows for a `None`: Python's own spelling.
#[must_use]
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

/// The same for `KeyboardFocusState`, which `text_focus_state` returns as a property
/// (`pyatv/interface.py:1255-1259`).
#[must_use]
pub fn focus_state(state: KeyboardFocusState) -> &'static str {
    match state {
        KeyboardFocusState::Unknown => "KeyboardFocusState.Unknown",
        KeyboardFocusState::Unfocused => "KeyboardFocusState.Unfocused",
        KeyboardFocusState::Focused => "KeyboardFocusState.Focused",
    }
}

/// `", ".join([str(item) for item in data])` (`atvremote.py:987-988`).
fn join<T>(items: &[T], render: impl Fn(&T) -> String) -> String {
    items.iter().map(render).collect::<Vec<_>>().join(", ")
}

/// The `{"name": ..., "identifier": ...}` object apps, accounts and output devices all share.
fn pair_value(name: Option<&str>, identifier: &str) -> Value {
    Value::Object(Map::from_iter([
        (
            "name".to_owned(),
            name.map_or(Value::Null, |it| Value::String(it.to_owned())),
        ),
        (
            "identifier".to_owned(),
            Value::String(identifier.to_owned()),
        ),
    ]))
}

/// The error a subcommand reports when no connected protocol serves it.
///
/// Upstream has no equivalent: its facade hands back an object for every capability and raises
/// `NotSupportedError` on first use. Here the capability is absent from the type, so the message
/// has to say which protocol would have supplied it.
///
/// Deliberately a [`pyatv::Error::NotSupported`] rather than a bare `anyhow!`, so that `main`'s
/// reporter recognises it and prints one plain line instead of a backtrace — this is the failure a
/// user meets whenever a device is not paired for the protocol they need, and it is not a crash.
#[must_use]
pub fn unsupported(what: &str, protocols: &str) -> anyhow::Error {
    anyhow::Error::new(pyatv::Error::NotSupported(format!(
        "{what} is not supported by any connected protocol (needs {protocols})"
    )))
}

#[cfg(test)]
mod tests {
    use super::{float, focus_state, join, optional, pair_value, power_state};
    use pyatv::{App, KeyboardFocusState, PowerState};

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
    fn enum_members_print_the_way_python_prints_them() {
        assert_eq!(power_state(PowerState::On), "PowerState.On");
        assert_eq!(power_state(PowerState::Off), "PowerState.Off");
        assert_eq!(power_state(PowerState::Unknown), "PowerState.Unknown");

        assert_eq!(
            focus_state(KeyboardFocusState::Focused),
            "KeyboardFocusState.Focused"
        );
        assert_eq!(
            focus_state(KeyboardFocusState::Unfocused),
            "KeyboardFocusState.Unfocused"
        );
    }

    #[test]
    fn lists_join_the_way_pretty_print_does() {
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

        let rendered = join(&apps, |app| {
            format!("App: {} ({})", app.name, app.identifier)
        });
        assert_eq!(
            rendered,
            "App: Music (com.apple.TVMusic), App: Netflix (com.netflix.Netflix)"
        );
        assert_eq!(join::<App>(&[], |_| String::new()), "");
    }

    #[test]
    fn name_identifier_pairs_render_a_missing_name_as_null() {
        let value = pair_value(None, "abc");
        assert!(value["name"].is_null());
        assert_eq!(value["identifier"], "abc");
    }
}
