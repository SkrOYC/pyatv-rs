//! The listeners `push_updates` registers.
//!
//! Text mode is upstream's `atvremote` listeners (`atvremote.py:504-537`): a playback block and a
//! twenty-dash rule per update, a line per power change, and a stack trace on stderr when the
//! connection drops. JSON mode is `atvscript`'s five printers (`atvscript.py:41-177`), which cover
//! power, volume, output devices and keyboard focus as well — none of which upstream's `atvremote`
//! reports at all, so `--json push_updates` is strictly richer than `atvremote push_updates`.
//!
//! Every listener is held by the caller as an `Arc` and registered weakly, so the whole set is kept
//! alive by [`Listeners`] for exactly as long as updates are wanted.

use std::sync::Arc;

use pyatv::{
    AudioListener, DeviceListener, KeyboardFocusState, KeyboardListener, OutputDevice,
    PlaybackListener, Playing, PowerListener, PowerState,
};
use serde_json::Value;
use tokio::sync::Notify;

use crate::json::{self, Envelope};
use crate::report::Reporter;

/// A listener set, alive for as long as this value is.
///
/// Dropping it unsubscribes every listener at once, because the facade holds only
/// [`std::sync::Weak`] references (`pyatv_core::interface::AppleTV::add_listener`).
#[derive(Debug)]
pub struct Listeners {
    /// Released when the device reports the connection lost or closed.
    ///
    /// `abort_sem` (`atvscript.py:383,404`), which is what lets `push_updates` return without the
    /// user pressing anything when the device goes away.
    pub aborted: Arc<Notify>,
    reporter: Reporter,
    playback: Arc<dyn PlaybackListener>,
    // The four below are never read again. They are fields because the facade holds only weak
    // references, so dropping any one of these `Arc`s is what unsubscribes that listener — keeping
    // them here is what keeps the subscription alive for the lifetime of `Listeners`.
    _power: Arc<dyn PowerListener>,
    _audio: Arc<dyn AudioListener>,
    _keyboard: Arc<dyn KeyboardListener>,
    _device: Arc<dyn DeviceListener>,
}

impl Listeners {
    /// Build the set and register it on `atv` and its push updater.
    ///
    /// Registration order is upstream's (`atvscript.py:310-321`), which matters only in that the
    /// push updater is started by the caller afterwards.
    pub fn register(reporter: Reporter, atv: &dyn pyatv::AppleTV) -> Self {
        let aborted = Arc::new(Notify::new());

        let playback: Arc<dyn PlaybackListener> = Arc::new(PlaybackPrinter { reporter });
        let power: Arc<dyn PowerListener> = Arc::new(PowerPrinter { reporter });
        let audio: Arc<dyn AudioListener> = Arc::new(AudioPrinter { reporter });
        let keyboard: Arc<dyn KeyboardListener> = Arc::new(KeyboardPrinter { reporter });
        let device: Arc<dyn DeviceListener> = Arc::new(DevicePrinter {
            reporter,
            aborted: Arc::clone(&aborted),
        });

        atv.add_power_listener(&power);
        atv.add_audio_listener(&audio);
        atv.add_keyboard_listener(&keyboard);
        atv.add_listener(&device);

        Self {
            aborted,
            reporter,
            playback,
            _power: power,
            _audio: audio,
            _keyboard: keyboard,
            _device: device,
        }
    }

    /// The playback listener, for the caller to hand to the push updater.
    #[must_use]
    pub fn playback(&self) -> &Arc<dyn PlaybackListener> {
        &self.playback
    }

    /// Print the opening state `atvscript push_updates` always emits first.
    ///
    /// "Current power state is always printed as the first update"
    /// (`docs/documentation/atvscript.md:246`), followed by the output device list
    /// (`atvscript.py:322-328`). Both are JSON-only: upstream's `atvremote` prints neither.
    pub fn emit_initial_state(&self, atv: &dyn pyatv::AppleTV) {
        if !self.reporter.is_json() {
            return;
        }

        let state = atv
            .power()
            .map_or(PowerState::Unknown, |power| power.power_state());
        json::emit(Envelope::success().value("power_state", json::power_state_name(state)));

        if let Some(audio) = atv.audio() {
            AudioPrinter {
                reporter: self.reporter,
            }
            .outputdevices_update(&[], &audio.output_devices());
        }
    }
}

/// Prints playback updates.
#[derive(Debug, Clone, Copy)]
struct PlaybackPrinter {
    reporter: Reporter,
}

impl PlaybackListener for PlaybackPrinter {
    /// Text: the same block `playing` prints, then twenty dashes as a rule
    /// (`atvremote.py:507-510`). JSON: one `output_playing` envelope (`atvscript.py:49-59`).
    ///
    /// The app is not available here — upstream reads `self.atv.metadata.app` inside the callback
    /// (`atvscript.py:51-55`) but this listener holds no device handle, so `app` and `app_id` are
    /// reported `null` on pushed updates. `--json playing` fills them in.
    fn playstatus_update(&self, playing: &Playing) {
        self.reporter.playing(playing, None);
        if !self.reporter.is_json() {
            println!("{}", "-".repeat(20));
        }
    }

    /// Text: one line that does not stop the stream, since the updater recovers on its own
    /// (`atvremote.py:512-514`). JSON: a failure envelope (`atvscript.py:61-63`).
    fn playstatus_error(&self, error: &pyatv::Error) {
        if self.reporter.is_json() {
            json::emit(Envelope::failure().exception(&anyhow::anyhow!(error.to_string())));
        } else {
            println!("An error occurred (restarting): {error}");
        }
    }
}

/// Prints power state changes.
#[derive(Debug, Clone, Copy)]
struct PowerPrinter {
    reporter: Reporter,
}

impl PowerListener for PowerPrinter {
    /// Text: `print("New power state:", new_state.name)` (`atvremote.py:520-524`), so the Python
    /// member name rather than the `PowerState.` prefixed form. JSON: `atvscript.py:73-82`.
    fn power_state_changed(&self, _old_state: PowerState, new_state: PowerState) {
        if self.reporter.is_json() {
            json::emit(Envelope::success().value("power_state", json::power_state_name(new_state)));
        } else {
            println!("New power state: {}", power_state_member(new_state));
        }
    }
}

/// Prints volume and playback-group changes. JSON only — upstream's `atvremote` has no audio
/// listener at all.
#[derive(Debug, Clone, Copy)]
struct AudioPrinter {
    reporter: Reporter,
}

impl AudioListener for AudioPrinter {
    /// `atvscript.py:92-97`.
    fn volume_update(&self, _old_level: f32, new_level: f32) {
        if self.reporter.is_json() {
            json::emit(Envelope::success().value("volume", f64::from(new_level)));
        }
    }

    /// `atvscript.py:118-134`.
    fn volume_device_update(&self, output_device: &OutputDevice, old_level: f32, new_level: f32) {
        if self.reporter.is_json() {
            json::emit(
                Envelope::success()
                    .value("output_device_id", output_device.identifier.as_str())
                    .value("old_level", f64::from(old_level))
                    .value("new_level", f64::from(new_level)),
            );
        }
    }

    /// `atvscript.py:99-116`.
    fn outputdevices_update(&self, _old_devices: &[OutputDevice], new_devices: &[OutputDevice]) {
        if self.reporter.is_json() {
            let values: Vec<Value> = new_devices.iter().map(json::output_device_value).collect();
            json::emit(Envelope::success().value("output_devices", Value::Array(values)));
        }
    }
}

/// Prints keyboard focus changes. JSON only, for the same reason [`AudioPrinter`] is.
#[derive(Debug, Clone, Copy)]
struct KeyboardPrinter {
    reporter: Reporter,
}

impl KeyboardListener for KeyboardPrinter {
    /// `atvscript.py:144-153`.
    fn focusstate_update(&self, _old_state: KeyboardFocusState, new_state: KeyboardFocusState) {
        if self.reporter.is_json() {
            json::emit(Envelope::success().value("focus_state", json::focus_state_name(new_state)));
        }
    }
}

/// Prints connection loss and closure, and releases the abort signal.
#[derive(Debug)]
struct DevicePrinter {
    reporter: Reporter,
    aborted: Arc<Notify>,
}

impl DeviceListener for DevicePrinter {
    /// Text: `atvremote.py:530-533`, which writes to stderr so that a redirected stdout still holds
    /// only results. JSON: a failure envelope carrying `connection: "lost"`
    /// (`atvscript.py:164-172`).
    fn connection_lost(&self, reason: &str) {
        if self.reporter.is_json() {
            json::emit(
                Envelope::failure()
                    .exception(&anyhow::anyhow!(reason.to_owned()))
                    .value("connection", "lost"),
            );
        } else {
            eprintln!("Connection lost: {reason}");
        }
        self.aborted.notify_waiters();
    }

    /// Text: upstream logs at debug and prints nothing (`atvremote.py:535-537`). JSON:
    /// `connection: "closed"` (`atvscript.py:174-177`).
    fn connection_closed(&self) {
        if self.reporter.is_json() {
            json::emit(Envelope::success().value("connection", "closed"));
        } else {
            tracing::debug!("connection was closed properly");
        }
        self.aborted.notify_waiters();
    }
}

/// A [`PowerState`] as `new_state.name` renders it: the member name alone
/// (`atvremote.py:524`).
fn power_state_member(state: PowerState) -> &'static str {
    match state {
        PowerState::Unknown => "Unknown",
        PowerState::Off => "Off",
        PowerState::On => "On",
    }
}

#[cfg(test)]
mod tests {
    use super::power_state_member;
    use pyatv::PowerState;

    /// `print("New power state:", new_state.name)` — the bare member name, not `PowerState.On`.
    #[test]
    fn power_updates_print_the_member_name_alone() {
        assert_eq!(power_state_member(PowerState::On), "On");
        assert_eq!(power_state_member(PowerState::Off), "Off");
        assert_eq!(power_state_member(PowerState::Unknown), "Unknown");
    }
}
