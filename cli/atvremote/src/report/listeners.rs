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
    App, AudioListener, DeviceListener, FeatureName, FeatureState, Features, KeyboardFocusState,
    KeyboardListener, Metadata, OutputDevice, PlaybackListener, Playing, PowerListener, PowerState,
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

        // `PushPrinter(args.output, atv)` (`atvscript.py:311`): the printer is given the device so
        // its callback can read the app that owns each update. Only the two handles the callback
        // actually reads are taken rather than the whole `AppleTV` — they are `Arc`s the facade
        // hands out for exactly this, and taking them here saves threading the device handle
        // through the whole command dispatcher.
        let playback: Arc<dyn PlaybackListener> = Arc::new(PlaybackPrinter {
            reporter,
            metadata: atv.metadata(),
            features: atv.features(),
        });
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

/// Prints playback updates, with the app that owns them.
#[derive(Debug)]
struct PlaybackPrinter {
    reporter: Reporter,
    /// `self.atv.metadata`, absent when no connected protocol reports metadata at all.
    metadata: Option<Arc<dyn Metadata>>,
    /// `self.atv.features`, which decides whether the app is worth asking for.
    features: Arc<dyn Features>,
}

impl PlaybackPrinter {
    /// The app that owns this update, read the way `PushPrinter.playstatus_update` reads it.
    ///
    /// `self.atv.metadata.app if not self.atv.features.in_state(Unavailable, App) else None`
    /// (`atvscript.py:51-55`). Note the gate: anything *but* `Unavailable` is asked, so a protocol
    /// reporting `Unknown` is still consulted. That is deliberately weaker than the one the
    /// one-shot `playing` command uses, which is `in_state(Available, App)`
    /// (`atvscript.py:300-307`, and `commands::media::playing` here).
    fn app(&self) -> Option<App> {
        let metadata = self.metadata.as_ref()?;
        (self.features.get_feature(FeatureName::App).state != FeatureState::Unavailable)
            .then(|| metadata.app())
            .flatten()
    }
}

impl PlaybackListener for PlaybackPrinter {
    /// Text: the same block `playing` prints, then twenty dashes as a rule
    /// (`atvremote.py:507-510`). JSON: one `output_playing` envelope (`atvscript.py:49-59`),
    /// including the `app`/`app_id` pair that `output_playing` adds.
    fn playstatus_update(&self, playing: &Playing) {
        self.reporter.playing(playing, self.app().as_ref());
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
    use std::sync::Arc;

    use super::{PlaybackPrinter, power_state_member};
    use crate::report::Reporter;
    use pyatv::{
        App, ArtworkInfo, BoxFuture, FeatureInfo, FeatureName, FeatureState, Features, Metadata,
        Playing, PowerState, Result,
    };

    /// `print("New power state:", new_state.name)` — the bare member name, not `PowerState.On`.
    #[test]
    fn power_updates_print_the_member_name_alone() {
        assert_eq!(power_state_member(PowerState::On), "On");
        assert_eq!(power_state_member(PowerState::Off), "Off");
        assert_eq!(power_state_member(PowerState::Unknown), "Unknown");
    }

    /// A device that always names the same app.
    #[derive(Debug)]
    struct FakeMetadata;

    impl Metadata for FakeMetadata {
        fn device_id(&self) -> Option<String> {
            None
        }

        fn playing(&self) -> BoxFuture<'_, Result<Playing>> {
            Box::pin(async { Ok(Playing::default()) })
        }

        fn artwork(
            &self,
            _width: Option<u32>,
            _height: Option<u32>,
        ) -> BoxFuture<'_, Result<Option<ArtworkInfo>>> {
            Box::pin(async { Ok(None) })
        }

        fn artwork_id(&self) -> Option<String> {
            None
        }

        fn app(&self) -> Option<App> {
            Some(App {
                name: "Music".to_owned(),
                identifier: "com.apple.TVMusic".to_owned(),
            })
        }
    }

    /// A feature set that reports one fixed state for everything.
    #[derive(Debug)]
    struct Fixed(FeatureState);

    impl Features for Fixed {
        fn get_feature(&self, _feature: FeatureName) -> FeatureInfo {
            FeatureInfo {
                state: self.0,
                reason: None,
            }
        }

        fn all_features(&self, _include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
            Vec::new()
        }
    }

    fn printer(metadata: Option<Arc<dyn Metadata>>, state: FeatureState) -> PlaybackPrinter {
        PlaybackPrinter {
            reporter: Reporter::new(true),
            metadata,
            features: Arc::new(Fixed(state)),
        }
    }

    /// `--json push_updates` used to report `app` and `app_id` as `null` on every update, because
    /// the printer held no device handle. Upstream's reads `self.atv.metadata.app` in the callback
    /// (`atvscript.py:51-55`), and so does this one now.
    #[test]
    fn a_pushed_update_names_the_app_that_owns_it() {
        let metadata: Arc<dyn Metadata> = Arc::new(FakeMetadata);
        let app = printer(Some(metadata), FeatureState::Available)
            .app()
            .expect("the device names an app");

        assert_eq!(app.name, "Music");
        assert_eq!(app.identifier, "com.apple.TVMusic");
    }

    /// The gate is `not in_state(Unavailable, App)`, so `Unknown` still asks — unlike the one-shot
    /// `playing` command, whose gate is `in_state(Available, App)`.
    #[test]
    fn the_app_is_asked_for_unless_the_feature_is_unavailable() {
        let metadata: Arc<dyn Metadata> = Arc::new(FakeMetadata);

        for state in [
            FeatureState::Available,
            FeatureState::Unknown,
            FeatureState::Unsupported,
        ] {
            assert!(
                printer(Some(Arc::clone(&metadata)), state).app().is_some(),
                "{state:?} is not Unavailable, so upstream asks the device"
            );
        }

        assert!(
            printer(Some(metadata), FeatureState::Unavailable)
                .app()
                .is_none(),
            "an Unavailable App feature is never asked for"
        );
    }

    /// A device with no metadata protocol at all reports no app rather than panicking.
    #[test]
    fn a_device_without_metadata_reports_no_app() {
        assert!(printer(None, FeatureState::Available).app().is_none());
    }
}
