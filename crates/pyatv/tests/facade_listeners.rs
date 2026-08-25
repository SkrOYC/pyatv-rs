//! Volume, output-device and keyboard-focus updates reaching a caller's listeners.
//!
//! The chain this exercises is three links long and every one of them is a port of something
//! specific: the protocol observes a push and dispatches it
//! (`pyatv/protocols/mrp/__init__.py:840,848,925`,
//! `pyatv/protocols/companion/__init__.py:451,512`), `pyatv_core::facade::ListenerHub` plays the
//! listening half of `FacadeAudio`/`FacadeKeyboard` and drops anything that did not actually change
//! (`pyatv/core/facade.py:451-493,560-568`), and the caller's `AudioListener`/`KeyboardListener`
//! sees the result (`pyatv/interface.py:1139-1159,1236-1244`).
//!
//! Everything runs against the hermetic device in [`support`], so the pushes are real protobufs and
//! real OPACK events crossing real sockets.

mod support;

use std::sync::{Arc, Mutex};

use pyatv::{AudioListener, KeyboardFocusState, KeyboardListener, OutputDevice};
use pyatv_proto_mrp::test_support::fake_state::DEVICE_UID;

use support::{FakeAppleTv, until};

/// Records every callback so a test can assert on the exact sequence, duplicates included.
#[derive(Debug, Default)]
struct Recorder {
    volumes: Mutex<Vec<(f32, f32)>>,
    devices: Mutex<Vec<Vec<OutputDevice>>>,
    device_volumes: Mutex<Vec<(String, f32)>>,
    focus: Mutex<Vec<(KeyboardFocusState, KeyboardFocusState)>>,
}

impl AudioListener for Recorder {
    fn volume_update(&self, old_level: f32, new_level: f32) {
        self.volumes
            .lock()
            .expect("uncontended")
            .push((old_level, new_level));
    }

    fn volume_device_update(&self, output_device: &OutputDevice, _old: f32, new_level: f32) {
        self.device_volumes
            .lock()
            .expect("uncontended")
            .push((output_device.identifier.clone(), new_level));
    }

    fn outputdevices_update(&self, _old: &[OutputDevice], new_devices: &[OutputDevice]) {
        self.devices
            .lock()
            .expect("uncontended")
            .push(new_devices.to_vec());
    }
}

impl KeyboardListener for Recorder {
    fn focusstate_update(&self, old_state: KeyboardFocusState, new_state: KeyboardFocusState) {
        self.focus
            .lock()
            .expect("uncontended")
            .push((old_state, new_state));
    }
}

/// `VOLUME_DID_CHANGE_MESSAGE` for this device becomes `AudioListener::volume_update`.
///
/// `MrpAudio._volume_did_change` dispatches `UpdatedState.Volume` when the message names our own
/// output UID (`mrp/__init__.py:836-840`), and the facade only fires when the value changed
/// (`facade.py:451-461`) — which the repeated push below pins.
#[tokio::test]
async fn an_mrp_volume_push_reaches_an_audio_listener() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let recorder = Arc::new(Recorder::default());
    atv.add_audio_listener(&(Arc::clone(&recorder) as Arc<dyn AudioListener>));

    device.mrp.state().volume_control(true, true, true);
    device.mrp.state().set_volume(0.5, DEVICE_UID);

    until("the volume update to arrive", || {
        (!recorder.volumes.lock().expect("uncontended").is_empty()).then_some(())
    })
    .await;

    // The same level again changes nothing, so nothing more is delivered.
    device.mrp.state().set_volume(0.5, DEVICE_UID);
    device.mrp.state().set_volume(0.2, DEVICE_UID);

    let seen = until("the second, different level", || {
        let volumes = recorder.volumes.lock().expect("uncontended").clone();
        (volumes.len() >= 2).then_some(volumes)
    })
    .await;

    assert_eq!(seen.len(), 2, "the repeated level must not be delivered");
    assert!((seen[0].1 - 50.0).abs() < 0.01, "{seen:?}");
    assert!((seen[1].0 - 50.0).abs() < 0.01, "{seen:?}");
    assert!((seen[1].1 - 20.0).abs() < 0.01, "{seen:?}");

    // And the facade reports the same level a listener was told about.
    let audio = atv.audio().expect("MRP registers Audio");
    assert!((audio.volume() - 20.0).abs() < 0.01, "{}", audio.volume());
}

/// A `VOLUME_DID_CHANGE_MESSAGE` naming *another* speaker becomes `volume_device_update`.
///
/// The `else` branch at `mrp/__init__.py:841-851`, which upstream dispatches as
/// `UpdatedState.OutputDeviceVolume`. It must not move this device's own volume.
#[tokio::test]
async fn a_volume_push_for_another_speaker_is_reported_separately() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let recorder = Arc::new(Recorder::default());
    atv.add_audio_listener(&(Arc::clone(&recorder) as Arc<dyn AudioListener>));

    device.mrp.state().volume_control(true, true, true);
    device.mrp.state().set_volume(0.4, "someone-elses-speaker");

    let seen = until("the per-device volume update", || {
        let volumes = recorder.device_volumes.lock().expect("uncontended").clone();
        (!volumes.is_empty()).then_some(volumes)
    })
    .await;

    assert_eq!(seen[0].0, "someone-elses-speaker");
    assert!((seen[0].1 - 40.0).abs() < 0.01, "{seen:?}");
    assert!(
        recorder.volumes.lock().expect("uncontended").is_empty(),
        "our own volume did not change"
    );
}

/// A `DEVICE_INFO_UPDATE_MESSAGE` that changes the group becomes `outputdevices_update`.
///
/// `_update_output_devices` (`mrp/__init__.py:913-925`), whose list the facade compares whole
/// before firing (`facade.py:463-473`). The names come through because
/// [`pyatv::OutputDevice`] carries them, which the pre-port `Vec<String>` could not.
#[tokio::test]
async fn an_mrp_group_change_reaches_an_audio_listener() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let recorder = Arc::new(Recorder::default());
    atv.add_audio_listener(&(Arc::clone(&recorder) as Arc<dyn AudioListener>));

    device
        .mrp
        .state()
        .add_output_devices(&["kitchen-speaker".to_owned()]);

    let groups = until("the output-device update", || {
        let groups = recorder.devices.lock().expect("uncontended").clone();
        groups
            .into_iter()
            .find(|group| {
                group
                    .iter()
                    .any(|entry| entry.identifier == "kitchen-speaker")
            })
            .map(|group| vec![group])
    })
    .await;

    let group = &groups[0];
    assert!(
        group.iter().any(|entry| entry.identifier == DEVICE_UID),
        "the group leader stays in its own group: {group:?}"
    );

    // The public accessor reports the same shape, names included.
    let devices = atv.audio().expect("MRP registers Audio").output_devices();
    assert!(
        devices
            .iter()
            .any(|entry| entry.identifier == "kitchen-speaker"),
        "{devices:?}"
    );
    assert!(
        devices.iter().all(|entry| entry.name.is_some()),
        "every entry carries the display name the DeviceInfoMessage gave it: {devices:?}"
    );
}

/// Companion's keyboard focus becomes `KeyboardListener::focusstate_update`.
///
/// `_handle_text_input` dispatches `UpdatedState.KeyboardFocus` whenever a `_tiStart` response or a
/// `_tiStarted`/`_tiStopped` push arrives (`companion/__init__.py:505-512`); the facade drops the
/// ones that did not change state (`facade.py:560-568`).
#[tokio::test]
async fn a_companion_focus_change_reaches_a_keyboard_listener() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let recorder = Arc::new(Recorder::default());
    atv.add_keyboard_listener(&(Arc::clone(&recorder) as Arc<dyn KeyboardListener>));

    let keyboard = atv.keyboard().expect("Companion registers Keyboard");
    // The fake ships with a focused field, and the session bring-up's `_tiStart` response already
    // told the facade so — before the listener above existed, which is why the transition the test
    // asserts on is the *next* one.
    assert_eq!(keyboard.text_focus_state(), KeyboardFocusState::Focused);
    assert!(recorder.focus.lock().expect("uncontended").is_empty());

    // Take the focus away, then read the field — a `_tiStart` round trip, and so a fresh signal.
    device
        .arrange_companion(|state| state.rti_text = None)
        .await;

    let text = keyboard.text_get().await.expect("text_get must succeed");
    assert_eq!(text, None, "nothing has focus, so there is no text");

    let seen = until("the focus update", || {
        let focus = recorder.focus.lock().expect("uncontended").clone();
        (!focus.is_empty()).then_some(focus)
    })
    .await;

    assert_eq!(
        seen[0],
        (KeyboardFocusState::Focused, KeyboardFocusState::Unfocused),
        "{seen:?}"
    );
    assert_eq!(keyboard.text_focus_state(), KeyboardFocusState::Unfocused);
}
