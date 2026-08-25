//! Unit tests for [`super::ListenerHub`], split out of `listeners.rs` for module-size
//! discipline. The filters that need a real [`crate::relayer::Relayer`] behind them are
//! exercised in `crate::facade::tests`, because only a facade owns one.

use std::sync::{Arc, Mutex};

use super::{ListenerHub, StateDispatcher};
use crate::consts::{KeyboardFocusState, PowerState, Protocol};
use crate::interface::{AudioListener, KeyboardListener, PowerListener};
use crate::models::OutputDevice;

#[derive(Debug, Default)]
struct Recorder {
    volumes: Mutex<Vec<(f32, f32)>>,
    devices: Mutex<Vec<(usize, usize)>>,
    device_volumes: Mutex<Vec<(String, f32, f32)>>,
    focus: Mutex<Vec<(KeyboardFocusState, KeyboardFocusState)>>,
    power: Mutex<Vec<(PowerState, PowerState)>>,
}

impl AudioListener for Recorder {
    fn volume_update(&self, old_level: f32, new_level: f32) {
        self.volumes
            .lock()
            .expect("uncontended")
            .push((old_level, new_level));
    }

    fn volume_device_update(&self, output_device: &OutputDevice, old_level: f32, new_level: f32) {
        self.device_volumes.lock().expect("uncontended").push((
            output_device.identifier.clone(),
            old_level,
            new_level,
        ));
    }

    fn outputdevices_update(&self, old_devices: &[OutputDevice], new_devices: &[OutputDevice]) {
        self.devices
            .lock()
            .expect("uncontended")
            .push((old_devices.len(), new_devices.len()));
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

impl PowerListener for Recorder {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        self.power
            .lock()
            .expect("uncontended")
            .push((old_state, new_state));
    }
}

fn hub() -> (ListenerHub, Arc<Recorder>) {
    let hub = ListenerHub::default();
    let recorder = Arc::new(Recorder::default());
    hub.add_audio_listener(&(Arc::clone(&recorder) as Arc<dyn AudioListener>));
    hub.add_keyboard_listener(&(Arc::clone(&recorder) as Arc<dyn KeyboardListener>));
    hub.add_power_listener(&(Arc::clone(&recorder) as Arc<dyn PowerListener>));
    (hub, recorder)
}

/// `test_audio_listener_volume_updates` / `test_audio_no_listener_volume_duplicates`
/// (`tests/core/test_facade.py:838-850`).
#[test]
fn volume_updates_fire_once_per_actual_change() {
    let (hub, recorder) = hub();

    hub.volume_updated(Protocol::Mrp, 20.0);
    hub.volume_updated(Protocol::Mrp, 20.0);
    hub.volume_updated(Protocol::Mrp, 30.0);

    assert_eq!(
        *recorder.volumes.lock().expect("uncontended"),
        vec![(0.0, 20.0), (20.0, 30.0)]
    );
    assert!((hub.volume() - 30.0).abs() < f32::EPSILON);
}

/// `test_audio_listener_output_devices_updates` and its duplicate-suppressing sibling
/// (`test_facade.py:852-888`).
#[test]
fn output_device_updates_fire_once_per_actual_change() {
    let (hub, recorder) = hub();
    let group = vec![OutputDevice::new("a").with_name("Kitchen")];

    hub.output_devices_updated(Protocol::Mrp, group.clone());
    hub.output_devices_updated(Protocol::Mrp, group.clone());
    hub.output_devices_updated(Protocol::Mrp, Vec::new());

    assert_eq!(
        *recorder.devices.lock().expect("uncontended"),
        vec![(0, 1), (1, 0)]
    );
}

/// `test_audio_listener_volume_device_updates` (`test_facade.py:890-...`): the group entry is
/// updated in place and the listener sees the device it belongs to.
#[test]
fn a_per_device_volume_updates_the_group_entry() {
    let (hub, recorder) = hub();
    hub.output_devices_updated(
        Protocol::Mrp,
        vec![OutputDevice::new("a").with_name("Kitchen")],
    );

    hub.output_device_volume_updated(Protocol::Mrp, "a", 40.0);
    hub.output_device_volume_updated(Protocol::Mrp, "a", 40.0);

    assert_eq!(
        *recorder.device_volumes.lock().expect("uncontended"),
        vec![("a".to_owned(), 0.0, 40.0)]
    );
    assert!((hub.output_devices()[0].volume - 40.0).abs() < f32::EPSILON);
}

/// A push for a speaker that is not in the group still reaches the listener, described by a
/// bare identifier (`facade.py:486-487`).
#[test]
fn a_per_device_volume_for_an_unknown_device_still_fires() {
    let (hub, recorder) = hub();
    hub.output_device_volume_updated(Protocol::Mrp, "stranger", 10.0);

    assert_eq!(
        *recorder.device_volumes.lock().expect("uncontended"),
        vec![("stranger".to_owned(), 0.0, 10.0)]
    );
}

/// `test_keyboard_listener_updates` / `test_keyboard_no_listener_duplicates`
/// (`test_facade.py:930-950`).
#[test]
fn keyboard_focus_updates_fire_once_per_actual_change() {
    let (hub, recorder) = hub();

    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Focused);
    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Focused);
    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Unfocused);

    assert_eq!(
        *recorder.focus.lock().expect("uncontended"),
        vec![
            (KeyboardFocusState::Unknown, KeyboardFocusState::Focused),
            (KeyboardFocusState::Focused, KeyboardFocusState::Unfocused),
        ]
    );
}

/// A hub nobody bound a relayer to has no incumbent to prefer, so it filters nothing.
///
/// This is the state a hub used by a single protocol — a test harness, an embedder wiring one
/// protocol by hand — is in, and it must stay permissive there. The filter itself is exercised
/// against a real relayer in `crate::facade::tests`, because only a facade owns one.
#[test]
fn an_unbound_hub_forwards_every_protocols_updates() {
    let (hub, recorder) = hub();

    hub.keyboard_focus_updated(Protocol::Mrp, KeyboardFocusState::Focused);
    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Unfocused);
    assert_eq!(recorder.focus.lock().expect("uncontended").len(), 2);

    // The untagged `PowerListener` impl, which carries no protocol to filter on.
    let listener: &dyn PowerListener = &hub;
    listener.power_state_changed(PowerState::Off, PowerState::On);
    assert_eq!(recorder.power.lock().expect("uncontended").len(), 1);
}

/// A tagged listener from an unbound hub is likewise forwarded rather than dropped.
#[test]
fn a_tagged_power_listener_without_a_relayer_still_reports() {
    let hub = Arc::new(ListenerHub::default());
    let recorder = Arc::new(Recorder::default());
    hub.add_power_listener(&(Arc::clone(&recorder) as Arc<dyn PowerListener>));

    hub.power_listener(Protocol::Mrp)
        .power_state_changed(PowerState::Off, PowerState::On);

    assert_eq!(
        *recorder.power.lock().expect("uncontended"),
        vec![(PowerState::Off, PowerState::On)]
    );
}

/// A listener the caller dropped stops being called rather than keeping itself alive.
#[test]
fn listeners_are_held_weakly() {
    let hub = ListenerHub::default();
    let recorder = Arc::new(Recorder::default());
    hub.add_audio_listener(&(Arc::clone(&recorder) as Arc<dyn AudioListener>));

    drop(recorder);
    hub.volume_updated(Protocol::Mrp, 50.0);
    assert!((hub.volume() - 50.0).abs() < f32::EPSILON);
}
