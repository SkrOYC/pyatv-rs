//! Where protocols report state changes and callers subscribe to them.
//!
//! [`ListenerHub`] plays two upstream roles at once. As a *sink* it is
//! `CoreStateDispatcher`/`ProtocolStateDispatcher` (`pyatv/core/__init__.py`): every protocol is
//! handed one and pushes `Volume`, `OutputDevices`, `OutputDeviceVolume` and `KeyboardFocus`
//! updates into it as they arrive off the wire. As a *source* it is the listening half of
//! `FacadeAudio` and `FacadeKeyboard` (`pyatv/core/facade.py:451-493,560-568`): it remembers the
//! last value, drops an update that did not actually change anything, and fans the rest out to
//! whatever the caller registered.
//!
//! The two are merged because the alternative — a dispatcher object plus a facade object that
//! subscribes to it — buys nothing in Rust. Upstream needs the split because a protocol has no
//! other way to reach a facade that does not exist yet; here the hub *is* the thing handed out
//! before the facade is finished.

use std::sync::{Arc, Mutex, Weak};

use crate::consts::{KeyboardFocusState, PowerState, Protocol};
use crate::interface::{AudioListener, DeviceListener, KeyboardListener, PowerListener};
use crate::models::OutputDevice;

/// Where a protocol reports state it observed on the wire.
///
/// The `state_dispatcher.dispatch(UpdatedState.X, value)` calls scattered through the protocol
/// implementations (`mrp/__init__.py:840,848,925`, `companion/__init__.py:451,512`,
/// `raop/__init__.py:307`). A protocol crate takes an `Option<Arc<dyn StateDispatcher>>` in its
/// setup options, exactly as it already does for [`PowerListener`], and never sees the facade.
pub trait StateDispatcher: Send + Sync + std::fmt::Debug {
    /// The device's own volume is now `level`, a percentage in `0.0..=100.0`.
    fn volume_updated(&self, protocol: Protocol, level: f32);
    /// The playback group is now `devices`.
    fn output_devices_updated(&self, protocol: Protocol, devices: Vec<OutputDevice>);
    /// One other output device's volume changed.
    fn output_device_volume_updated(&self, protocol: Protocol, identifier: &str, volume: f32);
    /// The on-screen keyboard's focus state changed.
    fn keyboard_focus_updated(&self, protocol: Protocol, state: KeyboardFocusState);
}

/// The last value seen for each deduplicated state.
#[derive(Debug, Default)]
struct Tracked {
    volume: f32,
    output_devices: Vec<OutputDevice>,
    focus: KeyboardFocusState,
    /// Which protocol's keyboard updates count, i.e. the keyboard relayer's main protocol.
    ///
    /// `message_filter=lambda message: message.protocol == self.main_protocol`
    /// (`facade.py:554-558`). `None` before any protocol registers a keyboard, in which case
    /// nothing is filtered out — there is no incumbent to prefer.
    keyboard_protocol: Option<Protocol>,
}

/// The listener registry a facade shares with the protocol connections reporting to it.
///
/// This is deliberately a separate, `Arc`-able object rather than a field on
/// [`crate::facade::FacadeAppleTV`]: a protocol's `setup()` needs somewhere to report a dropped
/// connection to, and it needs it *before* the facade has finished being assembled.
/// `FacadeAppleTV` itself cannot be shared at that point — `add_protocol` takes `&mut self` — so
/// the hub is created first, handed to every protocol, and kept by the facade afterwards.
///
/// Every list holds [`Weak`] references, so a caller that drops its listener unregisters it and
/// cannot leak it into the facade's lifetime. Upstream's `StateProducer` also holds listeners
/// weakly, and also has exactly one slot per interface; a list is used here because replacing a
/// previous caller's listener without telling them is not worth reproducing.
#[derive(Debug, Default)]
pub struct ListenerHub {
    devices: Mutex<Vec<Weak<dyn DeviceListener>>>,
    power: Mutex<Vec<Weak<dyn PowerListener>>>,
    audio: Mutex<Vec<Weak<dyn AudioListener>>>,
    keyboard: Mutex<Vec<Weak<dyn KeyboardListener>>>,
    tracked: Mutex<Tracked>,
}

/// Add a weakly held listener to one of the lists, dropping any that have since died.
///
/// A [`Weak`] whose target is gone is never removed by [`awake`] — it only skips it — so without
/// this the list grows for the lifetime of the connection every time a caller registers a
/// short-lived listener. Pruning on registration keeps it bounded by the number of *live*
/// listeners without needing a second pass anywhere else.
fn subscribe<T: ?Sized>(list: &Mutex<Vec<Weak<T>>>, listener: &Arc<T>) {
    if let Ok(mut listeners) = list.lock() {
        listeners.retain(|entry| entry.strong_count() > 0);
        listeners.push(Arc::downgrade(listener));
    }
}

/// Every listener still alive, taken out from under the lock before any of them is called.
///
/// Calling a listener while the lock is held would deadlock the moment a listener registers
/// another one, which is a perfectly reasonable thing for a caller to do.
fn awake<T: ?Sized>(list: &Mutex<Vec<Weak<T>>>) -> Vec<Arc<T>> {
    list.lock()
        .map(|listeners| listeners.iter().filter_map(Weak::upgrade).collect())
        .unwrap_or_default()
}

impl ListenerHub {
    /// Register a connection listener.
    pub fn add_listener(&self, listener: &Arc<dyn DeviceListener>) {
        subscribe(&self.devices, listener);
    }

    /// Register a power-state listener.
    pub fn add_power_listener(&self, listener: &Arc<dyn PowerListener>) {
        subscribe(&self.power, listener);
    }

    /// Register a volume and output-device listener.
    pub fn add_audio_listener(&self, listener: &Arc<dyn AudioListener>) {
        subscribe(&self.audio, listener);
    }

    /// Register a keyboard-focus listener.
    pub fn add_keyboard_listener(&self, listener: &Arc<dyn KeyboardListener>) {
        subscribe(&self.keyboard, listener);
    }

    /// Tell the hub which protocol's keyboard updates to accept.
    ///
    /// Called by the facade whenever a protocol registers, with the keyboard relayer's current
    /// main protocol. Upstream expresses the same filter as a `message_filter` on the dispatcher
    /// subscription (`pyatv/core/facade.py:554-558`); a focus change from any other protocol is
    /// dropped rather than reported.
    pub fn set_keyboard_protocol(&self, protocol: Option<Protocol>) {
        if let Ok(mut tracked) = self.tracked.lock() {
            tracked.keyboard_protocol = protocol;
        }
    }

    /// The last volume the hub saw, which is what a freshly registered listener has missed.
    #[must_use]
    pub fn volume(&self) -> f32 {
        self.tracked.lock().map_or(0.0, |tracked| tracked.volume)
    }

    /// The last playback group the hub saw.
    #[must_use]
    pub fn output_devices(&self) -> Vec<OutputDevice> {
        self.tracked
            .lock()
            .map(|tracked| tracked.output_devices.clone())
            .unwrap_or_default()
    }
}

impl DeviceListener for ListenerHub {
    fn connection_lost(&self, reason: &str) {
        tracing::debug!(reason, "a protocol connection was lost");
        for listener in awake(&self.devices) {
            listener.connection_lost(reason);
        }
    }

    fn connection_closed(&self) {
        for listener in awake(&self.devices) {
            listener.connection_closed();
        }
    }
}

impl PowerListener for ListenerHub {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        tracing::debug!(?old_state, ?new_state, "the device power state changed");
        for listener in awake(&self.power) {
            listener.power_state_changed(old_state, new_state);
        }
    }
}

impl StateDispatcher for ListenerHub {
    /// `FacadeAudio._volume_changed` (`facade.py:451-461`), including the "do not update state in
    /// case it didn't change" guard, which is what keeps a device that re-reports the same level
    /// every few seconds from waking the caller up for nothing.
    fn volume_updated(&self, protocol: Protocol, level: f32) {
        let Ok(mut tracked) = self.tracked.lock() else {
            return;
        };
        let old_level = tracked.volume;
        if (old_level - level).abs() < f32::EPSILON {
            return;
        }
        tracked.volume = level;
        drop(tracked);

        tracing::debug!(?protocol, old_level, new_level = level, "volume changed");
        for listener in awake(&self.audio) {
            listener.volume_update(old_level, level);
        }
    }

    /// `FacadeAudio._output_devices_changed` (`facade.py:463-473`).
    fn output_devices_updated(&self, protocol: Protocol, devices: Vec<OutputDevice>) {
        let Ok(mut tracked) = self.tracked.lock() else {
            return;
        };
        if tracked.output_devices == devices {
            return;
        }
        let old_devices = std::mem::replace(&mut tracked.output_devices, devices.clone());
        drop(tracked);

        tracing::debug!(?protocol, count = devices.len(), "output devices changed");
        for listener in awake(&self.audio) {
            listener.outputdevices_update(&old_devices, &devices);
        }
    }

    /// `FacadeAudio._output_device_volume_changed` (`facade.py:475-493`).
    ///
    /// The volume is written back onto the tracked group entry so a later
    /// [`ListenerHub::output_devices`] reports it, and a push naming a device that is not in the
    /// group produces a bare [`OutputDevice`] with just that identifier, as upstream's
    /// `OutputDevice(device_state.identifier)` fallback does.
    fn output_device_volume_updated(&self, protocol: Protocol, identifier: &str, volume: f32) {
        let Ok(mut tracked) = self.tracked.lock() else {
            return;
        };
        let (device, old_volume) = match tracked
            .output_devices
            .iter_mut()
            .find(|device| device.identifier == identifier)
        {
            Some(device) => {
                let old_volume = device.volume;
                device.volume = volume;
                (device.clone(), old_volume)
            }
            None => (OutputDevice::new(identifier).with_volume(volume), 0.0),
        };
        drop(tracked);

        if (old_volume - volume).abs() < f32::EPSILON {
            return;
        }

        tracing::debug!(
            ?protocol,
            identifier,
            volume,
            "output device volume changed"
        );
        for listener in awake(&self.audio) {
            listener.volume_device_update(&device, old_volume, volume);
        }
    }

    /// `FacadeKeyboard._focus_state_changed` (`facade.py:560-568`), including the
    /// only-the-main-protocol filter its `listen_to` applies (`facade.py:554-558`).
    fn keyboard_focus_updated(&self, protocol: Protocol, state: KeyboardFocusState) {
        let Ok(mut tracked) = self.tracked.lock() else {
            return;
        };
        if tracked
            .keyboard_protocol
            .is_some_and(|main| main != protocol)
        {
            return;
        }
        let old_state = tracked.focus;
        if old_state == state {
            return;
        }
        tracked.focus = state;
        drop(tracked);

        tracing::debug!(?old_state, new_state = ?state, "keyboard focus changed");
        for listener in awake(&self.keyboard) {
            listener.focusstate_update(old_state, state);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{ListenerHub, StateDispatcher};
    use crate::consts::{KeyboardFocusState, Protocol};
    use crate::interface::{AudioListener, KeyboardListener};
    use crate::models::OutputDevice;

    #[derive(Debug, Default)]
    struct Recorder {
        volumes: Mutex<Vec<(f32, f32)>>,
        devices: Mutex<Vec<(usize, usize)>>,
        device_volumes: Mutex<Vec<(String, f32, f32)>>,
        focus: Mutex<Vec<(KeyboardFocusState, KeyboardFocusState)>>,
    }

    impl AudioListener for Recorder {
        fn volume_update(&self, old_level: f32, new_level: f32) {
            self.volumes
                .lock()
                .expect("uncontended")
                .push((old_level, new_level));
        }

        fn volume_device_update(
            &self,
            output_device: &OutputDevice,
            old_level: f32,
            new_level: f32,
        ) {
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

    fn hub() -> (ListenerHub, Arc<Recorder>) {
        let hub = ListenerHub::default();
        let recorder = Arc::new(Recorder::default());
        hub.add_audio_listener(&(Arc::clone(&recorder) as Arc<dyn AudioListener>));
        hub.add_keyboard_listener(&(Arc::clone(&recorder) as Arc<dyn KeyboardListener>));
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

    /// Only the keyboard relayer's main protocol is listened to (`facade.py:554-558`).
    #[test]
    fn keyboard_focus_from_another_protocol_is_ignored() {
        let (hub, recorder) = hub();
        hub.set_keyboard_protocol(Some(Protocol::Companion));

        hub.keyboard_focus_updated(Protocol::Mrp, KeyboardFocusState::Focused);
        assert!(recorder.focus.lock().expect("uncontended").is_empty());

        hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Focused);
        assert_eq!(recorder.focus.lock().expect("uncontended").len(), 1);
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
}
