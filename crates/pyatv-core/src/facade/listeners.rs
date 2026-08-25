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

use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::consts::{KeyboardFocusState, PowerState, Protocol};
use crate::interface::{
    AudioListener, DeviceListener, Keyboard, KeyboardListener, Power, PowerListener,
};
use crate::models::OutputDevice;
use crate::relayer::Relayer;

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
    /// The relayers whose *current* main protocol decides whose updates are heard.
    ///
    /// Held [`Weak`] and consulted per update rather than snapshotted, because the answer changes:
    /// a takeover puts another protocol at the front of a relayer, and upstream's filters are
    /// closures over `self.main_protocol` (`facade.py:557`, `facade.py:777-781`) that see the new
    /// answer from the next message on. The facade owns both relayers, so a strong reference here
    /// would be a cycle.
    filters: Filters,
}

/// The relayers [`ListenerHub`] filters against, set once by the facade that owns them.
///
/// [`OnceLock`] rather than a lock: [`crate::facade::FacadeAppleTV::new`] binds both before any
/// protocol can report anything, and nothing rebinds them afterwards.
#[derive(Debug, Default)]
struct Filters {
    keyboard: OnceLock<Weak<Relayer<dyn Keyboard>>>,
    power: OnceLock<Weak<Relayer<dyn Power>>>,
}

/// Whether an update reported by `protocol` is the one its relayer currently answers with.
///
/// An unbound relayer, one that has been dropped, and one nobody has registered with all answer
/// "yes": there is no incumbent to prefer, so nothing is filtered out.
fn is_main<T: ?Sized>(slot: &OnceLock<Weak<Relayer<T>>>, protocol: Protocol) -> bool {
    slot.get()
        .and_then(Weak::upgrade)
        .and_then(|relayer| relayer.main_protocol())
        .is_none_or(|main| main == protocol)
}

/// A [`PowerListener`] that remembers which protocol reports through it.
///
/// [`PowerListener::power_state_changed`] carries no protocol of its own, but every connected
/// protocol is handed one and reports its own view of the same device: MRP and Companion both push
/// a transition, so a hub subscribed to both emits two callbacks for one event. Upstream avoids it
/// by wiring only the main instance's listener at all — `power.listener = self._interfaces[Power]`
/// (`facade.py:777-781`) — and binding the protocol at hand-out time is what lets the hub apply the
/// same rule without having to rewire anything when a takeover moves the main protocol.
#[derive(Debug)]
struct ProtocolPowerListener {
    hub: Arc<ListenerHub>,
    protocol: Protocol,
}

impl PowerListener for ProtocolPowerListener {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        self.hub
            .power_state_changed_from(Some(self.protocol), old_state, new_state);
    }
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

    /// Tell the hub which relayer decides whose keyboard updates to accept.
    ///
    /// Upstream expresses the same filter as a `message_filter` on the dispatcher subscription,
    /// `lambda message: message.protocol == self.main_protocol` (`pyatv/core/facade.py:554-558`).
    /// The closure is evaluated per message, so a takeover that moves the keyboard relayer's main
    /// protocol changes which protocol is heard; this holds the relayer and asks it the same
    /// question at the same moment. Only the first call has any effect.
    pub fn set_keyboard_relayer(&self, relayer: &Arc<Relayer<dyn Keyboard>>) {
        let _ = self.filters.keyboard.set(Arc::downgrade(relayer));
    }

    /// Tell the hub which relayer decides whose power updates to accept.
    ///
    /// Every connected protocol is handed a [`PowerListener`] and every one of them reports the
    /// same device, so a hub subscribed to all of them emits one callback per protocol for a single
    /// transition. Upstream wires only the main instance's listener at all — `power.listener =
    /// self._interfaces[Power]` (`facade.py:777-781`) — and this is the same rule expressed as a
    /// filter, so that a takeover moves it without anything having to be rewired. See
    /// [`ListenerHub::power_listener`] for how a report is attributed to a protocol in the first
    /// place. Only the first call has any effect.
    pub fn set_power_relayer(&self, relayer: &Arc<Relayer<dyn Power>>) {
        let _ = self.filters.power.set(Arc::downgrade(relayer));
    }

    /// The [`PowerListener`] to hand `protocol`'s `setup()`.
    ///
    /// Reports through it are attributed to `protocol` and dropped unless it is the power relayer's
    /// main protocol, so a device connected over both MRP and Companion produces one callback per
    /// transition rather than one per protocol.
    #[must_use]
    pub fn power_listener(self: &Arc<Self>, protocol: Protocol) -> Arc<dyn PowerListener> {
        Arc::new(ProtocolPowerListener {
            hub: Arc::clone(self),
            protocol,
        })
    }

    /// Fan a power transition out, unless a protocol other than the main one reported it.
    ///
    /// `protocol` is `None` for a report that arrived through [`ListenerHub`]'s own
    /// [`PowerListener`] impl, which carries no attribution and is therefore never filtered.
    fn power_state_changed_from(
        &self,
        protocol: Option<Protocol>,
        old_state: PowerState,
        new_state: PowerState,
    ) {
        if protocol.is_some_and(|reporter| !is_main(&self.filters.power, reporter)) {
            tracing::trace!(
                ?protocol,
                "ignoring a power update from a protocol that is not the main one"
            );
            return;
        }

        tracing::debug!(?old_state, ?new_state, "the device power state changed");
        for listener in awake(&self.power) {
            listener.power_state_changed(old_state, new_state);
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

/// The untagged entry point, for a caller that reports on behalf of no particular protocol.
///
/// A facade-assembled connection never uses it: [`ListenerHub::power_listener`] is what
/// `pyatv::connect` hands each protocol, precisely so the report can be attributed. It stays
/// because a hub used by a single protocol — a test harness, an embedder wiring one protocol by
/// hand — has nothing to disambiguate and should not have to name itself.
impl PowerListener for ListenerHub {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        self.power_state_changed_from(None, old_state, new_state);
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
        // Asked before the `tracked` lock is taken, and asked *now* rather than at registration:
        // a takeover of the keyboard relayer changes the answer, and must change it here too.
        if !is_main(&self.filters.keyboard, protocol) {
            tracing::trace!(
                ?protocol,
                "ignoring a focus update from a protocol that is not the main one"
            );
            return;
        }

        let Ok(mut tracked) = self.tracked.lock() else {
            return;
        };
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
mod tests;
