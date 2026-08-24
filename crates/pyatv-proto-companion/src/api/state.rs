//! Everything the device tells us asynchronously, readable from any thread.
//!
//! pyatv keeps these on the facade objects themselves — `CompanionPower._power_state`,
//! `CompanionAudio._volume`, `CompanionFeatures._control_flags`, `CompanionKeyboard._focus_state`
//! — each updated from its own event callback. Here every facade object is behind an `Arc` and the
//! updates arrive on one background task, so the four values live together in one small record and
//! the facades read it.
//!
//! Two [`Notify`]s stand in for pyatv's `asyncio.Event`s. `CompanionAudio` clears an event, sends a
//! HID or media-control command, then waits up to five seconds for the device to confirm with an
//! `_iMC` push carrying the volume bit (`__init__.py:461-487`); [`ApiState::volume_changed`] is
//! that event. There is no upstream equivalent of [`ApiState::power_changed`] — pyatv refuses
//! `await_new_state` outright — see [`crate::facade`] for why this port has one.

use std::sync::Mutex;

use pyatv_core::{KeyboardFocusState, PowerState};
use tokio::sync::Notify;

/// The media-control bitfield the device pushes under `_iMC`'s `_mcF` (`__init__.py:87-101`).
///
/// Bits `0x0040` and `0x0080` are unexplained even by pyatv's own source comments and are simply
/// carried through. `FastForward`/`Rewind` are defined but map to no [`pyatv_core::FeatureName`]
/// anywhere upstream, which is a real gap in pyatv's feature surface rather than a porting
/// omission (`docs/research/companion-port-spec.md` §12 finding 8).
pub mod media_control_flags {
    /// Nothing is controllable.
    pub const NO_CONTROLS: u64 = 0x0000;
    /// Play is available.
    pub const PLAY: u64 = 0x0001;
    /// Pause is available.
    pub const PAUSE: u64 = 0x0002;
    /// Next track is available.
    pub const NEXT_TRACK: u64 = 0x0004;
    /// Previous track is available.
    pub const PREVIOUS_TRACK: u64 = 0x0008;
    /// Fast forward is available. No feature maps to this bit.
    pub const FAST_FORWARD: u64 = 0x0010;
    /// Rewind is available. No feature maps to this bit.
    pub const REWIND: u64 = 0x0020;
    /// Volume is controllable.
    pub const VOLUME: u64 = 0x0100;
    /// Skipping forward is available.
    pub const SKIP_FORWARD: u64 = 0x0200;
    /// Skipping backward is available.
    pub const SKIP_BACKWARD: u64 = 0x0400;
}

/// A snapshot of everything the device has told us so far.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Observed {
    /// Last known power state, from `FetchAttentionState` or a pushed `(TV)SystemStatus`.
    pub power: PowerState,
    /// The last `_mcF` value, defaulting to "no controls" until the first `_iMC` arrives.
    ///
    /// pyatv seeds this with `MediaControlFlags.NoControls` (`__init__.py:584`) rather than with
    /// the fake device's `Volume` default, which is a test fixture's choice and not a client-side
    /// assumption.
    pub control_flags: u64,
    /// Volume as a percentage in `0.0..=100.0`.
    pub volume: f32,
    /// Whether a text field currently has focus.
    pub focus: KeyboardFocusState,
    /// Whether a power state has ever been observed, which is what gates
    /// [`pyatv_core::FeatureName::PowerState`] (`supports_power_updates`, `__init__.py:214-217`).
    pub power_known: bool,
}

impl Default for Observed {
    fn default() -> Self {
        Self {
            power: PowerState::Unknown,
            control_flags: media_control_flags::NO_CONTROLS,
            volume: 0.0,
            focus: KeyboardFocusState::Unknown,
            power_known: false,
        }
    }
}

/// Shared, mutable, observed device state plus the two wake-ups the facades await on.
#[derive(Debug, Default)]
pub struct ApiState {
    observed: Mutex<Observed>,
    /// Notified after an `_iMC` push with the volume bit set has been folded in.
    pub volume_changed: Notify,
    /// Notified after the power state changed.
    pub power_changed: Notify,
}

impl ApiState {
    /// The current snapshot.
    ///
    /// A poisoned lock hands back the value the panicking writer left behind rather than failing:
    /// every writer here replaces whole `Copy` fields, so there is no torn state to protect
    /// against, and reporting "the volume is unreadable" would be worse than reporting a stale
    /// volume.
    #[must_use]
    pub fn observed(&self) -> Observed {
        *self
            .observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Apply a mutation to the snapshot.
    fn update(&self, mutate: impl FnOnce(&mut Observed)) {
        let mut observed = self
            .observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mutate(&mut observed);
    }

    /// Record a new power state and wake anything waiting on one.
    pub fn set_power(&self, power: PowerState) {
        let mut changed = false;
        self.update(|observed| {
            changed = observed.power != power || !observed.power_known;
            observed.power = power;
            observed.power_known = true;
        });

        if changed {
            tracing::debug!(?power, "Companion power state changed");
            self.power_changed.notify_waiters();
        }
    }

    /// Record the media-control bitfield from an `_iMC` push.
    pub fn set_control_flags(&self, flags: u64) {
        tracing::debug!(
            flags = format!("{flags:#06X}"),
            "media control flags updated"
        );
        self.update(|observed| observed.control_flags = flags);
    }

    /// Record a volume read back with `GetVolume` and wake anything waiting on one.
    pub fn set_volume(&self, volume: f32) {
        self.update(|observed| observed.volume = volume);
        self.volume_changed.notify_waiters();
    }

    /// Record that the device reports no volume control at all.
    ///
    /// `else: self._volume = 0.0` (`__init__.py:447-449`) — "no volume control means we know
    /// nothing about the volume". Deliberately does **not** notify: pyatv only sets its event in
    /// the branch where the volume bit *is* present, so a device that answers an `_iMC` without it
    /// leaves `volume_up()` waiting for its five-second timeout.
    pub fn clear_volume(&self) {
        self.update(|observed| observed.volume = 0.0);
    }

    /// Record the keyboard focus state.
    pub fn set_focus(&self, focus: KeyboardFocusState) {
        self.update(|observed| observed.focus = focus);
    }
}

/// Focus follows the presence of `_tiD` in the payload, nothing else.
///
/// `_handle_text_input` (`__init__.py:505-512`): a payload carrying `_tiD` means a field is
/// focused and its contents are enclosed; one without means nothing is focused.
#[must_use]
pub fn focus_from_payload(content: &pyatv_opack::Value) -> KeyboardFocusState {
    if content.get("_tiD").is_some() {
        KeyboardFocusState::Focused
    } else {
        KeyboardFocusState::Unfocused
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiState, focus_from_payload, media_control_flags};
    use pyatv_core::{KeyboardFocusState, PowerState};
    use pyatv_opack::opack;

    #[test]
    fn a_fresh_state_knows_nothing() {
        let state = ApiState::default();
        let observed = state.observed();
        assert_eq!(observed.power, PowerState::Unknown);
        assert!(!observed.power_known);
        assert_eq!(observed.control_flags, media_control_flags::NO_CONTROLS);
        assert!((observed.volume - 0.0).abs() < f32::EPSILON);
        assert_eq!(observed.focus, KeyboardFocusState::Unknown);
    }

    #[test]
    fn observing_a_power_state_marks_it_known_even_when_it_is_unchanged() {
        let state = ApiState::default();
        state.set_power(PowerState::Unknown);
        assert!(state.observed().power_known);
    }

    #[test]
    fn clearing_the_volume_zeroes_it() {
        let state = ApiState::default();
        state.set_volume(42.0);
        assert!((state.observed().volume - 42.0).abs() < f32::EPSILON);
        state.clear_volume();
        assert!((state.observed().volume - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn focus_is_decided_by_the_presence_of_ti_d() {
        assert_eq!(
            focus_from_payload(&opack! { "_tiD" => "anything" }),
            KeyboardFocusState::Focused
        );
        assert_eq!(
            focus_from_payload(&opack! {}),
            KeyboardFocusState::Unfocused
        );
    }
}
