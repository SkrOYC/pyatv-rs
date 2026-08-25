//! Power state, derived entirely from the device's own `DeviceInfoMessage`.
//!
//! Port of `MrpPower` (`pyatv/protocols/mrp/__init__.py:625-695`). There is no power-state message:
//! the device reports how many logical devices it has, and that count *is* the power state.

use pyatv_core::consts::PowerState;

use crate::protobuf::DeviceInfoMessage;
use crate::state::MrpState;
use crate::state::notify::Notification;
use crate::{Error, Result};

/// Read the power state off a `DeviceInfoMessage` (`_get_power_state`, `__init__.py:686-695`).
///
/// `logicalDeviceCount >= 1` is on and everything else is off. Note this is the *device's* count,
/// not the fixed `logicalDeviceCount = 1` pyatv puts on its own outbound `DeviceInfoMessage`.
///
/// # An absent field is `Off`, not `Unknown`
///
/// Upstream reads `protobuf.extract_inner(message).logicalDeviceCount` and compares it, which on a
/// **proto2 optional int32** yields the type default `0` when the field was never set — so the
/// `>= 1` test fails, the `== 0` test succeeds, and pyatv reports `Off`. Its third branch is
/// unreachable from Python: there is no value of a scalar proto2 field that is neither `>= 1` nor
/// `== 0`.
///
/// `prost` models the same field as `Option<i32>` and hands back `None`, which makes the absence
/// visible where Python hides it — but *reporting* that absence as `Unknown` is a divergence, not
/// a refinement. A device that sends `DEVICE_INFO_MESSAGE` without the field is described by pyatv
/// as powered off, and `MrpPower.power_state` is what the facade relays; saying `Unknown` instead
/// makes `power_state()` disagree with pyatv on exactly the devices that omit it.
#[must_use]
pub fn from_device_info(info: &DeviceInfoMessage) -> PowerState {
    match info.logical_device_count.unwrap_or_default() {
        count if count >= 1 => PowerState::On,
        _ => PowerState::Off,
    }
}

impl MrpState {
    /// The device's last reported power state.
    #[must_use]
    pub fn power_state(&self) -> PowerState {
        *self.power.borrow()
    }

    /// Wait until the device reports `target`.
    ///
    /// `turn_on`/`turn_off` with `await_new_state=True` (`__init__.py:653-669`), where upstream
    /// keys an `asyncio.Event` per target state. A `watch` channel is used instead so a caller
    /// that arrives *after* the device already reported the target returns immediately rather
    /// than waiting for an event that has been and gone.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the state is dropped while waiting.
    pub async fn await_power_state(&self, target: PowerState) -> Result<()> {
        let mut receiver = self.power.subscribe();
        loop {
            if *receiver.borrow_and_update() == target {
                return Ok(());
            }
            receiver.changed().await.map_err(|_| Error::Closed)?;
        }
    }

    /// Record a new power state and notify the listener if it changed.
    ///
    /// `_update_power_state` (`__init__.py:671-684`) fires the listener only on a real transition,
    /// including the first `Unknown -> On` one, and defers the call with `loop.call_soon` rather
    /// than making it inline. Queueing it does the same thing more thoroughly; see
    /// [`crate::state::notify`].
    pub(super) fn update_power(&self, new_state: PowerState) {
        let old_state = self.power_state();
        if old_state == new_state {
            return;
        }

        self.power.send_replace(new_state);
        tracing::debug!(?old_state, ?new_state, "MRP power state changed");

        self.post(Notification::Power {
            old_state,
            new_state,
        });
    }
}
