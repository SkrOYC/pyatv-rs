//! Power state, derived entirely from the device's own `DeviceInfoMessage`.
//!
//! Port of `MrpPower` (`pyatv/protocols/mrp/__init__.py:625-695`). There is no power-state message:
//! the device reports how many logical devices it has, and that count *is* the power state.

use pyatv_core::consts::PowerState;

use crate::protobuf::DeviceInfoMessage;
use crate::state::MrpState;
use crate::{Error, Result};

/// Read the power state off a `DeviceInfoMessage` (`_get_power_state`, `__init__.py:686-695`).
///
/// `logicalDeviceCount >= 1` is on, `== 0` is off, and an absent field is unknown. Note this is the
/// *device's* count, not the fixed `logicalDeviceCount = 1` pyatv puts on its own outbound
/// `DeviceInfoMessage`.
#[must_use]
pub fn from_device_info(info: &DeviceInfoMessage) -> PowerState {
    match info.logical_device_count {
        Some(0) => PowerState::Off,
        Some(_) => PowerState::On,
        None => PowerState::Unknown,
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
    /// including the first `Unknown -> On` one.
    pub(super) fn update_power(&self, new_state: PowerState) {
        let old_state = self.power_state();
        if old_state == new_state {
            return;
        }

        self.power.send_replace(new_state);
        tracing::debug!(?old_state, ?new_state, "MRP power state changed");

        let listener = self
            .power_listener
            .lock()
            .ok()
            .and_then(|slot| slot.clone());
        if let Some(listener) = listener {
            listener.power_state_changed(old_state, new_state);
        }
    }
}
