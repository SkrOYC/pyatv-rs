//! `Power`: wake with a message, sleep with two button presses.
//!
//! Port of `MrpPower` (`pyatv/protocols/mrp/__init__.py:625-695`). The asymmetry is upstream's and
//! is not an oversight: `WAKE_DEVICE_MESSAGE` exists and has exactly this one caller, while there
//! is no power-off message at all — sleeping is "hold Home to open the power menu, then press
//! Select", driven entirely through HID.

use std::sync::Arc;

use pyatv_core::consts::PowerState;
use pyatv_core::interface::{BoxFuture, Power};
use pyatv_core::{Error as CoreError, Result as CoreResult};

use crate::facade::remote::MrpRemoteControl;
use crate::protocol::MrpProtocol;
use crate::{Result, messages};

/// MRP's power control.
#[derive(Debug)]
pub struct MrpPower {
    protocol: Arc<MrpProtocol>,
    remote: Arc<MrpRemoteControl>,
}

impl MrpPower {
    /// Wrap a connected protocol and the remote control it drives `turn_off` through.
    #[must_use]
    pub const fn new(protocol: Arc<MrpProtocol>, remote: Arc<MrpRemoteControl>) -> Self {
        Self { protocol, remote }
    }

    /// Wait for the device to report `target`, but only if it is not already there.
    ///
    /// `if await_new_state and self.power_state != PowerState.On` (`__init__.py:657-658`).
    async fn settle(&self, target: PowerState, await_new_state: bool) -> Result<()> {
        if !await_new_state || self.protocol.state().power_state() == target {
            return Ok(());
        }
        self.protocol.state().await_power_state(target).await
    }
}

impl Power for MrpPower {
    fn power_state(&self) -> PowerState {
        self.protocol.state().power_state()
    }

    /// `WAKE_DEVICE_MESSAGE`, fire-and-forget (`__init__.py:653-661`).
    fn turn_on(&self, await_new_state: bool) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.protocol
                .send(messages::wake_device())
                .await
                .map_err(CoreError::from)?;
            self.settle(PowerState::On, await_new_state)
                .await
                .map_err(Into::into)
        })
    }

    /// Hold Home, wait 100 ms, press Select (`__init__.py:663-669`).
    fn turn_off(&self, await_new_state: bool) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.remote
                .home_hold_then_select()
                .await
                .map_err(CoreError::from)?;
            self.settle(PowerState::Off, await_new_state)
                .await
                .map_err(Into::into)
        })
    }
}
