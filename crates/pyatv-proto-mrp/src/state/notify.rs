//! Delivering listener callbacks off the protocol actor's pump.
//!
//! Every inbound message is applied by [`crate::protocol::actor::Actor`]'s single `select!` loop,
//! which is also the only thing that writes to the transport and the only thing that drains the
//! tunnel's data channel. Calling a caller-supplied listener from inside that loop makes the
//! listener part of the protocol's critical path: a `playstatus_update` that blocks for a second
//! blocks every request for a second, stops the tunnel's `rply` acknowledgements for a second, and
//! on a long enough stall makes the receiver decide the channel is dead.
//!
//! Upstream has the same hazard and only half-mitigates it. `MrpPower` defers with
//! `self.loop.call_soon(self.listener.powerstate_update, …)` (`__init__.py:680`), which moves the
//! call off the current callback but still runs it on the event loop; `PlayerStateManager` calls
//! `_state_updated` straight through (`player_state.py:246-250`). Both block the loop if the
//! listener does.
//!
//! Here the callbacks are queued and run by one dedicated task instead. The queue is bounded and
//! drops its newest entry with a log when full, because a listener that has fallen sixty-four
//! updates behind is not going to catch up and the alternative — backpressure — puts the stall
//! straight back into the actor pump this module exists to keep clear.

use std::sync::Arc;

use pyatv_core::consts::{PowerState, Protocol};
use pyatv_core::models::{OutputDevice, Playing};
use tokio::sync::mpsc;

use super::Listeners;

/// How many undelivered callbacks queue before new ones are dropped.
///
/// Matches the inbound message queue's depth: a listener further behind than the protocol's own
/// buffering has already lost the thread of what is playing, and the next update supersedes every
/// one it missed anyway.
pub(super) const QUEUE_DEPTH: usize = 64;

/// One callback waiting to be delivered.
#[derive(Debug)]
pub(super) enum Notification {
    /// A new snapshot for `playstatus_update`.
    Playing(Box<Playing>),
    /// A push-channel failure for `playstatus_error`.
    PlaybackError(pyatv_core::Error),
    /// A transition for `powerstate_update`.
    Power {
        /// What the device was reporting.
        old_state: PowerState,
        /// What it reports now.
        new_state: PowerState,
    },
    /// This device's own volume, as a percentage (`UpdatedState.Volume`, `__init__.py:840`).
    Volume(f32),
    /// Another output device's volume (`UpdatedState.OutputDeviceVolume`, `__init__.py:848-851`).
    OutputDeviceVolume {
        /// Which speaker the level belongs to.
        identifier: String,
        /// Its new level, as a percentage.
        volume: f32,
    },
    /// The playback group was re-derived (`UpdatedState.OutputDevices`, `__init__.py:925`).
    OutputDevices(Vec<OutputDevice>),
}

/// Deliver queued callbacks until the state that feeds them goes away.
///
/// Ends when every [`mpsc::Sender`] is dropped, which happens when the [`super::MrpState`] is, so
/// the task cannot outlive the session it belongs to.
pub(super) async fn run(mut inbox: mpsc::Receiver<Notification>, listeners: Arc<Listeners>) {
    while let Some(notification) = inbox.recv().await {
        deliver(&notification, &listeners);
    }
    tracing::debug!("the MRP notifier stopped");
}

/// Run one callback, if anyone is still registered for it.
///
/// Shared with the synchronous test drain, so what a unit test exercises is the same dispatch the
/// task performs rather than a re-implementation of it.
pub(super) fn deliver(notification: &Notification, listeners: &Listeners) {
    match notification {
        Notification::Playing(playing) => {
            if let Some(listener) = listeners.push_listener() {
                listener.playstatus_update(playing);
            }
        }
        Notification::PlaybackError(error) => {
            if let Some(listener) = listeners.push_listener() {
                listener.playstatus_error(error);
            }
        }
        Notification::Power {
            old_state,
            new_state,
        } => {
            if let Some(listener) = listeners.power_listener() {
                listener.power_state_changed(*old_state, *new_state);
            }
        }
        Notification::Volume(level) => {
            if let Some(dispatcher) = listeners.state_dispatcher() {
                dispatcher.volume_updated(Protocol::Mrp, *level);
            }
        }
        Notification::OutputDeviceVolume { identifier, volume } => {
            if let Some(dispatcher) = listeners.state_dispatcher() {
                dispatcher.output_device_volume_updated(Protocol::Mrp, identifier, *volume);
            }
        }
        Notification::OutputDevices(devices) => {
            if let Some(dispatcher) = listeners.state_dispatcher() {
                dispatcher.output_devices_updated(Protocol::Mrp, devices.clone());
            }
        }
    }
}
