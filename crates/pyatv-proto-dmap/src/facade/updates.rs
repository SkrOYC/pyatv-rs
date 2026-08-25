//! `DmapPushUpdater`: the `playstatusupdate` long-poll loop.
//!
//! Port of `pyatv/protocols/dmap/__init__.py:448-524`. DMAP has no event channel: the "push" is a
//! `GET` the device holds open until playback state changes, answered with the new state and the
//! next revision number. The loop below re-issues it forever.

use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use pyatv_core::Result as CoreResult;
use pyatv_core::interface::{BoxFuture, DeviceListener, PlaybackListener, PushUpdater};
use tokio::task::JoinHandle;

use crate::Error;
use crate::client::BaseDmapAppleTV;

/// What the poller needs, kept behind one `Arc` so the spawned task can own a clone.
#[derive(Debug)]
struct Shared {
    apple_tv: Arc<BaseDmapAppleTV>,
    listener: Mutex<Option<Weak<dyn PlaybackListener>>>,
    device_listener: Option<Arc<dyn DeviceListener>>,
}

impl Shared {
    fn playback_listener(&self) -> Option<Arc<dyn PlaybackListener>> {
        self.listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade)
    }
}

/// Long-polls the device for playback changes.
#[derive(Debug)]
pub struct DmapPushUpdater {
    shared: Arc<Shared>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl DmapPushUpdater {
    /// Push updates for the device `apple_tv` is connected to.
    ///
    /// `device_listener` receives `connection_lost` when the poll fails at the transport level,
    /// which is the one error class that stops the loop.
    #[must_use]
    pub fn new(
        apple_tv: Arc<BaseDmapAppleTV>,
        device_listener: Option<Arc<dyn DeviceListener>>,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                apple_tv,
                listener: Mutex::new(None),
                device_listener,
            }),
            task: Mutex::new(None),
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Option<JoinHandle<()>>> {
        self.task.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PushUpdater for DmapPushUpdater {
    /// `active` (`__init__.py:461-464`): whether the poller task exists.
    fn active(&self) -> bool {
        self.locked()
            .as_ref()
            .is_some_and(|task| !task.is_finished())
    }

    fn set_listener(&self, listener: &Arc<dyn PlaybackListener>) {
        *self
            .shared
            .listener
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Arc::downgrade(listener));
    }

    /// `start` (`__init__.py:466-483`).
    ///
    /// The revision is reset to zero **every** time, restart included, so the first request comes
    /// back immediately with current state rather than blocking on a revision the device has
    /// already moved past. Starting an already-active updater does nothing.
    ///
    /// # Divergence: `initial_delay` actually takes effect
    ///
    /// Upstream's poller reads `if not first_call and self._initial_delay > 0`, and the only place
    /// it assigns `first_call = False` is *inside* that same block (`__init__.py:497-500`) — so
    /// `first_call` is never cleared and the delay never applies, on any iteration. That looks like
    /// a plain bug rather than an intent, since the field's own comment is "Delay before restarting
    /// after an error". Here the delay applies from the second iteration onward, which is what the
    /// comment describes. With the default of zero, which is what every upstream caller passes,
    /// the two behave identically.
    ///
    /// # Errors
    ///
    /// Never; the signature is the trait's.
    fn start(&self, initial_delay_ms: u64) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            let mut task = self.locked();
            if task.as_ref().is_some_and(|task| !task.is_finished()) {
                return Ok(());
            }

            // "Always start with 0 to trigger an immediate response for the first request."
            self.shared.apple_tv.reset_revision();

            let shared = Arc::clone(&self.shared);
            *task = Some(tokio::spawn(poll(
                shared,
                Duration::from_millis(initial_delay_ms),
            )));
            Ok(())
        })
    }

    /// `stop` (`__init__.py:485-489`): cancel the task.
    fn stop(&self) {
        if let Some(task) = self.locked().take() {
            task.abort();
        }
    }
}

/// `_poller` (`__init__.py:491-524`).
///
/// Three exits, and only one of them ends the loop:
///
/// * **cancellation** — [`PushUpdater::stop`] aborts the task, which is upstream's
///   `asyncio.CancelledError` branch;
/// * **a transport failure** — upstream's `aiohttp.ClientError` branch: notify
///   [`DeviceListener::connection_lost`] and stop. The loop does *not* restart itself; the caller
///   has to call `start` again.
/// * **anything else** — reset the revision to zero and report the error to the playback listener,
///   then keep going. Resetting is what makes the next request ask for current state instead of
///   long-polling from a revision the device has rejected, and it is what
///   `test_reset_revision_if_push_updates_fail` exercises
///   (`tests/protocols/dmap/test_dmap_functional.py:284-317`).
async fn poll(shared: Arc<Shared>, initial_delay: Duration) {
    let mut first_call = true;

    loop {
        if !first_call && !initial_delay.is_zero() {
            tracing::debug!(delay_ms = initial_delay.as_millis(), "delaying next poll");
            tokio::time::sleep(initial_delay).await;
        }
        first_call = false;

        tracing::debug!("waiting for playstatus updates");
        match shared.apple_tv.playstatus(true).await {
            Ok(playing) => {
                if let Some(listener) = shared.playback_listener() {
                    listener.playstatus_update(&playing);
                }
            }
            // `Error::Io` is this port's transport class: a refused connection, a socket that went
            // away, or a device that hung up mid-response — which is exactly what
            // `server_closes_connection` does (`tests/fake_device/dmap.py:219-220`).
            Err(error @ Error::Io(_)) => {
                tracing::debug!(%error, "a communication error happened");
                if let Some(listener) = &shared.device_listener {
                    listener.connection_lost(&error.to_string());
                }
                return;
            }
            Err(error) => {
                tracing::debug!(%error, "playstatus error occurred");
                shared.apple_tv.reset_revision();
                if let Some(listener) = shared.playback_listener() {
                    listener.playstatus_error(&error.into());
                }
            }
        }
    }
}
