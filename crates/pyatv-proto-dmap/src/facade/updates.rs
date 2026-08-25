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
    /// # Divergence: `initial_delay` actually takes effect, and only after an error
    ///
    /// Upstream's poller reads `if not first_call and self._initial_delay > 0`, and the only place
    /// it assigns `first_call = False` is *inside* that same block (`__init__.py:497-500`) — so
    /// `first_call` is never cleared and the delay never applies, on any iteration. That looks like
    /// a plain bug rather than an intent, since the field's own comment is "Delay before restarting
    /// after an error", so here the delay is applied — and applied where that comment says, after a
    /// failed poll and not after a successful one. Delaying after a *success* would insert latency
    /// into the long poll that is DMAP's entire push mechanism, which is the opposite of what a
    /// push updater is for. With the default of zero, which is what every upstream caller passes,
    /// the two behave identically.
    ///
    /// # Divergence: consecutive failures back off
    ///
    /// See [`backoff`].
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
///   then wait (see [`backoff`]) and keep going. Resetting is what makes the next request ask for
///   current state instead of long-polling from a revision the device has rejected, and it is what
///   `test_reset_revision_if_push_updates_fail` exercises
///   (`tests/protocols/dmap/test_dmap_functional.py:284-317`).
async fn poll(shared: Arc<Shared>, initial_delay: Duration) {
    let mut failures = 0u32;

    loop {
        tracing::debug!("waiting for playstatus updates");
        match shared.apple_tv.playstatus(true).await {
            Ok(playing) => {
                failures = 0;
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

                failures = failures.saturating_add(1);
                let delay = initial_delay.max(backoff(failures));
                tracing::debug!(
                    failures,
                    delay_ms = delay.as_millis(),
                    "delaying the next poll"
                );
                tokio::time::sleep(delay).await;
            }
        }
    }
}

/// The shortest a poll may be retried after a failure.
pub const MIN_BACKOFF: Duration = Duration::from_secs(1);

/// The longest a poll will be delayed however many times it has failed.
pub const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How long to wait after `failures` consecutive non-transport failures.
///
/// # Divergence: upstream has no delay at all
///
/// `_poller`'s error branch falls straight back into `while True` (`__init__.py:513-522`), so a
/// device answering a `playstatusupdate` immediately and non-2xx — which is exactly what a
/// revision the device has moved past produces, and what the fixture's own
/// `handle_playstatus` returns for a stale revision (`tests/fake_device/dmap.py:224-226`) — is
/// re-asked as fast as the network allows. That is a hot loop against a gen-3 Apple TV, and every
/// pass allocates a connection, a parse and a listener notification. The default `initial_delay` of
/// zero means nothing upstream slows it down.
///
/// Doubling from [`MIN_BACKOFF`] and capped at [`MAX_BACKOFF`] gives 1, 2, 4, 8, 16, 30, 30, ...
/// seconds. The first retry is a whole second later than upstream's, which is the deliberate part:
/// a failure that is going to clear (a revision reset, a re-login) clears within one second, and
/// one that is not should not be retried thirty times a second. A success resets the ladder, so a
/// device that is merely flapping never climbs it.
#[must_use]
pub fn backoff(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(u32::BITS - 1);
    MIN_BACKOFF
        .saturating_mul(1u32.checked_shl(doublings).unwrap_or(u32::MAX))
        .min(MAX_BACKOFF)
}

#[cfg(test)]
mod tests {
    use super::{MAX_BACKOFF, MIN_BACKOFF, backoff};

    /// The ladder, and that it is bounded at both ends.
    #[test]
    fn the_backoff_doubles_from_one_second_and_stops_at_thirty() {
        assert_eq!(backoff(1), MIN_BACKOFF);
        assert_eq!(backoff(2).as_secs(), 2);
        assert_eq!(backoff(3).as_secs(), 4);
        assert_eq!(backoff(4).as_secs(), 8);
        assert_eq!(backoff(5).as_secs(), 16);
        assert_eq!(backoff(6), MAX_BACKOFF, "32 seconds is over the cap");

        // A device that has been unreachable for a long time must not overflow its way back to a
        // short delay.
        for failures in [7u32, 32, 1_000, u32::MAX] {
            assert_eq!(backoff(failures), MAX_BACKOFF, "{failures} failures");
        }
    }

    /// `backoff(0)` is never reached by the loop — it counts a failure before asking — but it must
    /// not be a zero-length sleep if it ever were.
    #[test]
    fn no_failure_count_produces_a_zero_delay() {
        for failures in 0..8u32 {
            assert!(backoff(failures) >= MIN_BACKOFF, "{failures} failures");
        }
    }
}
