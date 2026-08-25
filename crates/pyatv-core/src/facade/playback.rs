//! `FacadePushUpdater`: start every protocol's push updater, forward only one.
//!
//! Port of `FacadePushUpdater` (`pyatv/core/facade.py:597-644`), which is the one facade that does
//! not relay per call. Two behaviours come straight from upstream and are easy to get wrong:
//!
//! * `start`/`stop` iterate **every** registered instance (`facade.py:625-634`), so a lower-priority
//!   protocol's updater is running and warm when a takeover makes it the main one. `start` is also
//!   where upstream subscribes — `instance.listener = self` — and `stop` where it unsubscribes
//!   again, which is why both of those happen inside [`PushUpdater::start`] and
//!   [`PushUpdater::stop`] here rather than in some setup step a caller has to know about.
//! * `playstatus_update`/`playstatus_error` forward **only** the main instance's events
//!   (`facade.py:636-644`), so a caller never sees two protocols racing to describe the same
//!   device.
//!
//! Upstream can compare `updater == self.main_instance` because the callback carries the updater.
//! [`crate::interface::PlaybackListener`] does not, so a per-protocol shim is registered with each
//! instance instead and remembers which protocol it belongs to.

use std::sync::{Arc, Mutex, Weak};

use crate::Result;
use crate::consts::Protocol;
use crate::interface::{BoxFuture, PlaybackListener, PushUpdater};
use crate::models::Playing;
use crate::relayer::Relayer;

/// Forwards one protocol's push updates, tagged with which protocol they came from.
#[derive(Debug)]
struct Shim {
    protocol: Protocol,
    facade: Weak<FacadePushUpdater>,
}

impl Shim {
    /// The caller's listener, but only if this shim's protocol is the one in charge right now.
    fn interested(&self) -> Option<Arc<dyn PlaybackListener>> {
        let facade = self.facade.upgrade()?;
        if facade.relayer.main_protocol() != Some(self.protocol) {
            return None;
        }
        facade.listener()
    }
}

impl PlaybackListener for Shim {
    fn playstatus_update(&self, playing: &Playing) {
        if let Some(listener) = self.interested() {
            listener.playstatus_update(playing);
        }
    }

    fn playstatus_error(&self, error: &crate::Error) {
        if let Some(listener) = self.interested() {
            listener.playstatus_error(error);
        }
    }
}

/// Fans start/stop out to every protocol and updates in from one.
#[derive(Debug)]
pub struct FacadePushUpdater {
    relayer: Arc<Relayer<dyn PushUpdater>>,
    /// A weak handle to this very object, so a shim can be built from `&self`.
    ///
    /// Every shim needs a back-reference to ask "am I still the main protocol?" at delivery time,
    /// and only an `Arc` can give one. Subscribing therefore used to need an `Arc<Self>` receiver,
    /// which [`PushUpdater`] cannot have and no caller reaching this object through
    /// [`crate::interface::AppleTV::push_updater`] could ever produce — so nothing was ever
    /// subscribed and no callback was ever delivered. Keeping the [`Weak`] from
    /// [`Arc::new_cyclic`] removes the need for the receiver entirely.
    this: Weak<Self>,
    listener: Mutex<Option<Weak<dyn PlaybackListener>>>,
    /// The shims registered with the protocol updaters.
    ///
    /// They have to be owned here: [`PushUpdater::set_listener`] holds its listener weakly, so a
    /// shim nobody keeps alive is unsubscribed the instant it is registered. Dropping them is
    /// therefore also how [`PushUpdater::stop`] performs upstream's `instance.listener = None`.
    shims: Mutex<Vec<Arc<Shim>>>,
}

impl FacadePushUpdater {
    /// Fan out over `relayer`.
    ///
    /// Returns an `Arc` because the shims registered with each protocol hold a [`Weak`] back to
    /// this object; see the `this` field.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn PushUpdater>>) -> Arc<Self> {
        Arc::new_cyclic(|this| Self {
            relayer,
            this: this.clone(),
            listener: Mutex::new(None),
            shims: Mutex::new(Vec::new()),
        })
    }

    fn listener(&self) -> Option<Arc<dyn PlaybackListener>> {
        self.listener
            .lock()
            .ok()
            .and_then(|slot| slot.as_ref().and_then(Weak::upgrade))
    }

    /// Subscribe one shim to every registered protocol updater, replacing any earlier set.
    ///
    /// `for instance in self.instances: instance.listener = self` (`facade.py:625-627`), except
    /// that each instance gets its own shim so the protocol it belongs to is recoverable.
    fn attach(&self) {
        let Ok(mut shims) = self.shims.lock() else {
            return;
        };
        shims.clear();
        for protocol in self.relayer.protocols() {
            let Some(instance) = self.relayer.get(protocol) else {
                continue;
            };
            let shim = Arc::new(Shim {
                protocol,
                facade: self.this.clone(),
            });
            instance.set_listener(&(Arc::clone(&shim) as Arc<dyn PlaybackListener>));
            shims.push(shim);
        }
    }

    /// Unsubscribe from every protocol updater, which is `instance.listener = None`.
    fn detach(&self) {
        if let Ok(mut shims) = self.shims.lock() {
            shims.clear();
        }
    }
}

impl PushUpdater for FacadePushUpdater {
    /// Whether the *main* instance is pushing, which is the one whose updates are forwarded.
    fn active(&self) -> bool {
        self.relayer
            .main_instance()
            .is_some_and(|instance| instance.active())
    }

    fn set_listener(&self, listener: &Arc<dyn PlaybackListener>) {
        if let Ok(mut slot) = self.listener.lock() {
            *slot = Some(Arc::downgrade(listener));
        }
    }

    /// Subscribe to and then start every registered updater (`facade.py:620-627`).
    ///
    /// Subscribing here rather than at construction time is what makes
    /// `atv.push_updater().set_listener(&mine)` followed by `start(0)` deliver callbacks with no
    /// further step, and it is also upstream's own ordering: a protocol that registered after the
    /// last `start` is picked up by the next one.
    ///
    /// # Errors
    ///
    /// Returns the first failure any protocol's `start` reported, after having tried all of them —
    /// one protocol refusing to start must not leave the others un-started.
    fn start(&self, initial_delay_ms: u64) -> BoxFuture<'_, Result<()>> {
        self.attach();

        Box::pin(async move {
            let mut first_error = None;
            for instance in self.relayer.instances() {
                if let Err(error) = instance.start(initial_delay_ms).await {
                    tracing::debug!(%error, "a push updater did not start");
                    first_error.get_or_insert(error);
                }
            }
            first_error.map_or(Ok(()), Err)
        })
    }

    /// Unsubscribe from and then stop every registered updater (`facade.py:629-634`).
    fn stop(&self) {
        self.detach();
        for instance in self.relayer.instances() {
            instance.stop();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use super::FacadePushUpdater;
    use crate::consts::{DeviceState, MediaType, Protocol};
    use crate::facade::DEFAULT_PRIORITIES;
    use crate::interface::{BoxFuture, PlaybackListener, PushUpdater};
    use crate::models::Playing;
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    /// A protocol updater that records start/stop and can post an update on demand.
    #[derive(Debug, Default)]
    struct Dummy {
        started: Mutex<bool>,
        listener: Mutex<Option<std::sync::Weak<dyn PlaybackListener>>>,
    }

    impl Dummy {
        fn post(&self, title: &str) {
            let listener = self
                .listener
                .lock()
                .expect("uncontended")
                .as_ref()
                .and_then(std::sync::Weak::upgrade);
            if let Some(listener) = listener {
                listener.playstatus_update(&Playing {
                    media_type: MediaType::Music,
                    device_state: DeviceState::Playing,
                    title: Some(title.to_owned()),
                    ..Playing::default()
                });
            }
        }
    }

    impl PushUpdater for Dummy {
        fn active(&self) -> bool {
            *self.started.lock().expect("uncontended")
        }

        fn set_listener(&self, listener: &Arc<dyn PlaybackListener>) {
            *self.listener.lock().expect("uncontended") = Some(Arc::downgrade(listener));
        }

        fn start(&self, _initial_delay_ms: u64) -> BoxFuture<'_, Result<()>> {
            *self.started.lock().expect("uncontended") = true;
            Box::pin(async { Ok(()) })
        }

        fn stop(&self) {
            *self.started.lock().expect("uncontended") = false;
        }
    }

    #[derive(Debug, Default)]
    struct Saving {
        titles: Mutex<Vec<String>>,
    }

    impl PlaybackListener for Saving {
        fn playstatus_update(&self, playing: &Playing) {
            self.titles
                .lock()
                .expect("uncontended")
                .push(playing.title.clone().unwrap_or_default());
        }

        fn playstatus_error(&self, _error: &Error) {}
    }

    /// `test_takeover_push_updates` (`tests/core/test_facade.py:598-...`): both updaters run, only
    /// the main protocol's updates reach the caller, and a takeover moves which one that is.
    #[tokio::test]
    async fn only_the_main_protocol_forwards_updates() {
        let relayer: Arc<Relayer<dyn PushUpdater>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        let mrp = Arc::new(Dummy::default());
        let dmap = Arc::new(Dummy::default());
        relayer
            .register(
                Protocol::Mrp,
                Arc::clone(&mrp) as Arc<dyn PushUpdater>,
                BTreeSet::new(),
            )
            .expect("the protocol is in the priority list");
        relayer
            .register(
                Protocol::Dmap,
                Arc::clone(&dmap) as Arc<dyn PushUpdater>,
                BTreeSet::new(),
            )
            .expect("the protocol is in the priority list");

        let facade = FacadePushUpdater::new(Arc::clone(&relayer));
        let saving = Arc::new(Saving::default());
        facade.set_listener(&(Arc::clone(&saving) as Arc<dyn PlaybackListener>));
        facade.start(0).await.expect("both start");

        assert!(mrp.active() && dmap.active(), "every instance is started");

        mrp.post("mrp-1");
        dmap.post("dmap-1");
        assert_eq!(*saving.titles.lock().expect("uncontended"), vec!["mrp-1"]);

        relayer.takeover(Protocol::Dmap).expect("free relayer");
        mrp.post("mrp-2");
        dmap.post("dmap-2");
        assert_eq!(
            *saving.titles.lock().expect("uncontended"),
            vec!["mrp-1", "dmap-2"]
        );

        relayer.release();
        mrp.post("mrp-3");
        assert_eq!(
            *saving.titles.lock().expect("uncontended"),
            vec!["mrp-1", "dmap-2", "mrp-3"]
        );

        facade.stop();
        assert!(!mrp.active() && !dmap.active(), "and every instance stops");
    }

    /// The regression this module's `this` field exists for: everything a library caller can reach
    /// is `&dyn PushUpdater`, and subscribing used to need an `Arc<Self>` receiver they had no way
    /// to name — so `set_listener` + `start` compiled, connected, and delivered nothing.
    #[tokio::test]
    async fn the_trait_object_path_delivers_updates() {
        let relayer: Arc<Relayer<dyn PushUpdater>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        let mrp = Arc::new(Dummy::default());
        relayer
            .register(
                Protocol::Mrp,
                Arc::clone(&mrp) as Arc<dyn PushUpdater>,
                BTreeSet::new(),
            )
            .expect("the protocol is in the priority list");

        let updater = FacadePushUpdater::new(relayer) as Arc<dyn PushUpdater>;
        let saving = Arc::new(Saving::default());
        updater.set_listener(&(Arc::clone(&saving) as Arc<dyn PlaybackListener>));
        updater.start(0).await.expect("MRP starts");

        mrp.post("through-the-trait");
        assert_eq!(
            *saving.titles.lock().expect("uncontended"),
            vec!["through-the-trait"]
        );

        // `stop` is upstream's `instance.listener = None`, so a late update is dropped...
        updater.stop();
        mrp.post("after-stop");
        assert_eq!(
            saving.titles.lock().expect("uncontended").len(),
            1,
            "a stopped updater must not forward anything"
        );

        // ...and starting again re-subscribes rather than staying deaf.
        updater.start(0).await.expect("MRP restarts");
        mrp.post("after-restart");
        assert_eq!(
            *saving.titles.lock().expect("uncontended"),
            vec!["through-the-trait", "after-restart"]
        );
    }
}
