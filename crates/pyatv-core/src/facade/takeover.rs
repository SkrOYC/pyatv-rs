//! Letting one protocol temporarily own an interface.
//!
//! Ports `FacadeAppleTV.takeover` (`pyatv/core/facade.py:804-830`) and the `Relayer.takeover` /
//! `Relayer.release` pair behind it (`pyatv/core/relayer.py:117-127`).
//!
//! # Why this exists
//!
//! AirPlay's `play_url` holds the whole playback open on one HTTP connection and its only way to
//! stop is to close that connection. So for as long as a URL is playing, `stop()` has to reach
//! *AirPlay's* remote control and not MRP's, even though MRP outranks AirPlay everywhere else.
//! Upstream expresses that as `takeover_release = self.core.takeover(RemoteControl)` around the
//! play, released in a `finally` (`pyatv/protocols/airplay/__init__.py:125,139`). RAOP does the
//! same for four interfaces at once while `stream_file` runs
//! (`pyatv/protocols/raop/__init__.py:350-352,403`), so that metadata, push updates, volume and
//! stop all describe the audio being streamed rather than whatever the device was showing before.
//!
//! # Shape in Rust
//!
//! Upstream returns a `_release` closure the caller must remember to call. Here
//! [`FacadeTakeover::claim`] returns a [`TakeoverGuard`] that releases on drop, so a `?` or a panic
//! in the middle of a playback cannot leave an interface permanently claimed. The guard also has an
//! explicit [`TakeoverGuard::release`] for callers that want to say so.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::consts::Protocol;
use crate::relayer::Relayer;
use crate::{Error, Result};

/// One capability that can be claimed.
///
/// The keys of upstream's `FacadeAppleTV._interfaces` dict, which are the interface *classes*
/// themselves (`facade.py:818-828`). Rust cannot key a map by trait, so this enumerates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Interface {
    /// [`crate::interface::RemoteControl`].
    RemoteControl,
    /// [`crate::interface::Metadata`].
    Metadata,
    /// [`crate::interface::PushUpdater`].
    PushUpdater,
    /// [`crate::interface::Stream`].
    Stream,
    /// [`crate::interface::Power`].
    Power,
    /// [`crate::interface::Apps`].
    Apps,
    /// [`crate::interface::Audio`].
    Audio,
    /// [`crate::interface::Keyboard`].
    Keyboard,
    /// [`crate::interface::TouchGestures`].
    TouchGestures,
    /// [`crate::interface::UserAccounts`].
    UserAccounts,
}

/// A relayer with its element type erased, so one registry can hold all of them.
trait Claimable: Send + Sync + std::fmt::Debug {
    fn claim(&self, protocol: Protocol) -> Result<()>;
    fn release(&self);
}

impl<T: ?Sized + Send + Sync + 'static> Claimable for Relayer<T> {
    fn claim(&self, protocol: Protocol) -> Result<()> {
        self.takeover(protocol)
    }

    fn release(&self) {
        Relayer::release(self);
    }
}

/// Every claimable interface, keyed so a protocol can name the ones it wants.
///
/// Built once by [`crate::facade::FacadeAppleTV::new`] over the same relayers the facade reads
/// from, and handed to each protocol's `setup()` as a [`FacadeTakeover`] before anything connects —
/// the same "the protocol needs this before the facade is finished" reason
/// [`crate::facade::ListenerHub`] documents.
#[derive(Debug, Default)]
pub struct TakeoverRegistry {
    entries: BTreeMap<Interface, Arc<dyn Claimable>>,
}

impl TakeoverRegistry {
    /// File a relayer under the interface it serves.
    pub fn insert<T: ?Sized + Send + Sync + 'static>(
        &mut self,
        interface: Interface,
        relayer: &Arc<Relayer<T>>,
    ) {
        self.entries
            .insert(interface, Arc::clone(relayer) as Arc<dyn Claimable>);
    }

    /// Claim `interfaces` for `protocol` until the returned guard is dropped.
    ///
    /// `FacadeAppleTV.takeover` (`facade.py:804-830`): interfaces are claimed in order, an
    /// interface this facade does not have is skipped rather than being an error, and a claim that
    /// fails part-way **rolls back the ones already taken** before reporting.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidState`] if any named interface is already claimed by another
    /// protocol. Nothing remains claimed in that case.
    pub fn claim(
        self: &Arc<Self>,
        protocol: Protocol,
        interfaces: &[Interface],
    ) -> Result<TakeoverGuard> {
        tracing::debug!(?protocol, ?interfaces, "takeover");

        let mut guard = TakeoverGuard {
            taken: Vec::with_capacity(interfaces.len()),
        };

        for interface in interfaces {
            let Some(relayer) = self.entries.get(interface) else {
                continue;
            };
            // `_release()` then `raise` (`facade.py:823-827`) — dropping `guard` here releases
            // whatever was already taken, which is the same rollback.
            relayer.claim(protocol).map_err(|error| match error {
                Error::InvalidState(reason) => {
                    Error::InvalidState(format!("{interface:?}: {reason}"))
                }
                other => other,
            })?;
            guard.taken.push(Arc::clone(relayer));
        }

        Ok(guard)
    }
}

/// Releases the interfaces it holds when dropped.
///
/// The `_release` callable upstream returns (`facade.py:811-814,830`), made unforgettable.
#[derive(Debug)]
#[must_use = "dropping the guard immediately releases the takeover"]
pub struct TakeoverGuard {
    taken: Vec<Arc<dyn Claimable>>,
}

impl TakeoverGuard {
    /// Release now rather than at the end of the scope.
    pub fn release(mut self) {
        self.release_all();
    }

    fn release_all(&mut self) {
        for relayer in self.taken.drain(..) {
            relayer.release();
        }
    }
}

impl Drop for TakeoverGuard {
    fn drop(&mut self) {
        self.release_all();
    }
}

/// A registry with one protocol's identity already bound to it.
///
/// `partial(atv.takeover, proto)` (`pyatv/__init__.py:138`), which upstream hands to every
/// protocol's `Core` so a protocol never has to name itself
/// (`pyatv/core/__init__.py:223,233`).
#[derive(Debug, Clone)]
pub struct FacadeTakeover {
    registry: Arc<TakeoverRegistry>,
    protocol: Protocol,
}

impl FacadeTakeover {
    /// Bind `protocol` to `registry`.
    #[must_use]
    pub fn new(registry: Arc<TakeoverRegistry>, protocol: Protocol) -> Self {
        Self { registry, protocol }
    }

    /// The protocol this handle claims on behalf of.
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Claim `interfaces` until the returned guard is dropped.
    ///
    /// # Errors
    ///
    /// As [`TakeoverRegistry::claim`].
    pub fn claim(&self, interfaces: &[Interface]) -> Result<TakeoverGuard> {
        self.registry.claim(self.protocol, interfaces)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::{Interface, TakeoverRegistry};
    use crate::consts::Protocol;
    use crate::relayer::Relayer;

    fn registry() -> (Arc<TakeoverRegistry>, Arc<Relayer<str>>, Arc<Relayer<str>>) {
        let audio: Arc<Relayer<str>> = Arc::new(Relayer::new(vec![Protocol::Mrp, Protocol::Raop]));
        let stream: Arc<Relayer<str>> = Arc::new(Relayer::new(vec![Protocol::Mrp, Protocol::Raop]));
        audio.register(Protocol::Mrp, Arc::from("mrp"), BTreeSet::new());
        audio.register(Protocol::Raop, Arc::from("raop"), BTreeSet::new());
        stream.register(Protocol::Mrp, Arc::from("mrp"), BTreeSet::new());

        let mut registry = TakeoverRegistry::default();
        registry.insert(Interface::Audio, &audio);
        registry.insert(Interface::Stream, &stream);
        (Arc::new(registry), audio, stream)
    }

    /// `test_takeover_and_release` (`tests/core/test_facade.py:544-566`).
    #[test]
    fn a_guard_claims_and_then_releases() {
        let (registry, audio, _) = registry();
        assert_eq!(audio.main_instance().as_deref(), Some("mrp"));

        let guard = registry
            .claim(Protocol::Raop, &[Interface::Audio])
            .expect("nothing claimed yet");
        assert_eq!(audio.main_instance().as_deref(), Some("raop"));

        guard.release();
        assert_eq!(audio.main_instance().as_deref(), Some("mrp"));
    }

    /// Dropping the guard is the same as releasing it, which is what makes the AirPlay `play_url`
    /// path safe against an early return.
    #[test]
    fn dropping_the_guard_releases() {
        let (registry, audio, _) = registry();
        {
            let _guard = registry
                .claim(Protocol::Raop, &[Interface::Audio])
                .expect("nothing claimed yet");
            assert_eq!(audio.main_instance().as_deref(), Some("raop"));
        }
        assert_eq!(audio.main_instance().as_deref(), Some("mrp"));
    }

    /// `test_takeover_failure_restores` (`test_facade.py:575-596`): the partial claim is rolled
    /// back, so the interface that *did* succeed is free again.
    #[test]
    fn a_failed_claim_releases_what_it_already_took() {
        let (registry, audio, stream) = registry();

        let _held = registry
            .claim(Protocol::Raop, &[Interface::Audio])
            .expect("nothing claimed yet");

        let error = registry
            .claim(Protocol::Dmap, &[Interface::Stream, Interface::Audio])
            .expect_err("Audio is already claimed");
        assert!(matches!(error, crate::Error::InvalidState(_)), "{error}");

        assert_eq!(
            stream.taken_over_by(),
            None,
            "Stream was claimed first and must have been rolled back"
        );
        assert_eq!(audio.taken_over_by(), Some(Protocol::Raop));
    }

    /// An interface the facade does not have is skipped, not an error (`facade.py:819-821`).
    #[test]
    fn an_unknown_interface_is_skipped() {
        let (registry, _, _) = registry();
        let guard = registry.claim(Protocol::Raop, &[Interface::Keyboard]);
        assert!(guard.is_ok());
    }
}
