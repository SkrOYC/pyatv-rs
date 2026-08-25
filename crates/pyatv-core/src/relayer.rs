//! Priority-based selection of one implementation among several protocols.
//!
//! Direct equivalent of `pyatv/core/relayer.py`. A device commonly exposes the same capability over
//! more than one protocol — for example both MRP and DMAP can report now-playing metadata — and
//! pyatv resolves this with a fixed per-capability priority list rather than by asking the user.
//!
//! # Selecting per method, not per trait
//!
//! Upstream's `Relayer.relay(target)` walks the priority list and picks the first instance whose
//! *class actually overrides* the named method (`relayer.py:96-115`); a protocol that inherits the
//! abstract base's body is skipped. That check matters: AirPlay and RAOP both register a `Stream`,
//! AirPlay implements only `play_url` and RAOP only `stream_file`, and without it the
//! higher-priority AirPlay registration would swallow `stream_file` and make it unreachable.
//!
//! Rust has no equivalent introspection — an `Arc<dyn Stream>` provably has every method — so the
//! same information is supplied explicitly at registration time as the set of [`FeatureName`]s the
//! protocol declares. That set already exists: it is the one every protocol's `setup()` puts in
//! `SetupData::features`, and upstream derives its own `FeatureName` list from the very
//! `@feature(...)` decorators that sit on these interface methods. [`Relayer::instance_for`] is
//! therefore the direct analogue of `_find_instance`, and [`Relayer::main_instance`] of
//! `main_instance`, for the methods that have no feature of their own.
//!
//! # Shared and interior-mutable
//!
//! A relayer is registered into as protocols connect, and read from by facade objects that were
//! handed out before those protocols existed. Both happen through `&self` so that one
//! `Arc<Relayer<T>>` can be shared between [`crate::facade::FacadeAppleTV`] and every wrapper it
//! hands a caller.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::consts::Protocol;
use crate::features::FeatureName;
use crate::{Error, Result};

/// One protocol's registration: the implementation and the features it declared.
struct Registration<T: ?Sized> {
    instance: Arc<T>,
    declared: BTreeSet<FeatureName>,
}

/// Mutable half of a relayer, behind one lock.
struct State<T: ?Sized> {
    instances: HashMap<Protocol, Registration<T>>,
    /// `Relayer._takeover_protocol` (`relayer.py:50`), which upstream keeps as a list of at most
    /// one so it can `chain(...)` it in front of the priorities. An `Option` says the same thing.
    takeover: Option<Protocol>,
}

/// Selects one registered implementation of `T` by protocol priority.
pub struct Relayer<T: ?Sized> {
    priorities: Vec<Protocol>,
    state: RwLock<State<T>>,
}

/// Written by hand rather than derived so that `T` itself need not be [`std::fmt::Debug`].
///
/// Deriving would put a `T: Debug` bound on the impl, which excludes every `Relayer<dyn Trait>` the
/// facade is built out of. The registered instances are not rendered in any case: an
/// `Arc<dyn RemoteControl>`'s `Debug` output is a protocol's whole connection state, which is not
/// what someone printing a relayer is asking for.
#[allow(
    clippy::missing_fields_in_debug,
    reason = "rendering the instances would dump every protocol connection's state"
)]
impl<T: ?Sized> std::fmt::Debug for Relayer<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = self.read();
        formatter
            .debug_struct("Relayer")
            .field("priorities", &self.priorities)
            .field(
                "registered",
                &state.instances.keys().copied().collect::<Vec<_>>(),
            )
            .field("takeover", &state.takeover)
            .finish()
    }
}

impl<T: ?Sized> Relayer<T> {
    /// Create a relayer that prefers protocols in the order given, most preferred first.
    ///
    /// Protocols absent from `priorities` can still be registered; they simply sort after every
    /// listed protocol, in [`Protocol::ALL`] order.
    #[must_use]
    pub fn new(priorities: Vec<Protocol>) -> Self {
        Self {
            priorities,
            state: RwLock::new(State {
                instances: HashMap::new(),
                takeover: None,
            }),
        }
    }

    /// Take the read lock, ignoring poisoning.
    ///
    /// Nothing held across the lock can panic — the guarded value is a map of `Arc`s and one
    /// `Option<Protocol>` — so a poisoned lock can only mean an unrelated thread died elsewhere,
    /// and refusing to route a command because of that would be strictly worse than proceeding.
    fn read(&self) -> RwLockReadGuard<'_, State<T>> {
        self.state
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Take the write lock, ignoring poisoning, for the reason [`Relayer::read`] gives.
    fn write(&self) -> RwLockWriteGuard<'_, State<T>> {
        self.state
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Register `instance` as the implementation supplied by `protocol`, replacing any previous
    /// registration for that protocol.
    ///
    /// `declared` is the protocol's `SetupData::features` set and decides which methods this
    /// instance is eligible to answer — see the module documentation. Pass an empty set for a
    /// registration that should only ever be reached through [`Relayer::main_instance`].
    pub fn register(&self, protocol: Protocol, instance: Arc<T>, declared: BTreeSet<FeatureName>) {
        self.write()
            .instances
            .insert(protocol, Registration { instance, declared });
    }

    /// Every protocol in selection order: the protocol holding a takeover first, then the
    /// configured priorities, then any remaining protocol in [`Protocol::ALL`] order.
    ///
    /// `chain(self._takeover_protocol, self._priorities)` (`relayer.py:60,68,92`). Each protocol is
    /// yielded at most once: naively chaining would repeat every prioritised protocol, which is
    /// harmless for a `find` but visibly wrong in [`Relayer::protocols`].
    fn search_order(&self, takeover: Option<Protocol>) -> impl Iterator<Item = Protocol> + '_ {
        takeover.into_iter().chain(
            self.priorities
                .iter()
                .copied()
                .chain(
                    Protocol::ALL
                        .into_iter()
                        .filter(|protocol| !self.priorities.contains(protocol)),
                )
                .filter(move |protocol| Some(*protocol) != takeover),
        )
    }

    /// The highest-priority registered implementation, if any.
    ///
    /// `main_instance` (`relayer.py:57-63`), which respects an active takeover.
    #[must_use]
    pub fn main_instance(&self) -> Option<Arc<T>> {
        let state = self.read();
        self.search_order(state.takeover)
            .find_map(|protocol| state.instances.get(&protocol))
            .map(|registration| Arc::clone(&registration.instance))
    }

    /// The implementation that should answer the method `feature` names.
    ///
    /// The analogue of `_find_instance` (`relayer.py:96-115`): the first protocol in selection
    /// order that declared `feature`. Returns `None` when nobody did, which is the case upstream
    /// raises `NotSupportedError` for.
    #[must_use]
    pub fn instance_for(&self, feature: FeatureName) -> Option<Arc<T>> {
        let state = self.read();
        self.search_order(state.takeover)
            .filter_map(|protocol| state.instances.get(&protocol))
            .find(|registration| registration.declared.contains(&feature))
            .map(|registration| Arc::clone(&registration.instance))
    }

    /// The protocol backing [`Relayer::main_instance`].
    #[must_use]
    pub fn main_protocol(&self) -> Option<Protocol> {
        let state = self.read();
        self.search_order(state.takeover)
            .find(|protocol| state.instances.contains_key(protocol))
    }

    /// The implementation registered by a specific protocol.
    #[must_use]
    pub fn get(&self, protocol: Protocol) -> Option<Arc<T>> {
        self.read()
            .instances
            .get(&protocol)
            .map(|registration| Arc::clone(&registration.instance))
    }

    /// Every protocol that registered an implementation, in priority order.
    #[must_use]
    pub fn protocols(&self) -> Vec<Protocol> {
        let state = self.read();
        self.search_order(state.takeover)
            .filter(|protocol| state.instances.contains_key(protocol))
            .collect()
    }

    /// Every registered implementation, in priority order.
    ///
    /// `instances` (`relayer.py:73-76`), which `FacadePushUpdater.start`/`stop` iterate so every
    /// connected protocol's updater is started, not only the main one (`facade.py:625-634`).
    #[must_use]
    pub fn instances(&self) -> Vec<Arc<T>> {
        let state = self.read();
        self.search_order(state.takeover)
            .filter_map(|protocol| state.instances.get(&protocol))
            .map(|registration| Arc::clone(&registration.instance))
            .collect()
    }

    /// Number of registered implementations.
    #[must_use]
    pub fn count(&self) -> usize {
        self.read().instances.len()
    }

    /// Whether nothing has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.read().instances.is_empty()
    }

    /// Temporarily put `protocol` ahead of the priority list.
    ///
    /// `takeover` (`relayer.py:117-123`). The claim is exclusive: a second one fails rather than
    /// nesting, and the protocol need not have registered anything — a takeover by a protocol with
    /// no instance simply falls through to the priority list, exactly as upstream's `chain` does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidState`] if another protocol already holds this relayer.
    pub fn takeover(&self, protocol: Protocol) -> Result<()> {
        let mut state = self.write();
        if let Some(holder) = state.takeover {
            return Err(Error::InvalidState(format!(
                "{holder:?} has already done takeover"
            )));
        }
        state.takeover = Some(protocol);
        Ok(())
    }

    /// Release a takeover, whether or not one is held.
    ///
    /// `release` (`relayer.py:125-127`), which likewise does not care.
    pub fn release(&self) {
        self.write().takeover = None;
    }

    /// The protocol currently holding this relayer, if any.
    #[must_use]
    pub fn taken_over_by(&self) -> Option<Protocol> {
        self.read().takeover
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::Relayer;
    use crate::consts::Protocol;
    use crate::features::FeatureName;

    fn declaring(features: &[FeatureName]) -> BTreeSet<FeatureName> {
        features.iter().copied().collect()
    }

    fn register(relayer: &Relayer<str>, protocol: Protocol, name: &'static str) {
        relayer.register(protocol, Arc::from(name), BTreeSet::new());
    }

    fn sample() -> Relayer<str> {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::Mrp, Protocol::Dmap]);
        // Registered in reverse priority order on purpose: selection must not depend on it.
        register(&relayer, Protocol::Dmap, "dmap");
        register(&relayer, Protocol::Mrp, "mrp");
        relayer
    }

    #[test]
    fn main_instance_follows_priority_not_registration_order() {
        let relayer = sample();
        assert_eq!(relayer.main_instance().as_deref(), Some("mrp"));
        assert_eq!(relayer.main_protocol(), Some(Protocol::Mrp));
        assert_eq!(relayer.count(), 2);
    }

    #[test]
    fn unlisted_protocols_sort_after_listed_ones() {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::Mrp]);
        register(&relayer, Protocol::Companion, "companion");
        assert_eq!(relayer.main_protocol(), Some(Protocol::Companion));

        register(&relayer, Protocol::Mrp, "mrp");
        assert_eq!(relayer.main_protocol(), Some(Protocol::Mrp));
        assert_eq!(
            relayer.protocols(),
            vec![Protocol::Mrp, Protocol::Companion]
        );
    }

    #[test]
    fn empty_relayer_selects_nothing() {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::Mrp]);
        assert!(relayer.is_empty());
        assert!(relayer.main_instance().is_none());
        assert!(relayer.get(Protocol::Mrp).is_none());
    }

    /// `test_takeover_and_release` (`tests/core/test_relayer.py:201-215`).
    #[test]
    fn takeover_then_release_restores_priority() {
        let relayer: Relayer<str> =
            Relayer::new(vec![Protocol::Mrp, Protocol::Dmap, Protocol::AirPlay]);
        register(&relayer, Protocol::AirPlay, "airplay");
        register(&relayer, Protocol::Mrp, "mrp");
        register(&relayer, Protocol::Dmap, "dmap");

        assert_eq!(relayer.main_instance().as_deref(), Some("mrp"));

        relayer.takeover(Protocol::AirPlay).expect("free relayer");
        assert_eq!(relayer.main_instance().as_deref(), Some("airplay"));

        relayer.release();
        assert_eq!(relayer.main_instance().as_deref(), Some("mrp"));
    }

    /// `test_takeover_overrides_main_protocol` (`test_relayer.py:179-186`).
    #[test]
    fn takeover_overrides_main_protocol() {
        let relayer = sample();
        relayer.takeover(Protocol::Dmap).expect("free relayer");
        assert_eq!(relayer.main_protocol(), Some(Protocol::Dmap));
        assert_eq!(relayer.taken_over_by(), Some(Protocol::Dmap));
    }

    /// `test_takeover_while_takeover_raises` (`test_relayer.py:218-224`): the second claim fails,
    /// and the first holder is named in the error.
    #[test]
    fn a_second_takeover_is_refused() {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::AirPlay]);
        register(&relayer, Protocol::AirPlay, "airplay");
        relayer.takeover(Protocol::Dmap).expect("free relayer");

        let error = relayer
            .takeover(Protocol::Dmap)
            .expect_err("already taken over");
        assert!(matches!(error, crate::Error::InvalidState(_)), "{error}");
        assert!(error.to_string().contains("Dmap"), "{error}");
    }

    /// `test_takeover_with_missing_implementation` (`test_relayer.py:241-248`): a takeover by a
    /// protocol that registered nothing falls straight through to the priority list.
    #[test]
    fn takeover_by_an_unregistered_protocol_falls_through() {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::AirPlay, Protocol::Dmap]);
        register(&relayer, Protocol::AirPlay, "airplay");

        relayer.takeover(Protocol::Dmap).expect("free relayer");

        assert_eq!(relayer.main_instance().as_deref(), Some("airplay"));
    }

    /// Releasing without a takeover is a no-op, as it is upstream (`relayer.py:125-127`).
    #[test]
    fn releasing_an_unclaimed_relayer_is_harmless() {
        let relayer = sample();
        relayer.release();
        assert_eq!(relayer.main_instance().as_deref(), Some("mrp"));
    }

    /// The per-method half of `_find_instance` (`relayer.py:96-115`): a higher-priority protocol
    /// that did not declare the feature is skipped rather than answering it.
    #[test]
    fn a_method_goes_to_the_protocol_that_declared_it() {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::AirPlay, Protocol::Raop]);
        relayer.register(
            Protocol::AirPlay,
            Arc::from("airplay"),
            declaring(&[FeatureName::PlayUrl, FeatureName::Stop]),
        );
        relayer.register(
            Protocol::Raop,
            Arc::from("raop"),
            declaring(&[FeatureName::StreamFile, FeatureName::Stop]),
        );

        assert_eq!(
            relayer.instance_for(FeatureName::PlayUrl).as_deref(),
            Some("airplay")
        );
        assert_eq!(
            relayer.instance_for(FeatureName::StreamFile).as_deref(),
            Some("raop"),
            "AirPlay outranks RAOP but never declared StreamFile"
        );
        assert_eq!(
            relayer.instance_for(FeatureName::Stop).as_deref(),
            Some("airplay"),
            "both declared Stop, so priority decides"
        );
        assert!(relayer.instance_for(FeatureName::Volume).is_none());
    }

    /// A takeover reorders per-method selection too, but does not make the holder answer a method
    /// it never declared — which is exactly upstream's behaviour, since `_find_instance` still
    /// applies the override check to the chained takeover protocol.
    #[test]
    fn takeover_reorders_per_method_selection_without_widening_it() {
        let relayer: Relayer<str> = Relayer::new(vec![Protocol::Mrp, Protocol::AirPlay]);
        relayer.register(
            Protocol::Mrp,
            Arc::from("mrp"),
            declaring(&[FeatureName::Stop, FeatureName::Up]),
        );
        relayer.register(
            Protocol::AirPlay,
            Arc::from("airplay"),
            declaring(&[FeatureName::Stop]),
        );

        relayer.takeover(Protocol::AirPlay).expect("free relayer");

        assert_eq!(
            relayer.instance_for(FeatureName::Stop).as_deref(),
            Some("airplay")
        );
        assert_eq!(
            relayer.instance_for(FeatureName::Up).as_deref(),
            Some("mrp"),
            "AirPlay holds the takeover but does not implement up()"
        );
    }

    /// `instances` yields everything, in priority order (`relayer.py:73-76`).
    #[test]
    fn instances_are_returned_in_priority_order() {
        let relayer = sample();
        let names: Vec<_> = relayer
            .instances()
            .into_iter()
            .map(|instance| instance.to_string())
            .collect();
        assert_eq!(names, vec!["mrp".to_owned(), "dmap".to_owned()]);
    }
}
