//! Priority-based selection of one implementation among several protocols.
//!
//! Direct equivalent of `pyatv/core/relayer.py`. A device commonly exposes the same capability over
//! more than one protocol — for example both MRP and DMAP can report now-playing metadata — and
//! pyatv resolves this with a fixed per-capability priority list rather than by asking the user.
//!
//! Upstream's `Relayer.relay(target)` walks the priority list and picks the first instance that
//! actually defines the named attribute, because Python cannot express "implements only part of an
//! interface" any other way. Rust's trait system makes that check unnecessary: an
//! `Arc<dyn RemoteControl>` provably has every method, so this port selects on registration order
//! alone and leaves per-method fallback to the individual implementations, which return
//! [`crate::Error::NotSupported`] for anything they cannot serve.

use std::collections::HashMap;
use std::sync::Arc;

use crate::consts::Protocol;

/// Selects one registered implementation of `T` by protocol priority.
#[derive(Debug)]
pub struct Relayer<T: ?Sized> {
    priorities: Vec<Protocol>,
    instances: HashMap<Protocol, Arc<T>>,
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
            instances: HashMap::new(),
        }
    }

    /// Register `instance` as the implementation supplied by `protocol`, replacing any previous
    /// registration for that protocol.
    pub fn register(&mut self, protocol: Protocol, instance: Arc<T>) {
        self.instances.insert(protocol, instance);
    }

    /// Every protocol in selection order: the configured priorities first, then any remaining
    /// protocol in [`Protocol::ALL`] order.
    ///
    /// Each protocol is yielded at most once. Naively chaining the two lists would repeat every
    /// prioritised protocol, which is harmless for a `find` but visibly wrong in
    /// [`Relayer::protocols`].
    fn search_order(&self) -> impl Iterator<Item = Protocol> + '_ {
        self.priorities.iter().copied().chain(
            Protocol::ALL
                .into_iter()
                .filter(|protocol| !self.priorities.contains(protocol)),
        )
    }

    /// The highest-priority registered implementation, if any.
    #[must_use]
    pub fn main_instance(&self) -> Option<&Arc<T>> {
        self.search_order()
            .find_map(|protocol| self.instances.get(&protocol))
    }

    /// The protocol backing [`Relayer::main_instance`].
    #[must_use]
    pub fn main_protocol(&self) -> Option<Protocol> {
        self.search_order()
            .find(|protocol| self.instances.contains_key(protocol))
    }

    /// The implementation registered by a specific protocol.
    #[must_use]
    pub fn get(&self, protocol: Protocol) -> Option<&Arc<T>> {
        self.instances.get(&protocol)
    }

    /// Every protocol that registered an implementation, in priority order.
    #[must_use]
    pub fn protocols(&self) -> Vec<Protocol> {
        self.search_order()
            .filter(|protocol| self.instances.contains_key(protocol))
            .collect()
    }

    /// Number of registered implementations.
    #[must_use]
    pub fn count(&self) -> usize {
        self.instances.len()
    }

    /// Whether nothing has been registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::Relayer;
    use crate::consts::Protocol;

    fn sample() -> Relayer<str> {
        let mut relayer: Relayer<str> = Relayer::new(vec![Protocol::Mrp, Protocol::Dmap]);
        // Registered in reverse priority order on purpose: selection must not depend on it.
        relayer.register(Protocol::Dmap, Arc::from("dmap"));
        relayer.register(Protocol::Mrp, Arc::from("mrp"));
        relayer
    }

    #[test]
    fn main_instance_follows_priority_not_registration_order() {
        let relayer = sample();
        assert_eq!(relayer.main_instance().map(AsRef::as_ref), Some("mrp"));
        assert_eq!(relayer.main_protocol(), Some(Protocol::Mrp));
        assert_eq!(relayer.count(), 2);
    }

    #[test]
    fn unlisted_protocols_sort_after_listed_ones() {
        let mut relayer: Relayer<str> = Relayer::new(vec![Protocol::Mrp]);
        relayer.register(Protocol::Companion, Arc::from("companion"));
        assert_eq!(relayer.main_protocol(), Some(Protocol::Companion));

        relayer.register(Protocol::Mrp, Arc::from("mrp"));
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
}
