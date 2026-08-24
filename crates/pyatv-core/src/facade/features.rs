//! Feature reporting across every connected protocol.
//!
//! Port of `FacadeFeatures` (`pyatv/core/facade.py:261-302`). Each protocol declares the set of
//! [`FeatureName`]s it *could* serve when it registers; the facade keeps a map from feature to the
//! highest-priority protocol that declared it, and forwards [`Features::get_feature`] there so the
//! answer reflects live device state rather than the static declaration.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, PoisonError, RwLock};

use crate::consts::Protocol;
use crate::features::{FeatureInfo, FeatureName, FeatureState};
use crate::interface::Features;

use super::DEFAULT_PRIORITIES;

/// Feature reporting for the assembled facade.
///
/// # Why the lock
///
/// [`super::FacadeAppleTV`] hands this out as an `Arc<dyn Features>` from `features()`, which takes
/// `&self`, and registers protocols into it from `add_protocol`, which takes `&mut self`. Reaching
/// through the `Arc` with `Arc::get_mut` looks like it should work — and it did, right up until a
/// caller held on to a handle from an earlier `features()` call, at which point `get_mut` returned
/// `None` and the whole registration was **silently discarded**, leaving that protocol's features
/// permanently `Unsupported`. Owning the mutability here instead removes the failure mode rather
/// than papering over it, and has the better property besides: a handle taken before a protocol
/// connected sees that protocol's features afterwards.
#[derive(Debug, Default)]
pub struct FacadeFeatures {
    state: RwLock<State>,
}

/// The registry itself, behind [`FacadeFeatures`]'s lock.
#[derive(Debug, Default)]
struct State {
    owners: HashMap<FeatureName, (Protocol, Arc<dyn Features>)>,
    /// Set when at least one protocol registered a push updater, which is how upstream answers
    /// [`FeatureName::PushUpdates`] without asking any protocol (`facade.py:289-295`).
    push_updates: bool,
}

impl FacadeFeatures {
    /// Record that `protocol` serves `features`, resolving ties by priority.
    ///
    /// `add_mapping` (`facade.py:274-284`): a feature already claimed by a higher-priority
    /// protocol keeps its owner, so registration order does not matter.
    pub fn add_mapping(
        &self,
        protocol: Protocol,
        features: &BTreeSet<FeatureName>,
        instance: &Arc<dyn Features>,
    ) {
        let mut state = self.write();
        for feature in features {
            let replace = match state.owners.get(feature) {
                None => true,
                Some((incumbent, _)) => has_higher_priority(protocol, *incumbent),
            };
            if replace {
                state
                    .owners
                    .insert(*feature, (protocol, Arc::clone(instance)));
            }
        }
    }

    /// Record that some protocol can push now-playing updates.
    pub fn set_push_updates(&self, available: bool) {
        self.write().push_updates = available;
    }

    /// The protocol that answers for a feature, if any protocol declared it.
    #[must_use]
    pub fn owner(&self, feature: FeatureName) -> Option<Protocol> {
        self.read()
            .owners
            .get(&feature)
            .map(|(protocol, _)| *protocol)
    }

    /// A poisoned lock hands back what the panicking writer left behind rather than failing:
    /// reporting "features are unreadable" would be strictly worse than reporting a registry that
    /// is missing one protocol's mappings.
    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, State> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `_has_higher_priority` (`facade.py:300-302`), with the one difference that a protocol missing
/// from [`DEFAULT_PRIORITIES`] sorts last instead of raising: upstream's `list.index` would throw,
/// and the list covers every [`Protocol`] variant today, so the branch is unreachable in practice.
fn has_higher_priority(first: Protocol, second: Protocol) -> bool {
    let rank = |protocol| {
        DEFAULT_PRIORITIES
            .iter()
            .position(|candidate| *candidate == protocol)
            .unwrap_or(usize::MAX)
    };
    rank(first) < rank(second)
}

impl Features for FacadeFeatures {
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        // The owning protocol is cloned out and the guard dropped before asking it, so a protocol
        // whose own `get_feature` reaches back into the facade cannot deadlock against this lock.
        let owner = {
            let state = self.read();
            if feature == FeatureName::PushUpdates && state.push_updates {
                return FeatureInfo::available();
            }
            state
                .owners
                .get(&feature)
                .map(|(_, instance)| Arc::clone(instance))
        };

        owner.map_or_else(FeatureInfo::unsupported, |instance| {
            instance.get_feature(feature)
        })
    }

    /// Every feature, filtered to the supported ones unless `include_unsupported` is set.
    ///
    /// `Features.all_features` (`pyatv/interface.py:1088-1095`) walks the whole enum rather than
    /// only the registered features, so a protocol that reports `Unavailable` for something it
    /// declared still appears in the list.
    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        FeatureName::ALL
            .into_iter()
            .map(|feature| (feature, self.get_feature(feature)))
            .filter(|(_, info)| include_unsupported || info.state != FeatureState::Unsupported)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::FacadeFeatures;
    use crate::consts::Protocol;
    use crate::features::{FeatureInfo, FeatureName, FeatureState};
    use crate::interface::Features;

    /// A protocol that answers with one fixed state, so the test can see which one was consulted.
    #[derive(Debug)]
    struct Fixed(FeatureState);

    impl Features for Fixed {
        fn get_feature(&self, _feature: FeatureName) -> FeatureInfo {
            FeatureInfo {
                state: self.0,
                reason: None,
            }
        }

        fn all_features(&self, _include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
            Vec::new()
        }
    }

    fn declare(features: [FeatureName; 1]) -> BTreeSet<FeatureName> {
        features.into_iter().collect()
    }

    #[test]
    fn the_highest_priority_protocol_answers_for_a_shared_feature() {
        let facade = FacadeFeatures::default();
        // Registered lowest-priority first on purpose.
        facade.add_mapping(
            Protocol::Companion,
            &declare([FeatureName::Play]),
            &(Arc::new(Fixed(FeatureState::Unavailable)) as Arc<dyn Features>),
        );
        facade.add_mapping(
            Protocol::Mrp,
            &declare([FeatureName::Play]),
            &(Arc::new(Fixed(FeatureState::Available)) as Arc<dyn Features>),
        );

        assert_eq!(facade.owner(FeatureName::Play), Some(Protocol::Mrp));
        assert_eq!(
            facade.get_feature(FeatureName::Play).state,
            FeatureState::Available
        );
    }

    #[test]
    fn a_lower_priority_protocol_never_displaces_the_incumbent() {
        let facade = FacadeFeatures::default();
        facade.add_mapping(
            Protocol::Mrp,
            &declare([FeatureName::Play]),
            &(Arc::new(Fixed(FeatureState::Available)) as Arc<dyn Features>),
        );
        facade.add_mapping(
            Protocol::Raop,
            &declare([FeatureName::Play]),
            &(Arc::new(Fixed(FeatureState::Unavailable)) as Arc<dyn Features>),
        );

        assert_eq!(facade.owner(FeatureName::Play), Some(Protocol::Mrp));
    }

    #[test]
    fn an_undeclared_feature_is_unsupported() {
        let facade = FacadeFeatures::default();
        assert_eq!(
            facade.get_feature(FeatureName::PlayUrl).state,
            FeatureState::Unsupported
        );
        assert!(facade.all_features(false).is_empty());
        assert_eq!(facade.all_features(true).len(), FeatureName::COUNT);
    }

    #[test]
    fn push_updates_is_available_when_any_protocol_registered_an_updater() {
        let facade = FacadeFeatures::default();
        assert_eq!(
            facade.get_feature(FeatureName::PushUpdates).state,
            FeatureState::Unsupported
        );
        facade.set_push_updates(true);
        assert_eq!(
            facade.get_feature(FeatureName::PushUpdates).state,
            FeatureState::Available
        );
    }

    #[test]
    fn unsupported_features_are_filtered_out_unless_requested() {
        let facade = FacadeFeatures::default();
        facade.add_mapping(
            Protocol::Companion,
            &declare([FeatureName::AppList]),
            &(Arc::new(Fixed(FeatureState::Available)) as Arc<dyn Features>),
        );

        let visible = facade.all_features(false);
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].0, FeatureName::AppList);
        assert_eq!(facade.all_features(true).len(), FeatureName::COUNT);
    }
}
