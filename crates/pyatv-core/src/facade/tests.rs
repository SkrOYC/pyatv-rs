//! Assembly tests for [`super::FacadeAppleTV`] itself, split out of `facade.rs` for module-size
//! discipline. The per-interface relaying wrappers each carry their own tests alongside them.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{FacadeAppleTV, SetupData};
use crate::consts::Protocol;
use crate::features::{FeatureInfo, FeatureName, FeatureState};
use crate::interface::{AppleTV, Features};
use crate::models::BaseService;

/// A protocol whose every feature is available, so the test can see whether it was consulted.
#[derive(Debug)]
struct Available;

impl Features for Available {
    fn get_feature(&self, _feature: FeatureName) -> FeatureInfo {
        FeatureInfo::available()
    }

    fn all_features(&self, _include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        Vec::new()
    }
}

fn setup_data(protocol: Protocol, feature: FeatureName) -> SetupData {
    let mut features = BTreeSet::new();
    features.insert(feature);
    SetupData {
        protocol: Some(protocol),
        features,
        features_impl: Some(Arc::new(Available)),
        ..SetupData::default()
    }
}

fn facade() -> FacadeAppleTV {
    FacadeAppleTV::new(BaseService::new(Protocol::Companion, 49153))
}

/// A feature handle taken before a protocol connects must see that protocol afterwards.
///
/// `add_protocol` used to reach into the registry with `Arc::get_mut`, which returns `None`
/// while any clone of the `Arc` is alive — and `features()` hands out exactly such a clone. A
/// caller that read `atv.features()` once and then connected another protocol therefore had
/// that protocol's entire feature mapping dropped on the floor, silently, with the feature
/// reporting `Unsupported` for the rest of the session.
#[test]
fn features_registered_after_a_handle_was_taken_are_still_visible() {
    let mut facade = facade();
    let handle = facade.features();
    assert_eq!(
        handle.get_feature(FeatureName::AppList).state,
        FeatureState::Unsupported
    );

    facade.add_protocol(setup_data(Protocol::Companion, FeatureName::AppList));

    assert_eq!(
        handle.get_feature(FeatureName::AppList).state,
        FeatureState::Available,
        "the handle taken earlier must see the new mapping"
    );
    assert_eq!(
        facade.features().get_feature(FeatureName::AppList).state,
        FeatureState::Available,
        "and so must a freshly taken one"
    );
}

/// The same for the push-updates flag, which takes the other branch of `add_protocol`.
#[test]
fn a_second_protocol_registers_even_with_handles_outstanding() {
    let mut facade = facade();
    facade.add_protocol(setup_data(Protocol::Companion, FeatureName::AppList));

    let handle = facade.features();
    facade.add_protocol(setup_data(Protocol::Mrp, FeatureName::Title));

    assert_eq!(
        handle.get_feature(FeatureName::Title).state,
        FeatureState::Available
    );
    assert_eq!(
        handle.get_feature(FeatureName::AppList).state,
        FeatureState::Available
    );
}

/// A facade with no protocols reports nothing and holds no handles.
#[test]
fn an_empty_facade_is_empty() {
    let facade = facade();
    assert!(facade.is_empty());
    assert!(facade.connected_protocols().is_empty());
    assert_eq!(
        facade.features().get_feature(FeatureName::AppList).state,
        FeatureState::Unsupported
    );
    assert!(facade.remote_control().is_none());
    assert!(facade.audio().is_none());
    assert!(facade.stream().is_none());
}
