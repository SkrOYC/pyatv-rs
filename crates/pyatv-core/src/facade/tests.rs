//! Assembly tests for [`super::FacadeAppleTV`] itself, split out of `facade.rs` for module-size
//! discipline. The per-interface relaying wrappers each carry their own tests alongside them.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::{FacadeAppleTV, Interface, SetupData, StateDispatcher};
use crate::consts::{KeyboardFocusState, PowerState, Protocol};
use crate::features::{FeatureInfo, FeatureName, FeatureState};
use crate::interface::{
    AppleTV, BoxFuture, Features, Keyboard, KeyboardListener, Power, PowerListener,
};
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

/// A keyboard registered only so the relayer has something to select; no method of it is called.
#[derive(Debug)]
struct SilentKeyboard;

impl Keyboard for SilentKeyboard {
    fn text_focus_state(&self) -> KeyboardFocusState {
        KeyboardFocusState::Unknown
    }

    fn text_get(&self) -> BoxFuture<'_, crate::Result<Option<String>>> {
        Box::pin(async { Ok(None) })
    }

    fn text_set(&self, _text: &str) -> BoxFuture<'_, crate::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn text_append(&self, _text: &str) -> BoxFuture<'_, crate::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn text_clear(&self) -> BoxFuture<'_, crate::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// The same for [`Power`].
#[derive(Debug)]
struct SilentPower;

impl Power for SilentPower {
    fn power_state(&self) -> PowerState {
        PowerState::Unknown
    }

    fn turn_on(&self, _await_new_state: bool) -> BoxFuture<'_, crate::Result<()>> {
        Box::pin(async { Ok(()) })
    }

    fn turn_off(&self, _await_new_state: bool) -> BoxFuture<'_, crate::Result<()>> {
        Box::pin(async { Ok(()) })
    }
}

/// Records what the facade's listener hub decided to forward.
#[derive(Debug, Default)]
struct Recorder {
    focus: Mutex<Vec<KeyboardFocusState>>,
    power: Mutex<Vec<PowerState>>,
}

impl Recorder {
    fn focus(&self) -> Vec<KeyboardFocusState> {
        self.focus.lock().expect("uncontended").clone()
    }

    fn power(&self) -> Vec<PowerState> {
        self.power.lock().expect("uncontended").clone()
    }
}

impl KeyboardListener for Recorder {
    fn focusstate_update(&self, _old_state: KeyboardFocusState, new_state: KeyboardFocusState) {
        self.focus.lock().expect("uncontended").push(new_state);
    }
}

impl PowerListener for Recorder {
    fn power_state_changed(&self, _old_state: PowerState, new_state: PowerState) {
        self.power.lock().expect("uncontended").push(new_state);
    }
}

fn keyboard_data(protocol: Protocol) -> SetupData {
    SetupData {
        protocol: Some(protocol),
        keyboard: Some(Arc::new(SilentKeyboard)),
        ..SetupData::default()
    }
}

fn power_data(protocol: Protocol) -> SetupData {
    SetupData {
        protocol: Some(protocol),
        power: Some(Arc::new(SilentPower)),
        ..SetupData::default()
    }
}

fn with_recorder(facade: &FacadeAppleTV) -> Arc<Recorder> {
    let recorder = Arc::new(Recorder::default());
    facade.add_keyboard_listener(&(Arc::clone(&recorder) as Arc<dyn KeyboardListener>));
    facade.add_power_listener(&(Arc::clone(&recorder) as Arc<dyn PowerListener>));
    recorder
}

/// The keyboard filter is `message.protocol == self.main_protocol` evaluated *per message*
/// (`facade.py:557`), so claiming and releasing the keyboard relayer changes which protocol is
/// heard. Snapshotting the main protocol at registration time — as this used to — left the
/// incumbent heard for the whole session, and a takeover's own focus updates silently discarded.
#[test]
fn a_keyboard_takeover_changes_which_protocol_is_heard() {
    let mut facade = facade();
    facade.add_protocol(keyboard_data(Protocol::Mrp));
    facade.add_protocol(keyboard_data(Protocol::Companion));
    let recorder = with_recorder(&facade);
    let hub = facade.listener_hub();

    // MRP outranks Companion in `DEFAULT_PRIORITIES`, so it is the main protocol.
    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Focused);
    assert!(recorder.focus().is_empty(), "Companion is not the main one");
    hub.keyboard_focus_updated(Protocol::Mrp, KeyboardFocusState::Focused);
    assert_eq!(recorder.focus(), vec![KeyboardFocusState::Focused]);

    let guard = facade
        .takeover(Protocol::Companion, &[Interface::Keyboard])
        .expect("the keyboard relayer is unclaimed");

    hub.keyboard_focus_updated(Protocol::Mrp, KeyboardFocusState::Unfocused);
    assert_eq!(
        recorder.focus().len(),
        1,
        "MRP stopped being the main protocol the moment Companion took over"
    );
    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Unfocused);
    assert_eq!(
        recorder.focus(),
        vec![KeyboardFocusState::Focused, KeyboardFocusState::Unfocused],
        "and Companion's updates are now the ones that pass"
    );

    drop(guard);
    hub.keyboard_focus_updated(Protocol::Companion, KeyboardFocusState::Focused);
    assert_eq!(
        recorder.focus().len(),
        2,
        "releasing hands MRP back the lead"
    );
    hub.keyboard_focus_updated(Protocol::Mrp, KeyboardFocusState::Focused);
    assert_eq!(recorder.focus().len(), 3);
}

/// Every protocol is handed a [`PowerListener`] and every one of them reports the same device, but
/// upstream subscribes only the main `Power` instance (`facade.py:777-781`). Without the filter a
/// device connected over both MRP and Companion emitted two callbacks per transition.
#[test]
fn one_power_transition_reaches_the_listener_once() {
    let mut facade = facade();
    facade.add_protocol(power_data(Protocol::Mrp));
    facade.add_protocol(power_data(Protocol::Companion));
    let recorder = with_recorder(&facade);

    let hub = facade.listener_hub();
    let from_mrp = hub.power_listener(Protocol::Mrp);
    let from_companion = hub.power_listener(Protocol::Companion);

    // `POWER_PRIORITIES` puts Companion first, so MRP's report is the one dropped.
    from_mrp.power_state_changed(PowerState::Off, PowerState::On);
    from_companion.power_state_changed(PowerState::Off, PowerState::On);
    assert_eq!(
        recorder.power(),
        vec![PowerState::On],
        "both protocols reported the same wake-up; the caller hears it once"
    );

    let guard = facade
        .takeover(Protocol::Mrp, &[Interface::Power])
        .expect("the power relayer is unclaimed");

    from_companion.power_state_changed(PowerState::On, PowerState::Off);
    from_mrp.power_state_changed(PowerState::On, PowerState::Off);
    assert_eq!(
        recorder.power(),
        vec![PowerState::On, PowerState::Off],
        "a takeover moves which protocol is believed, and still only one gets through"
    );
    drop(guard);
}
