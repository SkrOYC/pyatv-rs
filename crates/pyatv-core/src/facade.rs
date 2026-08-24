//! The facade that presents many protocol connections as one device.
//!
//! Equivalent to `pyatv/core/facade.py`. Each protocol crate's `setup()` produces a [`SetupData`]
//! describing which capability traits it can serve and which features it declares support for;
//! [`FacadeAppleTV::add_protocol`] files each handle into the matching
//! [`crate::relayer::Relayer`], and the assembled facade is what `pyatv::connect` hands back.
//!
//! See `docs/research/pyatv-architecture.md` §3 for the upstream `SetupData` contract and §6 for
//! the per-capability priority ordering reproduced in [`FacadeAppleTV::new`].

pub mod features;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, Weak};

use crate::Result;
use crate::consts::PowerState;
use crate::consts::Protocol;
use crate::features::FeatureName;
use crate::interface::{
    AppleTV, Apps, Audio, BoxFuture, DeviceListener, Features, Keyboard, Metadata, Power,
    PowerListener, ProtocolHandle, PushUpdater, RemoteControl, Stream, TouchGestures, UserAccounts,
};
use crate::models::{BaseService, DeviceInfo};
use crate::relayer::Relayer;

pub use features::FacadeFeatures;

/// The order every capability but [`Power`] resolves in.
///
/// `DEFAULT_PRIORITIES` verbatim (`pyatv/core/facade.py:37-43`). Upstream uses this one list for
/// remote control, metadata, push updates, streaming, apps, audio, keyboard, gestures and
/// accounts alike; only [`FacadeAppleTV`]'s power relayer overrides it.
pub const DEFAULT_PRIORITIES: [Protocol; 5] = [
    Protocol::Mrp,
    Protocol::Dmap,
    Protocol::Companion,
    Protocol::AirPlay,
    Protocol::Raop,
];

/// Power resolution order, preferring Companion.
///
/// `FacadePower.OVERRIDE_PRIORITIES` (`pyatv/core/facade.py:311-318`), whose own comment reads
/// "Generally favor Companion as it implements power better than MRP".
pub const POWER_PRIORITIES: [Protocol; 5] = [
    Protocol::Companion,
    Protocol::Mrp,
    Protocol::Dmap,
    Protocol::AirPlay,
    Protocol::Raop,
];

/// What one protocol contributes to the facade once it has connected.
///
/// Every capability handle is optional: DMAP has no [`Apps`], RAOP has no [`RemoteControl`], and so
/// on. `features` is the set the protocol declares it *could* serve; live availability is resolved
/// by asking `features_impl` at call time.
#[derive(Debug, Default)]
pub struct SetupData {
    /// Which protocol produced this data.
    pub protocol: Option<Protocol>,
    /// Features this protocol declares support for.
    pub features: BTreeSet<FeatureName>,
    /// The protocol's own live feature reporting, consulted for anything in `features`.
    pub features_impl: Option<Arc<dyn Features>>,
    /// Teardown hook, awaited by [`AppleTV::close`].
    pub handle: Option<Arc<dyn ProtocolHandle>>,
    /// Navigation and transport control, if implemented.
    pub remote_control: Option<Arc<dyn RemoteControl>>,
    /// Now-playing metadata, if implemented.
    pub metadata: Option<Arc<dyn Metadata>>,
    /// Push updates, if implemented.
    pub push_updater: Option<Arc<dyn PushUpdater>>,
    /// Media streaming, if implemented.
    pub stream: Option<Arc<dyn Stream>>,
    /// Power control, if implemented.
    pub power: Option<Arc<dyn Power>>,
    /// App management, if implemented.
    pub apps: Option<Arc<dyn Apps>>,
    /// Volume control, if implemented.
    pub audio: Option<Arc<dyn Audio>>,
    /// Keyboard entry, if implemented.
    pub keyboard: Option<Arc<dyn Keyboard>>,
    /// Trackpad gestures, if implemented.
    pub touch_gestures: Option<Arc<dyn TouchGestures>>,
    /// Account switching, if implemented.
    pub user_accounts: Option<Arc<dyn UserAccounts>>,
    /// Device facts this protocol was able to determine.
    pub device_info: DeviceInfo,
}

/// The listener registry a facade shares with the protocol connections reporting to it.
///
/// This is deliberately a separate, `Arc`-able object rather than a field on [`FacadeAppleTV`]: a
/// protocol's `setup()` needs somewhere to report a dropped connection to, and it needs it *before*
/// the facade has finished being assembled. `FacadeAppleTV` itself cannot be shared at that point
/// — `add_protocol` takes `&mut self` — so the hub is created first, handed to every protocol, and
/// kept by the facade afterwards.
///
/// Both lists hold [`Weak`] references, so a caller that drops its listener unregisters it and
/// cannot leak it into the facade's lifetime. Upstream's `StateProducer` also holds listeners
/// weakly, and also has exactly one slot per interface; a list is used here because replacing a
/// previous caller's listener without telling them is not worth reproducing.
#[derive(Debug, Default)]
pub struct ListenerHub {
    devices: Mutex<Vec<Weak<dyn DeviceListener>>>,
    power: Mutex<Vec<Weak<dyn PowerListener>>>,
}

impl ListenerHub {
    /// Register a connection listener.
    pub fn add_listener(&self, listener: &Arc<dyn DeviceListener>) {
        if let Ok(mut listeners) = self.devices.lock() {
            listeners.push(Arc::downgrade(listener));
        }
    }

    /// Register a power-state listener.
    pub fn add_power_listener(&self, listener: &Arc<dyn PowerListener>) {
        if let Ok(mut listeners) = self.power.lock() {
            listeners.push(Arc::downgrade(listener));
        }
    }
}

impl DeviceListener for ListenerHub {
    fn connection_lost(&self, reason: &str) {
        tracing::debug!(reason, "a protocol connection was lost");
        if let Ok(listeners) = self.devices.lock() {
            for listener in listeners.iter().filter_map(Weak::upgrade) {
                listener.connection_lost(reason);
            }
        }
    }

    fn connection_closed(&self) {
        if let Ok(listeners) = self.devices.lock() {
            for listener in listeners.iter().filter_map(Weak::upgrade) {
                listener.connection_closed();
            }
        }
    }
}

impl PowerListener for ListenerHub {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        tracing::debug!(?old_state, ?new_state, "the device power state changed");
        if let Ok(listeners) = self.power.lock() {
            for listener in listeners.iter().filter_map(Weak::upgrade) {
                listener.power_state_changed(old_state, new_state);
            }
        }
    }
}

/// Unified view of one device across every connected protocol.
#[derive(Debug)]
pub struct FacadeAppleTV {
    remote_control: Relayer<dyn RemoteControl>,
    metadata: Relayer<dyn Metadata>,
    push_updater: Relayer<dyn PushUpdater>,
    stream: Relayer<dyn Stream>,
    power: Relayer<dyn Power>,
    apps: Relayer<dyn Apps>,
    audio: Relayer<dyn Audio>,
    keyboard: Relayer<dyn Keyboard>,
    touch_gestures: Relayer<dyn TouchGestures>,
    user_accounts: Relayer<dyn UserAccounts>,
    features: Arc<FacadeFeatures>,
    handles: Vec<(Protocol, Arc<dyn ProtocolHandle>)>,
    listeners: Arc<ListenerHub>,
    device_info: DeviceInfo,
    service: BaseService,
}

impl FacadeAppleTV {
    /// Build an empty facade for `service`, with pyatv's per-capability priority ordering.
    #[must_use]
    pub fn new(service: BaseService) -> Self {
        fn default<T: ?Sized>() -> Relayer<T> {
            Relayer::new(DEFAULT_PRIORITIES.to_vec())
        }

        Self {
            remote_control: default(),
            metadata: default(),
            push_updater: default(),
            stream: default(),
            power: Relayer::new(POWER_PRIORITIES.to_vec()),
            apps: default(),
            audio: default(),
            keyboard: default(),
            touch_gestures: default(),
            user_accounts: default(),
            features: Arc::new(FacadeFeatures::default()),
            handles: Vec::new(),
            listeners: Arc::new(ListenerHub::default()),
            device_info: DeviceInfo::default(),
            service,
        }
    }

    /// File one connected protocol's capability handles into the relayers.
    ///
    /// Called once per protocol by `pyatv::connect` after that protocol's own `connect()` reported
    /// success, mirroring the body of `FacadeAppleTV.connect`'s setup loop
    /// (`pyatv/core/facade.py:753-774`). Protocols with nothing to contribute are skipped.
    pub fn add_protocol(&mut self, data: SetupData) {
        let Some(protocol) = data.protocol else {
            return;
        };

        macro_rules! register {
            ($field:ident) => {
                if let Some(instance) = data.$field {
                    self.$field.register(protocol, instance);
                }
            };
        }

        let has_push_updater = data.push_updater.is_some();

        register!(remote_control);
        register!(metadata);
        register!(push_updater);
        register!(stream);
        register!(power);
        register!(apps);
        register!(audio);
        register!(keyboard);
        register!(touch_gestures);
        register!(user_accounts);

        if let Some(features) = data.features_impl {
            // `add_mapping` (`facade.py:274-284`): a feature is owned by the highest-priority
            // protocol that declared it, and later registrations only win if they outrank the
            // incumbent.
            self.features
                .add_mapping(protocol, &data.features, &features);
        }
        if has_push_updater {
            self.features.set_push_updates(true);
        }

        if let Some(handle) = data.handle {
            self.handles.push((protocol, handle));
        }

        // `dict_merge(devinfo, setup_data.device_info())` (`facade.py:772`): a key already set by
        // a higher-priority protocol is never overwritten, since protocols are added in priority
        // order by `pyatv::connect`.
        self.device_info.merge_from(&data.device_info);
    }

    /// The registry to hand a protocol's `setup()` so its connection reports here.
    ///
    /// Taken before any protocol is set up — see [`ListenerHub`] for why it has to be a separate
    /// object — and handed to each of them, so a protocol that drops its socket reaches every
    /// listener the caller registers later.
    #[must_use]
    pub fn listener_hub(&self) -> Arc<ListenerHub> {
        Arc::clone(&self.listeners)
    }

    /// Every protocol that contributed at least one capability.
    #[must_use]
    pub fn connected_protocols(&self) -> BTreeSet<Protocol> {
        let mut protocols = BTreeSet::new();
        protocols.extend(self.remote_control.protocols());
        protocols.extend(self.metadata.protocols());
        protocols.extend(self.push_updater.protocols());
        protocols.extend(self.stream.protocols());
        protocols.extend(self.power.protocols());
        protocols.extend(self.apps.protocols());
        protocols.extend(self.audio.protocols());
        protocols.extend(self.keyboard.protocols());
        protocols.extend(self.touch_gestures.protocols());
        protocols.extend(self.user_accounts.protocols());
        protocols.extend(self.handles.iter().map(|(protocol, _)| *protocol));
        protocols
    }

    /// Whether any protocol registered anything at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.handles.is_empty() && self.connected_protocols().is_empty()
    }

    /// Replace the merged device facts, for callers that know more than the protocols did.
    pub fn set_device_info(&mut self, device_info: DeviceInfo) {
        self.device_info = device_info;
    }
}

impl DeviceListener for FacadeAppleTV {
    /// Fan a protocol's connection loss out to every registered listener.
    fn connection_lost(&self, reason: &str) {
        self.listeners.connection_lost(reason);
    }

    fn connection_closed(&self) {
        self.listeners.connection_closed();
    }
}

impl AppleTV for FacadeAppleTV {
    fn remote_control(&self) -> Option<Arc<dyn RemoteControl>> {
        self.remote_control.main_instance().cloned()
    }

    fn metadata(&self) -> Option<Arc<dyn Metadata>> {
        self.metadata.main_instance().cloned()
    }

    fn push_updater(&self) -> Option<Arc<dyn PushUpdater>> {
        self.push_updater.main_instance().cloned()
    }

    fn stream(&self) -> Option<Arc<dyn Stream>> {
        self.stream.main_instance().cloned()
    }

    fn power(&self) -> Option<Arc<dyn Power>> {
        self.power.main_instance().cloned()
    }

    fn apps(&self) -> Option<Arc<dyn Apps>> {
        self.apps.main_instance().cloned()
    }

    fn audio(&self) -> Option<Arc<dyn Audio>> {
        self.audio.main_instance().cloned()
    }

    fn keyboard(&self) -> Option<Arc<dyn Keyboard>> {
        self.keyboard.main_instance().cloned()
    }

    fn touch_gestures(&self) -> Option<Arc<dyn TouchGestures>> {
        self.touch_gestures.main_instance().cloned()
    }

    fn user_accounts(&self) -> Option<Arc<dyn UserAccounts>> {
        self.user_accounts.main_instance().cloned()
    }

    fn features(&self) -> Arc<dyn Features> {
        Arc::clone(&self.features) as Arc<dyn Features>
    }

    fn device_info(&self) -> &DeviceInfo {
        &self.device_info
    }

    fn service(&self) -> &BaseService {
        &self.service
    }

    fn add_listener(&self, listener: &Arc<dyn DeviceListener>) {
        self.listeners.add_listener(listener);
    }

    fn add_power_listener(&self, listener: &Arc<dyn PowerListener>) {
        self.listeners.add_power_listener(listener);
    }

    /// Close every protocol in turn.
    ///
    /// Upstream collects a task per protocol and lets the caller await them all
    /// (`facade.py:785-802`). Here they are awaited sequentially and a failure is logged rather
    /// than returned, because one protocol refusing to shut down cleanly must not leave the others
    /// connected. The first error is still reported so a caller can notice.
    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if let Some(push_updater) = self.push_updater.main_instance() {
                push_updater.stop();
            }

            let mut first_error = None;
            for (protocol, handle) in &self.handles {
                if let Err(error) = handle.close().await {
                    tracing::debug!(?protocol, %error, "a protocol did not close cleanly");
                    first_error.get_or_insert(error);
                }
            }

            self.connection_closed();
            first_error.map_or(Ok(()), Err)
        })
    }
}

#[cfg(test)]
mod tests {
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
    }
}
