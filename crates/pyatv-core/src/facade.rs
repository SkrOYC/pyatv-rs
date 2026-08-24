//! The facade that presents many protocol connections as one device.
//!
//! Equivalent to `pyatv/core/facade.py`. Each protocol crate's `setup()` produces a [`SetupData`]
//! describing which capability traits it can serve and which features it declares support for;
//! [`FacadeAppleTV::add_protocol`] files each handle into the matching
//! [`crate::relayer::Relayer`], and the assembled facade is what `pyatv::connect` hands back.
//!
//! See `docs/research/pyatv-architecture.md` §3 for the upstream `SetupData` contract and the
//! per-capability priority ordering reproduced in [`FacadeAppleTV::new`].

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use crate::Result;
use crate::consts::Protocol;
use crate::features::{FeatureInfo, FeatureName};
use crate::interface::{
    AppleTV, Apps, Audio, BoxFuture, Features, Keyboard, Metadata, Power, PushUpdater,
    RemoteControl, Stream, TouchGestures, UserAccounts,
};
use crate::models::{BaseService, DeviceInfo};
use crate::relayer::Relayer;

/// What one protocol contributes to the facade once it has connected.
///
/// Every capability handle is optional: DMAP has no [`Apps`], RAOP has no [`RemoteControl`], and so
/// on. `features` is the set the protocol declares it *could* serve; live availability is resolved
/// through [`Features::get_feature`] at call time.
#[derive(Debug, Default)]
pub struct SetupData {
    /// Which protocol produced this data.
    pub protocol: Option<Protocol>,
    /// Features this protocol declares support for.
    pub features: BTreeSet<FeatureName>,
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
    feature_owners: HashMap<FeatureName, Protocol>,
    device_info: DeviceInfo,
    service: BaseService,
}

impl FacadeAppleTV {
    /// Build an empty facade for `service`, with pyatv's per-capability priority ordering.
    ///
    /// The orderings below come from `pyatv/core/facade.py`: MRP leads for anything interactive,
    /// RAOP leads for audio because it owns the stream, and `AirPlay` leads for video streaming.
    #[must_use]
    pub fn new(service: BaseService) -> Self {
        use Protocol::{AirPlay, Companion, Dmap, Mrp, Raop};

        Self {
            remote_control: Relayer::new(vec![Mrp, Dmap, Companion]),
            metadata: Relayer::new(vec![Mrp, Dmap, Raop]),
            push_updater: Relayer::new(vec![Mrp, Dmap]),
            stream: Relayer::new(vec![AirPlay, Raop]),
            power: Relayer::new(vec![Companion, Mrp]),
            apps: Relayer::new(vec![Companion]),
            audio: Relayer::new(vec![Raop, Companion, Mrp]),
            keyboard: Relayer::new(vec![Companion]),
            touch_gestures: Relayer::new(vec![Companion, Mrp]),
            user_accounts: Relayer::new(vec![Companion]),
            feature_owners: HashMap::new(),
            device_info: DeviceInfo::default(),
            service,
        }
    }

    /// File one connected protocol's capability handles into the relayers.
    ///
    /// Called once per protocol by `pyatv::connect` after that protocol's own `connect()` reported
    /// success. Protocols with nothing to contribute are skipped.
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

        for feature in data.features {
            self.feature_owners.entry(feature).or_insert(protocol);
        }

        // TODO(step-1): merge `data.device_info` field-by-field instead of last-writer-wins.
        // pyatv unions every protocol's `DevInfoExtractor` output, preferring the most specific
        // source per field (see docs/research/pyatv-architecture.md §3).
        self.device_info = data.device_info;
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
        protocols
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
        // TODO(step-1): return a `FacadeFeatures` that asks the owning protocol for live
        // availability instead of reporting every declared feature as statically available.
        todo!("FacadeAppleTV::features")
    }

    fn device_info(&self) -> &DeviceInfo {
        &self.device_info
    }

    fn service(&self) -> &BaseService {
        &self.service
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        // TODO(step-1): fan out to every registered protocol's `close()` and join the results.
        Box::pin(async { Ok(()) })
    }
}

/// Static feature reporting driven purely by what each protocol declared at setup time.
///
/// A placeholder for pyatv's `FacadeFeatures`, which additionally consults the owning protocol at
/// call time to distinguish [`crate::features::FeatureState::Available`] from
/// [`crate::features::FeatureState::Unavailable`].
#[derive(Debug, Default)]
pub struct StaticFeatures {
    declared: BTreeSet<FeatureName>,
}

impl StaticFeatures {
    /// Report `declared` as available and everything else as unsupported.
    #[must_use]
    pub fn new(declared: BTreeSet<FeatureName>) -> Self {
        Self { declared }
    }
}

impl Features for StaticFeatures {
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        if self.declared.contains(&feature) {
            FeatureInfo::available()
        } else {
            FeatureInfo::unsupported()
        }
    }

    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        let declared = self
            .declared
            .iter()
            .map(|feature| (*feature, FeatureInfo::available()));

        if include_unsupported {
            // TODO(step-1): enumerate every `FeatureName` variant once the enum stops growing;
            // this needs either a `strum`-style derive or a hand-maintained `ALL` constant.
            declared.collect()
        } else {
            declared.collect()
        }
    }
}
