//! What DMAP contributes to [`pyatv_core::facade::FacadeAppleTV`].
//!
//! Port of `pyatv/protocols/dmap/__init__.py`'s interface half: the three static feature groups,
//! `DmapFeatures`, and [`setup`], this crate's equivalent of upstream's `setup()` generator
//! (`__init__.py:660-712`).
//!
//! DMAP contributes five capabilities and no more: remote control, metadata, push updates,
//! features and audio. There is no power interface, no apps, no keyboard, no gestures and no
//! streaming — gen 1-3 hardware has none of those, and neither does upstream's `interfaces` dict
//! (`__init__.py:676-682`).

pub mod audio;
pub mod features;
pub mod metadata;
pub mod remote;
pub mod updates;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use pyatv_core::facade::SetupData;
use pyatv_core::interface::{BoxFuture, DeviceListener, ProtocolHandle, PushUpdater};
use pyatv_core::{
    BaseService, DeviceInfo, DeviceModel, FeatureName, OperatingSystem, Protocol,
    Result as CoreResult,
};

use crate::Result;
use crate::client::BaseDmapAppleTV;
use crate::daap::DaapRequester;

pub use audio::DmapAudio;
pub use features::{AVAILABLE_FEATURES, DmapFeatures, FIELD_FEATURES, UNKNOWN_FEATURES};
pub use metadata::DmapMetadata;
pub use remote::DmapRemoteControl;
pub use updates::DmapPushUpdater;

/// The three DNS-SD service types DMAP is discovered under (`scan()`, `__init__.py:621-627`).
///
/// Already ported on the discovery side as `pyatv_mdns::scan::handlers::dmap`; repeated here
/// because `_device_info` re-applies the same per-service-type extraction after connecting
/// (`__init__.py:696-704`) and this crate cannot depend on `pyatv-mdns`.
pub const SERVICE_TYPES: [&str; 3] = [
    "_appletv-v2._tcp.local",
    "_touch-able._tcp.local",
    "_hscp._tcp.local",
];

/// The service type that identifies a Music/iTunes desktop app rather than an Apple TV.
pub const HSCP_SERVICE_TYPE: &str = "_hscp._tcp.local";

/// Everything [`setup`] needs.
#[derive(Debug, Clone)]
pub struct DmapSetupOptions {
    /// Where to send requests. The port is the service's SRV port, never a hardcoded 3689.
    pub peer: SocketAddr,
    /// The service being connected, for its credentials.
    pub service: BaseService,
    /// `core.config.identifier`, which [`DmapMetadata`] reports as its `device_id`.
    pub identifier: Option<String>,
    /// Which of [`SERVICE_TYPES`] the scan saw TXT records for, for [`device_facts`].
    pub service_types: Vec<String>,
    /// Notified if the push loop's connection drops.
    pub listener: Option<Arc<dyn DeviceListener>>,
}

/// The teardown hook the facade awaits on close.
///
/// `_close` (`__init__.py:691-694`) stops the push updater and reports `connection_closed()`. The
/// second half is the facade's job here — it owns the listener hub — so this only does the first.
#[derive(Debug)]
pub struct DmapHandle {
    push_updater: Arc<DmapPushUpdater>,
}

impl ProtocolHandle for DmapHandle {
    fn close(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.push_updater.stop();
            Ok(())
        })
    }
}

/// Every feature DMAP has an opinion about (`__init__.py:706-712`).
///
/// The union of the volume buttons, the always-available navigation keys, the always-unknown
/// transport commands, and every field-gated metadata feature. Membership here is what tells the
/// facade's relayer that DMAP is a candidate at all — even for the ones whose opinion is only
/// "unknown".
#[must_use]
pub fn supported_features() -> BTreeSet<FeatureName> {
    [FeatureName::VolumeDown, FeatureName::VolumeUp]
        .into_iter()
        .chain(AVAILABLE_FEATURES)
        .chain(UNKNOWN_FEATURES)
        .chain(FIELD_FEATURES.iter().map(|(feature, _)| *feature))
        .collect()
}

/// What DMAP's own service types say about the hardware.
///
/// `device_info` (`__init__.py:630-640`) merged across every DMAP service type present
/// (`_device_info`, `__init__.py:696-704`). It is deliberately thin: the operating system is
/// always [`OperatingSystem::Legacy`] — upstream's own comment calls this "border line OK, but will
/// do for now" — and only `_hscp._tcp.local` narrows the model, to Music (iTunes on a desktop, not
/// an Apple TV at all).
#[must_use]
pub fn device_facts(service_types: &[String]) -> DeviceInfo {
    let present: Vec<&str> = SERVICE_TYPES
        .into_iter()
        .filter(|candidate| service_types.iter().any(|it| it == candidate))
        .collect();

    if present.is_empty() {
        return DeviceInfo::default();
    }

    let info = DeviceInfo::default().with_operating_system(OperatingSystem::Legacy);
    if present.contains(&HSCP_SERVICE_TYPE) {
        info.with_model(DeviceModel::Music)
    } else {
        info
    }
}

/// Connect DMAP and describe what it contributes.
///
/// `setup()` with its `_connect` closure already run (`__init__.py:660-712`). The bring-up order is
/// upstream's and both halves matter: `login()` first, then **one immediate `playstatus()`** whose
/// only purpose is to prime the state [`DmapFeatures`] reads — upstream's comment is "Retrieve
/// initial state to have volume control state". Without it every field-gated feature would report
/// `Unavailable` until something else happened to poll.
///
/// # Errors
///
/// Returns [`crate::Error::InvalidCredentials`] if the stored credential is neither a pairing GUID
/// nor a Home Sharing ID, [`crate::Error::Authentication`] if the device refuses it, and
/// [`crate::Error::Io`] if the device is unreachable.
pub async fn setup(options: DmapSetupOptions) -> Result<SetupData> {
    let requester = Arc::new(DaapRequester::new(
        options.peer,
        options.service.credentials.clone().unwrap_or_default(),
    ));
    let apple_tv = Arc::new(BaseDmapAppleTV::new(requester));

    requester_login(&apple_tv).await?;

    let push_updater = Arc::new(DmapPushUpdater::new(
        Arc::clone(&apple_tv),
        options.listener,
    ));

    Ok(SetupData {
        protocol: Some(Protocol::Dmap),
        features: supported_features(),
        features_impl: Some(Arc::new(DmapFeatures::new(Arc::clone(&apple_tv)))),
        handle: Some(Arc::new(DmapHandle {
            push_updater: Arc::clone(&push_updater),
        })),
        remote_control: Some(Arc::new(DmapRemoteControl::new(Arc::clone(&apple_tv)))),
        metadata: Some(Arc::new(DmapMetadata::new(
            options.identifier,
            Arc::clone(&apple_tv),
        ))),
        push_updater: Some(push_updater as Arc<dyn PushUpdater>),
        audio: Some(Arc::new(DmapAudio::new(apple_tv))),
        device_info: device_facts(&options.service_types),
        ..SetupData::default()
    })
}

/// `_connect` (`__init__.py:684-689`): log in, then prime the play status.
async fn requester_login(apple_tv: &Arc<BaseDmapAppleTV>) -> Result<()> {
    apple_tv.requester().login().await?;
    apple_tv.playstatus(false).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AVAILABLE_FEATURES, DeviceModel, FIELD_FEATURES, HSCP_SERVICE_TYPE, OperatingSystem,
        SERVICE_TYPES, UNKNOWN_FEATURES, device_facts, supported_features,
    };
    use pyatv_core::FeatureName;

    /// The exact membership `__init__.py:706-712` builds: the two volume buttons plus the three
    /// groups, which are pairwise disjoint.
    #[test]
    fn the_declared_feature_set_matches_upstream() {
        let declared = supported_features();

        assert_eq!(
            declared.len(),
            2 + AVAILABLE_FEATURES.len() + UNKNOWN_FEATURES.len() + FIELD_FEATURES.len(),
            "the four groups should not overlap"
        );
        for feature in [FeatureName::VolumeUp, FeatureName::VolumeDown] {
            assert!(declared.contains(&feature), "{feature} must be declared");
        }
        for feature in AVAILABLE_FEATURES
            .into_iter()
            .chain(UNKNOWN_FEATURES)
            .chain(FIELD_FEATURES.iter().map(|(feature, _)| *feature))
        {
            assert!(declared.contains(&feature), "{feature} must be declared");
        }
    }

    /// `test_unsupported_features` (`tests/protocols/dmap/test_dmap_functional.py:209-220`): these
    /// are not declared, so the facade never asks DMAP about them.
    #[test]
    fn dmap_declares_nothing_gen_one_to_three_hardware_cannot_do() {
        let declared = supported_features();
        for feature in [
            FeatureName::Home,
            FeatureName::HomeHold,
            FeatureName::Suspend,
            FeatureName::WakeUp,
            FeatureName::PowerState,
            FeatureName::TurnOn,
            FeatureName::TurnOff,
            FeatureName::App,
            FeatureName::PlayUrl,
            FeatureName::StreamFile,
            FeatureName::AppList,
            FeatureName::TextSet,
        ] {
            assert!(
                !declared.contains(&feature),
                "{feature} must not be declared"
            );
        }
    }

    /// `test_basic_device_info` (`test_dmap_functional.py:194-195`): DMAP means legacy tvOS.
    #[test]
    fn any_dmap_service_type_means_a_legacy_operating_system() {
        for service_type in SERVICE_TYPES {
            let info = device_facts(&[service_type.to_owned()]);
            assert_eq!(
                info.operating_system(),
                OperatingSystem::Legacy,
                "{service_type}"
            );
        }
    }

    /// Only `_hscp._tcp.local` narrows the model, and it means desktop Music, not an Apple TV.
    #[test]
    fn only_hscp_identifies_the_music_app() {
        assert_eq!(
            device_facts(&[HSCP_SERVICE_TYPE.to_owned()]).model(),
            DeviceModel::Music
        );
        assert_eq!(
            device_facts(&["_appletv-v2._tcp.local".to_owned()]).model(),
            DeviceModel::Unknown
        );
    }

    /// A config carrying no DMAP TXT records at all contributes nothing, rather than asserting a
    /// legacy OS on no evidence.
    #[test]
    fn no_dmap_service_types_means_no_claims() {
        let info = device_facts(&["_airplay._tcp.local".to_owned()]);
        assert_eq!(info.operating_system(), OperatingSystem::Unknown);
        assert_eq!(info.model(), DeviceModel::Unknown);
    }
}
