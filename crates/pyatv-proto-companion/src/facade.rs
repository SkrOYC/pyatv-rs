//! What Companion contributes to [`pyatv_core::facade::FacadeAppleTV`].
//!
//! Port of `pyatv/protocols/companion/__init__.py`: the eight capability implementations, the
//! feature set the protocol declares, and [`setup`], which is this crate's equivalent of upstream's
//! `setup()` generator (`__init__.py:663-702`).
//!
//! # The guard clause matters
//!
//! `if not core.service.credentials: return None` (`__init__.py:665-668`). Companion with no
//! credentials is not a protocol that exists and fails on use — it is a protocol that does not
//! exist at all, so nothing is registered and the facade reports every Companion-only capability
//! as absent. [`setup`] reproduces that by returning `Ok(None)`.

pub mod device;
pub mod input;
pub mod remote;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

use pyatv_core::facade::SetupData;
use pyatv_core::interface::{BoxFuture, DeviceListener, Features, ProtocolHandle};
use pyatv_core::storage::InfoSettings;
use pyatv_core::{
    BaseService, DeviceInfo, DeviceModel, FeatureInfo, FeatureName, Protocol, device_info,
};
use pyatv_pairing::HapCredentials;

use crate::api::CompanionApi;
use crate::api::state::media_control_flags;
use crate::facade::device::{CompanionApps, CompanionAudio, CompanionPower, CompanionUserAccounts};
use crate::facade::input::{CompanionKeyboard, CompanionTouchGestures};
use crate::facade::remote::CompanionRemoteControl;
use crate::session::SystemInfo;
use crate::{Error, Result};

/// Features whose availability is decided by the `_mcF` bitfield rather than asserted.
///
/// `MEDIA_CONTROL_MAP` (`__init__.py:106-115`), verbatim. Note the two bits with no entry:
/// `FastForward` (`0x0010`) and `Rewind` (`0x0020`) exist in the flag set but map to no
/// [`FeatureName`] anywhere upstream, so a device advertising them still reports nothing.
pub const MEDIA_CONTROL_MAP: [(FeatureName, u64); 8] = [
    (FeatureName::Play, media_control_flags::PLAY),
    (FeatureName::Pause, media_control_flags::PAUSE),
    (FeatureName::Next, media_control_flags::NEXT_TRACK),
    (FeatureName::Previous, media_control_flags::PREVIOUS_TRACK),
    (FeatureName::Volume, media_control_flags::VOLUME),
    (FeatureName::SetVolume, media_control_flags::VOLUME),
    (FeatureName::SkipForward, media_control_flags::SKIP_FORWARD),
    (
        FeatureName::SkipBackward,
        media_control_flags::SKIP_BACKWARD,
    ),
];

/// Everything Companion claims it can do.
///
/// `SUPPORTED_FEATURES` (`__init__.py:117-157`), including the `+ list(MEDIA_CONTROL_MAP.keys())`
/// tail. Two members are dead for *resolution* purposes but present because this set is also the
/// registration set the facade's relayer consults:
///
/// * [`FeatureName::PowerState`] is special-cased ahead of the plain-membership branch.
/// * every [`MEDIA_CONTROL_MAP`] key is intercepted by the bitfield branch before it.
///
/// Also note what is *absent*: `VolumeUp`/`VolumeDown` are here (hardware buttons) while `Volume`
/// and `SetVolume` come from the bitfield instead — two different feature axes over two different
/// commands, not duplicates.
#[must_use]
pub fn supported_features() -> BTreeSet<FeatureName> {
    let declared = [
        // Apps.
        FeatureName::AppList,
        FeatureName::LaunchApp,
        // User accounts.
        FeatureName::AccountList,
        FeatureName::SwitchAccount,
        // Power.
        FeatureName::PowerState,
        FeatureName::TurnOn,
        FeatureName::TurnOff,
        // Remote control: navigation, i.e. HID.
        FeatureName::Up,
        FeatureName::Down,
        FeatureName::Left,
        FeatureName::Right,
        FeatureName::Select,
        FeatureName::Menu,
        FeatureName::Home,
        FeatureName::VolumeUp,
        FeatureName::VolumeDown,
        FeatureName::PlayPause,
        FeatureName::ChannelUp,
        FeatureName::ChannelDown,
        FeatureName::Screensaver,
        FeatureName::Guide,
        FeatureName::ControlCenter,
        // Keyboard.
        FeatureName::TextFocusState,
        FeatureName::TextGet,
        FeatureName::TextClear,
        FeatureName::TextAppend,
        FeatureName::TextSet,
        // Touch gestures.
        FeatureName::Swipe,
        FeatureName::TouchAction,
        FeatureName::Click,
    ];

    declared
        .into_iter()
        .chain(MEDIA_CONTROL_MAP.into_iter().map(|(feature, _)| feature))
        .collect()
}

/// Companion's live feature reporting.
///
/// `CompanionFeatures.get_feature` (`__init__.py:591-611`), branch for branch and **in order**:
///
/// 1. a [`MEDIA_CONTROL_MAP`] member is available iff its bit is set in the last `_mcF`;
/// 2. [`FeatureName::PowerState`] is available iff a power state has ever been observed;
/// 3. anything else in [`supported_features`] is available unconditionally — upstream's own
///    comment concedes "we don't have any way to verify it anyways";
/// 4. everything else is unavailable.
///
/// Step 4 says *unavailable*, not *unsupported*, which is upstream's choice and matters: the
/// facade's relayer only asks Companion about features Companion declared, so a fourth-branch
/// answer is unreachable through the facade and only a direct caller can see it.
#[derive(Debug)]
pub struct CompanionFeatures {
    api: Arc<CompanionApi>,
    declared: BTreeSet<FeatureName>,
}

impl CompanionFeatures {
    /// Wrap a connected session.
    #[must_use]
    pub fn new(api: Arc<CompanionApi>) -> Self {
        Self {
            api,
            declared: supported_features(),
        }
    }
}

impl Features for CompanionFeatures {
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        let observed = self.api.observed();

        if let Some((_, bit)) = MEDIA_CONTROL_MAP
            .iter()
            .find(|(candidate, _)| *candidate == feature)
        {
            return if observed.control_flags & bit == 0 {
                FeatureInfo::unavailable()
            } else {
                FeatureInfo::available()
            };
        }

        if feature == FeatureName::PowerState {
            return if observed.power_known {
                FeatureInfo::available()
            } else {
                FeatureInfo::unsupported()
            };
        }

        if self.declared.contains(&feature) {
            return FeatureInfo::available();
        }

        FeatureInfo::unavailable()
    }

    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        FeatureName::ALL
            .into_iter()
            .map(|feature| (feature, self.get_feature(feature)))
            .filter(|(feature, _)| include_unsupported || self.declared.contains(feature))
            .collect()
    }
}

/// The teardown hook the facade awaits on close.
#[derive(Debug)]
pub struct CompanionHandle {
    api: Arc<CompanionApi>,
}

impl ProtocolHandle for CompanionHandle {
    fn close(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move { self.api.close().await.map_err(Into::into) })
    }
}

/// Everything [`setup`] needs beyond the credentials.
#[derive(Debug, Clone)]
pub struct CompanionSetupOptions {
    /// Where to dial. The port comes from the mDNS SRV record, never a hardcoded default.
    pub peer: SocketAddr,
    /// The service being connected, for its credentials and TXT properties.
    pub service: BaseService,
    /// This controller's persisted identity, sent in `_systemInfo`.
    pub info: InfoSettings,
    /// Notified if the connection drops without the caller asking.
    pub listener: Option<Arc<dyn DeviceListener>>,
}

/// Connect Companion and describe what it contributes.
///
/// `setup()` (`__init__.py:663-702`) with its `_connect` closure already run: upstream yields a
/// `SetupData` holding a not-yet-awaited coroutine and lets `FacadeAppleTV.connect()` drive it,
/// whereas here connecting is what produces the handles in the first place. The observable order is
/// the same — bring-up, then `power.initialize()`, then registration.
///
/// # Errors
///
/// Returns [`Error::Connect`] if the device is unreachable, [`Error::Pairing`] if it refuses the
/// stored credentials, and [`Error::InvalidCredentials`] if the stored string does not parse.
///
/// Returns `Ok(None)` — not an error — when the service has no credentials at all, which is
/// upstream's guard clause and means "this device has no Companion protocol", not "Companion
/// failed".
pub async fn setup(options: CompanionSetupOptions) -> Result<Option<SetupData>> {
    let Some(credentials) = options
        .service
        .credentials
        .as_deref()
        .filter(|it| !it.is_empty())
    else {
        tracing::debug!("not adding Companion as credentials are missing");
        return Ok(None);
    };

    let credentials = HapCredentials::parse(credentials).map_err(Error::Pairing)?;
    let info = system_info(&options.info, credentials.client_id.clone());

    let api =
        Arc::new(CompanionApi::connect(options.peer, &credentials, &info, options.listener).await?);

    // `await power.initialize()` inside `_connect` (`__init__.py:684-687`). Infallible by design:
    // newer tvOS refuses `FetchAttentionState`, and that must not fail the connection.
    api.initialize_power().await;

    Ok(Some(SetupData {
        protocol: Some(Protocol::Companion),
        features: supported_features(),
        features_impl: Some(Arc::new(CompanionFeatures::new(Arc::clone(&api)))),
        handle: Some(Arc::new(CompanionHandle {
            api: Arc::clone(&api),
        })),
        remote_control: Some(Arc::new(CompanionRemoteControl::new(Arc::clone(&api)))),
        power: Some(Arc::new(CompanionPower::new(Arc::clone(&api)))),
        apps: Some(Arc::new(CompanionApps::new(Arc::clone(&api)))),
        audio: Some(Arc::new(CompanionAudio::new(Arc::clone(&api)))),
        keyboard: Some(Arc::new(CompanionKeyboard::new(Arc::clone(&api)))),
        touch_gestures: Some(Arc::new(CompanionTouchGestures::new(Arc::clone(&api)))),
        user_accounts: Some(Arc::new(CompanionUserAccounts::new(api))),
        device_info: device_facts(&options.service),
        ..SetupData::default()
    }))
}

/// Build the `_systemInfo` identity from the persisted controller settings.
///
/// `system_info` reads `self.core.settings.info` (`api.py:190-191`), which is exactly
/// [`InfoSettings`]. The `_i` field must never be empty — a null one stops the device pushing
/// power-state events at all — so an empty stored `rp_id` falls back rather than being sent as-is.
fn system_info(info: &InfoSettings, client_id: Vec<u8>) -> SystemInfo {
    SystemInfo {
        name: info.name.clone(),
        model: info.model.clone(),
        device_id: info.device_id.clone(),
        rp_id: Some(info.rp_id.clone()).filter(|it| !it.is_empty()),
        client_id,
    }
}

/// What Companion's TXT record says about the hardware.
///
/// `device_info()` (`__init__.py:637-645`): the `rpmd` property, both raw and resolved. The raw
/// value is always recorded; the resolved model only when the lookup produced something.
fn device_facts(service: &BaseService) -> DeviceInfo {
    let Some(raw_model) = service.property("rpmd") else {
        return DeviceInfo::default();
    };

    let info = DeviceInfo::default().with_raw_model(raw_model);
    match device_info::lookup_model(Some(raw_model)) {
        DeviceModel::Unknown => info,
        model => info.with_model(model),
    }
}

#[cfg(test)]
mod tests {
    use super::{MEDIA_CONTROL_MAP, supported_features};
    use pyatv_core::FeatureName;

    /// The exact membership `__init__.py:117-157` produces: 30 asserted features plus the eight
    /// media-control keys, minus the overlap of nothing — the two sets are disjoint.
    #[test]
    fn the_declared_feature_set_matches_upstream() {
        let declared = supported_features();
        assert_eq!(declared.len(), 30 + MEDIA_CONTROL_MAP.len());

        for (feature, _) in MEDIA_CONTROL_MAP {
            assert!(declared.contains(&feature), "{feature} must be declared");
        }
        for feature in [
            FeatureName::AppList,
            FeatureName::LaunchApp,
            FeatureName::PowerState,
            FeatureName::ControlCenter,
            FeatureName::TextFocusState,
            FeatureName::TouchAction,
        ] {
            assert!(declared.contains(&feature), "{feature} must be declared");
        }
    }

    /// Companion declares neither metadata nor streaming; those belong to MRP and `AirPlay`.
    #[test]
    fn companion_declares_nothing_it_cannot_serve() {
        let declared = supported_features();
        for feature in [
            FeatureName::Title,
            FeatureName::Artwork,
            FeatureName::PlayUrl,
            FeatureName::StreamFile,
            FeatureName::PushUpdates,
            FeatureName::SetPosition,
            FeatureName::Stop,
        ] {
            assert!(
                !declared.contains(&feature),
                "{feature} must not be declared"
            );
        }
    }

    /// Volume buttons and absolute volume are different axes over different commands.
    #[test]
    fn hardware_volume_buttons_are_not_the_same_feature_as_the_volume_level() {
        let declared = supported_features();
        assert!(declared.contains(&FeatureName::VolumeUp));
        assert!(declared.contains(&FeatureName::VolumeDown));

        assert!(
            !MEDIA_CONTROL_MAP
                .iter()
                .any(|(feature, _)| *feature == FeatureName::VolumeUp)
        );
        assert!(
            MEDIA_CONTROL_MAP
                .iter()
                .any(|(feature, _)| *feature == FeatureName::Volume)
        );
    }
}
