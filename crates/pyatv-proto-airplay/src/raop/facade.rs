//! What the RAOP protocol contributes to the facade.
//!
//! Port of `RaopStream`, `RaopAudio`, `RaopFeatures`, `RaopMetadata`, `RaopRemoteControl`,
//! `RaopPushUpdater` and the `setup()` generator that wires them together
//! (`pyatv/protocols/raop/__init__.py:70-256, 274-435, 545-591`).
//!
//! # Where this lives
//!
//! AirPlay's own facade types are in `crate::setup::interfaces`; RAOP's are here rather than
//! alongside them because they are a *separate* `SetupData` registered under
//! [`Protocol::Raop`], with its own thirteen declared features
//! and its own priority slot in the relayer. Upstream keeps them in separate modules for the same
//! reason.

pub mod updates;

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use pyatv_core::consts::{DeviceModel, OperatingSystem, Protocol};
use pyatv_core::device_info::{lookup_model, lookup_os_from_identifier};
use pyatv_core::facade::SetupData;
use pyatv_core::features::{FeatureInfo, FeatureName, FeatureState};
use pyatv_core::interface::{Audio, BoxFuture, Features, Stream};
use pyatv_core::models::{BaseService, DeviceInfo};
use pyatv_pairing::HapCredentials;

use crate::audio::Source;
use crate::raop::manager::{ManagerListener, RaopPlaybackManager};
use crate::raop::metadata::TrackMetadata;
use crate::raop::volume::{step_down, step_up};

pub use updates::{RaopMetadata, RaopPushUpdater, RaopRemoteControl};

use updates::unsupported;

/// The features `Protocol::Raop` declares.
///
/// `setup()`'s feature set (`raop/__init__.py:575-591`) — exactly thirteen names, no more and no
/// fewer. `PushUpdates` is declared but has no entry in `get_feature`, so it resolves through the
/// catch-all; that is upstream's shape, not an omission here.
pub const DECLARED_FEATURES: [FeatureName; 13] = [
    FeatureName::StreamFile,
    FeatureName::PushUpdates,
    FeatureName::Artist,
    FeatureName::Album,
    FeatureName::Title,
    FeatureName::Position,
    FeatureName::TotalTime,
    FeatureName::SetVolume,
    FeatureName::Volume,
    FeatureName::VolumeUp,
    FeatureName::VolumeDown,
    FeatureName::Stop,
    FeatureName::Pause,
];

/// Everything [`setup`] needs.
#[derive(Debug, Clone)]
pub struct RaopSetupOptions {
    /// The device's address.
    pub address: IpAddr,
    /// The RAOP service, for its port and TXT record.
    pub service: BaseService,
    /// Credentials to pair-verify with.
    ///
    /// `extract_credentials(core.service)` (`raop/__init__.py:355`). On the tvOS 27 test device
    /// this has to come from the Companion pairing rather than from the RAOP service's own empty
    /// field, for the reason [`crate::setup::tunnel_credentials`] documents at length.
    pub credentials: HapCredentials,
}

/// Describe what RAOP contributes to the facade.
///
/// `setup()` (`raop/__init__.py:545-591`). Upstream's `_connect` is `async def … return True`, so
/// there is nothing to connect here either: the RTSP connection is opened per `stream_file` call
/// and closed again when it finishes.
#[must_use]
pub fn setup(options: &RaopSetupOptions) -> SetupData {
    let mut service = options.service.clone();
    service.credentials = Some(options.credentials.to_string());

    let manager = Arc::new(RaopPlaybackManager::new(options.address, service));
    let push_updater = Arc::new(RaopPushUpdater::new(Arc::clone(&manager)));

    SetupData {
        protocol: Some(Protocol::Raop),
        features: DECLARED_FEATURES.into_iter().collect(),
        features_impl: Some(Arc::new(RaopFeatures::new(Arc::clone(&manager)))),
        stream: Some(Arc::new(RaopStream::new(
            Arc::clone(&manager),
            options.credentials.clone(),
            Arc::clone(&push_updater),
        ))),
        audio: Some(Arc::new(RaopAudio::new(Arc::clone(&manager)))),
        metadata: Some(Arc::new(RaopMetadata::new(Arc::clone(&manager)))),
        remote_control: Some(Arc::new(RaopRemoteControl::new(Arc::clone(&manager)))),
        push_updater: Some(push_updater),
        device_info: device_facts(&options.service),
        ..SetupData::default()
    }
}

/// What a RAOP TXT record says about the hardware.
///
/// `device_info` (`raop/__init__.py:474-500`): `am` gives the raw model, the resolved model and the
/// operating system, and `ov` the version. The `_airport._tcp` `wama` backfill is not reproduced —
/// it belongs to whoever merges the two services' properties, and this function only sees one.
#[must_use]
pub fn device_facts(service: &BaseService) -> DeviceInfo {
    let mut info = DeviceInfo::default();

    if let Some(raw_model) = service.property("am") {
        info = info.with_raw_model(raw_model);
        match lookup_model(Some(raw_model)) {
            DeviceModel::Unknown => {}
            model => info = info.with_model(model),
        }
        match lookup_os_from_identifier(raw_model) {
            OperatingSystem::Unknown => {}
            operating_system => info = info.with_operating_system(operating_system),
        }
    }
    if let Some(version) = service.property("ov") {
        info = info.with_version(version);
    }

    info
}

/// RAOP's streaming surface.
#[derive(Debug)]
pub struct RaopStream {
    manager: Arc<RaopPlaybackManager>,
    credentials: HapCredentials,
    push_updater: Arc<RaopPushUpdater>,
}

impl RaopStream {
    /// Stream to the device `manager` owns.
    #[must_use]
    pub fn new(
        manager: Arc<RaopPlaybackManager>,
        credentials: HapCredentials,
        push_updater: Arc<RaopPushUpdater>,
    ) -> Self {
        Self {
            manager,
            credentials,
            push_updater,
        }
    }

    /// The session manager behind this stream.
    ///
    /// `RaopStream.playback_manager` (`raop/__init__.py:337`), which upstream's `RaopRemoteControl`
    /// and `RaopAudio` reach for the same reasons a caller here would: stopping a running stream
    /// and reading the volume.
    #[must_use]
    pub fn manager(&self) -> Arc<RaopPlaybackManager> {
        Arc::clone(&self.manager)
    }

    /// Stream a file, a URL or a buffer.
    ///
    /// The [`Stream`] trait only offers a path; this is the full surface `stream_file` has
    /// upstream, so a caller inside this workspace can hand it a URL or bytes without going back
    /// through a temporary file.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::InvalidState`] if a stream is already running, [`crate::Error::Audio`]
    /// if the source cannot be decoded, and whatever the RTSP and streaming layers return.
    pub async fn stream_source(&self, source: Source) -> crate::Result<()> {
        self.stream_source_with(source, None, false).await
    }

    /// The same, with the caller's own metadata.
    ///
    /// The remaining two arguments of `stream_file(file, metadata, override_missing_metadata)`
    /// (`raop/__init__.py:334-341`), which the [`Stream`] trait has nowhere to put: `metadata`
    /// replaces whatever the file carries, and `override_missing_metadata` turns that into a merge
    /// where the caller's values win and the file's fill the gaps.
    ///
    /// # Errors
    ///
    /// As [`RaopStream::stream_source`].
    pub async fn stream_source_with(
        &self,
        source: Source,
        metadata: Option<TrackMetadata>,
        override_missing_metadata: bool,
    ) -> crate::Result<()> {
        let updater = Arc::clone(&self.push_updater);
        let listener =
            ManagerListener::new(&self.manager, Box::new(move || updater.state_changed()));

        // Boxed for the same reason the manager boxes its own: the whole session future is well
        // past clippy's `large_futures` threshold.
        Box::pin(self.manager.stream(
            source,
            &self.credentials,
            metadata,
            override_missing_metadata,
            Some(listener),
        ))
        .await
    }
}

impl Stream for RaopStream {
    fn play_url(&self, url: &str) -> BoxFuture<'_, pyatv_core::Result<()>> {
        let url = url.to_owned();
        Box::pin(async move {
            Err(pyatv_core::Error::NotSupported(format!(
                "RAOP cannot play {url}; AirPlay does that"
            )))
        })
    }

    fn stream_file(&self, path: &Path) -> BoxFuture<'_, pyatv_core::Result<()>> {
        // A `str` source is a URL if it matches `^http(|s)://` and a path otherwise
        // (`audio_source.py:731-735`); a `Path` that spells a URL is treated the same way, so
        // `atvremote stream_file http://…` works exactly as upstream's does.
        let source = path
            .to_str()
            .map_or_else(|| Source::from_path(path), Source::from_str_source);

        Box::pin(async move {
            Box::pin(self.stream_source(source))
                .await
                .map_err(Into::into)
        })
    }

    fn close(&self) {
        self.manager.stop();
    }
}

/// RAOP's volume control.
#[derive(Debug)]
pub struct RaopAudio {
    manager: Arc<RaopPlaybackManager>,
}

impl RaopAudio {
    /// Control the volume of the device `manager` owns.
    #[must_use]
    pub fn new(manager: Arc<RaopPlaybackManager>) -> Self {
        Self { manager }
    }
}

impl Audio for RaopAudio {
    fn volume(&self) -> f32 {
        self.manager.volume()
    }

    fn set_volume(&self, level: f32) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move { self.manager.set_volume(level).await.map_err(Into::into) })
    }

    fn volume_up(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move {
            self.manager
                .set_volume(step_up(self.manager.volume()))
                .await
                .map_err(Into::into)
        })
    }

    fn volume_down(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move {
            self.manager
                .set_volume(step_down(self.manager.volume()))
                .await
                .map_err(Into::into)
        })
    }

    fn output_devices(&self) -> Vec<String> {
        Vec::new()
    }

    fn add_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, pyatv_core::Result<()>> {
        unsupported("add_output_devices")
    }

    fn remove_output_devices(
        &self,
        _identifiers: &[String],
    ) -> BoxFuture<'_, pyatv_core::Result<()>> {
        unsupported("remove_output_devices")
    }

    fn set_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, pyatv_core::Result<()>> {
        unsupported("set_output_devices")
    }
}

/// RAOP's live feature reporting.
#[derive(Debug)]
pub struct RaopFeatures {
    manager: Arc<RaopPlaybackManager>,
}

impl RaopFeatures {
    /// Report against the device `manager` owns.
    #[must_use]
    pub fn new(manager: Arc<RaopPlaybackManager>) -> Self {
        Self { manager }
    }
}

impl Features for RaopFeatures {
    /// `RaopFeatures.get_feature` (`raop/__init__.py:214-254`), branch for branch. `Position` and
    /// `TotalTime` are gated on the *same* field — the metadata's duration — and the four volume
    /// names are unconditionally available, with the source comment "as far as known, volume
    /// controls are always supported".
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        if feature == FeatureName::StreamFile {
            return FeatureInfo::available();
        }

        let metadata = self.manager.playback_info().map(|info| info.metadata);
        let present = |value: Option<&String>| {
            if value.is_some_and(|value| !value.is_empty()) {
                FeatureInfo::available()
            } else {
                FeatureInfo::unavailable()
            }
        };

        match feature {
            FeatureName::Title => present(metadata.as_ref().and_then(|it| it.title.as_ref())),
            FeatureName::Artist => present(metadata.as_ref().and_then(|it| it.artist.as_ref())),
            FeatureName::Album => present(metadata.as_ref().and_then(|it| it.album.as_ref())),
            FeatureName::Position | FeatureName::TotalTime => {
                if metadata
                    .as_ref()
                    .and_then(|it| it.duration)
                    .is_some_and(|duration| duration > 0.0)
                {
                    FeatureInfo::available()
                } else {
                    FeatureInfo::unavailable()
                }
            }
            FeatureName::SetVolume
            | FeatureName::Volume
            | FeatureName::VolumeUp
            | FeatureName::VolumeDown => FeatureInfo::available(),
            FeatureName::Stop | FeatureName::Pause => {
                if self.manager.is_streaming() {
                    FeatureInfo::available()
                } else {
                    FeatureInfo::unavailable()
                }
            }
            _ => FeatureInfo::unavailable(),
        }
    }

    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        FeatureName::ALL
            .iter()
            .map(|feature| (*feature, self.get_feature(*feature)))
            .filter(|(_, info)| include_unsupported || info.state != FeatureState::Unsupported)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    use pyatv_core::consts::{DeviceState, MediaType, Protocol};
    use pyatv_core::features::{FeatureName, FeatureState};
    use pyatv_core::interface::Features as _;
    use pyatv_core::models::BaseService;
    use pyatv_pairing::HapCredentials;

    use super::{
        DECLARED_FEATURES, RaopFeatures, RaopMetadata, RaopSetupOptions, device_facts, setup,
    };
    use crate::raop::manager::RaopPlaybackManager;

    fn service() -> BaseService {
        let mut service = BaseService::new(Protocol::Raop, 7000);
        for (key, value) in [
            ("et", "0,3,5"),
            ("md", "0,1,2"),
            ("am", "AppleTV14,1"),
            ("ov", "27.0"),
            ("ft", "0x4A7FDFD5,0x3C177FDE"),
        ] {
            service
                .properties
                .insert((*key).to_owned(), (*value).to_owned());
        }
        service
    }

    fn credentials() -> HapCredentials {
        HapCredentials::parse(&format!(
            "{}:{}:{}:{}",
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(36),
            "dd".repeat(36)
        ))
        .expect("well-formed HAP credentials")
    }

    fn manager() -> Arc<RaopPlaybackManager> {
        Arc::new(RaopPlaybackManager::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            service(),
        ))
    }

    /// Exactly thirteen names, matching `test_metadata_features`/`test_volume_features`.
    #[test]
    fn raop_declares_thirteen_features() {
        let data = setup(&RaopSetupOptions {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            service: service(),
            credentials: credentials(),
        });

        assert_eq!(data.protocol, Some(Protocol::Raop));
        assert_eq!(data.features.len(), DECLARED_FEATURES.len());
        for feature in DECLARED_FEATURES {
            assert!(data.features.contains(&feature), "{feature}");
        }
        assert!(data.stream.is_some());
        assert!(data.audio.is_some());
        assert!(data.metadata.is_some());
        assert!(data.remote_control.is_some());
        assert!(data.push_updater.is_some());
    }

    /// With nothing streaming: `StreamFile` and the four volume names are available, `Stop` and
    /// `Pause` are not, and neither is anything metadata-derived.
    #[test]
    fn an_idle_session_reports_only_the_unconditional_features() {
        let features = RaopFeatures::new(manager());

        for available in [
            FeatureName::StreamFile,
            FeatureName::SetVolume,
            FeatureName::Volume,
            FeatureName::VolumeUp,
            FeatureName::VolumeDown,
        ] {
            assert_eq!(
                features.get_feature(available).state,
                FeatureState::Available,
                "{available}"
            );
        }

        for unavailable in [
            FeatureName::Stop,
            FeatureName::Pause,
            FeatureName::Title,
            FeatureName::Artist,
            FeatureName::Album,
            FeatureName::Position,
            FeatureName::TotalTime,
            FeatureName::PlayUrl,
        ] {
            assert_eq!(
                features.get_feature(unavailable).state,
                FeatureState::Unavailable,
                "{unavailable}"
            );
        }
    }

    /// Nothing streaming reports idle with an unknown media type, not an empty `Playing`.
    #[test]
    fn an_idle_session_is_idle_and_unknown() {
        let playing = RaopMetadata::new(manager()).snapshot();

        assert_eq!(playing.device_state, DeviceState::Idle);
        assert_eq!(playing.media_type, MediaType::Unknown);
        assert_eq!(playing.title, None);
    }

    /// `am` gives the model and the operating system; `ov` gives the version.
    #[test]
    fn the_device_facts_come_from_am_and_ov() {
        let info = device_facts(&service());

        assert_eq!(info.raw_model(), Some("AppleTV14,1"));
        assert_eq!(info.version().as_deref(), Some("27.0"));
    }
}
