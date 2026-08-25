//! What the AirPlay protocol contributes to the facade, and how the MRP tunnel is reached.
//!
//! Port of `pyatv/protocols/airplay/__init__.py`: `AirPlayFeatures` (`__init__.py:57-76`),
//! `AirPlayRemoteControl` (`__init__.py:168-177`), `device_info` (`__init__.py:203-222`), the first
//! `SetupData` `setup()` yields (`__init__.py:303-336`) and the tunnel gate that decides whether a
//! second one follows (`__init__.py:374-387`).
//!
//! # Scope
//!
//! [`setup`] covers only AirPlay's *own* contributions. The tunnelled MRP session it can host is a
//! separate `SetupData` tagged `Protocol::MRP`, assembled by the umbrella crate out of
//! [`remote_control_tunnel`] and `pyatv-proto-mrp` — this crate must not depend on the latter, so it
//! stops at handing back a live [`DataStreamChannel`].
//!
//! `play_url` itself lives in [`crate::stream`]; what this module does is decide the address,
//! credentials and protocol version one needs, and hand the facade an [`AirPlayStream`] holding
//! them. [`AirPlayFeatures`] reports the feature the way upstream does, from the advertised feature
//! bits, independently of whether this particular registration can act on it.

mod credentials;
mod interfaces;

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use pyatv_core::airplay::{
    AirPlayFlags, AirPlayVersion, CredentialsKind, get_protocol_version,
    is_remote_control_supported,
};
use pyatv_core::consts::{DeviceModel, Protocol};
use pyatv_core::device_info::lookup_model;
use pyatv_core::facade::{FacadeTakeover, SetupData};
use pyatv_core::features::FeatureName;
use pyatv_core::models::{BaseService, DeviceInfo};
use pyatv_pairing::{AuthenticationType, HapCredentials};

pub use credentials::{play_credentials, tunnel_credentials};
pub use interfaces::{AirPlayFeatures, AirPlayRemoteControl, AirPlayStream};

use crate::ap2::{Ap2Session, DataStreamChannel, InfoSettings, SeqnoPolicy};
use crate::stream::PlayOptions;
use crate::{Error, Result};

/// The features `Protocol::AirPlay` declares, before availability is resolved per call.
///
/// `set([FeatureName.PlayUrl, FeatureName.Stop])` (`__init__.py:335`) — exactly two, and neither of
/// them is anything the tunnel provides.
pub const DECLARED_FEATURES: [FeatureName; 2] = [FeatureName::PlayUrl, FeatureName::Stop];

/// What the AirPlay TXT record says about the hardware.
///
/// `device_info` (`__init__.py:203-222`): `model` becomes the raw and resolved model plus the
/// operating system, `osvers` the version, `deviceid` the MAC, and `psi` — falling back to `pi` —
/// the output-device identifier.
#[must_use]
pub fn device_facts(service: &BaseService) -> DeviceInfo {
    let mut info = DeviceInfo::default();

    if let Some(raw_model) = service.property("model") {
        info = info.with_raw_model(raw_model);
        match lookup_model(Some(raw_model)) {
            DeviceModel::Unknown => {}
            model => info = info.with_model(model),
        }
    }
    if let Some(version) = service.property("osvers") {
        info = info.with_version(version);
    }
    if let Some(mac) = service.property("deviceid") {
        info = info.with_mac(mac);
    }
    if let Some(output_device_id) = service.property("psi").or_else(|| service.property("pi")) {
        info = info.with_output_device_id(output_device_id);
    }

    info
}

/// Everything [`setup`] needs.
#[derive(Debug, Clone)]
pub struct AirPlaySetupOptions {
    /// The AirPlay service being connected, for its TXT properties.
    pub service: BaseService,
    /// Where the device is, so `play_url` has somewhere to connect
    /// (`__init__.py:124-126` reads `config.address` and `service.port`).
    pub address: IpAddr,
    /// What `play_url` should pair-verify with, from [`play_credentials`]. `None` leaves the
    /// registered [`AirPlayStream`] unconfigured, so it reports `play_url` unsupported rather than
    /// failing the whole connect — upstream's registration is unconditional too.
    pub credentials: Option<HapCredentials>,
    /// How `play_url` claims `RemoteControl` while a URL is playing.
    ///
    /// `partial(atv.takeover, proto)` handed to every protocol through `Core`
    /// (`pyatv/__init__.py:138`, `pyatv/core/__init__.py:223`). `None` outside a facade.
    pub takeover: Option<FacadeTakeover>,
    /// Which protocol version to play with. Upstream reads
    /// `settings.protocols.raop.protocol_version` even for the AirPlay-proper path
    /// (`__init__.py:150-156`), and its default is
    /// [`AirPlayVersion::Auto`].
    pub protocol_version: AirPlayVersion,
}

/// Describe what the AirPlay protocol contributes to the facade.
///
/// The first `SetupData` `setup()` yields (`__init__.py:322-336`), which upstream produces
/// unconditionally — there is no connection to make, `_connect` is `async def … return True`.
///
/// Two things upstream yields from the same generator are deliberately not here. The synthesised
/// RAOP service (`__init__.py:338-372`) belongs to RAOP's own setup and to the umbrella that owns
/// the `BaseConfig`; the MRP tunnel (`__init__.py:374-387`) is a `Protocol::MRP` registration the
/// umbrella assembles from [`remote_control_tunnel`].
#[must_use]
pub fn setup(options: &AirPlaySetupOptions) -> SetupData {
    let flags = airplay_flags(&options.service);
    let stream = if let Some(credentials) = options.credentials.clone() {
        AirPlayStream::new(PlayOptions::new(
            SocketAddr::new(options.address, options.service.port),
            credentials,
            get_protocol_version(&options.service, options.protocol_version),
        ))
        .with_takeover(options.takeover.clone())
    } else {
        tracing::debug!("no credentials for AirPlay, registering play_url as unsupported");
        AirPlayStream::unconfigured()
    };

    SetupData {
        protocol: Some(Protocol::AirPlay),
        features: DECLARED_FEATURES.into_iter().collect(),
        features_impl: Some(Arc::new(AirPlayFeatures::new(flags))),
        // The same stream, so that `stop()` reaches the playback `play_url` started
        // (`__init__.py:329-333` passes one instance to both).
        remote_control: Some(Arc::new(AirPlayRemoteControl::new(stream.clone()))),
        stream: Some(Arc::new(stream)),
        device_info: device_facts(&options.service),
        ..SetupData::default()
    }
}

/// Parse a service's `features`/`ft` TXT value, treating a malformed one as no flags.
fn airplay_flags(service: &BaseService) -> AirPlayFlags {
    let raw = service
        .property("features")
        .or_else(|| service.property("ft"))
        .unwrap_or("0x0");

    pyatv_core::airplay::parse_features(raw).unwrap_or_else(|error| {
        tracing::debug!(%error, "unparsable AirPlay feature string, assuming no flags");
        AirPlayFlags::empty()
    })
}

/// Whether a tunnel should be attempted at all.
///
/// The `elif` chain of `setup()` (`__init__.py:374-387`) minus the `MrpTunnel` setting, which
/// belongs to whoever owns the settings: `is_remote_control_supported`
/// (`utils.py:165-180`, ported in `pyatv_core::airplay`) *and* credentials whose type the channel
/// accepts. Upstream allows HAP and transient here; only HAP survives
/// `is_remote_control_supported` for an `AppleTV*` model, and the test device refuses transient
/// pairing outright, so [`tunnel_credentials`] never produces one.
#[must_use]
pub fn is_tunnel_supported(service: &BaseService, credentials: &HapCredentials) -> bool {
    let kind = match credentials.authentication_type() {
        AuthenticationType::Hap => CredentialsKind::Hap,
        AuthenticationType::Transient => CredentialsKind::Transient,
        AuthenticationType::Null | AuthenticationType::Legacy => CredentialsKind::Other,
    };

    is_remote_control_supported(service, kind)
        && matches!(kind, CredentialsKind::Hap | CredentialsKind::Transient)
}

/// Bring up a remote-control tunnel and hand back the channel MRP rides on.
///
/// `_create_mrp_tunnel_data`'s `_connect_rc` (`__init__.py:268-285`) up to but not including
/// `session.start_keep_alive(...)` and `mrp_connect()`: connect, pair-verify, both `SETUP`s, both
/// side channels. What the caller does next is
/// [`Ap2Session::start_keep_alive`](crate::ap2::Ap2Session::start_keep_alive) — which is left here
/// rather than done inside, because the `DeviceListener` a lost keepalive has to report to belongs
/// to whoever is assembling the facade — and then attach an `MrpTransport` to the returned channel
/// and run MRP's own bring-up over it.
///
/// The session must be kept alive for as long as the channel is used — dropping it stops the
/// `/feedback` keepalive, and a receiver drops the tunnel roughly thirty seconds later.
///
/// # Errors
///
/// Returns [`Error::NotAuthenticated`] if the device rejects the credentials — including the `470`
/// upstream maps to `InvalidCredentialsError` — [`Error::Io`] if any socket fails, and
/// [`Error::Plist`] if a `SETUP` reply does not carry the port it must.
pub async fn remote_control_tunnel(
    address: IpAddr,
    port: u16,
    credentials: &HapCredentials,
    info: InfoSettings,
    policy: SeqnoPolicy,
) -> Result<(Ap2Session, Arc<DataStreamChannel>)> {
    let mut session = Ap2Session::connect(address, port, credentials, info).await?;

    let channel = session
        .setup_remote_control(policy)
        .await
        .map_err(tunnel_error)?;

    Ok((session, channel))
}

/// Translate the one status a failed tunnel setup has a specific meaning for.
///
/// `470 Connection Authorization Required` becomes an authentication failure rather than a generic
/// status error, exactly as upstream re-raises it (`__init__.py:277-281`). The device answers it
/// with an empty body and no TLV, so there is nothing else to go on.
fn tunnel_error(error: Error) -> Error {
    match error {
        Error::Status { status: 470, .. } => Error::NotAuthenticated { status: 470 },
        other => other,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::{
        AirPlayFeatures, AirPlaySetupOptions, DECLARED_FEATURES, device_facts, is_tunnel_supported,
        setup,
    };
    use pyatv_core::airplay::AirPlayFlags;
    use pyatv_core::consts::{DeviceModel, Protocol};
    use pyatv_core::features::{FeatureName, FeatureState};
    use pyatv_core::interface::Features as _;
    use pyatv_core::models::BaseService;
    use pyatv_pairing::HapCredentials;

    /// The test device's own TXT record (`docs/research/airplay-control-mrp-tunnel-port-spec.md`
    /// §1), so the assertions below are about real values rather than invented ones.
    pub(super) fn test_device_service() -> BaseService {
        let mut service = BaseService::new(Protocol::AirPlay, 7000);
        service.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
        for (key, value) in [
            ("features", "0x4A7FDFD5,0x3C177FDE"),
            ("flags", "0x18644"),
            ("model", "AppleTV14,1"),
            ("osvers", "27.0"),
            ("deviceid", "AA:BB:CC:DD:EE:FF"),
            ("psi", "00000000-1111-2222-3333-444444444444"),
        ] {
            service
                .properties
                .insert((*key).to_owned(), (*value).to_owned());
        }
        service
    }

    pub(super) fn hap_credentials() -> HapCredentials {
        HapCredentials::parse(&format!(
            "{}:{}:{}:{}",
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(36),
            "dd".repeat(36)
        ))
        .expect("well-formed HAP credentials")
    }

    /// Both video bits are set on the test device, so `PlayUrl` reports available.
    #[test]
    fn play_url_is_available_when_either_video_bit_is_set() {
        let features = AirPlayFeatures::new(AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V1);
        assert_eq!(
            features.get_feature(FeatureName::PlayUrl).state,
            FeatureState::Available
        );

        let features = AirPlayFeatures::new(AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V2);
        assert_eq!(
            features.get_feature(FeatureName::PlayUrl).state,
            FeatureState::Available
        );
    }

    /// With neither bit set, `PlayUrl` falls through to the catch-all like everything else.
    #[test]
    fn play_url_is_unavailable_without_a_video_bit() {
        let features = AirPlayFeatures::new(AirPlayFlags::empty());
        assert_eq!(
            features.get_feature(FeatureName::PlayUrl).state,
            FeatureState::Unavailable
        );
    }

    /// `Stop` is unconditional, and everything else is `Unavailable` — including names the tunnel
    /// serves, which are answered by the MRP registration instead.
    #[test]
    fn stop_is_always_available_and_nothing_else_is() {
        let features = AirPlayFeatures::new(AirPlayFlags::empty());

        assert_eq!(
            features.get_feature(FeatureName::Stop).state,
            FeatureState::Available
        );
        for feature in [
            FeatureName::Up,
            FeatureName::Volume,
            FeatureName::Title,
            FeatureName::PowerState,
        ] {
            assert_eq!(
                features.get_feature(feature).state,
                FeatureState::Unavailable,
                "{feature}"
            );
        }
    }

    /// Options pointing at the test device, with whatever credentials the caller wants.
    fn setup_options(credentials: Option<HapCredentials>) -> AirPlaySetupOptions {
        AirPlaySetupOptions {
            service: test_device_service(),
            address: "10.0.0.5".parse().expect("an address"),
            credentials,
            takeover: None,
            protocol_version: pyatv_core::airplay::AirPlayVersion::Auto,
        }
    }

    /// Exactly two declared names (`__init__.py:335`).
    #[test]
    fn airplay_declares_two_features() {
        let data = setup(&setup_options(Some(hap_credentials())));

        assert_eq!(data.protocol, Some(Protocol::AirPlay));
        assert_eq!(data.features.len(), 2);
        for feature in DECLARED_FEATURES {
            assert!(data.features.contains(&feature), "{feature}");
        }
        assert!(data.stream.is_some());
        assert!(data.remote_control.is_some());
    }

    /// Without credentials the registration still happens — upstream's is unconditional — and
    /// `play_url` reports itself unsupported when it is called.
    #[tokio::test]
    async fn a_stream_without_credentials_refuses_to_play() {
        let data = setup(&setup_options(None));
        let stream = data.stream.expect("a stream is always registered");

        let error = stream
            .play_url("http://example/video.mp4")
            .await
            .expect_err("there is nowhere to play to");
        assert!(
            matches!(error, pyatv_core::Error::NotSupported(_)),
            "{error}"
        );
    }

    #[test]
    fn device_facts_come_out_of_the_txt_record() {
        let info = device_facts(&test_device_service());

        assert_eq!(info.raw_model(), Some("AppleTV14,1"));
        assert_eq!(info.model(), DeviceModel::AppleTv4KGen3);
        assert_eq!(info.version().as_deref(), Some("27.0"));
        assert_eq!(info.mac(), Some("AA:BB:CC:DD:EE:FF"));
        assert_eq!(
            info.output_device_id(),
            Some("00000000-1111-2222-3333-444444444444")
        );
    }

    /// `psi` wins over `pi` when both are present (`__init__.py:219-222`).
    #[test]
    fn psi_takes_precedence_over_pi() {
        let mut service = test_device_service();
        service
            .properties
            .insert("pi".to_owned(), "fallback".to_owned());

        assert_eq!(
            device_facts(&service).output_device_id(),
            Some("00000000-1111-2222-3333-444444444444")
        );

        service.properties.remove("psi");
        assert_eq!(device_facts(&service).output_device_id(), Some("fallback"));
    }

    /// The gate that upstream's `elif` chain applies, on the test device's real TXT values.
    #[test]
    fn the_tunnel_gate_accepts_hap_on_an_apple_tv() {
        assert!(is_tunnel_supported(
            &test_device_service(),
            &hap_credentials()
        ));
        assert!(!is_tunnel_supported(
            &test_device_service(),
            &HapCredentials::transient()
        ));
        assert!(!is_tunnel_supported(
            &test_device_service(),
            &HapCredentials::null()
        ));
    }

    /// tvOS below 13 is refused whatever the credentials are (`utils.py:151-153`).
    #[test]
    fn the_tunnel_gate_refuses_old_tvos() {
        let mut service = test_device_service();
        service
            .properties
            .insert("osvers".to_owned(), "12.4".to_owned());

        assert!(!is_tunnel_supported(&service, &hap_credentials()));
    }
}
