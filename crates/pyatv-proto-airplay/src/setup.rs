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
//! `play_url` is Step 5 and is a documented stub here; [`AirPlayFeatures`] still reports it the way
//! upstream does, from the advertised feature bits, because that reporting is what the facade and
//! `atvremote` read and it is correct today even though the implementation is not there yet.

mod interfaces;

use std::net::IpAddr;
use std::sync::Arc;

use pyatv_core::airplay::{AirPlayFlags, CredentialsKind, is_remote_control_supported};
use pyatv_core::consts::{DeviceModel, Protocol};
use pyatv_core::device_info::lookup_model;
use pyatv_core::facade::SetupData;
use pyatv_core::features::FeatureName;
use pyatv_core::models::{BaseConfig, BaseService, DeviceInfo};
use pyatv_pairing::{AuthenticationType, HapCredentials};

pub use interfaces::{AirPlayFeatures, AirPlayRemoteControl, AirPlayStream};

use crate::ap2::{Ap2Session, DataStreamChannel, InfoSettings, SeqnoPolicy};
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

    SetupData {
        protocol: Some(Protocol::AirPlay),
        features: DECLARED_FEATURES.into_iter().collect(),
        features_impl: Some(Arc::new(AirPlayFeatures::new(flags))),
        remote_control: Some(Arc::new(AirPlayRemoteControl)),
        stream: Some(Arc::new(AirPlayStream)),
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

/// Pick the credentials the MRP tunnel should authenticate with.
///
/// **A deliberate divergence from pyatv, and the one that makes the tunnel reachable at all on
/// current hardware.** Upstream reads `extract_credentials(core.service)`
/// (`auth/__init__.py:120-133`), i.e. the *AirPlay* service's own stored credentials. On the tvOS 27
/// test device that string is always empty, because AirPlay pair-setup never displays a PIN there
/// and so can never be completed (`docs/RISKS.md` M7).
///
/// The live experiment in `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` established
/// that the AirPlay `/pair-verify` endpoint accepts **any** HAP pairing registered on the device,
/// whichever protocol created it — verified twice, with two independent controller identities — and
/// that transient pairing is refused outright with `470`. So this falls back to the Companion
/// service's credentials, which a user *can* obtain because Companion pairing does show a PIN.
///
/// Returns `None` when neither service holds credentials that parse as HAP. Legacy, transient and
/// null credentials are all rejected: `is_remote_control_supported` would refuse them for an
/// `AppleTV*` model anyway, and the device refuses the transient handshake before any TLV is
/// exchanged.
///
/// Pure over the configuration — it opens no connection and reads no storage.
#[must_use]
pub fn tunnel_credentials(config: &BaseConfig) -> Option<HapCredentials> {
    for protocol in [Protocol::AirPlay, Protocol::Companion] {
        let Some(credentials) = config
            .get_service(protocol)
            .and_then(|service| service.credentials.as_deref())
            .filter(|it| !it.is_empty())
        else {
            continue;
        };

        match HapCredentials::parse(credentials) {
            Ok(parsed) if parsed.authentication_type() == AuthenticationType::Hap => {
                tracing::debug!(
                    ?protocol,
                    "using this service's HAP credentials for the tunnel"
                );
                return Some(parsed);
            }
            Ok(parsed) => tracing::debug!(
                ?protocol,
                auth_type = ?parsed.authentication_type(),
                "ignoring non-HAP credentials for the tunnel"
            ),
            Err(error) => {
                tracing::debug!(?protocol, %error, "ignoring unparsable credentials");
            }
        }
    }

    None
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
/// `mrp_connect()`: connect, pair-verify, both `SETUP`s, both side channels, keepalive started.
/// What the umbrella does next is attach an `MrpTransport` to the returned channel and run MRP's
/// own bring-up over it.
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
mod tests {
    use super::{
        AirPlayFeatures, AirPlaySetupOptions, DECLARED_FEATURES, device_facts, is_tunnel_supported,
        setup, tunnel_credentials,
    };
    use pyatv_core::airplay::AirPlayFlags;
    use pyatv_core::consts::{DeviceModel, Protocol};
    use pyatv_core::features::{FeatureName, FeatureState};
    use pyatv_core::interface::Features as _;
    use pyatv_core::models::{BaseConfig, BaseService};
    use pyatv_pairing::HapCredentials;

    /// The test device's own TXT record (`docs/research/airplay-control-mrp-tunnel-port-spec.md`
    /// §1), so the assertions below are about real values rather than invented ones.
    fn test_device_service() -> BaseService {
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

    fn hap_credentials() -> HapCredentials {
        HapCredentials::parse(&format!(
            "{}:{}:{}:{}",
            "aa".repeat(32),
            "bb".repeat(32),
            "cc".repeat(36),
            "dd".repeat(36)
        ))
        .expect("well-formed HAP credentials")
    }

    /// Both video bits are set on the test device, so `PlayUrl` reports available even though the
    /// implementation is a Step 5 stub.
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

    /// Exactly two declared names (`__init__.py:335`).
    #[test]
    fn airplay_declares_two_features() {
        let data = setup(&AirPlaySetupOptions {
            service: test_device_service(),
        });

        assert_eq!(data.protocol, Some(Protocol::AirPlay));
        assert_eq!(data.features.len(), 2);
        for feature in DECLARED_FEATURES {
            assert!(data.features.contains(&feature), "{feature}");
        }
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

    /// The documented divergence: with no AirPlay credentials, Companion's are used.
    #[test]
    fn companion_credentials_are_the_fallback() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));
        config.add_service(test_device_service());

        assert!(tunnel_credentials(&config).is_none());

        let mut companion = BaseService::new(Protocol::Companion, 49_152);
        companion.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
        companion.credentials = Some(hap_credentials().to_string());
        config.add_service(companion);

        assert_eq!(tunnel_credentials(&config), Some(hap_credentials()));
    }

    /// AirPlay's own credentials win when it has any, which is upstream's only source.
    #[test]
    fn airplay_credentials_win_over_companions() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));

        let mut airplay = test_device_service();
        let airplay_credentials = HapCredentials::parse(&format!(
            "{}:{}:{}:{}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(36),
            "44".repeat(36)
        ))
        .expect("well-formed");
        airplay.credentials = Some(airplay_credentials.to_string());
        config.add_service(airplay);

        let mut companion = BaseService::new(Protocol::Companion, 49_152);
        companion.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
        companion.credentials = Some(hap_credentials().to_string());
        config.add_service(companion);

        assert_eq!(tunnel_credentials(&config), Some(airplay_credentials));
    }

    /// Non-HAP credentials are skipped rather than returned and rejected later.
    #[test]
    fn transient_and_null_credentials_are_not_used() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));

        let mut companion = BaseService::new(Protocol::Companion, 49_152);
        companion.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
        companion.credentials = Some(HapCredentials::transient().to_string());
        config.add_service(companion);

        assert_eq!(tunnel_credentials(&config), None);
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
