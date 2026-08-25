//! Which credentials to authenticate an AirPlay connection with.
//!
//! Two callers want an answer and they want slightly different ones: the MRP tunnel
//! ([`tunnel_credentials`]) needs a HAP pairing or nothing, because it is the only kind its
//! channels can derive keys from; `play_url` ([`play_credentials`]) will take whatever the service
//! itself holds, since `AirPlay` 1 devices are authenticated with legacy credentials or with none
//! at all.
//!
//! Both share one divergence from upstream, and it is the divergence that makes either feature
//! usable on current hardware. See [`tunnel_credentials`] for the evidence.

use pyatv_core::consts::Protocol;
use pyatv_core::models::{BaseConfig, BaseService};
use pyatv_pairing::{AuthenticationType, HapCredentials};

use crate::Result;
use crate::auth::extract_credentials;

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

/// Pick the credentials `play_url` should authenticate with.
///
/// Upstream reads one place and one place only: `parse_credentials(self.service.credentials)`, the
/// AirPlay service's own stored string (`__init__.py:84,152`). That is tried first here too, so a
/// device paired the ordinary way behaves exactly as it does under pyatv.
///
/// **The fallback is the same divergence [`tunnel_credentials`] documents.** On the tvOS 27 test
/// device the AirPlay service can never hold credentials, while its `/pair-verify` accepts any HAP
/// pairing registered on the device whichever protocol created it. `play_url` verifies through the
/// very same `verify_connection` call the tunnel does, so the same substitution works and the same
/// evidence backs it.
///
/// Last comes [`extract_credentials`], upstream's own inference: a device advertising the AirPlay 2
/// pairing bits gets transient credentials, anything else gets none. That is last rather than
/// second because the test device refuses transient pairing outright with `470`, so trying it ahead
/// of a Companion pairing that works would turn a playable device into an error.
///
/// # Errors
///
/// Returns [`crate::Error::Pairing`] if the AirPlay service's own credential string is malformed —
/// a caller asked for those credentials specifically, so silently reaching past them would hide a
/// typo in a settings file.
pub fn play_credentials(config: &BaseConfig, service: &BaseService) -> Result<HapCredentials> {
    if let Some(stored) = service.credentials.as_deref().filter(|it| !it.is_empty()) {
        return Ok(HapCredentials::parse(stored)?);
    }

    if let Some(borrowed) = tunnel_credentials(config) {
        tracing::debug!("no AirPlay credentials stored, playing with another service's pairing");
        return Ok(borrowed);
    }

    extract_credentials(service)
}

#[cfg(test)]
mod tests {
    use super::{play_credentials, tunnel_credentials};
    use crate::setup::tests::{hap_credentials, test_device_service};
    use pyatv_core::consts::Protocol;
    use pyatv_core::models::{BaseConfig, BaseService};
    use pyatv_pairing::{AuthenticationType, HapCredentials};

    fn companion() -> BaseService {
        let mut companion = BaseService::new(Protocol::Companion, 49_152);
        companion.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
        companion.credentials = Some(hap_credentials().to_string());
        companion
    }

    fn other_credentials() -> HapCredentials {
        HapCredentials::parse(&format!(
            "{}:{}:{}:{}",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(36),
            "44".repeat(36)
        ))
        .expect("well-formed")
    }

    /// The documented divergence: with no AirPlay credentials, Companion's are used.
    #[test]
    fn companion_credentials_are_the_fallback() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));
        config.add_service(test_device_service());

        assert!(tunnel_credentials(&config).is_none());

        config.add_service(companion());
        assert_eq!(tunnel_credentials(&config), Some(hap_credentials()));
    }

    /// AirPlay's own credentials win when it has any, which is upstream's only source.
    #[test]
    fn airplay_credentials_win_over_companions() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));

        let mut airplay = test_device_service();
        airplay.credentials = Some(other_credentials().to_string());
        config.add_service(airplay);
        config.add_service(companion());

        assert_eq!(tunnel_credentials(&config), Some(other_credentials()));
    }

    /// Non-HAP credentials are skipped rather than returned and rejected later.
    #[test]
    fn transient_and_null_credentials_are_not_used() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));

        let mut companion = companion();
        companion.credentials = Some(HapCredentials::transient().to_string());
        config.add_service(companion);

        assert_eq!(tunnel_credentials(&config), None);
    }

    /// AirPlay's own credentials win, then Companion's, then upstream's inference. The middle step
    /// is this port's divergence; the last is what pyatv would have done on its own.
    #[test]
    fn play_credentials_fall_back_in_order() {
        let mut config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));
        let service = test_device_service();
        config.add_service(service.clone());

        // Neither service has credentials, so upstream's inference applies — and this device
        // advertises the AirPlay 2 pairing bits, so it infers transient.
        assert_eq!(
            play_credentials(&config, &service)
                .expect("credentials")
                .authentication_type(),
            AuthenticationType::Transient
        );

        // A Companion HAP pairing is preferred over that inference, because the device refuses
        // transient pairing outright.
        config.add_service(companion());
        assert_eq!(
            play_credentials(&config, &service).expect("credentials"),
            hap_credentials()
        );

        // And the service's own beat everything.
        let mut own = service.clone();
        own.credentials = Some(other_credentials().to_string());
        assert_eq!(
            play_credentials(&config, &own).expect("credentials"),
            other_credentials()
        );
    }

    /// A malformed stored string is an error rather than a silent fall-through, so a typo in a
    /// settings file is visible.
    #[test]
    fn a_malformed_stored_credential_is_an_error() {
        let config = BaseConfig::new("Living Room", "10.0.0.5".parse().expect("an address"));
        let mut service = test_device_service();
        service.credentials = Some("not:credentials".to_owned());

        assert!(play_credentials(&config, &service).is_err());
    }
}
