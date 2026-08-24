//! Password, pairing and remote-control classification from `AirPlay` TXT records.
//!
//! Ports `pyatv/protocols/airplay/utils.py:24-34,44-47,121-180,262-278`.

use std::collections::HashMap;

use crate::consts::PairingRequirement;
use crate::device_info::matches_hardware_identifier;
use crate::models::BaseService;

/// Status-flag bit meaning "the device shows a PIN".
///
/// Verbatim from `pyatv/protocols/airplay/utils.py:25`.
pub const PIN_REQUIRED: u64 = 0x8;

/// Status-flag bit meaning "a password is required".
///
/// Verbatim from `pyatv/protocols/airplay/utils.py:26`.
pub const PASSWORD_BIT: u64 = 0x80;

/// Status-flag bit meaning "legacy pairing is required".
///
/// Verbatim from `pyatv/protocols/airplay/utils.py:27`.
pub const LEGACY_PAIRING_BIT: u64 = 0x200;

/// Models pyatv refuses to pair with.
///
/// Verbatim from `pyatv/protocols/airplay/utils.py:34` (`UNSUPPORTED_MODELS = [r"^Mac\d+,\d+$"]`).
/// Stored as the literal prefix because the rest of the upstream pattern is the fixed
/// `\d+,\d+` shape [`matches_hardware_identifier`] already understands.
const UNSUPPORTED_MODEL_PREFIXES: [&str; 1] = ["Mac"];

/// What kind of credentials a caller holds for a service.
///
/// The part of `pyatv/auth/hap_pairing.py::AuthenticationType` that
/// [`is_remote_control_supported`] actually distinguishes. It is restated here rather than imported
/// because credentials live in `pyatv-pairing`, which depends on this crate; a full
/// `AuthenticationType` in core would invert the dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum CredentialsKind {
    /// Transient HAP credentials, i.e. `TRANSIENT_CREDENTIALS`.
    Transient,
    /// Full HAP credentials from a completed pairing.
    Hap,
    /// Anything else: no credentials, or legacy `AirPlay` credentials.
    #[default]
    Other,
}

/// Read the status flags out of a service's TXT record.
///
/// Ports `_get_flags` (`pyatv/protocols/airplay/utils.py:44-47`). The value lives under `sf` on
/// `AirPlay` 1 and under `flags` on `AirPlay` 2; upstream takes the first non-empty of the two and
/// falls back to `0x0`.
///
/// Upstream calls `int(flags, 16)`, which raises on garbage. Here a malformed value reads as `0`:
/// one badly-behaved receiver should not abort a whole scan.
fn get_flags(properties: &HashMap<String, String>) -> u64 {
    let raw = properties
        .get("sf")
        .filter(|it| !it.is_empty())
        .or_else(|| properties.get("flags").filter(|it| !it.is_empty()))
        .map_or("0x0", String::as_str);

    let digits = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"));
    match digits {
        Some(digits) => u64::from_str_radix(digits, 16).unwrap_or(0),
        None => u64::from_str_radix(raw, 16).unwrap_or(0),
    }
}

/// Whether the service demands a password.
///
/// Ports `is_password_required` (`pyatv/protocols/airplay/utils.py:121-136`). Two independent
/// signals, either of which is sufficient: the `pw` key set to `true` (case-insensitively), or
/// [`PASSWORD_BIT`] set in the status flags.
#[must_use]
pub fn is_password_required(service: &BaseService) -> bool {
    if service
        .properties
        .get("pw")
        .is_some_and(|it| it.eq_ignore_ascii_case("true"))
    {
        return true;
    }

    get_flags(&service.properties) & PASSWORD_BIT != 0
}

/// Whether the service must be paired before use.
///
/// Ports `get_pairing_requirement` (`pyatv/protocols/airplay/utils.py:139-157`):
///
/// - [`PairingRequirement::Mandatory`] when [`LEGACY_PAIRING_BIT`] or [`PIN_REQUIRED`] is set.
/// - [`PairingRequirement::Unsupported`] when `act` (Access Control Type) is `"2"`, which appears
///   to mean "Current User" — a mode pyatv cannot pair with.
/// - [`PairingRequirement::NotNeeded`] otherwise. Upstream calls this optimistic, and it is: the
///   absence of a bit is being read as proof that pairing is unnecessary.
#[must_use]
pub fn get_pairing_requirement(service: &BaseService) -> PairingRequirement {
    if get_flags(&service.properties) & (LEGACY_PAIRING_BIT | PIN_REQUIRED) != 0 {
        return PairingRequirement::Mandatory;
    }

    if service.properties.get("act").is_some_and(|it| it == "2") {
        return PairingRequirement::Unsupported;
    }

    PairingRequirement::NotNeeded
}

/// Fill in a discovered service's password and pairing fields from its TXT record.
///
/// Ports `update_service_details` (`pyatv/protocols/airplay/utils.py:262-278`). This is what a scan
/// handler calls once it has collected the TXT keys for an `AirPlay` or RAOP service.
///
/// The three pairing branches are checked in this order and the order matters:
///
/// 1. `acl` (Access Control List) set to `"1"` means the device restricts pairing to members of the
///    same home, which pyatv does not implement → [`PairingRequirement::Disabled`].
/// 2. The model matches [`UNSUPPORTED_MODEL_PREFIXES`] → [`PairingRequirement::Unsupported`].
/// 3. Otherwise, whatever [`get_pairing_requirement`] says.
pub fn update_service_details(service: &mut BaseService) {
    service.requires_password = is_password_required(service);

    let model = service
        .properties
        .get("model")
        .map_or("", String::as_str)
        .to_owned();

    service.pairing = if service.properties.get("acl").is_some_and(|it| it == "1") {
        PairingRequirement::Disabled
    } else if UNSUPPORTED_MODEL_PREFIXES
        .iter()
        .any(|prefix| matches_hardware_identifier(&model, prefix, true))
    {
        PairingRequirement::Unsupported
    } else {
        get_pairing_requirement(service)
    };
}

/// Whether the device can tunnel a remote-control (MRP) session over `AirPlay`.
///
/// Ports `is_remote_control_supported` (`pyatv/protocols/airplay/utils.py:160-180`), including the
/// `TODO` above it: upstream does not know how to detect this properly and is guessing from the
/// model string and the advertised OS version. Both the model prefixes and the version threshold
/// are heuristics.
///
/// - `AudioAccessory*` (HomePods) support it, but only with transient credentials.
/// - `AppleTV*` support it from tvOS 13 onwards, and only with full HAP credentials.
/// - Anything else does not.
///
/// Simplification: upstream compares `credentials == TRANSIENT_CREDENTIALS`, i.e. against one
/// specific credentials value, where this takes [`CredentialsKind::Transient`]. Any credentials
/// whose type is transient are constructed from that same singleton in practice, so the two agree.
///
/// A non-numeric `osvers` reads as version `0`. Upstream lets `float()` raise instead.
#[must_use]
pub fn is_remote_control_supported(service: &BaseService, credentials: CredentialsKind) -> bool {
    let model = service.properties.get("model").map_or("", String::as_str);

    if model.starts_with("AudioAccessory") {
        return credentials == CredentialsKind::Transient;
    }
    if !model.starts_with("AppleTV") {
        return false;
    }

    let major: u32 = service
        .properties
        .get("osvers")
        .map_or("0", String::as_str)
        .split('.')
        .next()
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);

    major >= 13 && credentials == CredentialsKind::Hap
}

#[cfg(test)]
mod tests {
    use super::{
        CredentialsKind, get_pairing_requirement, is_password_required,
        is_remote_control_supported, update_service_details,
    };
    use crate::consts::{PairingRequirement, Protocol};
    use crate::models::BaseService;

    fn service(protocol: Protocol, properties: &[(&str, &str)]) -> BaseService {
        let mut service = BaseService::new(protocol, 0);
        service.identifier = Some("id".to_owned());
        for (key, value) in properties {
            service
                .properties
                .insert((*key).to_owned(), (*value).to_owned());
        }
        service
    }

    /// Ports `tests/protocols/airplay/test_utils.py::test_is_password_required`.
    #[test]
    fn is_password_required_matches_upstream() {
        let cases: [(&[(&str, &str)], bool); 8] = [
            (&[], false),
            (&[("pw", "false")], false),
            (&[("pw", "true")], true),
            (&[("pw", "TRUE")], true),
            (&[("sf", "0x1")], false),
            (&[("sf", "0x80")], true),
            (&[("flags", "0x1")], false),
            (&[("flags", "0x80")], true),
        ];

        for (properties, expected) in cases {
            assert_eq!(
                is_password_required(&service(Protocol::Raop, properties)),
                expected,
                "{properties:?}"
            );
        }
    }

    /// Ports `tests/protocols/airplay/test_utils.py::test_get_pairing_requirement`.
    #[test]
    fn get_pairing_requirement_matches_upstream() {
        let cases: [(&[(&str, &str)], PairingRequirement); 10] = [
            (&[("sf", "0x1")], PairingRequirement::NotNeeded),
            (&[("sf", "0x200")], PairingRequirement::Mandatory),
            (&[("ft", "0x1")], PairingRequirement::NotNeeded),
            (&[("flags", "0x1")], PairingRequirement::NotNeeded),
            (&[("flags", "0x200")], PairingRequirement::Mandatory),
            (&[("features", "0x1")], PairingRequirement::NotNeeded),
            (&[("sf", "0x8")], PairingRequirement::Mandatory),
            (&[("flags", "0x8")], PairingRequirement::Mandatory),
            (&[("flags", "0x0")], PairingRequirement::NotNeeded),
            // "Current User" access control, which pyatv cannot pair with.
            (&[("act", "2")], PairingRequirement::Unsupported),
        ];

        for (properties, expected) in cases {
            assert_eq!(
                get_pairing_requirement(&service(Protocol::AirPlay, properties)),
                expected,
                "{properties:?}"
            );
        }
    }

    /// `sf` is consulted before `flags`.
    #[test]
    fn status_flags_prefer_sf_over_flags() {
        let service = service(Protocol::AirPlay, &[("sf", "0x0"), ("flags", "0x200")]);
        assert_eq!(
            get_pairing_requirement(&service),
            PairingRequirement::NotNeeded
        );
    }

    /// A garbled status-flag value must read as zero rather than abort the scan.
    #[test]
    fn status_flags_degrade_on_garbage() {
        let service = service(Protocol::AirPlay, &[("sf", "not-a-number")]);
        assert_eq!(
            get_pairing_requirement(&service),
            PairingRequirement::NotNeeded
        );
    }

    /// Ports `tests/protocols/airplay/test_utils.py::test_is_remote_control_supported`.
    #[test]
    fn is_remote_control_supported_matches_upstream() {
        /// One upstream parametrisation: TXT properties, credentials held, expected answer.
        type Case = (
            &'static [(&'static str, &'static str)],
            CredentialsKind,
            bool,
        );

        let cases: [Case; 10] = [
            (&[], CredentialsKind::Other, false),
            (
                &[("model", "AudioAccessory1,2")],
                CredentialsKind::Other,
                false,
            ),
            (
                &[("model", "AudioAccessory1,2")],
                CredentialsKind::Transient,
                true,
            ),
            (&[("model", "Foo")], CredentialsKind::Other, false),
            (&[("osvers", "13.0")], CredentialsKind::Other, false),
            (
                &[("osvers", "13.0"), ("model", "AppleTV5,6")],
                CredentialsKind::Other,
                false,
            ),
            (
                &[("osvers", "13.0"), ("model", "AppleTV5,6")],
                CredentialsKind::Transient,
                false,
            ),
            // Legacy credentials are neither transient nor HAP.
            (
                &[("osvers", "13.0"), ("model", "AppleTV5,6")],
                CredentialsKind::Other,
                false,
            ),
            (
                &[("osvers", "13.0"), ("model", "AppleTV5,6")],
                CredentialsKind::Hap,
                true,
            ),
            (
                &[("osvers", "8.4.4"), ("model", "AppleTV5,6")],
                CredentialsKind::Hap,
                false,
            ),
        ];

        for (properties, credentials, expected) in cases {
            assert_eq!(
                is_remote_control_supported(&service(Protocol::AirPlay, properties), credentials),
                expected,
                "{properties:?} {credentials:?}"
            );
        }
    }

    /// `acl=1` beats everything else, even a status flag that would say Mandatory.
    #[test]
    fn update_service_details_disables_pairing_for_access_controlled_devices() {
        let mut service = service(Protocol::AirPlay, &[("acl", "1"), ("sf", "0x200")]);
        update_service_details(&mut service);
        assert_eq!(service.pairing, PairingRequirement::Disabled);
    }

    /// `^Mac\d+,\d+$` is the one model family pyatv will not pair with.
    #[test]
    fn update_service_details_marks_macs_unsupported() {
        let mut service = service(Protocol::AirPlay, &[("model", "Mac14,3"), ("sf", "0x200")]);
        update_service_details(&mut service);
        assert_eq!(service.pairing, PairingRequirement::Unsupported);
    }

    /// The pattern is fully anchored, so a Mac-like model that is not exactly `Mac<n>,<n>` falls
    /// through to the normal classification.
    #[test]
    fn update_service_details_anchors_the_unsupported_model_pattern() {
        let mut service = service(
            Protocol::AirPlay,
            &[("model", "MacBookPro14,3"), ("sf", "0x200")],
        );
        update_service_details(&mut service);
        assert_eq!(service.pairing, PairingRequirement::Mandatory);
    }

    #[test]
    fn update_service_details_fills_in_password_and_pairing() {
        let mut service = service(
            Protocol::AirPlay,
            &[("pw", "true"), ("sf", "0x8"), ("model", "AppleTV6,2")],
        );
        update_service_details(&mut service);

        assert!(service.requires_password);
        assert_eq!(service.pairing, PairingRequirement::Mandatory);
    }

    #[test]
    fn update_service_details_leaves_an_open_device_alone() {
        let mut service = service(Protocol::Raop, &[("model", "AppleTV6,2")]);
        update_service_details(&mut service);

        assert!(!service.requires_password);
        assert_eq!(service.pairing, PairingRequirement::NotNeeded);
    }
}
