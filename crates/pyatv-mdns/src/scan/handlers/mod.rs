//! Per-protocol scan handlers, device-info extractors and service-info finishers.
//!
//! Every pyatv protocol module exposes the same three discovery entry points
//! (`pyatv/protocols/__init__.py:27-73`):
//!
//! ```python
//! def scan() -> Mapping[str, ScanHandlerDeviceInfoName]: ...
//! def device_info(service_type: str, properties: Mapping[str, Any]) -> Dict[str, Any]: ...
//! async def service_info(service, devinfo, services) -> None: ...
//! ```
//!
//! The three type aliases below are the Rust shape of those, and each submodule ports one
//! protocol's implementation verbatim. Nothing here does I/O: a handler turns one already-parsed
//! [`Service`] into a [`BaseService`], which is what makes the whole layer testable from fixtures.

mod airplay;
mod companion;
mod dmap;
mod mrp;
mod raop;

use std::collections::HashMap;

use pyatv_core::device_info::DeviceInfoValue;
use pyatv_core::{BaseService, DeviceInfo};

use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

pub use airplay::AIRPLAY;
pub use companion::{COMPANION, PAIRING_DISABLED_MASK, PAIRING_WITH_PIN_SUPPORTED_MASK};
pub use dmap::{APPLETV_V2, HSCP, TOUCH_ABLE};
pub use mrp::{MRP, TVOS_15_BUILD_MAJOR};
pub use raop::{AIRPORT, RAOP};

/// Turn one discovered mDNS service into a display name plus a [`BaseService`].
///
/// `ScanHandler` in `pyatv/core/scan.py:48`. Returning `None` means "this service type carries
/// useful TXT data but is not a protocol endpoint" — `_airport._tcp.local` is the one built-in
/// case (`pyatv/protocols/raop/__init__.py:461-464`). Its properties are still recorded against
/// the device; see [`crate::scan::registry`].
pub type ScanHandler = fn(&Service, &Response) -> Option<(String, BaseService)>;

/// Pull [`DeviceInfo`] fields out of one service type's TXT record.
///
/// `DevInfoExtractor` in `pyatv/core/scan.py:53`. The `ServiceType` argument matters only for
/// DMAP, which returns a different model for `_hscp._tcp.local` than for its two siblings
/// (`pyatv/protocols/dmap/__init__.py:630-640`).
pub type DevInfoExtractor = fn(ServiceType, &Properties) -> HashMap<String, DeviceInfoValue>;

/// Finish a service once every service for the device has been discovered and merged.
///
/// `ServiceInfoMethod` in `pyatv/core/scan.py:54-56`. The slice is the snapshot of *all* the
/// device's services that upstream passes as `properties_map`; RAOP is the one protocol that
/// actually reads it, consulting its `AirPlay` sibling's access-control keys
/// (`pyatv/protocols/raop/__init__.py:496-514`).
///
/// Upstream's is `async` purely because pyatv declares it so; none of the five implementations
/// awaits anything, so this port is synchronous.
pub type ServiceInfoFn = fn(&mut BaseService, &DeviceInfo, &[BaseService]);

/// Everything one protocol contributes for one DNS-SD service type.
#[derive(Debug, Clone, Copy)]
pub struct ProtocolHandlers {
    /// The service type this entry is keyed by.
    pub service_type: ServiceType,
    /// `scan()[service_type][0]`.
    pub handler: ScanHandler,
    /// `device_info`, shared by every service type the protocol registers.
    pub extractor: DevInfoExtractor,
    /// `service_info`, registered per protocol rather than per service type.
    pub service_info: ServiceInfoFn,
}

/// Every scan handler pyatv registers, in the order the `PROTOCOLS` dict iterates
/// (`pyatv/protocols/__init__.py:37-73`): `AirPlay`, Companion, DMAP, MRP, RAOP — with each
/// protocol's own service types in the order its `scan()` returns them.
///
/// Reproducing that order matters less than it looks. It fixes only which service types a scan
/// asks for and in what sequence; it does **not** decide device-info precedence, which is
/// response-arrival order (see [`crate::scan::registry::build_configs`]).
///
/// `AIRPORT` sits next to `RAOP` because `pyatv/protocols/raop/__init__.py:458-465` registers both
/// from one `scan()`. The two meta types (`_device-info._tcp` and `_sleep-proxy._udp`) are absent
/// because no protocol owns them — the registry adds them itself.
pub const ALL: [ProtocolHandlers; 8] = [
    AIRPLAY, COMPANION, APPLETV_V2, TOUCH_ABLE, HSCP, MRP, RAOP, AIRPORT,
];

/// Copy a service's TXT record into the plain map [`BaseService`] stores.
///
/// [`Properties`] already lowercases its keys the way pyatv's `CaseInsensitiveDict` does
/// (`pyatv/support/collections.py:31-73`), so the resulting `HashMap` can be looked up with the
/// lowercase spelling every `device_info`/`service_info` implementation uses.
pub(crate) fn owned_properties(properties: &Properties) -> HashMap<String, String> {
    properties
        .iter()
        .map(|(key, value)| (key.to_owned(), value.clone()))
        .collect()
}

/// Derive the identifier a service type advertises itself by.
///
/// Ports `pyatv/helpers.py:54-87` (`get_unique_id`) in full. This is the same function the scanner
/// uses to decide it has found the device the caller asked for and the one that ends up on
/// [`BaseService::identifier`], which is what keeps the two answers in agreement
/// (`pyatv/core/scan.py:89-96`).
///
/// Per branch:
///
/// - `_touch-able._tcp.local` / `_appletv-v2._tcp.local`: everything before the first `_` of the
///   *instance name*, not a TXT key. Untested upstream — pyatv's own fixtures never put an `_` in
///   these names, so `split("_")[0]` is always the whole name there. See
///   `docs/research/discovery-port-spec.md` §9.10.
/// - `_hscp._tcp.local`: the `Machine ID` TXT key, with a literal space.
/// - `_mediaremotetv._tcp.local`: `UniqueIdentifier`.
/// - `_airplay._tcp.local`: `deviceid`, which is also what becomes [`DeviceInfo::MAC`].
/// - `_companion-link._tcp.local`: `rpmrtid`, absent on most devices, which is why a
///   Companion-only device is never [`pyatv_core::BaseConfig::ready`].
/// - `_raop._tcp.local`: the `id` half of an `id@name` instance name, else the `pk` TXT key for
///   receivers that leave the identifier out.
/// - anything else: `None`.
#[must_use]
pub fn get_unique_id(
    service_type: ServiceType,
    service_name: &str,
    properties: &Properties,
) -> Option<String> {
    match service_type {
        ServiceType::TouchAble | ServiceType::AppleTvV2 => Some(
            service_name
                .split('_')
                .next()
                .unwrap_or(service_name)
                .to_owned(),
        ),
        ServiceType::Hscp => properties.get("Machine ID").cloned(),
        ServiceType::MediaRemoteTv => properties.get("UniqueIdentifier").cloned(),
        ServiceType::AirPlay => properties.get("deviceid").cloned(),
        ServiceType::CompanionLink => properties.get("rpmrtid").cloned(),
        ServiceType::Raop => match service_name.split_once('@') {
            Some((identifier, _)) => Some(identifier.to_owned()),
            None => properties.get("pk").cloned(),
        },
        ServiceType::AirPort | ServiceType::DeviceInfo | ServiceType::SleepProxy => None,
    }
}

/// Every identifier a response advertises, in service order.
///
/// Ports `get_unique_identifiers` (`pyatv/core/scan.py:89-96`). Multicast scanning uses this to
/// stop the moment the wanted device answers.
#[must_use]
pub fn unique_identifiers(response: &Response) -> Vec<String> {
    response
        .services
        .iter()
        .filter_map(|service| {
            let service_type = ServiceType::from_wire_name(&service.service_type)?;
            get_unique_id(service_type, &service.name, &service.properties)
        })
        .filter(|identifier| !identifier.is_empty())
        .collect()
}

/// The leading `(\d+)` of a build number, when it is followed by an uppercase ASCII letter.
///
/// `re.match(r"^(\d+)[A-Z]", build)`, which appears identically in `lookup_version`
/// (`pyatv/support/device_info.py:119-125`) and in MRP's tvOS-15 check
/// (`pyatv/protocols/mrp/__init__.py:1032-1038`).
fn build_major(build: &str) -> Option<u32> {
    let digits_len = build
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(build.len());
    if digits_len == 0 || !build[digits_len..].starts_with(|c: char| c.is_ascii_uppercase()) {
        return None;
    }
    build[..digits_len].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{build_major, get_unique_id};
    use crate::dns::Properties;
    use crate::service_types::ServiceType;

    fn properties(pairs: &[(&str, &str)]) -> Properties {
        let mut map = Properties::new();
        for (key, value) in pairs {
            map.insert(key, (*value).to_owned());
        }
        map
    }

    /// `tests/protocols/airplay/test_airplay_scan.py:28` — `deviceid` is the `AirPlay` identifier.
    #[test]
    fn airplay_identifier_is_deviceid() {
        assert_eq!(
            get_unique_id(
                ServiceType::AirPlay,
                "AirPlay ATV",
                &properties(&[("deviceid", "AA:BB:CC:DD:EE:FF")])
            )
            .as_deref(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    /// `tests/protocols/raop/test_raop_scan.py` — `"{id}@{name}"` instance names.
    #[test]
    fn raop_identifier_comes_from_the_instance_name() {
        assert_eq!(
            get_unique_id(
                ServiceType::Raop,
                "AABBCCDDEEFF@RAOP ATV",
                &Properties::new()
            )
            .as_deref(),
            Some("AABBCCDDEEFF")
        );
    }

    /// `pyatv/helpers.py:78-86` — receivers that leave the id out fall back to `pk`.
    #[test]
    fn raop_identifier_falls_back_to_the_public_key() {
        assert_eq!(
            get_unique_id(
                ServiceType::Raop,
                "RAOP ATV",
                &properties(&[("pk", "abc123")])
            )
            .as_deref(),
            Some("abc123")
        );
        assert_eq!(
            get_unique_id(ServiceType::Raop, "RAOP ATV", &Properties::new()),
            None
        );
    }

    /// `pyatv/helpers.py:67-68` — legacy DMAP splits the instance name, it reads no TXT key.
    #[test]
    fn legacy_dmap_identifiers_come_from_the_instance_name() {
        for service_type in [ServiceType::TouchAble, ServiceType::AppleTvV2] {
            assert_eq!(
                get_unique_id(service_type, "DMAP service", &Properties::new()).as_deref(),
                Some("DMAP service")
            );
            assert_eq!(
                get_unique_id(service_type, "abc_def", &Properties::new()).as_deref(),
                Some("abc")
            );
        }
    }

    /// `pyatv/helpers.py:69-70` — a literal space in the TXT key, matched case-insensitively.
    #[test]
    fn hscp_identifier_is_the_machine_id() {
        assert_eq!(
            get_unique_id(
                ServiceType::Hscp,
                "HSCP Name",
                &properties(&[("machine id", "DMAP service")])
            )
            .as_deref(),
            Some("DMAP service")
        );
    }

    /// `tests/protocols/companion/test_companion_scan.py:23-31` — the fixture has no `rpmrtid`,
    /// so a lone Companion service can never make a device ready.
    #[test]
    fn companion_has_no_identifier_without_rpmrtid() {
        assert_eq!(
            get_unique_id(
                ServiceType::CompanionLink,
                "Companion",
                &properties(&[("rpHA", "33efedd528a")])
            ),
            None
        );
    }

    #[test]
    fn enrichment_only_types_never_yield_an_identifier() {
        for service_type in [
            ServiceType::AirPort,
            ServiceType::DeviceInfo,
            ServiceType::SleepProxy,
        ] {
            assert_eq!(
                get_unique_id(service_type, "whatever", &Properties::new()),
                None
            );
        }
    }

    #[test]
    fn build_major_matches_the_upstream_regex() {
        assert_eq!(build_major("19J346"), Some(19));
        assert_eq!(build_major("18M60"), Some(18));
        assert_eq!(build_major(""), None);
        assert_eq!(build_major("J346"), None);
        // Lowercase letter: `[A-Z]` does not match.
        assert_eq!(build_major("19j346"), None);
    }
}
