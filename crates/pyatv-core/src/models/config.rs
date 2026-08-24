//! A single physical device and every protocol service discovered on it.
//!
//! Ports `pyatv/interface.py::BaseConfig` (`pyatv/interface.py:1320-1468`) together with its only
//! concrete subclass `pyatv/conf.py::AppleTV` (`pyatv/conf.py:17-96`). Upstream splits them so a
//! caller can hand-build a config without the scanner; here one struct covers both, because the
//! abstract half carries no state beyond the Zeroconf properties.
//!
//! The service collection is a `Vec` rather than a map because `AppleTV._services` is a
//! `Dict[Protocol, BaseService]` whose `services` property returns `list(...values())` — i.e. it is
//! already keyed by protocol *and* insertion-ordered, and [`BaseConfig::add_service`] preserves
//! both properties.

use std::net::IpAddr;

use crate::consts::Protocol;
use crate::device_info::DeviceInfo;
use crate::models::service::BaseService;

/// The protocols [`BaseConfig::identifier`] consults, in order.
///
/// Verbatim from `pyatv/interface.py:1388-1394`. Note that it is *not* the same order as
/// [`MAIN_SERVICE_PRIORITY`]: `identifier` includes Companion (last), `main_service` excludes it.
const IDENTIFIER_PRIORITY: [Protocol; 5] = [
    Protocol::Mrp,
    Protocol::Dmap,
    Protocol::AirPlay,
    Protocol::Raop,
    Protocol::Companion,
];

/// The protocols [`BaseConfig::main_service`] consults, in order.
///
/// Verbatim from `pyatv/interface.py:1407-1411`. Companion is absent upstream: it cannot drive a
/// session on its own, so a Companion-only device has no main service.
const MAIN_SERVICE_PRIORITY: [Protocol; 4] = [
    Protocol::Mrp,
    Protocol::Dmap,
    Protocol::AirPlay,
    Protocol::Raop,
];

/// A single physical device and every protocol service discovered on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseConfig {
    /// Human-readable device name from the mDNS instance name.
    pub name: String,
    /// Address the device answered from.
    pub address: IpAddr,
    /// Whether the device answered from deep sleep, i.e. via a sleep proxy.
    ///
    /// Mirrors `pyatv/conf.py:51-54` (`AppleTV.deep_sleep`); the scanner sets it when the mDNS
    /// response came from `_sleep-proxy._udp`.
    pub deep_sleep: bool,
    /// Hardware and OS details merged from every service's device-info extractor.
    pub device_info: DeviceInfo,
    /// Every discovered service, at most one per protocol, in discovery order.
    pub services: Vec<BaseService>,
}

impl BaseConfig {
    /// A config for a device found at `address`, with no services yet.
    ///
    /// Mirrors `AppleTV.__init__` (`pyatv/conf.py:25-39`), whose only required arguments are the
    /// address and the name; everything else defaults and is filled in by
    /// [`BaseConfig::add_service`] as discovery progresses.
    #[must_use]
    pub fn new(name: impl Into<String>, address: IpAddr) -> Self {
        Self {
            name: name.into(),
            address,
            deep_sleep: false,
            device_info: DeviceInfo::default(),
            services: Vec::new(),
        }
    }

    /// Add a service, merging it into the existing one when the protocol is already known.
    ///
    /// Ports `pyatv/conf.py:56-65` (`AppleTV.add_service`): a second sighting of the same protocol
    /// does not replace the first, it is folded in through [`BaseService::merge`]. Discovery relies
    /// on this because one device answers on several mDNS service types, each carrying a partial
    /// view — for example `_airplay._tcp` supplies the identifier while `_raop._tcp` supplies the
    /// audio parameters.
    pub fn add_service(&mut self, service: BaseService) {
        if let Some(existing) = self
            .services
            .iter_mut()
            .find(|it| it.protocol == service.protocol)
        {
            existing.merge(&service);
        } else {
            self.services.push(service);
        }
    }

    /// The service for a given protocol, if the device advertises one.
    ///
    /// Ports `pyatv/conf.py:67-73` (`AppleTV.get_service`).
    #[must_use]
    pub fn get_service(&self, protocol: Protocol) -> Option<&BaseService> {
        self.services.iter().find(|it| it.protocol == protocol)
    }

    /// Mutable access to the service for a given protocol.
    ///
    /// Not a distinct method upstream: `AppleTV.get_service` hands back a mutable object because
    /// every Python object is mutable. Split in two here so callers state their intent.
    pub fn get_service_mut(&mut self, protocol: Protocol) -> Option<&mut BaseService> {
        self.services.iter_mut().find(|it| it.protocol == protocol)
    }

    /// Whether the config is usable, i.e. at least one service carries an identifier.
    ///
    /// Ports `pyatv/interface.py:1377-1383` (`BaseConfig.ready`).
    #[must_use]
    pub fn ready(&self) -> bool {
        self.services.iter().any(|it| it.identifier.is_some())
    }

    /// The main identifier for this device.
    ///
    /// Ports `pyatv/interface.py:1385-1398` (`BaseConfig.identifier`): the first identifier found
    /// walking [`IDENTIFIER_PRIORITY`], *not* the first service in discovery order. Devices
    /// advertise a different identifier per protocol, so the priority is what makes the value
    /// stable across scans.
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        IDENTIFIER_PRIORITY
            .iter()
            .find_map(|&protocol| self.get_service(protocol)?.identifier.as_deref())
    }

    /// Every identifier this device is known by, in discovery order.
    ///
    /// Ports `pyatv/interface.py:1400-1403` (`BaseConfig.all_identifiers`). Callers match a device
    /// against a user-supplied id by testing membership in this list, because any one of a
    /// device's per-protocol identifiers is a legitimate way to name it.
    #[must_use]
    pub fn all_identifiers(&self) -> Vec<&str> {
        self.services
            .iter()
            .filter_map(|it| it.identifier.as_deref())
            .collect()
    }

    /// The service that should drive the connection when the caller does not pick one.
    ///
    /// Ports `pyatv/interface.py:1405-1415` (`BaseConfig.main_service`) with its `protocol`
    /// argument omitted: upstream's `main_service(protocol=X)` is defined to return
    /// `get_service(X)`, so [`BaseConfig::get_service`] already covers that case.
    ///
    /// Deliberately **not** filtered by [`BaseService::enabled`], matching upstream. The
    /// enabled check lives one level up in `pyatv/__init__.py:129-133`, where `connect()` skips
    /// disabled services as it sets each protocol up; see [`BaseConfig::enabled_services`].
    ///
    /// Returns `None` where pyatv raises `NoServiceError`.
    #[must_use]
    pub fn main_service(&self) -> Option<&BaseService> {
        MAIN_SERVICE_PRIORITY
            .iter()
            .find_map(|&protocol| self.get_service(protocol))
    }

    /// Every service the user has left enabled, in discovery order.
    ///
    /// This is the filter `pyatv/__init__.py:129-133` applies inside `connect()` before setting a
    /// protocol up.
    pub fn enabled_services(&self) -> impl Iterator<Item = &BaseService> {
        self.services.iter().filter(|it| it.enabled)
    }

    /// Set credentials on a protocol's service, reporting whether the protocol was present.
    ///
    /// Ports `pyatv/interface.py:1417-1423` (`BaseConfig.set_credentials`).
    pub fn set_credentials(&mut self, protocol: Protocol, credentials: impl Into<String>) -> bool {
        match self.get_service_mut(protocol) {
            Some(service) => {
                service.credentials = Some(credentials.into());
                true
            }
            None => false,
        }
    }
}

impl std::fmt::Display for BaseConfig {
    /// Reproduces `pyatv/interface.py:1448-1463` (`BaseConfig.__str__`), which is exactly what
    /// `atvremote scan` prints per device. The column alignment, the ` - ` list prefix and the
    /// Python-style `None`/`True`/`False` renderings are all part of that output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Upstream builds both blocks with `"\n".join(...)`, then interpolates them followed by a
        // literal "\n". An empty list therefore still costs one blank line. Reproduced, not tidied.
        let identifiers = self
            .all_identifiers()
            .iter()
            .map(|identifier| format!(" - {identifier}"))
            .collect::<Vec<_>>()
            .join("\n");
        let services = self
            .services
            .iter()
            .map(|service| format!(" - {service}"))
            .collect::<Vec<_>>()
            .join("\n");

        write!(
            f,
            "       Name: {name}\n   Model/SW: {device_info}\n    Address: {address}\n        MAC: {mac}\n Deep Sleep: {deep_sleep}\nIdentifiers:\n{identifiers}\nServices:\n{services}",
            name = self.name,
            device_info = self.device_info,
            address = self.address,
            mac = self.device_info.mac().unwrap_or("None"),
            deep_sleep = if self.deep_sleep { "True" } else { "False" },
        )
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::BaseConfig;
    use crate::consts::Protocol;
    use crate::models::service::BaseService;

    fn config() -> BaseConfig {
        BaseConfig::new("Living Room", IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)))
    }

    fn service(protocol: Protocol, port: u16, identifier: Option<&str>) -> BaseService {
        let mut service = BaseService::new(protocol, port);
        service.identifier = identifier.map(ToOwned::to_owned);
        service
    }

    #[test]
    fn new_starts_empty_and_not_ready() {
        let config = config();
        assert!(config.services.is_empty());
        assert!(!config.ready());
        assert!(config.identifier().is_none());
        assert!(config.main_service().is_none());
    }

    #[test]
    fn add_service_merges_a_second_sighting_of_the_same_protocol() {
        let mut config = config();
        config.add_service(service(Protocol::AirPlay, 7000, Some("aa")));

        let mut second = service(Protocol::AirPlay, 8000, Some("bb"));
        second.credentials = Some("creds".to_owned());
        second
            .properties
            .insert("model".into(), "AppleTV6,2".into());
        config.add_service(second);

        assert_eq!(config.services.len(), 1);
        let merged = config.get_service(Protocol::AirPlay).expect("service");
        // merge() only carries credentials/password/properties across.
        assert_eq!(merged.credentials.as_deref(), Some("creds"));
        assert_eq!(
            merged.properties.get("model").map(String::as_str),
            Some("AppleTV6,2")
        );
        assert_eq!(merged.identifier.as_deref(), Some("aa"));
        assert_eq!(merged.port, 7000);
    }

    #[test]
    fn add_service_appends_a_new_protocol_in_discovery_order() {
        let mut config = config();
        config.add_service(service(Protocol::Raop, 7000, Some("raop")));
        config.add_service(service(Protocol::Mrp, 49152, Some("mrp")));

        assert_eq!(
            config
                .services
                .iter()
                .map(|it| it.protocol)
                .collect::<Vec<_>>(),
            vec![Protocol::Raop, Protocol::Mrp]
        );
    }

    /// MRP outranks everything, regardless of the order services were discovered in.
    #[test]
    fn identifier_follows_the_upstream_priority_not_discovery_order() {
        let mut config = config();
        config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));
        config.add_service(service(Protocol::AirPlay, 7000, Some("airplay-id")));
        config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

        assert_eq!(config.identifier(), Some("mrp-id"));
    }

    #[test]
    fn identifier_skips_services_without_one() {
        let mut config = config();
        config.add_service(service(Protocol::Mrp, 49152, None));
        config.add_service(service(Protocol::Dmap, 3689, Some("dmap-id")));

        assert_eq!(config.identifier(), Some("dmap-id"));
    }

    /// Companion is last in the identifier order but is still consulted.
    #[test]
    fn identifier_falls_back_to_companion() {
        let mut config = config();
        config.add_service(service(Protocol::Companion, 49153, Some("companion-id")));
        assert_eq!(config.identifier(), Some("companion-id"));
    }

    #[test]
    fn all_identifiers_keeps_discovery_order_and_drops_empty_ones() {
        let mut config = config();
        config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));
        config.add_service(service(Protocol::Companion, 49153, None));
        config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

        assert_eq!(config.all_identifiers(), vec!["raop-id", "mrp-id"]);
    }

    #[test]
    fn ready_needs_one_identifier() {
        let mut config = config();
        config.add_service(service(Protocol::Companion, 49153, None));
        assert!(!config.ready());
        config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));
        assert!(config.ready());
    }

    #[test]
    fn main_service_prefers_mrp_then_dmap_then_airplay_then_raop() {
        let mut config = config();
        config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));
        assert_eq!(
            config.main_service().map(|it| it.protocol),
            Some(Protocol::Raop)
        );

        config.add_service(service(Protocol::AirPlay, 7000, Some("airplay-id")));
        assert_eq!(
            config.main_service().map(|it| it.protocol),
            Some(Protocol::AirPlay)
        );

        config.add_service(service(Protocol::Dmap, 3689, Some("dmap-id")));
        assert_eq!(
            config.main_service().map(|it| it.protocol),
            Some(Protocol::Dmap)
        );

        config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));
        assert_eq!(
            config.main_service().map(|it| it.protocol),
            Some(Protocol::Mrp)
        );
    }

    /// Companion cannot drive a session, so it is absent from upstream's `main_service` list.
    #[test]
    fn main_service_ignores_companion_only_devices() {
        let mut config = config();
        config.add_service(service(Protocol::Companion, 49153, Some("companion-id")));
        assert!(config.main_service().is_none());
    }

    /// Upstream's `main_service` has no `enabled` check; `connect()` filters separately.
    #[test]
    fn main_service_does_not_filter_disabled_services() {
        let mut config = config();
        let mut mrp = service(Protocol::Mrp, 49152, Some("mrp-id"));
        mrp.enabled = false;
        config.add_service(mrp);

        assert_eq!(
            config.main_service().map(|it| it.protocol),
            Some(Protocol::Mrp)
        );
        assert_eq!(config.enabled_services().count(), 0);
    }

    #[test]
    fn set_credentials_reports_whether_the_protocol_exists() {
        let mut config = config();
        config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

        assert!(config.set_credentials(Protocol::Mrp, "abc"));
        assert!(!config.set_credentials(Protocol::Dmap, "abc"));
        assert_eq!(
            config
                .get_service(Protocol::Mrp)
                .and_then(|it| it.credentials.as_deref()),
            Some("abc")
        );
    }

    #[test]
    fn display_matches_pyatv_base_config_str() {
        let mut config = config();
        config.add_service(service(Protocol::Mrp, 49152, Some("mrp-id")));

        let expected = [
            "       Name: Living Room",
            "   Model/SW: Unknown, Unknown OS",
            "    Address: 10.0.0.5",
            "        MAC: None",
            " Deep Sleep: False",
            "Identifiers:",
            " - mrp-id",
            "Services:",
            " - Protocol: MRP, Port: 49152, Credentials: None, Requires Password: False, \
             Password: None, Pairing: Unsupported",
        ]
        .join("\n");

        assert_eq!(config.to_string(), expected);
    }

    /// An empty device still renders both headings, each followed by the blank line upstream's
    /// `"\n".join([])` leaves behind.
    #[test]
    fn display_keeps_the_blank_lines_of_an_empty_config() {
        let expected = [
            "       Name: Living Room",
            "   Model/SW: Unknown, Unknown OS",
            "    Address: 10.0.0.5",
            "        MAC: None",
            " Deep Sleep: False",
            "Identifiers:",
            "",
            "Services:",
            "",
        ]
        .join("\n");

        assert_eq!(config().to_string(), expected);
    }
}
