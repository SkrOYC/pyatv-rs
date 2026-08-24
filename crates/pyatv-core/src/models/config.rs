//! A single physical device and every protocol service discovered on it.
//!
//! Ports `pyatv/interface.py::BaseConfig` (`pyatv/interface.py:1320-1468`) together with its only
//! concrete subclass `pyatv/conf.py::AppleTV` (`pyatv/conf.py:17-96`). Upstream splits them so a
//! caller can hand-build a config without the scanner; here one struct covers both, because the
//! abstract half carries no state beyond the Zeroconf properties — which this struct holds too,
//! see [`BaseConfig::set_properties`].
//!
//! The service collection is a `Vec` rather than a map because `AppleTV._services` is a
//! `Dict[Protocol, BaseService]` whose `services` property returns `list(...values())` — i.e. it is
//! already keyed by protocol *and* insertion-ordered, and [`BaseConfig::add_service`] preserves
//! both properties.

use std::collections::HashMap;
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
    /// Every TXT record the scan saw for this device, keyed by DNS-SD service type.
    ///
    /// Private because of the key invariants below; read it through [`BaseConfig::properties`],
    /// [`BaseConfig::property`] or [`BaseConfig::has_properties`] and write it through
    /// [`BaseConfig::set_properties`].
    properties: HashMap<String, HashMap<String, String>>,
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
            properties: HashMap::new(),
        }
    }

    /// Record the per-service-type TXT records the scan collected for this device.
    ///
    /// The scanner-side half of `AppleTV(properties=...)` (`pyatv/conf.py:25-37`), fed by
    /// `BaseScanner._properties[address]` (`pyatv/core/scan.py:227-231`). Kept off
    /// [`BaseConfig::new`] so a hand-built config stays as cheap to write as upstream's, where the
    /// argument is optional.
    ///
    /// Two key invariants the caller must uphold, both inherited from upstream:
    ///
    /// - The outer key is the DNS-SD service type **without a trailing dot**, exactly as pyatv
    ///   spells it: `"_airplay._tcp.local"`, `"_raop._tcp.local"`. That is the literal RAOP and
    ///   DMAP look themselves up by at connect time
    ///   (`pyatv/protocols/raop/__init__.py:562-567`, `pyatv/protocols/dmap/__init__.py:696-703`).
    /// - Inner keys are ASCII-lowercased, as on [`BaseService::properties`]. Read them back with
    ///   [`BaseConfig::property`], which lowercases before looking up.
    pub fn set_properties(&mut self, properties: HashMap<String, HashMap<String, String>>) {
        self.properties = properties;
    }

    /// [`BaseConfig::set_properties`] in builder form.
    #[must_use]
    pub fn with_properties(mut self, properties: HashMap<String, HashMap<String, String>>) -> Self {
        self.set_properties(properties);
        self
    }

    /// The TXT record a given DNS-SD service type advertised, if the scan saw that type.
    ///
    /// Ports `BaseConfig.properties` (`pyatv/interface.py:1373-1376`) at its only real call sites,
    /// which index it rather than iterating: `core.config.properties.get(service_type)` in RAOP's
    /// `_device_info` (`pyatv/protocols/raop/__init__.py:564`) and the `in` test plus lookup in
    /// DMAP's (`pyatv/protocols/dmap/__init__.py:699-702`).
    ///
    /// `service_type` is matched as spelled, so pass the dotless form —
    /// `"_airplay._tcp.local"`, not `"_airplay._tcp.local."`.
    ///
    /// Note this is **not** the same data as [`BaseService::properties`]: a service type that
    /// produced no [`BaseService`] at all still lands here, which is the entire reason
    /// `_airport._tcp.local` and `_sleep-proxy._udp.local` are visible to a device-info extractor.
    #[must_use]
    pub fn properties(&self, service_type: &str) -> Option<&HashMap<String, String>> {
        self.properties.get(service_type)
    }

    /// Whether the scan saw a given DNS-SD service type for this device.
    ///
    /// `service_type in core.config.properties` (`pyatv/protocols/dmap/__init__.py:699`).
    #[must_use]
    pub fn has_properties(&self, service_type: &str) -> bool {
        self.properties.contains_key(service_type)
    }

    /// One TXT key from one service type's record, matched case-insensitively.
    ///
    /// The [`BaseService::property`] convention applied to the config-level map: the stored inner
    /// keys are lowercase, so a wire-cased literal has to be folded before the lookup.
    #[must_use]
    pub fn property(&self, service_type: &str, key: &str) -> Option<&str> {
        let properties = self.properties.get(service_type)?;
        if let Some(value) = properties.get(key) {
            return Some(value.as_str());
        }
        properties
            .get(&key.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Every service type the scan saw for this device, with its TXT record.
    ///
    /// The whole `Mapping` upstream's `BaseConfig.properties` property returns, for the callers
    /// that genuinely want to walk it rather than index it.
    #[must_use]
    pub fn all_properties(&self) -> &HashMap<String, HashMap<String, String>> {
        &self.properties
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

    /// Apply persisted settings, so each service carries its stored credentials and password.
    ///
    /// Ports `pyatv/interface.py:1428-1440` (`BaseConfig.apply`) together with the
    /// [`BaseService::apply`] it delegates to: a setting that is unset never clears a value the
    /// config already has, so credentials passed on the command line survive a settings file that
    /// has none. Protocols the device does not advertise are skipped.
    ///
    /// This is what `scan()` and `connect()` call after reading storage
    /// (`pyatv/__init__.py:96-97,120-121`), and it is the reason a paired device needs no
    /// credential arguments on later runs.
    pub fn apply(&mut self, settings: &crate::storage::Settings) {
        for protocol in Protocol::ALL {
            let credentials = settings.protocols.credentials(protocol).map(str::to_owned);
            let password = settings.protocols.password(protocol).map(str::to_owned);

            if let Some(service) = self.get_service_mut(protocol) {
                service.apply(credentials.as_deref(), password.as_deref());
            }
        }
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
    ///
    /// [`BaseConfig::properties`] is deliberately absent: upstream's `__str__` never prints the
    /// Zeroconf property map, only the name, device info, address, MAC, deep-sleep flag,
    /// identifiers and services.
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
    use std::collections::HashMap;
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

    /// The map RAOP and DMAP index at connect time, keyed by the dotless service type.
    #[test]
    fn properties_are_keyed_by_service_type_and_read_case_insensitively() {
        let config = config().with_properties(HashMap::from([(
            "_airplay._tcp.local".to_owned(),
            HashMap::from([("deviceid".to_owned(), "AA:BB:CC:DD:EE:FF".to_owned())]),
        )]));

        assert!(config.has_properties("_airplay._tcp.local"));
        assert!(!config.has_properties("_raop._tcp.local"));
        // The trailing-dot spelling is a different key, as it is upstream.
        assert!(!config.has_properties("_airplay._tcp.local."));

        assert_eq!(
            config
                .properties("_airplay._tcp.local")
                .and_then(|it| it.get("deviceid"))
                .map(String::as_str),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(
            config.property("_airplay._tcp.local", "DeviceID"),
            Some("AA:BB:CC:DD:EE:FF")
        );
        assert_eq!(config.property("_airplay._tcp.local", "missing"), None);
        assert_eq!(config.property("_raop._tcp.local", "deviceid"), None);
        assert_eq!(config.all_properties().len(), 1);
    }

    #[test]
    fn properties_default_to_empty() {
        let config = config();
        assert!(config.all_properties().is_empty());
        assert!(config.properties("_airplay._tcp.local").is_none());
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

    #[test]
    fn apply_puts_each_protocols_settings_on_its_own_service() {
        let mut config = config();
        config.add_service(service(Protocol::Companion, 49153, Some("companion-id")));
        config.add_service(service(Protocol::Raop, 7000, Some("raop-id")));

        let mut settings = crate::storage::Settings::default();
        settings
            .protocols
            .set_credentials(Protocol::Companion, Some("companion-creds".to_owned()));
        settings
            .protocols
            .set_credentials(Protocol::Raop, Some("raop-creds".to_owned()));
        settings
            .protocols
            .set_password(Protocol::Raop, Some("hunter2".to_owned()));
        // A protocol the device does not advertise must not invent a service.
        settings
            .protocols
            .set_credentials(Protocol::Mrp, Some("mrp-creds".to_owned()));

        config.apply(&settings);

        let companion = config.get_service(Protocol::Companion).expect("service");
        assert_eq!(companion.credentials.as_deref(), Some("companion-creds"));
        assert_eq!(companion.password, None);

        let raop = config.get_service(Protocol::Raop).expect("service");
        assert_eq!(raop.credentials.as_deref(), Some("raop-creds"));
        assert_eq!(raop.password.as_deref(), Some("hunter2"));

        assert!(config.get_service(Protocol::Mrp).is_none());
    }

    #[test]
    fn apply_never_clears_a_value_the_config_already_has() {
        let mut config = config();
        let mut companion = service(Protocol::Companion, 49153, Some("companion-id"));
        companion.credentials = Some("from-the-command-line".to_owned());
        config.add_service(companion);

        config.apply(&crate::storage::Settings::default());

        assert_eq!(
            config
                .get_service(Protocol::Companion)
                .and_then(|it| it.credentials.as_deref()),
            Some("from-the-command-line")
        );
    }
}
