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
    /// walking `IDENTIFIER_PRIORITY`, *not* the first service in discovery order. Devices
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

// [`std::fmt::Display`] for [`BaseConfig`] lives in `display.rs`, and the settings-application
// impl block lives in `apply.rs`; both were split out to keep this file under the 500 LoC rule.
mod apply;
mod display;
#[cfg(test)]
mod tests;
