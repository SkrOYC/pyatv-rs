//! Grouping mDNS responses into one [`BaseConfig`] per device.
//!
//! Ports `BaseScanner` (`pyatv/core/scan.py:109-249`) minus its transport: `process()` is the
//! abstract half that the unicast/multicast scanners implement, and everything below it is pure.
//! [`build_configs`] is that pure half, taking the responses a transport already collected, which
//! is what makes the whole pipeline testable from fixtures with no socket in sight.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use pyatv_core::device_info::{DeviceInfoValue, lookup_internal_name};
use pyatv_core::{BaseConfig, BaseService, DeviceInfo, DeviceModel, Protocol};

use super::handlers::{
    self, DevInfoExtractor, ProtocolHandlers, ScanHandler, ServiceInfoFn, owned_properties,
};
use crate::browse::ScanOptions;
use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// Which handlers a scan runs, keyed by DNS-SD service type.
///
/// `BaseScanner._services` / `_service_infos` (`pyatv/core/scan.py:114-134`). Backed by a `Vec`
/// because there are ten entries at most and because registration order is what
/// [`ScanRegistry::service_types`] hands to the transport.
#[derive(Debug, Clone)]
pub struct ScanRegistry {
    entries: Vec<Registration>,
}

/// One registered service type.
#[derive(Debug, Clone, Copy)]
struct Registration {
    service_type: ServiceType,
    /// `None` for the two meta types, matching upstream's `_empty_handler`.
    handler: Option<ScanHandler>,
    /// `None` for the two meta types, matching upstream's `_empty_extractor`.
    extractor: Option<DevInfoExtractor>,
    service_info: Option<ServiceInfoFn>,
}

impl ScanRegistry {
    /// Build the registry for a protocol filter, empty meaning "every protocol".
    ///
    /// Ports the registration loop in `pyatv/__init__.py:76-88`. The filter is applied **here**,
    /// at registration time, rather than to the finished configs: a protocol that was filtered out
    /// never gets a handler, so its services are never discovered at all. That is what makes
    /// `tests/test_scan_functional.py:127-140` see exactly two services on a device advertising
    /// three.
    ///
    /// `_device-info._tcp.local` and `_sleep-proxy._udp.local` are always registered, with no
    /// handler and no extractor (`pyatv/core/scan.py:114-120`). They exist so that a response
    /// carrying them is not logged as an unsupported service, and — for `_device-info` — so its
    /// `model` TXT key still reaches [`Response::model`].
    #[must_use]
    pub fn new(protocols: &HashSet<Protocol>) -> Self {
        let mut entries = vec![
            Registration {
                service_type: ServiceType::DeviceInfo,
                handler: None,
                extractor: None,
                service_info: None,
            },
            Registration {
                service_type: ServiceType::SleepProxy,
                handler: None,
                extractor: None,
                service_info: None,
            },
        ];

        entries.extend(
            handlers::ALL
                .iter()
                .filter(|entry| {
                    protocols.is_empty()
                        || entry
                            .service_type
                            .protocol()
                            .is_some_and(|protocol| protocols.contains(&protocol))
                })
                .map(
                    |&ProtocolHandlers {
                         service_type,
                         handler,
                         extractor,
                         service_info,
                     }| Registration {
                        service_type,
                        handler: Some(handler),
                        extractor: Some(extractor),
                        service_info: Some(service_info),
                    },
                ),
        );

        Self { entries }
    }

    /// The registry pyatv builds when no protocol filter is given.
    #[must_use]
    pub fn default_registry() -> Self {
        Self::new(&HashSet::new())
    }

    /// Every registered service type, in registration order.
    ///
    /// `BaseScanner.services` (`pyatv/core/scan.py:141-145`) — the list handed to the transport as
    /// the set of names to query for.
    #[must_use]
    pub fn service_types(&self) -> Vec<ServiceType> {
        self.entries
            .iter()
            .map(|entry| entry.service_type)
            .collect()
    }

    fn find(&self, service_type: ServiceType) -> Option<&Registration> {
        self.entries
            .iter()
            .find(|entry| entry.service_type == service_type)
    }
}

impl Default for ScanRegistry {
    fn default() -> Self {
        Self::default_registry()
    }
}

/// One device under construction, i.e. `FoundDevice` (`pyatv/core/scan.py:68-76`) plus the
/// per-service-type property map `BaseScanner._properties` keeps alongside it.
#[derive(Debug)]
struct FoundDevice {
    /// The name proposed by the **first** handler that produced a service for this address.
    name: String,
    address: IpAddr,
    deep_sleep: bool,
    /// `lookup_internal_name(response.model)` — the *internal* codename table, not the public one.
    model: DeviceModel,
    services: Vec<BaseService>,
}

/// Turn collected mDNS responses into one config per device.
///
/// Ports `BaseScanner.handle_response` / `_service_discovered` / `_get_device_info` / `discover`
/// (`pyatv/core/scan.py:147-249`) as one pass, then applies the `_should_include` filter from
/// `pyatv/__init__.py:47-56`.
///
/// The rules that are easy to get subtly wrong, in the order they apply:
///
/// 1. **Address/port gate** (`pyatv/core/scan.py:200-201`): a service with no address or port `0`
///    is recorded nowhere at all, not even in the property map. This is why a deep-sleeping device
///    surfaces through [`Response::deep_sleep`] rather than through its services.
/// 2. **Name** comes from the first handler at an address that returned a service, and is never
///    revised afterwards.
/// 3. **Properties are recorded even when the handler returned `None`**
///    (`pyatv/core/scan.py:227-231`). `_airport._tcp.local` relies on this entirely.
/// 4. **Device-info precedence is insertion order, first writer wins.** Upstream merges every
///    extractor's output with `dict_merge(..., allow_overwrite=False)` over a dict iterated in
///    insertion order, so whichever service type was processed first claims any contested key.
///    There is no static per-protocol priority table; see
///    `docs/research/discovery-port-spec.md` §9.11.
/// 5. **The `_device-info._tcp` model is merged last and never overwrites**, so a model another
///    protocol already resolved wins over the internal-codename lookup.
/// 6. **`service_info` runs only after every service has been added**, so it sees the merged
///    result and a snapshot of the device's other services.
///
/// Divergence: upstream returns devices in mDNS-arrival order, because its accumulator is an
/// insertion-ordered dict. A [`HashMap`] input has no arrival order to preserve, so addresses are
/// processed — and devices returned — in sorted order, which is at least reproducible. Service
/// order *within* one response is preserved, and that is what rules 2 and 4 actually depend on.
#[must_use]
pub fn build_configs<S: std::hash::BuildHasher>(
    responses: &HashMap<IpAddr, Response, S>,
    options: &ScanOptions,
) -> Vec<BaseConfig> {
    let registry = ScanRegistry::new(&options.protocols);

    let mut addresses: Vec<&IpAddr> = responses.keys().collect();
    addresses.sort_unstable();

    let mut found: Vec<FoundDevice> = Vec::new();
    // Per address, the properties each service type posted, in the order they were posted.
    let mut properties: Vec<(IpAddr, Vec<(ServiceType, Properties)>)> = Vec::new();

    for address in addresses {
        let Some(response) = responses.get(address) else {
            continue;
        };
        for service in &response.services {
            handle_service(&registry, service, response, &mut found, &mut properties);
        }
    }

    found
        .into_iter()
        .map(|device| {
            let device_properties = properties
                .iter()
                .find(|(address, _)| *address == device.address)
                .map_or(&[][..], |(_, entries)| entries.as_slice());
            materialise(&registry, device, device_properties)
        })
        .filter(|config| should_include(config, &options.identifiers))
        .collect()
}

/// `BaseScanner.handle_response`'s body for one service, plus `_service_discovered`
/// (`pyatv/core/scan.py:183-231`).
fn handle_service(
    registry: &ScanRegistry,
    service: &Service,
    response: &Response,
    found: &mut Vec<FoundDevice>,
    properties: &mut Vec<(IpAddr, Vec<(ServiceType, Properties)>)>,
) {
    let Some(service_type) = ServiceType::from_wire_name(&service.service_type) else {
        tracing::warn!(
            service = %service.name,
            service_type = %service.service_type,
            "discovered unsupported service"
        );
        return;
    };
    let Some(registration) = registry.find(service_type) else {
        // Registered upstream but filtered out by `protocol=` here. Upstream never sees these
        // because it never asks for them; skipping quietly is the same outcome.
        return;
    };

    // `if service.address is None or service.port == 0: return`.
    let (Some(address), true) = (service.address, service.port != 0) else {
        return;
    };

    if let Some(handler) = registration.handler
        && let Some((name, base_service)) = handler(service, response)
    {
        tracing::debug!(
            service = %service.name,
            %address,
            port = service.port,
            protocol = ?base_service.protocol,
            "auto-discovered service"
        );

        match found.iter_mut().find(|device| device.address == address) {
            Some(device) => device.services.push(base_service),
            None => found.push(FoundDevice {
                name,
                address,
                deep_sleep: response.deep_sleep,
                model: lookup_internal_name(response.model.as_deref()),
                services: vec![base_service],
            }),
        }
    }

    // Recorded regardless of whether a service was produced.
    let index = if let Some(index) = properties.iter().position(|(known, _)| *known == address) {
        index
    } else {
        properties.push((address, Vec::new()));
        properties.len() - 1
    };
    let entries = &mut properties[index].1;
    match entries.iter_mut().find(|(known, _)| *known == service_type) {
        // Re-assigning an existing dict key keeps its position.
        Some((_, slot)) => *slot = service.properties.clone(),
        None => entries.push((service_type, service.properties.clone())),
    }
}

/// `_get_device_info` (`pyatv/core/scan.py:233-249`) plus the config assembly and `service_info`
/// pass from `discover` (`pyatv/core/scan.py:147-176`).
fn materialise(
    registry: &ScanRegistry,
    device: FoundDevice,
    properties: &[(ServiceType, Properties)],
) -> BaseConfig {
    let mut merged: HashMap<String, DeviceInfoValue> = HashMap::new();

    for (service_type, service_properties) in properties {
        let Some(extractor) = registry.find(*service_type).and_then(|it| it.extractor) else {
            continue;
        };
        for (key, value) in extractor(*service_type, service_properties) {
            // `dict_merge(..., allow_overwrite=False)`: first writer wins.
            merged.entry(key).or_insert(value);
        }
    }

    if device.model != DeviceModel::Unknown {
        merged
            .entry(DeviceInfo::MODEL.to_owned())
            .or_insert(DeviceInfoValue::Model(device.model));
    }

    let device_info = DeviceInfo::from_properties(&merged).unwrap_or_else(|error| {
        tracing::warn!(%error, "discarding malformed device info");
        DeviceInfo::default()
    });

    let mut config = BaseConfig::new(device.name, device.address);
    config.deep_sleep = device.deep_sleep;
    config.device_info = device_info.clone();
    // `AppleTV(properties=self._properties[address])` (`pyatv/core/scan.py:155-161`). Every
    // registered service type that answered is here, including the ones that produce no
    // `BaseService` — `_sleep-proxy._udp`, `_device-info._tcp` and `_airport._tcp` — because rule 3
    // above records properties whether or not a handler fired. RAOP's and DMAP's `_device_info()`
    // read this map back at connect time, keyed by the same dotless service-type literals their
    // `scan()` registers.
    config.set_properties(
        properties
            .iter()
            .map(|(service_type, service_properties)| {
                (
                    service_type.property_key().to_owned(),
                    owned_properties(service_properties),
                )
            })
            .collect(),
    );
    for service in device.services {
        config.add_service(service);
    }

    // "Apply service_info after adding all services in case a merge happens."
    //
    // Upstream hands each `service_info` live references to the device's other services; this
    // hands it a snapshot taken before the pass. The two agree because no `service_info`
    // implementation mutates another service, and the only fields any of them *reads* from a
    // sibling — RAOP reading `AirPlay`'s `acl`/`act` — are TXT properties that `service_info`
    // never writes.
    let snapshot = config.services.clone();
    for service in &mut config.services {
        if let Some(service_info) = registry
            .entries
            .iter()
            .find(|entry| entry.service_type.protocol() == Some(service.protocol))
            .and_then(|entry| entry.service_info)
        {
            service_info(service, &device_info, &snapshot);
        }
    }

    config
}

/// `_should_include` (`pyatv/__init__.py:47-56`).
///
/// A config with no identifier on any service is dropped even when it has services, which is what
/// makes a Companion-only device invisible.
fn should_include(config: &BaseConfig, identifiers: &HashSet<String>) -> bool {
    if !config.ready() {
        return false;
    }
    if identifiers.is_empty() {
        return true;
    }
    config
        .all_identifiers()
        .iter()
        .any(|identifier| identifiers.contains(*identifier))
}
