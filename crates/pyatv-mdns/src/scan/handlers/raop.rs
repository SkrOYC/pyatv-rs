//! RAOP scan handlers (`_raop._tcp` and `_airport._tcp`), extractor and service-info finisher.
//!
//! Ports `pyatv/protocols/raop/__init__.py:438-514`.

use std::collections::HashMap;

use pyatv_core::airplay::update_service_details;
use pyatv_core::device_info::{DeviceInfoValue, lookup_model, lookup_os_from_identifier};
use pyatv_core::{
    BaseService, DeviceInfo, DeviceModel, OperatingSystem, PairingRequirement, Protocol,
};

use super::{ProtocolHandlers, get_unique_id, owned_properties};
use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// RAOP's own registration, `pyatv/protocols/raop/__init__.py:461`.
pub const RAOP: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::Raop,
    handler,
    extractor: device_info,
    service_info,
};

/// `_airport._tcp.local`, registered by RAOP with a handler that always returns `None`
/// (`pyatv/protocols/raop/__init__.py:462-465`).
///
/// It contributes no service and no protocol, ever. It exists only so that an `AirPort` Express's
/// `wama` TXT key — advertised under this type and nowhere else — reaches `device_info` through
/// the registry's "record properties regardless of whether a service was produced" step
/// (`pyatv/core/scan.py:227-231`).
pub const AIRPORT: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::AirPort,
    handler: airport_handler,
    extractor: device_info,
    service_info,
};

/// Strip the identifier prefix off a RAOP instance name.
///
/// Ports `raop_name_from_service_name` (`pyatv/protocols/raop/__init__.py:438-442`). RAOP instance
/// names are conventionally `"{identifier}@{display name}"`; with no `@` the whole string is the
/// display name.
#[must_use]
pub fn name_from_service_name(service_name: &str) -> &str {
    match service_name.split_once('@') {
        Some((_, name)) => name,
        None => service_name,
    }
}

/// Ports `raop_service_handler` (`pyatv/protocols/raop/__init__.py:445-458`).
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let name = name_from_service_name(&service.name).to_owned();

    let mut base = BaseService::new(Protocol::Raop, service.port);
    base.identifier = get_unique_id(ServiceType::Raop, &service.name, &service.properties);
    base.properties = owned_properties(&service.properties);

    Some((name, base))
}

/// `lambda service, response: None` (`pyatv/protocols/raop/__init__.py:463`).
fn airport_handler(_service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    None
}

/// Ports `device_info` (`pyatv/protocols/raop/__init__.py:469-494`), shared by both service types.
///
/// The `wama` branch is the awkward one and is reproduced literally:
///
/// - `wama` is a comma-separated `key=value` list *inside* one TXT value, except that its first
///   segment has no key on the wire. Upstream prepends the literal text `"macaddress="` to the raw
///   value before splitting, which is what names that first segment.
/// - The MAC is written only if `am` did not already supply one, reformatted dashes-to-colons and
///   upper-cased.
/// - `syVs` **unconditionally overwrites** any `ov`-derived version, with no presence guard. That
///   asymmetry against the MAC branch directly above it is upstream's, not a transcription slip.
fn device_info(
    _service_type: ServiceType,
    properties: &Properties,
) -> HashMap<String, DeviceInfoValue> {
    let mut devinfo = HashMap::new();

    if let Some(raw_model) = properties.get("am") {
        devinfo.insert(
            DeviceInfo::RAW_MODEL.to_owned(),
            DeviceInfoValue::Text(raw_model.clone()),
        );
        let model = lookup_model(Some(raw_model));
        if model != DeviceModel::Unknown {
            devinfo.insert(DeviceInfo::MODEL.to_owned(), DeviceInfoValue::Model(model));
        }
        let operating_system = lookup_os_from_identifier(raw_model);
        if operating_system != OperatingSystem::Unknown {
            devinfo.insert(
                DeviceInfo::OPERATING_SYSTEM.to_owned(),
                DeviceInfoValue::OperatingSystem(operating_system),
            );
        }
    }
    if let Some(version) = properties.get("ov") {
        devinfo.insert(
            DeviceInfo::VERSION.to_owned(),
            DeviceInfoValue::Text(version.clone()),
        );
    }

    if let Some(wama) = properties.get("wama") {
        let prefixed = format!("macaddress={wama}");
        // `dict(...)` over the split pairs, so a repeated key takes its last value; hence `rev`.
        // A segment with no `=` makes upstream's `dict()` raise; here it reads as an empty value,
        // because one malformed TXT record should not abort a whole scan.
        let nested: Vec<(&str, &str)> = prefixed
            .split(',')
            .map(|entry| entry.split_once('=').unwrap_or((entry, "")))
            .collect();
        let lookup = |wanted: &str| {
            nested
                .iter()
                .rev()
                .find(|(key, _)| *key == wanted)
                .map(|(_, value)| *value)
        };

        if !devinfo.contains_key(DeviceInfo::MAC)
            && let Some(mac) = lookup("macaddress")
        {
            devinfo.insert(
                DeviceInfo::MAC.to_owned(),
                DeviceInfoValue::Text(mac.replace('-', ":").to_uppercase()),
            );
        }
        if let Some(version) = lookup("syVs") {
            devinfo.insert(
                DeviceInfo::VERSION.to_owned(),
                DeviceInfoValue::Text(version.to_owned()),
            );
        }
    }

    devinfo
}

/// Ports `service_info` (`pyatv/protocols/raop/__init__.py:496-514`).
///
/// The clearest cross-service rule in the whole scan layer: the first two branches read the
/// **`AirPlay` sibling's** access-control keys, and only the fallback looks at RAOP's own TXT
/// record. With no `AirPlay` service on the device both cross-service branches are skipped and it
/// goes straight to `update_service_details`, which then treats RAOP's own `pw`/`sf`/`flags`/
/// `model`/`act` keys exactly as it would an `AirPlay` service's.
fn service_info(service: &mut BaseService, _devinfo: &DeviceInfo, services: &[BaseService]) {
    let airplay = services
        .iter()
        .find(|it| it.protocol == Protocol::AirPlay)
        .map(|it| &it.properties);

    if airplay.is_some_and(|it| it.get("acl").is_some_and(|value| value == "1")) {
        service.pairing = PairingRequirement::Disabled;
    } else if airplay.is_some_and(|it| it.get("act").is_some_and(|value| value == "2")) {
        service.pairing = PairingRequirement::Unsupported;
    } else {
        update_service_details(service);
    }
}
