//! MRP scan handler, device-info extractor and service-info finisher.
//!
//! Ports `pyatv/protocols/mrp/__init__.py:1025-1097`.

use std::collections::HashMap;

use pyatv_core::device_info::{DeviceInfoValue, lookup_version};
use pyatv_core::{BaseService, DeviceInfo, OperatingSystem, PairingRequirement, Protocol};

use super::{ProtocolHandlers, build_major, get_unique_id, owned_properties};
use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// Build-number major from which pyatv stops trusting the standalone MRP port.
///
/// `pyatv/protocols/mrp/__init__.py:1036` (`if base >= 19`). Build major 19 is tvOS 15 under the
/// same `major - 4` heuristic [`lookup_version`] uses; tvOS 15 dropped the separate MRP listener
/// and moved MRP inside an `AirPlay` 2 data stream.
pub const TVOS_15_BUILD_MAJOR: u32 = 19;

/// MRP's registration, `pyatv/protocols/mrp/__init__.py:1055-1063`.
pub const MRP: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::MediaRemoteTv,
    handler,
    extractor: device_info,
    service_info,
};

/// Ports `mrp_service_handler` (`pyatv/protocols/mrp/__init__.py:1025-1052`).
///
/// Two details are easy to get wrong:
///
/// - The display name is the `Name` TXT key, falling back to the literal `"Unknown"` — *not* the
///   mDNS instance name, which for MRP is a separate "service name" that upstream ignores here.
/// - The tvOS-15 self-disable reads only MRP's own `SystemBuildVersion`. It is not a cross-check
///   against the `AirPlay` service's advertised OS version, despite that sounding plausible; the
///   `AirPlay`/MRP interaction is a connect-time tunnel decision instead
///   (`docs/research/discovery-port-spec.md` §7.2). A disabled service is still attached to the
///   config with `enabled = false`, never dropped
///   (`tests/test_scan_functional.py:143-150`).
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let build = service
        .properties
        .get("SystemBuildVersion")
        .map_or("", String::as_str);
    let enabled = build_major(build).is_none_or(|major| major < TVOS_15_BUILD_MAJOR);

    let name = service
        .properties
        .get("Name")
        .cloned()
        .unwrap_or_else(|| "Unknown".to_owned());

    let mut base = BaseService::new(Protocol::Mrp, service.port);
    base.identifier = get_unique_id(
        ServiceType::MediaRemoteTv,
        &service.name,
        &service.properties,
    );
    base.properties = owned_properties(&service.properties);
    base.enabled = enabled;

    Some((name, base))
}

/// Ports `device_info` (`pyatv/protocols/mrp/__init__.py:1069-1086`).
///
/// The unconditional [`OperatingSystem::TvOs`] is upstream's, and upstream calls it a guess:
/// "MRP has only been seen on Apple TV and HomePod, which both run tvOS, so an educated guess is
/// made here. It is border line OK, but will do for now."
fn device_info(
    _service_type: ServiceType,
    properties: &Properties,
) -> HashMap<String, DeviceInfoValue> {
    let mut devinfo = HashMap::new();

    if let Some(build) = properties.get("systembuildversion") {
        devinfo.insert(
            DeviceInfo::BUILD_NUMBER.to_owned(),
            DeviceInfoValue::Text(build.clone()),
        );
        if let Some(version) = lookup_version(Some(build)) {
            devinfo.insert(
                DeviceInfo::VERSION.to_owned(),
                DeviceInfoValue::Text(version.into_owned()),
            );
        }
    }
    if let Some(mac) = properties.get("macaddress") {
        devinfo.insert(
            DeviceInfo::MAC.to_owned(),
            DeviceInfoValue::Text(mac.clone()),
        );
    }

    devinfo.insert(
        DeviceInfo::OPERATING_SYSTEM.to_owned(),
        DeviceInfoValue::OperatingSystem(OperatingSystem::TvOs),
    );

    devinfo
}

/// Ports `service_info` (`pyatv/protocols/mrp/__init__.py:1089-1105`).
///
/// Upstream's docstring: "Pairing has never been enforced by MRP (maybe by design), but it is
/// possible to pair if `AllowPairing` is YES."
///
/// The first branch reads oddly and is reproduced as written: a service disabled by the tvOS-15
/// rule reports [`PairingRequirement::NotNeeded`] rather than `Unsupported`. It never matters in
/// practice because a disabled service is skipped before pairing is ever considered.
fn service_info(service: &mut BaseService, _devinfo: &DeviceInfo, _services: &[BaseService]) {
    service.pairing = if !service.enabled {
        PairingRequirement::NotNeeded
    } else if service
        .properties
        .get("allowpairing")
        .is_some_and(|it| it.eq_ignore_ascii_case("yes"))
    {
        PairingRequirement::Optional
    } else {
        PairingRequirement::Disabled
    };
}
