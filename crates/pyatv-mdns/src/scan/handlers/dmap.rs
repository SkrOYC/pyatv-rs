//! DMAP scan handlers for its three DNS-SD service types, extractor and service-info finisher.
//!
//! Ports `pyatv/protocols/dmap/__init__.py:577-658`. All three types map onto the single
//! [`Protocol::Dmap`], so a device announcing more than one of them ends up with a single merged
//! service (`tests/protocols/dmap/test_dmap_scan.py:24-45`).

use std::collections::HashMap;

use pyatv_core::device_info::DeviceInfoValue;
use pyatv_core::{
    BaseService, DeviceInfo, DeviceModel, OperatingSystem, PairingRequirement, Protocol,
};

use super::{ProtocolHandlers, get_unique_id, owned_properties};
use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// `_appletv-v2._tcp.local` — DMAP over Home Sharing.
/// `pyatv/protocols/dmap/__init__.py:625` (`homesharing_service_handler`).
pub const APPLETV_V2: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::AppleTvV2,
    handler: homesharing_handler,
    extractor: device_info,
    service_info,
};

/// `_touch-able._tcp.local` — plain legacy DMAP.
/// `pyatv/protocols/dmap/__init__.py:626` (`dmap_service_handler`).
pub const TOUCH_ABLE: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::TouchAble,
    handler: dmap_handler,
    extractor: device_info,
    service_info,
};

/// `_hscp._tcp.local` — Home Sharing Control Protocol, i.e. the Music/iTunes desktop app.
/// `pyatv/protocols/dmap/__init__.py:627` (`hscp_service_handler`).
pub const HSCP: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::Hscp,
    handler: hscp_handler,
    extractor: device_info,
    service_info,
};

/// Build the shared part of all three handlers.
fn dmap_service(service: &Service, service_type: ServiceType) -> BaseService {
    let mut base = BaseService::new(Protocol::Dmap, service.port);
    base.identifier = get_unique_id(service_type, &service.name, &service.properties);
    base.properties = owned_properties(&service.properties);
    base
}

/// Ports `homesharing_service_handler` (`pyatv/protocols/dmap/__init__.py:577-590`).
///
/// The display name is the `Name` TXT key. Uniquely among the scan handlers, this one takes
/// credentials straight off the wire: `hG` is the Home Sharing GUID, and pyatv uses it directly as
/// DMAP credentials rather than requiring a pairing flow.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn homesharing_handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let name = service
        .properties
        .get("Name")
        .cloned()
        .unwrap_or_else(|| "Unknown".to_owned());

    let mut base = dmap_service(service, ServiceType::AppleTvV2);
    base.credentials = service.properties.get("hG").cloned();

    Some((name, base))
}

/// Ports `dmap_service_handler` (`pyatv/protocols/dmap/__init__.py:593-604`).
///
/// Display name is the `CtlN` TXT key, and no credentials are set — a device found only this way
/// has to be paired (`tests/protocols/dmap/test_dmap_scan.py:113-128`).
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn dmap_handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let name = service
        .properties
        .get("CtlN")
        .cloned()
        .unwrap_or_else(|| "Unknown".to_owned());

    Some((name, dmap_service(service, ServiceType::TouchAble)))
}

/// Ports `hscp_service_handler` (`pyatv/protocols/dmap/__init__.py:607-620`).
///
/// Display name is the `Machine Name` TXT key — note the literal space, resolved case-insensitively
/// like every other key. Credentials come from `hG` as with Home Sharing.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn hscp_handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let name = service
        .properties
        .get("Machine Name")
        .cloned()
        .unwrap_or_else(|| "Unknown".to_owned());

    let mut base = dmap_service(service, ServiceType::Hscp);
    base.credentials = service.properties.get("hG").cloned();

    Some((name, base))
}

/// Ports `device_info` (`pyatv/protocols/dmap/__init__.py:630-640`).
///
/// Reads no TXT keys at all. The blanket [`OperatingSystem::Legacy`] is upstream's acknowledged
/// heuristic ("Like with MRP, this is also border line OK, but will do for now"), and HSCP is
/// hardcoded to [`DeviceModel::Music`] because it is the desktop Music/iTunes app rather than a
/// piece of Apple TV hardware.
fn device_info(
    service_type: ServiceType,
    _properties: &Properties,
) -> HashMap<String, DeviceInfoValue> {
    let mut devinfo = HashMap::new();

    devinfo.insert(
        DeviceInfo::OPERATING_SYSTEM.to_owned(),
        DeviceInfoValue::OperatingSystem(OperatingSystem::Legacy),
    );

    if service_type == ServiceType::Hscp {
        devinfo.insert(
            DeviceInfo::MODEL.to_owned(),
            DeviceInfoValue::Model(DeviceModel::Music),
        );
    }

    devinfo
}

/// Ports `service_info` (`pyatv/protocols/dmap/__init__.py:643-658`).
///
/// Upstream's docstring: "If Home Sharing is enabled, then the 'hG' property is present and can be
/// used as credentials. If not enabled, then pairing must be performed."
fn service_info(service: &mut BaseService, _devinfo: &DeviceInfo, _services: &[BaseService]) {
    service.pairing = if service.property("hG").is_some() {
        PairingRequirement::Optional
    } else {
        PairingRequirement::Mandatory
    };
}
