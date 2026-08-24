//! `AirPlay` scan handler, device-info extractor and service-info finisher.
//!
//! Ports `pyatv/protocols/airplay/__init__.py:180-230`.

use std::collections::HashMap;

use pyatv_core::airplay::update_service_details;
use pyatv_core::device_info::{DeviceInfoValue, lookup_model, lookup_os_from_identifier};
use pyatv_core::{BaseService, DeviceInfo, DeviceModel, OperatingSystem, Protocol};

use super::{ProtocolHandlers, get_unique_id, owned_properties};
use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// `AirPlay`'s registration, `pyatv/protocols/airplay/__init__.py:194-201`.
pub const AIRPLAY: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::AirPlay,
    handler,
    extractor: device_info,
    service_info,
};

/// Ports `airplay_service_handler` (`pyatv/protocols/airplay/__init__.py:180-191`).
///
/// Display name is the mDNS instance name; identifier is the `deviceid` TXT key.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let mut base = BaseService::new(Protocol::AirPlay, service.port);
    base.identifier = get_unique_id(ServiceType::AirPlay, &service.name, &service.properties);
    base.properties = owned_properties(&service.properties);

    Some((service.name.clone(), base))
}

/// Ports `device_info` (`pyatv/protocols/airplay/__init__.py:203-222`).
///
/// Worth knowing:
///
/// - `deviceid` becomes [`DeviceInfo::MAC`] verbatim, so an `AirPlay` service's identifier and its
///   MAC address are by construction the same string
///   (`tests/test_scan_functional.py:106-115` asserts exactly that).
/// - `osvers` is trusted as a display-ready version string and is *not* run through
///   `lookup_version`, unlike MRP's build number.
/// - `psi` wins over `pi` for the output-device id when both are present.
/// - The OS comes from the *string* arm of `lookup_os`, i.e. the Mac-identifier regexes, so it only
///   ever resolves for a Mac advertising `AirPlay`.
fn device_info(
    _service_type: ServiceType,
    properties: &Properties,
) -> HashMap<String, DeviceInfoValue> {
    let mut devinfo = HashMap::new();

    if let Some(raw_model) = properties.get("model") {
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
    if let Some(version) = properties.get("osvers") {
        devinfo.insert(
            DeviceInfo::VERSION.to_owned(),
            DeviceInfoValue::Text(version.clone()),
        );
    }
    if let Some(mac) = properties.get("deviceid") {
        devinfo.insert(
            DeviceInfo::MAC.to_owned(),
            DeviceInfoValue::Text(mac.clone()),
        );
    }
    if let Some(output_device_id) = properties.get("psi").or_else(|| properties.get("pi")) {
        devinfo.insert(
            DeviceInfo::OUTPUT_DEVICE_ID.to_owned(),
            DeviceInfoValue::Text(output_device_id.clone()),
        );
    }

    devinfo
}

/// Ports `service_info` (`pyatv/protocols/airplay/__init__.py:225-230`), a one-line delegate to
/// the shared `update_service_details` (`pyatv/protocols/airplay/utils.py:262-278`), which lives
/// in `pyatv-core` here because discovery may not depend on a protocol crate.
fn service_info(service: &mut BaseService, _devinfo: &DeviceInfo, _services: &[BaseService]) {
    update_service_details(service);
}
