//! Companion scan handler, device-info extractor and service-info finisher.
//!
//! Ports `pyatv/protocols/companion/__init__.py:60-79,614-661`.

use std::collections::HashMap;

use pyatv_core::device_info::{DeviceInfoValue, lookup_model};
use pyatv_core::{BaseService, DeviceInfo, DeviceModel, PairingRequirement, Protocol};

use super::{ProtocolHandlers, get_unique_id, owned_properties};
use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// `rpfl` bit meaning the device refuses to pair.
///
/// Verbatim from `pyatv/protocols/companion/__init__.py:70`.
///
/// Upstream oddity, reproduced deliberately: the comment above this constant works the mask out as
/// `0x62792 & ~0xB67A2 & ~0x627B6 & ~0xB67A2 = 0x20`, but the constant it then assigns is `0x04`.
/// The value is what has been validated against real `rpfl` observations, so the value is what is
/// ported; see `docs/research/discovery-port-spec.md` §9.3.
pub const PAIRING_DISABLED_MASK: u64 = 0x04;

/// `rpfl` bit meaning the device will show a PIN.
///
/// Verbatim from `pyatv/protocols/companion/__init__.py:79`. Same comment/value mismatch as
/// [`PAIRING_DISABLED_MASK`]: the comment says "masking 0x40000", the constant is `0x4000`.
pub const PAIRING_WITH_PIN_SUPPORTED_MASK: u64 = 0x4000;

/// Companion's registration, `pyatv/protocols/companion/__init__.py:628-635`.
pub const COMPANION: ProtocolHandlers = ProtocolHandlers {
    service_type: ServiceType::CompanionLink,
    handler,
    extractor: device_info,
    service_info,
};

/// Ports `companion_service_handler` (`pyatv/protocols/companion/__init__.py:614-625`).
///
/// Unlike MRP there is no version gating and no `enabled` override — a Companion service is always
/// enabled as discovered. The display name is the mDNS instance name, not a TXT key.
///
/// The identifier comes from `rpmrtid`, which most devices do not advertise. A Companion-only
/// device therefore has no identifier at all, is not
/// [`ready`](pyatv_core::BaseConfig::ready), and is dropped from the scan results — exactly what
/// `tests/protocols/companion/test_companion_scan.py:23-31` asserts.
#[allow(
    clippy::unnecessary_wraps,
    reason = "the ScanHandler fn pointer type requires Option; only _airport ever returns None"
)]
fn handler(service: &Service, _response: &Response) -> Option<(String, BaseService)> {
    let mut base = BaseService::new(Protocol::Companion, service.port);
    base.identifier = get_unique_id(
        ServiceType::CompanionLink,
        &service.name,
        &service.properties,
    );
    base.properties = owned_properties(&service.properties);

    Some((service.name.clone(), base))
}

/// Ports `device_info` (`pyatv/protocols/companion/__init__.py:637-644`).
///
/// `rpmd` carries the public model identifier, e.g. `AppleTV11,1`. The raw string is always kept;
/// the resolved [`DeviceModel`] is only written when the lookup actually recognises it, so a
/// device Apple shipped after pyatv's table was last updated still surfaces its raw model.
fn device_info(
    _service_type: ServiceType,
    properties: &Properties,
) -> HashMap<String, DeviceInfoValue> {
    let mut devinfo = HashMap::new();

    if let Some(raw_model) = properties.get("rpmd") {
        devinfo.insert(
            DeviceInfo::RAW_MODEL.to_owned(),
            DeviceInfoValue::Text(raw_model.clone()),
        );
        let model = lookup_model(Some(raw_model));
        if model != DeviceModel::Unknown {
            devinfo.insert(DeviceInfo::MODEL.to_owned(), DeviceInfoValue::Model(model));
        }
    }

    devinfo
}

/// Ports `service_info` (`pyatv/protocols/companion/__init__.py:648-661`).
///
/// The fallback is [`PairingRequirement::Unsupported`], not `NotNeeded`: Companion pairing is
/// opt-in only when the PIN bit is actually observed.
///
/// Upstream calls `int(flags, 16)`, which raises on garbage. A malformed `rpfl` reads as `0` here
/// so one badly-behaved device cannot abort a scan; the outcome is the same `Unsupported`.
fn service_info(service: &mut BaseService, _devinfo: &DeviceInfo, _services: &[BaseService]) {
    let raw = service.properties.get("rpfl").map_or("0x0", String::as_str);
    let digits = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X"));
    let flags = u64::from_str_radix(digits.unwrap_or(raw), 16).unwrap_or(0);

    service.pairing = if flags & PAIRING_DISABLED_MASK != 0 {
        PairingRequirement::Disabled
    } else if flags & PAIRING_WITH_PIN_SUPPORTED_MASK != 0 {
        PairingRequirement::Mandatory
    } else {
        PairingRequirement::Unsupported
    };
}
