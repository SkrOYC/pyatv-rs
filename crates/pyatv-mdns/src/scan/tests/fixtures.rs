//! Fixture builders transcribed from pyatv's own `tests/fake_udns.py`.
//!
//! Each builder reproduces one `fake_udns.*_service()` function's TXT dictionary **verbatim**
//! (`tests/fake_udns.py:29-158`), because those dictionaries are what pyatv's whole scan test suite
//! is validated against. Where a fixture is deliberately impoverished — Companion advertising
//! neither `rpfl` nor `rpmrtid`, RAOP advertising nothing at all — that is upstream's shape, and
//! reproducing it is the point: it is what makes "a Companion-only device is invisible" testable.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::dns::Properties;
use crate::service::{Response, Service};
use crate::service_types::ServiceType;

/// `tests/test_scan_functional.py:25` and the per-protocol scan tests' `IP_1`.
pub const IP_1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

/// `tests/test_scan_functional.py:29` (`SERVICE_2_IP`).
pub const IP_2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

/// Build one service instance with an explicit TXT record.
pub fn service(
    service_type: ServiceType,
    name: &str,
    address: IpAddr,
    port: u16,
    properties: &[(&str, &str)],
) -> Service {
    let mut txt = Properties::new();
    for (key, value) in properties {
        txt.insert(key, (*value).to_owned());
    }

    Service {
        service_type: service_type.property_key().to_owned(),
        name: name.to_owned(),
        address: Some(address),
        port,
        properties: txt,
    }
}

/// `fake_udns.mrp_service` (`tests/fake_udns.py:29-48`), whose default `version` is `18M60`.
pub fn mrp_service(
    service_name: &str,
    atv_name: &str,
    identifier: &str,
    address: IpAddr,
    port: u16,
) -> Service {
    mrp_service_with_version(service_name, atv_name, identifier, address, port, "18M60")
}

/// The same, with the build number spelled out — `19J346` is tvOS 15.0 and disables MRP.
pub fn mrp_service_with_version(
    service_name: &str,
    atv_name: &str,
    identifier: &str,
    address: IpAddr,
    port: u16,
    version: &str,
) -> Service {
    service(
        ServiceType::MediaRemoteTv,
        service_name,
        address,
        port,
        &[
            ("Name", atv_name),
            ("UniqueIdentifier", identifier),
            ("SystemBuildVersion", version),
        ],
    )
}

/// `fake_udns.airplay_service` (`tests/fake_udns.py:51-68`) without a model: `deviceid` plus
/// `features=0x1` only, so no status flags and therefore `NotNeeded` pairing.
pub fn airplay_service(atv_name: &str, deviceid: &str, address: IpAddr, port: u16) -> Service {
    service(
        ServiceType::AirPlay,
        atv_name,
        address,
        port,
        &[("deviceid", deviceid), ("features", "0x1")],
    )
}

/// The `model=` branch of `fake_udns.airplay_service`, which also hardcodes `flags=0x8`
/// (`PIN_REQUIRED`) whatever the model is — so this fixture is always pairing-`Mandatory` unless a
/// higher-priority rule in `update_service_details` overrides it.
pub fn airplay_service_with_model(
    atv_name: &str,
    deviceid: &str,
    address: IpAddr,
    port: u16,
    model: &str,
) -> Service {
    service(
        ServiceType::AirPlay,
        atv_name,
        address,
        port,
        &[
            ("deviceid", deviceid),
            ("features", "0x1"),
            ("model", model),
            ("flags", "0x8"),
        ],
    )
}

/// `fake_udns.homesharing_service` (`tests/fake_udns.py:71-84`). Port is fixed at 3689 upstream.
pub fn homesharing_service(
    service_name: &str,
    atv_name: &str,
    hsgid: &str,
    address: IpAddr,
) -> Service {
    service(
        ServiceType::AppleTvV2,
        service_name,
        address,
        3689,
        &[("hG", hsgid), ("Name", atv_name)],
    )
}

/// `fake_udns.device_service` (`tests/fake_udns.py:87-99`) — plain DMAP, no credentials.
pub fn device_service(service_name: &str, atv_name: &str, address: IpAddr) -> Service {
    service(
        ServiceType::TouchAble,
        service_name,
        address,
        3689,
        &[("CtlN", atv_name)],
    )
}

/// `fake_udns.companion_service` (`tests/fake_udns.py:102-115`).
///
/// Note what is *missing*: no `rpmrtid` (so no identifier) and no `rpfl` (so pairing reads
/// `Unsupported`). Both absences are upstream's and both are load-bearing for the tests.
pub fn companion_service(service_name: &str, address: IpAddr, port: u16) -> Service {
    service(
        ServiceType::CompanionLink,
        service_name,
        address,
        port,
        &[("rpHA", "33efedd528a")],
    )
}

/// `fake_udns.raop_service` (`tests/fake_udns.py:118-131`): instance name `"{id}@{name}"`, and an
/// entirely empty TXT record.
pub fn raop_service(name: &str, identifier: &str, address: IpAddr, port: u16) -> Service {
    service(
        ServiceType::Raop,
        &format!("{identifier}@{name}"),
        address,
        port,
        &[],
    )
}

/// `fake_udns.hscp_service` (`tests/fake_udns.py:134-158`). The instance name is the literal
/// `"HSCP Name"`; the display name comes from the `Machine Name` TXT key instead.
pub fn hscp_service(
    name: &str,
    identifier: &str,
    hsgid: &str,
    address: IpAddr,
    port: u16,
) -> Service {
    service(
        ServiceType::Hscp,
        "HSCP Name",
        address,
        port,
        &[
            ("Machine Name", name),
            ("Machine ID", identifier),
            ("hG", hsgid),
        ],
    )
}

/// A `_sleep-proxy._udp.local` instance, named the way real proxies name them:
/// `"70-35-60-63.1 Ohana"` (`tests/core/test_scan.py:47-53`).
pub fn sleep_proxy_service(name: &str, address: IpAddr, port: u16) -> Service {
    service(ServiceType::SleepProxy, name, address, port, &[])
}

/// A response with no sleep proxy and no `_device-info` model.
pub fn response(services: Vec<Service>) -> Response {
    Response {
        services,
        deep_sleep: false,
        model: None,
    }
}

/// A response with the deep-sleep flag and the raw `_device-info._tcp.local` `model` TXT value
/// spelled out — the two fields the transport derives and the scan layer consumes.
pub fn response_with(services: Vec<Service>, deep_sleep: bool, model: Option<&str>) -> Response {
    Response {
        services,
        deep_sleep,
        model: model.map(ToOwned::to_owned),
    }
}

/// One response per address, keyed the way the transports return them.
pub fn responses(entries: Vec<(IpAddr, Response)>) -> HashMap<IpAddr, Response> {
    entries.into_iter().collect()
}

/// The common case: every service is at one address.
pub fn at(address: IpAddr, services: Vec<Service>) -> HashMap<IpAddr, Response> {
    responses(vec![(address, response(services))])
}
