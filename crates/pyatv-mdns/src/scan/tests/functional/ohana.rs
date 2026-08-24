//! The multi-service "Ohana" device from `tests/core/test_scan.py`, plus multi-address grouping.

use pyatv_core::{DeviceModel, Protocol};

use super::{SERVICE_1_ID, SERVICE_1_NAME, SERVICE_1_SERVICE_NAME, SERVICE_2_ID, SERVICE_2_NAME};
use crate::scan::tests::fixtures::{
    IP_1, IP_2, airplay_service, at, companion_service, mrp_service, raop_service, response,
    response_with, responses, service, sleep_proxy_service,
};
use crate::scan::tests::scan;
use crate::service_types::ServiceType;
/// The "Ohana" device from `tests/core/test_scan.py:171-183`: sleep proxy, `AirPlay`, RAOP and
/// Companion on one address, with `_device-info._tcp.local` reporting the internal codename
/// `J305AP`. Only RAOP's `"{id}@{name}"` instance name carries an identifier here, and that alone
/// is enough to make the device ready.
#[test]
fn the_ohana_device_resolves_from_its_raop_instance_name() {
    let all = responses(vec![(
        IP_1,
        response_with(
            vec![
                sleep_proxy_service("70-35-60-63.1 Ohana", IP_1, 54942),
                airplay_service_without_txt(),
                raop_service("Ohana", "54E61BF2ED74", IP_1, 7000),
                service(ServiceType::CompanionLink, "Ohana", IP_1, 49152, &[]),
            ],
            false,
            Some("J305AP"),
        ),
    )]);

    let devices = scan(&all);
    assert_eq!(devices.len(), 1);
    assert!(!devices[0].deep_sleep);
    assert_eq!(devices[0].device_info.model(), DeviceModel::AppleTv4KGen2);
    assert_eq!(devices[0].identifier(), Some("54E61BF2ED74"));
    // Sleep proxy contributes no service; the other three each do.
    assert_eq!(devices[0].services.len(), 3);
}

/// `tests/core/test_scan.py:265-277` (`test_scan_with_zeroconf_complete_and_device_info`) — every
/// service type that answered is on the config's property map, keyed by its dotless DNS-SD name,
/// including the two that produced no `BaseService`.
#[test]
fn the_ohana_device_keeps_every_service_types_txt_record() {
    let all = responses(vec![(
        IP_1,
        response_with(
            vec![
                sleep_proxy_service("70-35-60-63.1 Ohana", IP_1, 54942),
                airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_1, 7000),
                raop_service("Ohana", "54E61BF2ED74", IP_1, 7000),
                companion_service("Ohana", IP_1, 49152),
            ],
            false,
            Some("J305AP"),
        ),
    )]);

    let devices = scan(&all);
    assert_eq!(devices.len(), 1);
    let config = &devices[0];

    for service_type in [
        "_sleep-proxy._udp.local",
        "_airplay._tcp.local",
        "_raop._tcp.local",
        "_companion-link._tcp.local",
    ] {
        assert!(
            config.has_properties(service_type),
            "expected {service_type} in the property map"
        );
    }
    // `_hscp._tcp.local` never answered.
    assert!(!config.has_properties("_hscp._tcp.local"));

    // The TXT values come across, and the accessor folds the wire casing the fixtures use.
    assert_eq!(
        config.property("_airplay._tcp.local", "deviceid"),
        Some(SERVICE_2_ID)
    );
    assert_eq!(
        config.property("_companion-link._tcp.local", "rpHA"),
        Some("33efedd528a")
    );
    // RAOP and the sleep proxy both advertise an empty TXT record; present, but empty.
    assert!(
        config
            .properties("_raop._tcp.local")
            .expect("raop properties")
            .is_empty()
    );
}

/// A protocol filter stops a service type from being queried at all, so its TXT record never
/// reaches the property map either — matching upstream, where an unregistered type is skipped
/// before `_service_discovered` runs.
#[test]
fn a_filtered_out_protocol_contributes_no_properties() {
    let all = responses(vec![(
        IP_1,
        response(vec![
            airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_1, 7000),
            companion_service("Ohana", IP_1, 49152),
        ]),
    )]);

    let devices = super::super::scan_protocols(&all, &[Protocol::AirPlay]);
    assert_eq!(devices.len(), 1);
    assert!(devices[0].has_properties("_airplay._tcp.local"));
    assert!(!devices[0].has_properties("_companion-link._tcp.local"));
}

/// `tests/core/test_scan.py:315-321` — the same device without the `_device-info` model leaves the
/// model unknown but still resolves.
#[test]
fn the_ohana_device_without_device_info_has_an_unknown_model() {
    let all = responses(vec![(
        IP_1,
        response(vec![
            sleep_proxy_service("70-35-60-63.1 Ohana", IP_1, 54942),
            airplay_service_without_txt(),
            raop_service("Ohana", "54E61BF2ED74", IP_1, 7000),
            service(ServiceType::CompanionLink, "Ohana", IP_1, 49152, &[]),
        ]),
    )]);

    let devices = scan(&all);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_info.model(), DeviceModel::Unknown);
}

/// `tests/core/test_scan.py:324-330` — `AirPlay` alone with an empty TXT record has no `deviceid`,
/// hence no identifier, hence no device.
#[test]
fn the_ohana_device_with_only_airplay_is_not_ready() {
    let all = responses(vec![(
        IP_1,
        response_with(
            vec![
                sleep_proxy_service("70-35-60-63.1 Ohana", IP_1, 54942),
                airplay_service_without_txt(),
            ],
            false,
            Some("J305AP"),
        ),
    )]);

    assert!(scan(&all).is_empty());
}

/// Two devices at two addresses both come back, and each keeps its own services.
#[test]
fn two_addresses_produce_two_devices() {
    let all = responses(vec![
        (
            IP_1,
            response(vec![mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            )]),
        ),
        (
            IP_2,
            response(vec![
                airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_2, 7000),
                companion_service("Companion", IP_2, 49153),
            ]),
        ),
    ]);

    let devices = scan(&all);
    assert_eq!(devices.len(), 2);
    assert_eq!(devices[0].address, IP_1);
    assert_eq!(devices[0].services.len(), 1);
    assert_eq!(devices[1].address, IP_2);
    assert_eq!(devices[1].services.len(), 2);
}

/// `pyatv/interface.py:1385-1398` — `identifier` walks `[MRP, DMAP, AirPlay, RAOP, Companion]`,
/// while `all_identifiers` is in discovery order.
#[test]
fn the_main_identifier_follows_the_protocol_priority_not_discovery_order() {
    let all = at(
        IP_1,
        vec![
            airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_1, 7000),
            mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            ),
        ],
    );

    let devices = scan(&all);
    assert_eq!(devices[0].identifier(), Some(SERVICE_1_ID));
    assert_eq!(
        devices[0].all_identifiers(),
        vec![SERVICE_2_ID, SERVICE_1_ID]
    );
}

/// A service type nothing registers is skipped without disturbing the rest of the response.
#[test]
fn an_unknown_service_type_does_not_abort_the_response() {
    let mut stray = airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_1, 7000);
    stray.service_type = "_http._tcp.local".to_owned();

    let all = at(
        IP_1,
        vec![
            stray,
            mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            ),
        ],
    );

    let devices = scan(&all);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].services.len(), 1);
    assert_eq!(devices[0].name, SERVICE_1_NAME);
}

/// The `AirPlay` fixture from `tests/core/test_scan.py`, whose TXT record is genuinely empty.
fn airplay_service_without_txt() -> crate::service::Service {
    service(ServiceType::AirPlay, "Ohana", IP_1, 7000, &[])
}
