//! The protocol filter, and RAOP reading its `AirPlay` sibling.

use pyatv_core::{PairingRequirement, Protocol};

use super::{
    SERVICE_1_ID, SERVICE_1_NAME, SERVICE_1_SERVICE_NAME, SERVICE_2_ID, SERVICE_2_NAME,
    SERVICE_3_ID,
};
use crate::scan::tests::fixtures::{IP_1, airplay_service, at, mrp_service, raop_service, service};
use crate::scan::tests::{scan, scan_protocols};
use crate::service_types::ServiceType;

/// `tests/test_scan_functional.py:127-140` — the protocol filter is applied at registration time,
/// so a filtered-out protocol's services are never discovered at all.
#[test]
fn the_protocol_filter_drops_services_rather_than_devices() {
    let all = at(
        IP_1,
        vec![
            mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            ),
            airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_1, 7000),
            raop_service(SERVICE_2_NAME, SERVICE_3_ID, IP_1, 5000),
        ],
    );

    let devices = scan_protocols(&all, &[Protocol::Mrp, Protocol::Raop]);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].services.len(), 2);
    assert!(devices[0].get_service(Protocol::Mrp).is_some());
    assert!(devices[0].get_service(Protocol::Raop).is_some());
    assert!(devices[0].get_service(Protocol::AirPlay).is_none());
}

/// RAOP's `service_info` reads the **`AirPlay` sibling's** access-control keys, not its own
/// (`pyatv/protocols/raop/__init__.py:502-511`).
#[test]
fn raop_pairing_follows_its_airplay_siblings_access_control() {
    for (key, value, expected) in [
        ("acl", "1", PairingRequirement::Disabled),
        ("act", "2", PairingRequirement::Unsupported),
    ] {
        let all = at(
            IP_1,
            vec![
                service(
                    ServiceType::AirPlay,
                    SERVICE_2_NAME,
                    IP_1,
                    7000,
                    &[("deviceid", SERVICE_2_ID), (key, value)],
                ),
                raop_service(SERVICE_2_NAME, SERVICE_3_ID, IP_1, 5000),
            ],
        );

        assert_eq!(
            scan(&all)[0]
                .get_service(Protocol::Raop)
                .map(|it| it.pairing),
            Some(expected),
            "airplay {key}={value}"
        );
    }
}

/// With no `AirPlay` sibling, RAOP falls back to reading its own TXT record exactly as an
/// `AirPlay` service would be read.
#[test]
fn raop_without_an_airplay_sibling_reads_its_own_properties() {
    let all = at(
        IP_1,
        vec![service(
            ServiceType::Raop,
            "raopid@HomePod",
            IP_1,
            5000,
            &[("pk", "abc"), ("sf", "0x200"), ("pw", "true")],
        )],
    );

    let raop = scan(&all)[0]
        .get_service(Protocol::Raop)
        .cloned()
        .expect("RAOP service");
    // `LEGACY_PAIRING_BIT` (0x200) forces pairing; `pw=true` forces a password.
    assert_eq!(raop.pairing, PairingRequirement::Mandatory);
    assert!(raop.requires_password);
}
