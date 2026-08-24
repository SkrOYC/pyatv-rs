//! Response grouping, the address/port gate, and deep sleep.

use super::{
    SERVICE_1_ID, SERVICE_1_NAME, SERVICE_1_SERVICE_NAME, SERVICE_2_ID, SERVICE_2_NAME,
    SERVICE_3_ID,
};
use crate::scan::tests::fixtures::{
    IP_1, IP_2, airplay_service, at, mrp_service, raop_service, response, response_with, responses,
    sleep_proxy_service,
};
use crate::scan::tests::{scan, scan_identifiers};

/// `tests/test_scan_functional.py:67-69`.
#[test]
fn nothing_answered_means_no_devices() {
    assert!(scan(&responses(vec![])).is_empty());
    assert!(scan(&at(IP_1, vec![])).is_empty());
}

/// `tests/test_scan_functional.py:72-81` — the identifier filter matches on *any* of a device's
/// identifiers, and the other address is dropped entirely.
#[test]
fn scanning_for_a_particular_device_drops_the_others() {
    let all = responses(vec![
        (
            IP_1,
            response(vec![
                airplay_service(SERVICE_2_NAME, SERVICE_2_ID, IP_1, 7000),
                mrp_service(
                    SERVICE_1_SERVICE_NAME,
                    SERVICE_1_NAME,
                    SERVICE_1_ID,
                    IP_1,
                    49152,
                ),
                raop_service(SERVICE_2_NAME, SERVICE_3_ID, IP_1, 5000),
            ]),
        ),
        (
            IP_2,
            response(vec![airplay_service("Other", "other_id", IP_2, 7000)]),
        ),
    ]);

    let devices = scan_identifiers(&all, &[SERVICE_1_ID, SERVICE_2_ID]);
    assert_eq!(devices.len(), 1);
    // The first handler to produce a service names the device; `AirPlay` came first here.
    assert_eq!(devices[0].name, SERVICE_2_NAME);
    assert_eq!(devices[0].address, IP_1);
}

/// `tests/test_scan_functional.py:84-91` — a single identifier works the same way.
#[test]
fn scanning_for_one_identifier_picks_the_right_address() {
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
            response(vec![airplay_service(
                SERVICE_2_NAME,
                SERVICE_2_ID,
                IP_2,
                7000,
            )]),
        ),
    ]);

    let devices = scan_identifiers(&all, &[SERVICE_2_ID]);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, SERVICE_2_NAME);
    assert_eq!(devices[0].address, IP_2);
}

/// `tests/test_scan_functional.py:94-103` — a sleeping device with a usable identifier still
/// produces a config, flagged. This is the canonical counter-example to "sleeping devices never
/// appear"; see `docs/research/discovery-port-spec.md` §8.7.
#[test]
fn a_deep_sleeping_device_still_appears() {
    let all = responses(vec![(
        IP_1,
        response_with(
            vec![mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            )],
            true,
            None,
        ),
    )]);

    let devices = scan(&all);
    assert_eq!(devices.len(), 1);
    assert!(devices[0].deep_sleep);
}

/// A device visible only through a sleep proxy has no protocol service and no identifier, so it is
/// filtered out — the sleep-proxy type has no handler at all
/// (`pyatv/core/scan.py:114-120`).
#[test]
fn a_sleep_proxy_only_device_is_not_returned() {
    let all = responses(vec![(
        IP_1,
        response_with(
            vec![sleep_proxy_service("70-35-60-63.1 Ohana", IP_1, 54942)],
            true,
            None,
        ),
    )]);

    assert!(scan(&all).is_empty());
}

/// The address/port gate (`pyatv/core/scan.py:200-201`): the placeholder shape a sleep proxy
/// answers with is discarded before any handler runs.
#[test]
fn services_with_no_port_are_discarded_entirely() {
    let all = at(
        IP_1,
        vec![mrp_service(
            SERVICE_1_SERVICE_NAME,
            SERVICE_1_NAME,
            SERVICE_1_ID,
            IP_1,
            0,
        )],
    );
    assert!(scan(&all).is_empty());
}

/// The same gate for a service that never resolved an address.
#[test]
fn services_with_no_address_are_discarded_entirely() {
    let mut orphan = mrp_service(
        SERVICE_1_SERVICE_NAME,
        SERVICE_1_NAME,
        SERVICE_1_ID,
        IP_1,
        49152,
    );
    orphan.address = None;

    assert!(scan(&responses(vec![(IP_1, response(vec![orphan]))])).is_empty());
}
