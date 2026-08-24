//! Device-info merging and its first-writer-wins precedence rule.

use pyatv_core::{DeviceModel, OperatingSystem, Protocol};

use super::{SERVICE_1_ID, SERVICE_1_NAME, SERVICE_1_SERVICE_NAME, SERVICE_2_ID, SERVICE_2_NAME};
use crate::scan::tests::fixtures::{
    IP_1, airplay_service, at, mrp_service, response_with, responses, service,
};
use crate::scan::tests::{scan, scan_protocols};
use crate::service_types::ServiceType;

/// `tests/test_scan_functional.py:106-115` — MRP and `AirPlay` on one device, and the MAC comes
/// from `AirPlay`'s `deviceid` because MRP's fixture advertises no `MACAddress`.
#[test]
fn device_info_merges_across_services() {
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
        ],
    );

    let devices = scan(&all);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_info.mac(), Some(SERVICE_2_ID));
    assert_eq!(devices[0].services.len(), 2);
}

/// Device-info precedence is first-writer-wins in service-discovery order, *not* a per-protocol
/// priority table (`pyatv/support/collections.py:11-28`, `dict_merge` without `allow_overwrite`).
/// Here MRP is discovered first and its unconditional tvOS claim beats `AirPlay`'s macOS one.
#[test]
fn the_first_service_discovered_wins_a_contested_device_info_key() {
    let mrp_first = at(
        IP_1,
        vec![
            mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            ),
            service(
                ServiceType::AirPlay,
                SERVICE_2_NAME,
                IP_1,
                7000,
                &[("deviceid", SERVICE_2_ID), ("model", "MacBookPro5,67")],
            ),
        ],
    );
    assert_eq!(
        scan(&mrp_first)[0].device_info.operating_system(),
        OperatingSystem::TvOs
    );

    let airplay_first = at(
        IP_1,
        vec![
            service(
                ServiceType::AirPlay,
                SERVICE_2_NAME,
                IP_1,
                7000,
                &[("deviceid", SERVICE_2_ID), ("model", "MacBookPro5,67")],
            ),
            mrp_service(
                SERVICE_1_SERVICE_NAME,
                SERVICE_1_NAME,
                SERVICE_1_ID,
                IP_1,
                49152,
            ),
        ],
    );
    assert_eq!(
        scan(&airplay_first)[0].device_info.operating_system(),
        OperatingSystem::MacOs
    );
}

/// `tests/test_scan_functional.py:117-124` — `J105aAP` is an *internal* codename, resolved through
/// the `_device-info._tcp.local` model rather than any of MRP's own TXT keys.
#[test]
fn the_device_info_model_resolves_an_internal_codename() {
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
            false,
            Some("J105aAP"),
        ),
    )]);

    let devices = scan_protocols(&all, &[Protocol::Mrp]);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_info.model(), DeviceModel::Gen4K);
}

/// The internal-codename model is merged **last and never overwrites**
/// (`pyatv/core/scan.py:245-247`), so a model another protocol already resolved wins.
#[test]
fn an_already_resolved_model_beats_the_internal_codename() {
    let all = responses(vec![(
        IP_1,
        response_with(
            vec![service(
                ServiceType::CompanionLink,
                "Companion",
                IP_1,
                49153,
                &[("rpmrtid", "companion_id"), ("rpmd", "AudioAccessory5,1")],
            )],
            false,
            // Would resolve to Gen4K on its own.
            Some("J105aAP"),
        ),
    )]);

    assert_eq!(
        scan(&all)[0].device_info.model(),
        DeviceModel::HomePodMini,
        "Companion's rpmd was written first and must not be overwritten"
    );
}

/// An unrecognised `_device-info` model simply leaves the model unknown.
#[test]
fn an_unknown_internal_codename_leaves_the_model_unresolved() {
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
            false,
            Some("dummy"),
        ),
    )]);

    assert_eq!(scan(&all)[0].device_info.model(), DeviceModel::Unknown);
}
