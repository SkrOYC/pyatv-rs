//! DMAP and its three service types, ported from `tests/protocols/dmap/test_dmap_scan.py`.

use pyatv_core::{DeviceModel, OperatingSystem, PairingRequirement, Protocol};

use super::{DMAP_HSGID, DMAP_NAME, DMAP_SERVICE_NAME};
use crate::scan::tests::fixtures::{IP_1, at, device_service, homesharing_service, hscp_service};
use crate::scan::tests::{assert_device, scan};

/// `tests/protocols/dmap/test_dmap_scan.py:24-45` — the Home Sharing service's `hG` credentials
/// survive the merge with the plain DMAP service.
#[test]
fn dmap_home_sharing_merges_with_plain_dmap() {
    let responses = at(
        IP_1,
        vec![
            device_service(DMAP_SERVICE_NAME, DMAP_NAME, IP_1),
            homesharing_service(DMAP_SERVICE_NAME, DMAP_NAME, DMAP_HSGID, IP_1),
        ],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].services.len(), 1, "all three types are one DMAP");
    assert_device(
        &devices[0],
        DMAP_NAME,
        IP_1,
        DMAP_SERVICE_NAME,
        Protocol::Dmap,
        3689,
        Some(DMAP_HSGID),
    );
    // `hG` present means pairing is only optional
    // (`pyatv/protocols/dmap/__init__.py:654-657`).
    assert_eq!(
        devices[0].get_service(Protocol::Dmap).map(|it| it.pairing),
        Some(PairingRequirement::Optional)
    );
}

/// `tests/protocols/dmap/test_dmap_scan.py:113-128` — no Home Sharing, no credentials, and pairing
/// becomes mandatory.
#[test]
fn dmap_without_home_sharing_has_no_credentials() {
    let responses = at(
        IP_1,
        vec![device_service(DMAP_SERVICE_NAME, DMAP_NAME, IP_1)],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        DMAP_NAME,
        IP_1,
        DMAP_SERVICE_NAME,
        Protocol::Dmap,
        3689,
        None,
    );
    assert_eq!(
        devices[0].get_service(Protocol::Dmap).map(|it| it.pairing),
        Some(PairingRequirement::Mandatory)
    );
}

/// `tests/protocols/dmap/test_dmap_scan.py:72-89` — HSCP names itself from `Machine Name`,
/// identifies itself by `Machine ID`, and is hardcoded to the Music model.
#[test]
fn hscp_yields_a_music_device() {
    let responses = at(
        IP_1,
        vec![hscp_service(
            DMAP_NAME,
            DMAP_SERVICE_NAME,
            DMAP_HSGID,
            IP_1,
            3689,
        )],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        DMAP_NAME,
        IP_1,
        DMAP_SERVICE_NAME,
        Protocol::Dmap,
        3689,
        Some(DMAP_HSGID),
    );
    assert_eq!(devices[0].device_info.model(), DeviceModel::Music);
    assert_eq!(
        devices[0].device_info.operating_system(),
        OperatingSystem::Legacy
    );
}
