//! MRP, ported from `tests/protocols/mrp/test_mrp_scan.py`.

use pyatv_core::{OperatingSystem, PairingRequirement, Protocol};

use super::{MRP_ID, MRP_NAME, MRP_PORT, MRP_SERVICE_NAME};
use crate::scan::tests::fixtures::{IP_1, at, mrp_service, mrp_service_with_version, service};
use crate::scan::tests::{assert_device, scan, scan_protocols};
use crate::service_types::ServiceType;

/// `tests/protocols/mrp/test_mrp_scan.py:22-33`.
#[test]
fn mrp_service_yields_one_device() {
    let responses = at(
        IP_1,
        vec![mrp_service(
            MRP_SERVICE_NAME,
            MRP_NAME,
            MRP_ID,
            IP_1,
            MRP_PORT,
        )],
    );
    let devices = scan_protocols(&responses, &[Protocol::Mrp]);

    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        MRP_NAME,
        IP_1,
        MRP_ID,
        Protocol::Mrp,
        MRP_PORT,
        None,
    );
}

/// The display name is MRP's `Name` TXT key, not its mDNS instance name
/// (`pyatv/protocols/mrp/__init__.py:1041`).
#[test]
fn mrp_takes_its_display_name_from_the_name_txt_key() {
    let responses = at(
        IP_1,
        vec![mrp_service(
            MRP_SERVICE_NAME,
            MRP_NAME,
            MRP_ID,
            IP_1,
            MRP_PORT,
        )],
    );
    assert_eq!(scan(&responses)[0].name, MRP_NAME);
}

/// No `Name` key at all falls back to the literal `"Unknown"`.
#[test]
fn mrp_without_a_name_key_is_called_unknown() {
    let responses = at(
        IP_1,
        vec![service(
            ServiceType::MediaRemoteTv,
            MRP_SERVICE_NAME,
            IP_1,
            MRP_PORT,
            &[("UniqueIdentifier", MRP_ID)],
        )],
    );
    assert_eq!(scan(&responses)[0].name, "Unknown");
}

/// MRP is always reported as tvOS, an upstream guess
/// (`pyatv/protocols/mrp/__init__.py:1081-1083`), and `18M60` resolves to 14.7.
#[test]
fn mrp_device_info_is_tvos_with_a_resolved_version() {
    let responses = at(
        IP_1,
        vec![mrp_service(
            MRP_SERVICE_NAME,
            MRP_NAME,
            MRP_ID,
            IP_1,
            MRP_PORT,
        )],
    );
    let info = &scan(&responses)[0].device_info;

    assert_eq!(info.operating_system(), OperatingSystem::TvOs);
    assert_eq!(info.build_number(), Some("18M60"));
    assert_eq!(info.version().as_deref(), Some("14.7"));
}

/// `tests/test_scan_functional.py:143-150` — the service stays attached, just disabled.
#[test]
fn mrp_disables_itself_on_tvos_15() {
    let responses = at(
        IP_1,
        vec![mrp_service_with_version(
            MRP_SERVICE_NAME,
            MRP_NAME,
            MRP_ID,
            IP_1,
            MRP_PORT,
            "19J346",
        )],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    let service = devices[0]
        .get_service(Protocol::Mrp)
        .expect("MRP service is attached even when disabled");
    assert!(!service.enabled);
    // A disabled service reports `NotNeeded`, not `Unsupported`
    // (`pyatv/protocols/mrp/__init__.py:1097-1098`).
    assert_eq!(service.pairing, PairingRequirement::NotNeeded);
}

/// `18M60` is build major 18, below the threshold, so MRP stays enabled — and with no
/// `AllowPairing` key its pairing requirement is `Disabled`.
#[test]
fn mrp_below_tvos_15_stays_enabled_with_pairing_disabled() {
    let responses = at(
        IP_1,
        vec![mrp_service(
            MRP_SERVICE_NAME,
            MRP_NAME,
            MRP_ID,
            IP_1,
            MRP_PORT,
        )],
    );
    let service = scan(&responses)[0]
        .get_service(Protocol::Mrp)
        .cloned()
        .expect("MRP service");

    assert!(service.enabled);
    assert_eq!(service.pairing, PairingRequirement::Disabled);
}

/// `AllowPairing: YES` makes pairing optional (`pyatv/protocols/mrp/__init__.py:1099-1100`).
#[test]
fn mrp_with_allowpairing_yes_is_optional() {
    let responses = at(
        IP_1,
        vec![service(
            ServiceType::MediaRemoteTv,
            MRP_SERVICE_NAME,
            IP_1,
            MRP_PORT,
            &[
                ("Name", MRP_NAME),
                ("UniqueIdentifier", MRP_ID),
                ("AllowPairing", "YES"),
            ],
        )],
    );

    assert_eq!(
        scan(&responses)[0]
            .get_service(Protocol::Mrp)
            .map(|it| it.pairing),
        Some(PairingRequirement::Optional)
    );
}
