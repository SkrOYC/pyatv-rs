//! Companion, ported from `tests/protocols/companion/test_companion_scan.py`.

use pyatv_core::{DeviceModel, PairingRequirement, Protocol};

use super::{COMPANION_NAME, COMPANION_PORT, MRP_ID, MRP_PORT, MRP_SERVICE_NAME};
use crate::scan::tests::fixtures::{IP_1, at, companion_service, mrp_service, service};
use crate::scan::tests::scan;
use crate::service_types::ServiceType;

/// `tests/protocols/companion/test_companion_scan.py:23-31` — a lone Companion service has no
/// identifier, so the device is never ready and never returned.
#[test]
fn a_lone_companion_service_yields_nothing() {
    let responses = at(
        IP_1,
        vec![companion_service(COMPANION_NAME, IP_1, COMPANION_PORT)],
    );
    assert!(scan(&responses).is_empty());
}

/// `tests/protocols/companion/test_companion_scan.py:37-59` — MRP lends it an identifier.
#[test]
fn companion_becomes_visible_alongside_mrp() {
    let responses = at(
        IP_1,
        vec![
            mrp_service(MRP_SERVICE_NAME, COMPANION_NAME, MRP_ID, IP_1, MRP_PORT),
            companion_service(COMPANION_NAME, IP_1, COMPANION_PORT),
        ],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].name, COMPANION_NAME);
    assert!(devices[0].get_service(Protocol::Mrp).is_some());
    assert_eq!(
        devices[0]
            .get_service(Protocol::Companion)
            .map(|it| it.port),
        Some(COMPANION_PORT)
    );
}

/// With no `rpfl` the fixture falls into the `Unsupported` fallback
/// (`pyatv/protocols/companion/__init__.py:659-660`).
#[test]
fn companion_without_rpfl_is_pairing_unsupported() {
    let responses = at(
        IP_1,
        vec![
            mrp_service(MRP_SERVICE_NAME, COMPANION_NAME, MRP_ID, IP_1, MRP_PORT),
            companion_service(COMPANION_NAME, IP_1, COMPANION_PORT),
        ],
    );

    assert_eq!(
        scan(&responses)[0]
            .get_service(Protocol::Companion)
            .map(|it| it.pairing),
        Some(PairingRequirement::Unsupported)
    );
}

/// The two `rpfl` masks, exactly as the constants are written upstream — `0x04` and `0x4000`,
/// which is *not* what the derivation comments beside them compute
/// (`docs/research/discovery-port-spec.md` §9.3).
///
/// Every hex value here is one upstream records as observed on real hardware
/// (`pyatv/protocols/companion/__init__.py:60-79`), which makes this a check on the masks rather
/// than on arithmetic. Note that `0x62792` — labelled "Unsupported/Mandatory" in that comment —
/// has neither bit set and lands on `Unsupported`; that is the constants-versus-comment
/// disagreement in action, and the constants are what is ported.
#[test]
fn companion_pairing_follows_the_rpfl_masks() {
    for (flags, expected) in [
        // Apple TV 4K, pairable.
        ("0x367A2", PairingRequirement::Mandatory),
        ("0x36782", PairingRequirement::Mandatory),
        // "Only devices in same home".
        ("0x627B6", PairingRequirement::Disabled),
        // HomePod mini, and Mac mini / MacBook.
        ("0x62792", PairingRequirement::Unsupported),
        ("0x20000", PairingRequirement::Unsupported),
        // Absent or malformed reads as `0x0`.
        ("garbage", PairingRequirement::Unsupported),
    ] {
        let responses = at(
            IP_1,
            vec![service(
                ServiceType::CompanionLink,
                COMPANION_NAME,
                IP_1,
                COMPANION_PORT,
                &[("rpmrtid", "companion_id"), ("rpfl", flags)],
            )],
        );

        assert_eq!(
            scan(&responses)[0]
                .get_service(Protocol::Companion)
                .map(|it| it.pairing),
            Some(expected),
            "rpfl={flags}"
        );
    }
}

/// `rpmd` resolves the model and always keeps the raw string
/// (`pyatv/protocols/companion/__init__.py:637-644`).
#[test]
fn companion_rpmd_populates_the_model() {
    let responses = at(
        IP_1,
        vec![service(
            ServiceType::CompanionLink,
            COMPANION_NAME,
            IP_1,
            COMPANION_PORT,
            &[("rpmrtid", "companion_id"), ("rpmd", "AppleTV11,1")],
        )],
    );
    let info = &scan(&responses)[0].device_info;

    assert_eq!(info.model(), DeviceModel::AppleTv4KGen2);
    assert_eq!(info.raw_model(), Some("AppleTV11,1"));
}
