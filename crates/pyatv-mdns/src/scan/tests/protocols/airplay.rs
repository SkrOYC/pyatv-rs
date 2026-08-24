//! `AirPlay`, ported from `tests/protocols/airplay/test_airplay_scan.py`.

use pyatv_core::{DeviceModel, OperatingSystem, PairingRequirement, Protocol};

use super::{AIRPLAY_ID, AIRPLAY_NAME};
use crate::scan::tests::fixtures::{
    IP_1, airplay_service, airplay_service_with_model, at, service,
};
use crate::scan::tests::{assert_device, scan};
use crate::service_types::ServiceType;

/// `tests/protocols/airplay/test_airplay_scan.py:19-45`.
#[test]
fn airplay_service_yields_one_device() {
    let responses = at(
        IP_1,
        vec![airplay_service(AIRPLAY_NAME, AIRPLAY_ID, IP_1, 7000)],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        AIRPLAY_NAME,
        IP_1,
        AIRPLAY_ID,
        Protocol::AirPlay,
        7000,
        None,
    );
    // `deviceid` doubles as the MAC (`pyatv/protocols/airplay/__init__.py:216-217`).
    assert_eq!(devices[0].device_info.mac(), Some(AIRPLAY_ID));
}

/// The bare fixture carries no status flags, so pairing is optimistically `NotNeeded`
/// (`pyatv/protocols/airplay/utils.py:139-157`).
#[test]
fn airplay_without_flags_needs_no_pairing() {
    let responses = at(
        IP_1,
        vec![airplay_service(AIRPLAY_NAME, AIRPLAY_ID, IP_1, 7000)],
    );

    let service = scan(&responses)[0]
        .get_service(Protocol::AirPlay)
        .cloned()
        .expect("AirPlay service");
    assert_eq!(service.pairing, PairingRequirement::NotNeeded);
    assert!(!service.requires_password);
}

/// `fake_udns.airplay_service`'s `model=` branch sets `flags=0x8` (`PIN_REQUIRED`).
#[test]
fn airplay_with_a_model_requires_pairing_and_resolves_the_model() {
    let responses = at(
        IP_1,
        vec![airplay_service_with_model(
            AIRPLAY_NAME,
            AIRPLAY_ID,
            IP_1,
            7000,
            "AppleTV6,2",
        )],
    );
    let device = &scan(&responses)[0];

    assert_eq!(
        device.get_service(Protocol::AirPlay).map(|it| it.pairing),
        Some(PairingRequirement::Mandatory)
    );
    assert_eq!(device.device_info.model(), DeviceModel::Gen4K);
    assert_eq!(device.device_info.raw_model(), Some("AppleTV6,2"));
}

/// A bare `Mac\d+,\d+` model is refused outright, ahead of the flag-derived requirement
/// (`pyatv/protocols/airplay/utils.py:265-275`).
#[test]
fn airplay_on_a_bare_mac_model_is_unsupported() {
    let responses = at(
        IP_1,
        vec![airplay_service_with_model(
            "MacBook", AIRPLAY_ID, IP_1, 7000, "Mac14,3",
        )],
    );
    let device = &scan(&responses)[0];

    assert_eq!(
        device.get_service(Protocol::AirPlay).map(|it| it.pairing),
        Some(PairingRequirement::Unsupported)
    );
    // The same string still matches `lookup_os`'s prefix-only `Mac\d+,\d+` pattern, so the OS does
    // resolve — the two regexes differ only in the trailing `$` anchor.
    assert_eq!(
        device.device_info.operating_system(),
        OperatingSystem::MacOs
    );
    // `Mac14,3` is in neither model table, so only the raw string survives.
    assert_eq!(device.device_info.model(), DeviceModel::Unknown);
    assert_eq!(device.device_info.raw_model(), Some("Mac14,3"));
}

/// `acl=1` beats even the unsupported-model rule.
#[test]
fn airplay_with_access_control_is_pairing_disabled() {
    let responses = at(
        IP_1,
        vec![service(
            ServiceType::AirPlay,
            AIRPLAY_NAME,
            IP_1,
            7000,
            &[("deviceid", AIRPLAY_ID), ("acl", "1"), ("flags", "0x8")],
        )],
    );

    assert_eq!(
        scan(&responses)[0]
            .get_service(Protocol::AirPlay)
            .map(|it| it.pairing),
        Some(PairingRequirement::Disabled)
    );
}
