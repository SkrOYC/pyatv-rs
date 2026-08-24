//! RAOP and `_airport._tcp`, ported from `tests/protocols/raop/test_raop_scan.py`.

use pyatv_core::{DeviceModel, Protocol};

use super::{RAOP_ID, RAOP_NAME, RAOP_PORT};
use crate::scan::tests::fixtures::{IP_1, at, raop_service, service};
use crate::scan::tests::{assert_device, scan};
use crate::service_types::ServiceType;

/// `tests/protocols/raop/test_raop_scan.py:21-43`.
#[test]
fn raop_service_yields_one_device() {
    let responses = at(
        IP_1,
        vec![raop_service(RAOP_NAME, RAOP_ID, IP_1, RAOP_PORT)],
    );
    let devices = scan(&responses);

    assert_eq!(devices.len(), 1);
    assert_device(
        &devices[0],
        RAOP_NAME,
        IP_1,
        RAOP_ID,
        Protocol::Raop,
        RAOP_PORT,
        None,
    );
}

/// `_airport._tcp.local` never contributes a service, only device info
/// (`pyatv/protocols/raop/__init__.py:462-465`). `wama`'s first comma-separated segment is an
/// unkeyed MAC that pyatv names itself, and `syVs` overrides the version.
#[test]
fn airport_enriches_device_info_without_adding_a_service() {
    let responses = at(
        IP_1,
        vec![
            raop_service(RAOP_NAME, RAOP_ID, IP_1, RAOP_PORT),
            service(
                ServiceType::AirPort,
                "AirPort Express",
                IP_1,
                5009,
                &[("wama", "00-11-22-33-44-55,syVs=7.8.1,raMA=aa-bb")],
            ),
        ],
    );
    let device = &scan(&responses)[0];

    assert_eq!(device.services.len(), 1, "AirPort adds no service");
    assert_eq!(device.services[0].protocol, Protocol::Raop);
    assert_eq!(device.device_info.mac(), Some("00:11:22:33:44:55"));
    assert_eq!(device.device_info.version().as_deref(), Some("7.8.1"));
}

/// `am` supplies the model and MAC-free device info; `wama` must not overwrite an `am`-derived MAC.
#[test]
fn raop_am_and_ov_populate_device_info() {
    let responses = at(
        IP_1,
        vec![service(
            ServiceType::Raop,
            &format!("{RAOP_ID}@{RAOP_NAME}"),
            IP_1,
            RAOP_PORT,
            &[("am", "AudioAccessory5,1"), ("ov", "16.0")],
        )],
    );
    let info = &scan(&responses)[0].device_info;

    assert_eq!(info.model(), DeviceModel::HomePodMini);
    assert_eq!(info.raw_model(), Some("AudioAccessory5,1"));
    assert_eq!(info.version().as_deref(), Some("16.0"));
}
