//! `pyatv::connect` against a legacy DMAP Apple TV.
//!
//! Counterpart of `tests/protocols/dmap/test_dmap_functional.py`'s `get_connected_device`
//! (`:73-90`). The protocol-level behaviour is covered inside `pyatv-proto-dmap`; what this proves
//! is the seam that only exists here — that `connect()` routes a `Protocol::Dmap` service into
//! `pyatv_proto_dmap::facade::setup`, hands it the right address, credentials and service types,
//! and files the result into the facade's relayers.
//!
//! A gen 1-3 Apple TV never advertises anything else, so the device stands up alone rather than
//! alongside the AirPlay/Companion fakes the other tests here use.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use pyatv::{FeatureName, FeatureState, MediaType};
use pyatv_core::consts::Protocol;
use pyatv_core::storage::MemoryStorage;
use pyatv_core::{BaseConfig, BaseService};
use pyatv_proto_dmap::test_support::fake_dmap::FakeDmapDevice;
use pyatv_proto_dmap::test_support::fake_state::HSGID;

/// The DNS-SD type a gen 2/3 Apple TV answers under.
const APPLETV_V2: &str = "_appletv-v2._tcp.local";

/// A config describing the fake device, with the Home Sharing credential already on the service.
fn config(device: &FakeDmapDevice, service_type: &str) -> BaseConfig {
    let mut service = BaseService::new(Protocol::Dmap, device.port());
    service.identifier = Some("dmapid".to_owned());
    service.credentials = Some(HSGID.to_owned());

    let mut properties = HashMap::new();
    properties.insert(service_type.to_owned(), HashMap::new());

    let mut config = BaseConfig::new("Apple TV", IpAddr::V4(Ipv4Addr::LOCALHOST));
    config.add_service(service);
    config.set_properties(properties);
    config
}

/// Everything DMAP registers is reachable through the facade `connect()` returns.
#[tokio::test]
async fn connect_brings_up_dmap_and_files_it_into_the_facade() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_music();

    let atv = pyatv::connect(
        &config(&device, APPLETV_V2),
        None,
        Arc::new(MemoryStorage::new()),
    )
    .await
    .expect("connect must succeed against the fake");

    let playing = atv
        .metadata()
        .expect("DMAP must register Metadata")
        .playing()
        .await
        .expect("playing() must not fail");
    assert_eq!(playing.title.as_deref(), Some("music"));
    assert_eq!(playing.media_type, MediaType::Music);

    atv.remote_control()
        .expect("DMAP must register RemoteControl")
        .play_pause()
        .await
        .expect("play_pause must reach the device");

    assert!(
        atv.push_updater().is_some(),
        "DMAP must register a PushUpdater"
    );
    assert!(atv.audio().is_some(), "DMAP must register Audio");
    assert_eq!(
        atv.features().get_feature(FeatureName::Select).state,
        FeatureState::Available
    );
    // Nothing on gen 1-3 hardware streams or lists apps, and no other protocol is connected to
    // supply them.
    assert!(atv.apps().is_none());
    assert!(atv.power().is_none());

    use_cases.assert_no_protocol_errors();
    atv.close().await.expect("closing must succeed");
}

/// `_device_info` reads the TXT records back per service type (`dmap/__init__.py:696-704`), so the
/// service type the scan saw is what decides the reported model.
#[tokio::test]
async fn the_service_type_decides_what_the_device_is_reported_as() {
    let appletv = FakeDmapDevice::start().await;
    let atv = pyatv::connect(
        &config(&appletv, APPLETV_V2),
        None,
        Arc::new(MemoryStorage::new()),
    )
    .await
    .expect("connect must succeed");
    assert_eq!(
        atv.device_info().operating_system(),
        pyatv_core::OperatingSystem::Legacy
    );
    assert_eq!(
        atv.device_info().model(),
        pyatv_core::DeviceModel::Unknown,
        "an Apple TV must not be reported as the Music app"
    );

    // `_hscp._tcp.local` is iTunes/Music on a desktop, not an Apple TV at all.
    let music = FakeDmapDevice::start().await;
    let atv = pyatv::connect(
        &config(&music, "_hscp._tcp.local"),
        None,
        Arc::new(MemoryStorage::new()),
    )
    .await
    .expect("connect must succeed");
    assert_eq!(atv.device_info().model(), pyatv_core::DeviceModel::Music);
}

/// A device that refuses the credential fails the whole connect, because DMAP is the only protocol
/// there is — `connect()` only tolerates a protocol failing when another one succeeded.
#[tokio::test]
async fn a_refused_credential_fails_the_connect() {
    let device = FakeDmapDevice::start().await;
    device.use_cases().make_login_fail();

    let error = pyatv::connect(
        &config(&device, APPLETV_V2),
        None,
        Arc::new(MemoryStorage::new()),
    )
    .await
    .expect_err("a device that refuses the credential must not connect");

    // `connect()` wraps the last protocol failure in `ConnectionFailed` rather than surfacing it
    // raw, so the reason string is where the underlying 503 shows up.
    let pyatv_core::Error::ConnectionFailed { reason, .. } = &error else {
        panic!("expected a connection failure, got {error:?}");
    };
    assert!(
        reason.contains("authentication failed") && reason.contains("503"),
        "the refused login must be visible in the reason, was {reason:?}"
    );
}
