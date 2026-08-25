//! Standing three hermetic devices up so `pyatv::connect` has something to connect to.
//!
//! Each protocol crate ships its own fake behind a `test-support` feature; this module is the wiring
//! that makes them look like one Apple TV. The shape is the tvOS 15+ one described in
//! `docs/research/airplay-control-mrp-tunnel-port-spec.md` §1.3: an `_airplay._tcp` service, a
//! `_companion-link._tcp` service, and **no** `_mediaremotetv._tcp` at all — so the only way MRP can
//! answer is through the tunnel.

#![allow(
    dead_code,
    reason = "each test binary uses a different subset of this harness"
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use pyatv::{BaseConfig, BaseService, MemoryStorage, Protocol};
use pyatv_core::interface::PairingHandler as _;
use pyatv_pairing::server::{AIRPLAY_PIN, PIN_CODE};
use pyatv_pairing::{HapCredentials, PairSetup};
use pyatv_proto_airplay::auth::{HKP_HAP, PAIR_SETUP_PATH, PIN_START_PATH, hap_headers};
use pyatv_proto_airplay::test_support::fake_airplay::{FakeAirPlayDevice, FakeOptions};
use pyatv_proto_companion::auth::PairSetupOptionsCompanion;
use pyatv_proto_companion::pairing::{CompanionPairingHandler, CompanionPairingOptions};
use pyatv_proto_companion::test_support::fake_companion::FakeCompanionDevice;
use pyatv_proto_companion::test_support::fake_state::DeviceState;
use pyatv_proto_mrp::test_support::fake_mrp::FakeMrpDevice;
use pyatv_proto_mrp::test_support::fake_state::FakeDeviceState;

/// The identifier every service is filed under, so the config resolves to one device.
pub const DEVICE_IDENTIFIER: &str = "AA:BB:CC:DD:EE:FF";

/// How long a poll waits before giving up; generous, since it only bounds a failing test.
pub const DEADLINE: Duration = Duration::from_secs(5);

/// How often a poll re-checks.
pub const TICK: Duration = Duration::from_millis(10);

/// The three fakes, kept alive for the duration of a test.
///
/// Dropping this stops every accept loop, which is also how a test can simulate the device going
/// away without asking it to.
#[derive(Debug)]
pub struct FakeAppleTv {
    /// The AirPlay 2 receiver, whose data channel is bridged onto `mrp`.
    pub airplay: FakeAirPlayDevice,
    /// The MRP device sitting behind the tunnel.
    pub mrp: FakeMrpDevice,
    /// The Companion device on its own port.
    pub companion: FakeCompanionDevice,
    airplay_credentials: HapCredentials,
    companion_credentials: String,
}

impl FakeAppleTv {
    /// Start all three, pair AirPlay and Companion, and leave everything ready to connect to.
    pub async fn start() -> Self {
        Self::start_with(false).await
    }

    /// As [`FakeAppleTv::start`], with a receiver that refuses every remote-control `SETUP`.
    ///
    /// The tunnel then fails *after* pair-verify, which is where a real refusal lands, so what a
    /// test built on this exercises is the bring-up failure path rather than the gate that
    /// declines before dialling.
    pub async fn start_without_a_tunnel() -> Self {
        Self::start_with(true).await
    }

    async fn start_with(refuse_setup: bool) -> Self {
        let mrp = FakeMrpDevice::start(PIN_CODE).await;
        let airplay = FakeAirPlayDevice::start_with(FakeOptions {
            pin: AIRPLAY_PIN,
            data_bridge: Some(mrp.address()),
            refuse_setup,
            ..FakeOptions::default()
        })
        .await;
        let companion = FakeCompanionDevice::start(PIN_CODE).await;

        let airplay_credentials = pair_airplay(&airplay).await;
        let companion_credentials = pair_companion(&companion).await;

        Self {
            airplay,
            mrp,
            companion,
            airplay_credentials,
            companion_credentials,
        }
    }

    /// Change what the MRP device believes before connecting.
    pub fn arrange_mrp(&self, arrange: impl FnOnce(&Arc<FakeDeviceState>)) {
        arrange(&self.mrp.state());
    }

    /// Change what the Companion device believes before connecting.
    pub async fn arrange_companion(&self, arrange: impl FnOnce(&mut DeviceState)) {
        arrange(&mut *self.companion.state().lock().await);
    }

    /// The config a scan of this device would have produced, credentials included.
    ///
    /// The TXT record is the tvOS 27 test device's, decoded in the port spec §1: `AppleTV14,1` on
    /// tvOS 27, with the feature bits that make `get_protocol_version` say AirPlay 2 and
    /// `is_remote_control_supported` say yes.
    pub fn config(&self) -> BaseConfig {
        let mut config = BaseConfig::new("Fake", IpAddr::V4(Ipv4Addr::LOCALHOST));

        let mut airplay = BaseService::new(Protocol::AirPlay, self.airplay.address().port());
        airplay.identifier = Some(DEVICE_IDENTIFIER.to_owned());
        airplay.credentials = Some(self.airplay_credentials.to_string());
        for (key, value) in [
            ("features", "0x4A7FDFD5,0x3C177FDE"),
            ("flags", "0x18644"),
            ("model", "AppleTV14,1"),
            ("osvers", "27.0"),
            ("deviceid", DEVICE_IDENTIFIER),
        ] {
            airplay
                .properties
                .insert((*key).to_owned(), (*value).to_owned());
        }
        config.add_service(airplay);

        let mut companion = BaseService::new(Protocol::Companion, self.companion.address().port());
        companion.identifier = Some(DEVICE_IDENTIFIER.to_owned());
        companion.credentials = Some(self.companion_credentials.clone());
        config.add_service(companion);

        config
    }

    /// Run the real `pyatv::connect` against all three.
    pub async fn connect(&self) -> Arc<dyn pyatv::AppleTV> {
        pyatv::connect(&self.config(), None, Arc::new(MemoryStorage::new()))
            .await
            .expect("connect must succeed against the fakes")
    }
}

/// Run AirPlay pair-setup against the fake receiver and keep the credentials.
///
/// The same six-message exchange `atvremote pair --protocol airplay` drives, over the real HTTP
/// routes (`pyatv/protocols/airplay/server_auth.py:150-264`).
async fn pair_airplay(device: &FakeAirPlayDevice) -> HapCredentials {
    use pyatv_proto_airplay::HttpConnection;

    let mut http = HttpConnection::connect(device.address())
        .await
        .expect("the fake receiver must accept a connection");
    let headers = hap_headers(HKP_HAP);

    http.post(PIN_START_PATH, &headers, b"")
        .await
        .expect("pin-start must be answered");

    let (mut setup, m1) = PairSetup::start(None);
    let m2 = http
        .post(PAIR_SETUP_PATH, &headers, &m1)
        .await
        .expect("M1 must be answered");

    setup.set_pin(AIRPLAY_PIN);
    let m3 = setup.handle_m2(&m2.body).expect("M2 must parse");
    let m4 = http
        .post(PAIR_SETUP_PATH, &headers, &m3)
        .await
        .expect("M3 must be answered");

    let m5 = setup.handle_m4(&m4.body).expect("M4 must parse");
    let m6 = http
        .post(PAIR_SETUP_PATH, &headers, &m5)
        .await
        .expect("M5 must be answered");

    let credentials = setup.handle_m6(&m6.body).expect("M6 must parse");
    http.close().await.expect("closing must succeed");
    credentials
}

/// Run Companion pair-setup and return the credential string.
async fn pair_companion(device: &FakeCompanionDevice) -> String {
    let mut service = BaseService::new(Protocol::Companion, device.address().port());
    service.identifier = Some(DEVICE_IDENTIFIER.to_owned());

    let handler = CompanionPairingHandler::new(
        CompanionPairingOptions {
            address: device.address().ip(),
            service,
            device_identifier: DEVICE_IDENTIFIER.to_owned(),
            setup: PairSetupOptionsCompanion::default(),
        },
        Arc::new(MemoryStorage::new()),
    );

    handler.begin().await.expect("pairing must begin");
    handler.pin(PIN_CODE).expect("the PIN must be accepted");
    handler.finish().await.expect("pairing must finish");
    handler
        .service()
        .credentials
        .expect("pairing must produce credentials")
}

/// Poll `check` until it yields a value or [`DEADLINE`] passes.
///
/// The devices push state asynchronously, so there is no point at which "the update has arrived" is
/// synchronously observable; pyatv's own tests poll for the same reason (`tests/utils.py`).
pub async fn until<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(TICK).await;
    }
}
