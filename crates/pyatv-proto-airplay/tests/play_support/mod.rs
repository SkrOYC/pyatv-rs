//! Shared bring-up for the `play_url` integration tests.
//!
//! A module rather than a copy in each test binary: pairing against the hermetic receiver and
//! pointing a player at it is the same twelve requests every time, and only the scenario after it
//! differs. Lives in a subdirectory so `cargo test` does not build it as a test binary of its own.

use pyatv_proto_airplay::test_support as support;

use std::time::Duration;

use pyatv_core::airplay::AirPlayMajorVersion;
use pyatv_pairing::server::AIRPLAY_PIN;
use pyatv_pairing::{HapCredentials, PairSetup};
use pyatv_proto_airplay::HttpConnection;
use pyatv_proto_airplay::auth::{HKP_HAP, PAIR_SETUP_PATH, PIN_START_PATH, hap_headers};
use pyatv_proto_airplay::setup::AirPlayStream;
use pyatv_proto_airplay::stream::{AirPlayPlayer, PlayOptions, PlayTiming};

use support::fake_airplay::{FakeAirPlayDevice, FakeOptions};
use support::fake_play::PlayMode;

/// What every test plays.
pub const URL: &str = "http://airplaystream/video.mp4";

/// `START_POSITION = 0.8` (`test_airplay_player.py:15`), fractional on purpose so the plist number
/// type is exercised too.
pub const START_POSITION: f64 = 0.8;

/// Fast enough that a test spends milliseconds where pyatv would spend seconds, slow enough that
/// the poll loop still interleaves with the keepalive.
pub fn quick() -> PlayTiming {
    PlayTiming {
        retry_delay: Duration::from_millis(10),
        poll_interval: Duration::from_millis(10),
        feedback_interval: Duration::from_millis(30),
    }
}

/// Pair once, so pair-verify has a registered controller (identical to `airplay_tunnel.rs`).
pub async fn pair(device: &FakeAirPlayDevice) -> HapCredentials {
    let mut http = HttpConnection::connect(device.address())
        .await
        .expect("connection should open");
    let headers = hap_headers(HKP_HAP);

    http.post(PIN_START_PATH, &headers, b"")
        .await
        .expect("pin-start should be answered");

    let (mut setup, m1) = PairSetup::start(None);
    let m2 = http
        .post(PAIR_SETUP_PATH, &headers, &m1)
        .await
        .expect("M1 should be answered");

    setup.set_pin(AIRPLAY_PIN);
    let m3 = setup.handle_m2(&m2.body).expect("M2 should parse");
    let m4 = http
        .post(PAIR_SETUP_PATH, &headers, &m3)
        .await
        .expect("M3 should be answered");

    let m5 = setup.handle_m4(&m4.body).expect("M4 should parse");
    let m6 = http
        .post(PAIR_SETUP_PATH, &headers, &m5)
        .await
        .expect("M5 should be answered");

    let credentials = setup.handle_m6(&m6.body).expect("M6 should parse");
    http.close().await.expect("closing should succeed");
    credentials
}

/// A receiver expecting `AirPlay` 2, paired, with a player pointed at it.
pub async fn ap2(options: FakeOptions) -> (FakeAirPlayDevice, AirPlayPlayer) {
    let device = FakeAirPlayDevice::start_with(options).await;
    let credentials = pair(&device).await;

    let player = AirPlayPlayer::connect(&PlayOptions {
        timing: quick(),
        ..PlayOptions::new(device.address(), credentials, AirPlayMajorVersion::V2)
    })
    .await
    .expect("the receiver should accept a connection");

    (device, player)
}

/// The same receiver, behind the facade's [`AirPlayStream`] rather than a bare player.
///
/// This is what `setup()` registers and what `atvremote play_url` reaches, so the tests that care
/// about the `Stream`/`RemoteControl` pair — the stop signal in particular — go through here.
pub async fn ap2_stream(options: FakeOptions) -> (FakeAirPlayDevice, AirPlayStream) {
    let device = FakeAirPlayDevice::start_with(options).await;
    let credentials = pair(&device).await;

    let stream = AirPlayStream::new(PlayOptions {
        timing: quick(),
        ..PlayOptions::new(device.address(), credentials, AirPlayMajorVersion::V2)
    });

    (device, stream)
}

/// A receiver expecting `AirPlay` 1, which needs no pairing at all: null credentials make
/// pair-verify a no-op that sends nothing, exactly as `NO_CREDENTIALS` does upstream
/// (`test_airplay_player.py:24`).
pub async fn ap1() -> (FakeAirPlayDevice, AirPlayPlayer) {
    let device = FakeAirPlayDevice::start_with(FakeOptions {
        play_mode: PlayMode::AirPlayV1,
        ..FakeOptions::default()
    })
    .await;

    let player = AirPlayPlayer::connect(&PlayOptions {
        timing: quick(),
        ..PlayOptions::new(
            device.address(),
            HapCredentials::null(),
            AirPlayMajorVersion::V1,
        )
    })
    .await
    .expect("the receiver should accept a connection");

    (device, player)
}
