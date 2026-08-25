//! Shared bring-up for the RAOP streaming tests.
//!
//! Pairing against the hermetic receiver and pointing a [`RaopStream`] at it is the same handful of
//! requests every time; only the scenario after it differs. Lives in a subdirectory so `cargo test`
//! does not build it as a test binary of its own.

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::consts::Protocol;
use pyatv_core::models::BaseService;
use pyatv_pairing::server::AIRPLAY_PIN;
use pyatv_pairing::{HapCredentials, PairSetup};
use pyatv_proto_airplay::HttpConnection;
use pyatv_proto_airplay::auth::{HKP_HAP, PAIR_SETUP_PATH, PIN_START_PATH, hap_headers};
use pyatv_proto_airplay::raop::facade::{RaopPushUpdater, RaopStream};
use pyatv_proto_airplay::raop::manager::RaopPlaybackManager;
use pyatv_proto_airplay::test_support::fake_raop::{
    FakeRaopDevice, FakeRaopOptions, FakeRaopState, RaopVersion,
};

/// The live test device's own `ft` value: bits 38 and 48 both set, so AirPlay 2.
pub const AIRPLAY_2_FEATURES: &str = "0x4A7FDFD5,0x3C177FDE";

/// A feature string with neither modern bit, so AirPlay 1.
pub const AIRPLAY_1_FEATURES: &str = "0x5A7FFFF7,0x1E";

/// How long a test waits for a background effect before giving up.
pub const SETTLE: Duration = Duration::from_secs(5);

/// Pair once, so pair-verify has a registered controller.
pub async fn pair(device: &FakeRaopDevice) -> HapCredentials {
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

/// The `_raop._tcp` service a scan would have produced for `device`.
pub fn service(device: &FakeRaopDevice, features: &str, password: Option<&str>) -> BaseService {
    let mut service = BaseService::new(Protocol::Raop, device.address().port());
    service.properties = device.properties();
    service
        .properties
        .insert("ft".to_owned(), features.to_owned());
    service.password = password.map(str::to_owned);
    service
}

/// A paired AirPlay 2 receiver with a [`RaopStream`] pointed at it.
pub async fn ap2(
    options: FakeRaopOptions,
) -> (FakeRaopDevice, Arc<RaopStream>, Arc<FakeRaopState>) {
    let device = FakeRaopDevice::start_with(FakeRaopOptions {
        version: RaopVersion::V2,
        ..options
    })
    .await;
    let credentials = pair(&device).await;
    let service = service(&device, AIRPLAY_2_FEATURES, None);
    let state = device.state();

    let stream = stream(&device, service, credentials);
    (device, stream, state)
}

/// An AirPlay 1 receiver, which needs no pairing at all: a `HapCredentials::default()` selects the
/// null pair-verify, which sends nothing.
pub async fn ap1(
    options: FakeRaopOptions,
) -> (FakeRaopDevice, Arc<RaopStream>, Arc<FakeRaopState>) {
    let password = options.password.clone();
    let device = FakeRaopDevice::start_with(FakeRaopOptions {
        version: RaopVersion::V1,
        ..options
    })
    .await;
    let service = service(&device, AIRPLAY_1_FEATURES, password.as_deref());
    let state = device.state();

    let stream = stream(&device, service, HapCredentials::default());
    (device, stream, state)
}

fn stream(
    device: &FakeRaopDevice,
    service: BaseService,
    credentials: HapCredentials,
) -> Arc<RaopStream> {
    let manager = Arc::new(RaopPlaybackManager::new(device.address().ip(), service));
    let push_updater = Arc::new(RaopPushUpdater::new(Arc::clone(&manager)));

    Arc::new(RaopStream::new(manager, credentials, push_updater))
}

/// A mono 44.1 kHz sine WAV of `seconds`, as bytes.
///
/// Mono on purpose: the receiver's format is stereo, so the pipeline's channel duplication is on
/// the path every test takes rather than only in the unit tests.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    reason = "a fixture generator: the durations are literals under a second and the samples are \
              deliberately quantised to 16 bits"
)]
pub fn sine_wav(seconds: f32) -> Vec<u8> {
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: 44_100,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };

    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = hound::WavWriter::new(&mut cursor, spec).expect("the header should write");
        let frames = (44_100.0 * seconds) as u32;
        for index in 0..frames {
            let phase = index as f32 / 44_100.0 * 440.0 * std::f32::consts::TAU;
            let sample = (phase.sin() * 0.5 * f32::from(i16::MAX)) as i16;
            writer.write_sample(sample).expect("a sample should write");
        }
        writer.finalize().expect("the file should finalise");
    }

    cursor.into_inner()
}

/// How many frames a WAV of `seconds` carries.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the durations are literals under a second; see `sine_wav`"
)]
pub fn frames(seconds: f32) -> usize {
    (44_100.0 * seconds) as usize
}

/// Serve `wav` over loopback HTTP once, returning the port.
///
/// A hand-rolled four-line server rather than a dependency: the crate's own downloader speaks
/// `Content-Length`-framed HTTP/1.1 and nothing else, so that is all this has to answer.
pub async fn serve_wav(wav: Vec<u8>) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback port must succeed in tests");
    let port = listener
        .local_addr()
        .expect("a bound listener must have an address")
        .port();

    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let wav = wav.clone();
            tokio::spawn(async move {
                let mut discard = [0u8; 4096];
                let _ = stream.read(&mut discard).await;

                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: audio/wav\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    wav.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&wav).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    port
}
