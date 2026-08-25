//! The AirPlay 2 remote-control tunnel, end to end against a hermetic receiver.
//!
//! pyatv has no equivalent: nothing in its test tree ever answers a remote-control `SETUP` or
//! frames a `DataHeader` (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §16.2). These
//! tests run the real sequence over real loopback sockets — pair-setup, pair-verify, the encrypted
//! control connection, both `SETUP`s, both side channels and MRP bytes in both directions — so the
//! key derivations, the read/write swap, the HAP framing and the `DataHeader` framing are all
//! exercised together rather than mocked apart.

use pyatv_proto_airplay::test_support as support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use pyatv_pairing::server::AIRPLAY_PIN;
use pyatv_pairing::{HapCredentials, PairSetup};
use pyatv_proto_airplay::ap2::{Ap2Session, SeqnoPolicy};
use pyatv_proto_airplay::auth::{HKP_HAP, PAIR_SETUP_PATH, PIN_START_PATH, hap_headers};
use pyatv_proto_airplay::{HttpConnection, InfoSettings};

use support::fake_airplay::{FakeAirPlayDevice, FakeOptions};

/// A stand-in `ProtocolMessage`: the leading `0x08` is field 1 (`type`), wire type 0.
///
/// Forty bytes, deliberately. pyatv's unprefixed-message heuristic reasons that "the minimal
/// message length is at least 40" (`channels.py:204-210`), and an eight-byte message really would
/// be ambiguous — its length prefix would itself be `0x08`. Testing with a realistic length is what
/// makes the round trip mean anything.
const MRP_MESSAGE: &[u8] = b"\x08\x2A\x52\x241A2B3C4D-5E6F-4A8B-9C0D-1E2F3A4B5C6D";

/// How long a test waits for something the receiver does asynchronously.
const SETTLE: Duration = Duration::from_millis(500);

/// Pair once against the fake, so pair-verify has a registered controller to verify against.
async fn pair(device: &FakeAirPlayDevice) -> HapCredentials {
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

/// Bring a session all the way up against `device`.
async fn tunnel(device: &FakeAirPlayDevice) -> Ap2Session {
    let credentials = pair(device).await;

    let mut session = Ap2Session::connect(
        device.address().ip(),
        device.address().port(),
        &credentials,
        InfoSettings::default(),
    )
    .await
    .expect("pair-verify should succeed with the credentials just negotiated");

    session
        .setup_remote_control(SeqnoPolicy::Fixed)
        .await
        .expect("remote control setup should succeed");

    session
}

/// Wait for `predicate` to hold, or give up after [`SETTLE`].
async fn settle(mut predicate: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + SETTLE;
    while tokio::time::Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    predicate()
}

/// The whole sequence, and an MRP message travelling both ways over it.
///
/// This is the test the tunnel exists for: if the event channel's swapped keys, the data channel's
/// seeded salt, the HAP block framing or the `DataHeader` framing were wrong in either direction,
/// the round trip could not complete.
#[tokio::test]
async fn a_session_comes_up_and_round_trips_mrp_bytes() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let state = device.state();

    let session = tunnel(&device).await;

    let ports = session.ports().expect("setup must record the ports");
    assert_ne!(ports.event.port, 0);
    assert_ne!(ports.data_port, 0);
    assert_ne!(ports.event.port, ports.data_port);
    assert_eq!(ports.event.skip_record, None);

    assert!(
        settle(|| state.event_connected.load(Ordering::SeqCst)).await,
        "the controller must dial the event port"
    );
    assert!(
        settle(|| state.data_connected.load(Ordering::SeqCst)).await,
        "the controller must dial the data port"
    );

    let channel = session.data_channel().expect("the data channel must be up");
    channel
        .send(MRP_MESSAGE)
        .await
        .expect("the send should queue");

    let echoed = tokio::time::timeout(SETTLE, channel.recv())
        .await
        .expect("the receiver must answer within the settle window")
        .expect("the channel must still be open");
    assert_eq!(&echoed[..], MRP_MESSAGE);

    // The receiver saw exactly the bytes that were sent, unwrapped from the envelope it was
    // handed rather than from one this port also wrote.
    assert_eq!(
        state.mrp_received.lock().await.as_slice(),
        &[MRP_MESSAGE.to_vec()]
    );

    // And the controller acknowledged the receiver's own `sync` frame, which is what stops a real
    // device treating the channel as unresponsive.
    assert!(
        settle(|| state.replies_seen.load(Ordering::SeqCst) >= 1).await,
        "the controller must acknowledge inbound sync frames"
    );
}

/// The `seqno` is drawn once and repeated, which is pyatv's behaviour and this port's default.
#[tokio::test]
async fn the_fixed_seqno_policy_repeats_one_value() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let session = tunnel(&device).await;
    let channel = session.data_channel().expect("the data channel must be up");

    let seqno = channel.seqno();
    assert!(
        (0x1_0000_0000..0x1_FFFF_FFFF).contains(&seqno),
        "randrange(0x100000000, 0x1FFFFFFFF), got {seqno:#x}"
    );

    channel.send(MRP_MESSAGE).await.expect("queues");
    channel.send(MRP_MESSAGE).await.expect("queues");

    assert_eq!(channel.seqno(), seqno, "Fixed must never advance the seqno");
}

/// The documented knob: `Increment` advances per frame, so the divergence can be tested against
/// hardware without patching the channel.
#[tokio::test]
async fn the_increment_seqno_policy_advances() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let credentials = pair(&device).await;

    let mut session = Ap2Session::connect(
        device.address().ip(),
        device.address().port(),
        &credentials,
        InfoSettings::default(),
    )
    .await
    .expect("pair-verify should succeed");
    let channel = session
        .setup_remote_control(SeqnoPolicy::Increment)
        .await
        .expect("setup should succeed");

    let first = channel.seqno();
    channel.send(MRP_MESSAGE).await.expect("queues");

    assert_eq!(channel.seqno(), first + 1);
}

/// With no `skipRecord` in the reply — every receiver pyatv was written against — `RECORD` is sent.
#[tokio::test]
async fn record_is_sent_when_the_receiver_does_not_ask_to_skip_it() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let state = device.state();

    let _session = tunnel(&device).await;

    assert_eq!(state.records.load(Ordering::SeqCst), 1);
}

/// The tvOS 27 divergence: `skipRecord: true` suppresses it.
#[tokio::test]
async fn record_is_skipped_when_the_receiver_asks() {
    let device = FakeAirPlayDevice::start_with(FakeOptions {
        skip_record: Some(true),
        ..FakeOptions::default()
    })
    .await;
    let state = device.state();

    let session = tunnel(&device).await;

    assert_eq!(state.records.load(Ordering::SeqCst), 0);
    assert_eq!(
        session
            .ports()
            .expect("ports must be recorded")
            .event
            .skip_record,
        Some(true)
    );
}

/// `skipRecord: false` is not the same as an absent key: it means "do send it".
#[tokio::test]
async fn an_explicit_false_skip_record_still_sends_the_record() {
    let device = FakeAirPlayDevice::start_with(FakeOptions {
        skip_record: Some(false),
        ..FakeOptions::default()
    })
    .await;
    let state = device.state();

    let _session = tunnel(&device).await;

    assert_eq!(state.records.load(Ordering::SeqCst), 1);
}

/// A `timingPort` is read when the receiver sends one, and its absence is not an error.
#[tokio::test]
async fn a_timing_port_is_read_when_present() {
    let device = FakeAirPlayDevice::start_with(FakeOptions {
        timing_port: Some(6002),
        ..FakeOptions::default()
    })
    .await;

    let session = tunnel(&device).await;

    assert_eq!(
        session
            .ports()
            .expect("ports must be recorded")
            .event
            .timing_port,
        Some(6002)
    );
}

/// The event channel answers whatever the receiver pushes at it, and surfaces it to the caller.
///
/// The reply's header order is upstream's and is asserted verbatim: `Content-Length` and
/// `Audio-Latency` first because the request carried its own `Server`, then that `Server` echoed
/// back, then the `CSeq` (`channels.py:75-95` through `http.py:141-167`).
#[tokio::test]
async fn the_event_channel_answers_a_receiver_request() {
    let probe = b"POST /event RTSP/1.0\r\nCSeq: 4\r\nServer: AirTunes/980.67.2\r\n\r\n".to_vec();
    let device = FakeAirPlayDevice::start_with(FakeOptions {
        event_probe: Some(probe),
        ..FakeOptions::default()
    })
    .await;
    let state = device.state();

    let session = tunnel(&device).await;

    let request = tokio::time::timeout(
        SETTLE,
        session
            .event_channel()
            .expect("the event channel must be up")
            .recv(),
    )
    .await
    .expect("the request must arrive")
    .expect("the channel must be open");

    assert_eq!(request.method, "POST");
    assert_eq!(request.uri, "/event");

    // The reply is written before the request is forwarded, but the receiver still has to read it.
    let deadline = tokio::time::Instant::now() + SETTLE;
    while state.event_replies.lock().await.is_empty() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let replies = state.event_replies.lock().await;
    assert_eq!(
        replies.as_slice(),
        ["RTSP/1.0 200 OK\r\n\
             Content-Length: 0\r\n\
             Audio-Latency: 0\r\n\
             Server: AirTunes/980.67.2\r\n\
             CSeq: 4\r\n\r\n"
            .to_owned()]
    );
}

/// The keepalive really does post `/feedback`, at the cadence a receiver expects.
#[tokio::test]
async fn the_keepalive_posts_feedback() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let state = device.state();

    let mut session = tunnel(&device).await;
    assert_eq!(state.feedbacks.load(Ordering::SeqCst), 0);

    session.start_keep_alive(None);

    // One interval plus slack: the loop sleeps *before* its first send, as upstream's does.
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert!(
        state.feedbacks.load(Ordering::SeqCst) >= 1,
        "expected at least one /feedback, got {}",
        state.feedbacks.load(Ordering::SeqCst)
    );

    session.stop_keep_alive();
    let after_stop = state.feedbacks.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    assert_eq!(
        state.feedbacks.load(Ordering::SeqCst),
        after_stop,
        "stopping the keepalive must stop the requests"
    );
}

/// The `SETUP` bodies the receiver actually saw carry pyatv's exact key sets.
///
/// The byte-level comparison against pyatv's own encoder lives in `airplay_tunnel_kat.rs`; this
/// checks that the values which reach the wire during a real session are the same ones.
#[tokio::test]
async fn the_setup_bodies_reach_the_receiver_intact() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let state = device.state();

    let session = tunnel(&device).await;

    let event = state
        .event_setup
        .lock()
        .await
        .clone()
        .expect("an event SETUP");
    let event = event.as_dictionary().expect("a dictionary");
    let mut keys: Vec<&str> = event.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "deviceID",
            "isRemoteControlOnly",
            "macAddress",
            "model",
            "name",
            "osBuildVersion",
            "osName",
            "osVersion",
            "sessionUUID",
            "sourceVersion",
            "timingProtocol",
        ]
    );
    assert_eq!(event["isRemoteControlOnly"].as_boolean(), Some(true));
    assert_eq!(event["sourceVersion"].as_string(), Some("550.10"));
    assert_eq!(event["timingProtocol"].as_string(), Some("None"));

    let data = state.data_setup.lock().await.clone().expect("a data SETUP");
    let stream = data.as_dictionary().expect("a dictionary")["streams"]
        .as_array()
        .expect("an array")[0]
        .as_dictionary()
        .expect("a dictionary");
    assert_eq!(stream["controlType"].as_signed_integer(), Some(2));
    assert_eq!(stream["type"].as_signed_integer(), Some(130));
    assert_eq!(stream["wantsDedicatedSocket"].as_boolean(), Some(true));
    assert_eq!(
        stream["clientTypeUUID"].as_string(),
        Some("1910A70F-DBC0-4242-AF95-115DB30604E1")
    );
    // The seed on the wire is the one the session salted the data channel's keys with — if it
    // were not, neither side could have decrypted anything on that socket.
    assert_eq!(
        stream["seed"].as_unsigned_integer(),
        Some(session.ports().expect("ports must be recorded").seed)
    );
    assert_ne!(
        stream["channelID"].as_string(),
        stream["clientUUID"].as_string(),
        "channelID and clientUUID are independent draws"
    );
}

/// Closing the session stops both channels and the control connection.
#[tokio::test]
async fn closing_the_session_shuts_the_channels_down() {
    let device = FakeAirPlayDevice::start_with(FakeOptions::default()).await;
    let mut session = tunnel(&device).await;
    let channel = session.data_channel().expect("the data channel must be up");

    session.close().await.expect("closing should succeed");

    assert!(
        tokio::time::timeout(SETTLE, channel.recv())
            .await
            .expect("recv must not hang after close")
            .is_err(),
        "a closed channel must report end of stream rather than blocking"
    );
}
