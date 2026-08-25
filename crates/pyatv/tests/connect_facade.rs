//! `pyatv::connect` against a whole hermetic Apple TV: AirPlay, the MRP tunnel it carries, and
//! Companion, all at once.
//!
//! Every other test in this workspace exercises one protocol in isolation. This one exercises the
//! thing that only exists when they are together — the relayer priorities of
//! `docs/research/pyatv-architecture.md` §6 — and the seam that only exists in this crate: the
//! AirPlay data-stream channel presented to MRP as a `ByteChannel`.
//!
//! The device shape is deliberately the modern one (`airplay-control-mrp-tunnel-port-spec.md` §1.3):
//! no `_mediaremotetv._tcp` service is advertised at all, so an MRP registration can only have come
//! through the tunnel. If the tunnel is broken, `metadata()` is `None` and every assertion below
//! fails at once.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use pyatv::{DeviceListener, DeviceState, FeatureName, FeatureState, InputAction, PowerState};
use pyatv_core::consts::Protocol;

use support::{FakeAppleTv, until, until_async};

/// A listener that only counts, so a test can assert on what did *not* happen.
#[derive(Debug, Default)]
struct CountingListener {
    lost: AtomicUsize,
    closed: AtomicUsize,
}

impl DeviceListener for CountingListener {
    fn connection_lost(&self, reason: &str) {
        eprintln!("connection_lost: {reason}");
        self.lost.fetch_add(1, Ordering::SeqCst);
    }

    fn connection_closed(&self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}

/// Both protocols connect, and each capability is answered by the one pyatv's priority tables pick.
///
/// The three assertions are chosen so that a wrong priority list cannot pass any of them by
/// accident: MRP and Companion both register `RemoteControl` and `Power`, and they are made to
/// disagree — the Companion device is asleep while the MRP device reports itself powered on, and
/// only one of the two fakes can record a button press.
#[tokio::test]
async fn the_facade_relays_each_capability_to_the_protocol_pyatv_prefers() {
    let device = FakeAppleTv::start().await;
    device.arrange_mrp(|state| state.example_video());
    device
        .arrange_companion(|state| {
            // `SystemStatus.Asleep`, which Companion reports as `PowerState::Off` — the MRP device
            // is powered on, so this value can only have come from Companion.
            state.system_status = Some(0x01);
            state.installed_apps = vec![
                ("com.apple.TVMusic".to_owned(), "Music".to_owned()),
                ("com.netflix.Netflix".to_owned(), "Netflix".to_owned()),
            ];
        })
        .await;

    let atv = device.connect().await;

    // ---- Metadata: MRP only (Companion registers none) ----
    let playing = atv
        .metadata()
        .expect("the tunnel must register MRP's Metadata")
        .playing()
        .await
        .expect("playing() must not fail");
    assert_eq!(playing.title.as_deref(), Some("dummy"));
    assert_eq!(playing.device_state, DeviceState::Paused);
    assert_eq!(playing.total_time, Some(123));

    // ---- Apps: Companion only ----
    let apps = atv
        .apps()
        .expect("Companion must register Apps")
        .app_list()
        .await
        .expect("the app list must be readable");
    assert_eq!(apps.len(), 2);
    assert_eq!(apps[0].identifier, "com.apple.TVMusic");

    // ---- Power: `POWER_PRIORITIES` puts Companion ahead of MRP (`facade.py:311-318`) ----
    assert_eq!(
        atv.power()
            .expect("both protocols register Power")
            .power_state(),
        PowerState::Off,
        "Companion is asleep and MRP is awake, so Off proves Companion answered"
    );

    // ---- RemoteControl: `DEFAULT_PRIORITIES` puts MRP first (`facade.py:37-43`) ----
    atv.remote_control()
        .expect("both protocols register RemoteControl")
        .select(InputAction::SingleTap)
        .await
        .expect("select must reach the device");

    let mrp_state = device.mrp.state();
    until("the MRP device to record a select", || {
        mrp_state.with(|inner| inner.last_button_pressed.clone())
    })
    .await;
    assert_eq!(
        mrp_state.with(|inner| inner.last_button_pressed.clone()),
        Some("select".to_owned()),
        "the press must have gone through the tunnel, not to Companion"
    );

    atv.close().await.expect("closing must succeed");
}

/// The facade reports both protocols, and neither the direct MRP socket nor a second AirPlay
/// registration appears — the tunnel registers under `Protocol::Mrp`, not `Protocol::AirPlay`.
#[tokio::test]
async fn the_tunnel_registers_as_mrp_alongside_airplay_and_companion() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    // A feature only MRP declares, and one only Companion does, both resolving means both are in.
    let features = atv.features();
    assert_ne!(
        features.get_feature(FeatureName::Title).state,
        FeatureState::Unsupported,
        "Title is MRP's, so it proves the tunnel registered"
    );
    assert_ne!(
        features.get_feature(FeatureName::AppList).state,
        FeatureState::Unsupported,
        "AppList is Companion's"
    );
    // AirPlay's own registration is separate from the tunnel's and declares exactly two names.
    assert_ne!(
        features.get_feature(FeatureName::PlayUrl).state,
        FeatureState::Unsupported,
        "PlayUrl is AirPlay's own"
    );

    // Push updates only exist because a protocol registered a `PushUpdater`, which only MRP does.
    assert!(
        atv.push_updater().is_some(),
        "MRP must register the push updater"
    );

    atv.close().await.expect("closing must succeed");
}

/// The device's own `DEVICE_INFO_MESSAGE` reaches the facade through the tunnel.
///
/// The build number and model are things only MRP knows — the AirPlay TXT record carries `model`
/// and `osvers` but no build — so seeing one is proof the tunnelled bring-up exchange completed.
#[tokio::test]
async fn device_info_merges_what_the_tunnel_learned_with_what_the_scan_knew() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let info = atv.device_info();
    assert!(
        info.build_number().is_some(),
        "the build number can only have come from the tunnelled DEVICE_INFO_MESSAGE: {info:?}"
    );
    assert_eq!(
        info.mac(),
        Some(support::DEVICE_IDENTIFIER),
        "and the scan's own TXT values must survive the merge"
    );

    atv.close().await.expect("closing must succeed");
}

/// Closing tears both protocols down, and the caller's listener hears about it exactly once.
///
/// The specific regression this guards is a tunnel that reports its own orderly shutdown as a
/// *lost* connection: the MRP reader sees the data channel close and, without the `Ok(None)`
/// mapping in `pyatv::tunnel`, would treat that end-of-stream as a failure.
#[tokio::test]
async fn closing_tears_everything_down_without_reporting_a_loss() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let listener = Arc::new(CountingListener::default());
    atv.add_listener(&(Arc::clone(&listener) as Arc<dyn DeviceListener>));

    // Prove the tunnel is live before closing it, so a passing test cannot be a tunnel that never
    // came up in the first place.
    atv.metadata()
        .expect("MRP must be registered")
        .playing()
        .await
        .expect("playing() must not fail while connected");

    atv.close().await.expect("closing must succeed");

    // Give anything spurious a chance to fire before checking that nothing did.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    assert_eq!(
        listener.lost.load(Ordering::SeqCst),
        0,
        "an orderly close is not a lost connection"
    );
    assert!(
        listener.closed.load(Ordering::SeqCst) >= 1,
        "the caller must be told the device was closed"
    );

    // The AirPlay control connection stops being fed, which is what a receiver watches for.
    let airplay_state = device.airplay.state();
    let feedbacks = airplay_state.feedbacks.load(Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(
        airplay_state.feedbacks.load(Ordering::SeqCst),
        feedbacks,
        "the keepalive must stop when the session closes"
    );
}

/// Without credentials the gate declines, and `connect` still succeeds over what is left.
///
/// `is_remote_control_supported` requires HAP credentials for an `AppleTV*` model
/// (`pyatv/protocols/airplay/utils.py:165-180`), so a config with none must produce an AirPlay-only
/// facade rather than a failure — a device with working AirPlay should stay usable.
#[tokio::test]
async fn a_device_with_no_credentials_connects_without_a_tunnel() {
    let device = FakeAppleTv::start().await;

    let mut config = device.config();
    for protocol in [Protocol::AirPlay, Protocol::Companion] {
        config
            .get_service_mut(protocol)
            .expect("the config carries both services")
            .credentials = None;
    }

    let atv = pyatv::connect(&config, None, Arc::new(pyatv::MemoryStorage::new()))
        .await
        .expect("AirPlay alone must still connect");

    assert!(
        atv.metadata().is_none(),
        "no credentials means no tunnel, so nothing registers Metadata"
    );
    assert_ne!(
        atv.features().get_feature(FeatureName::PlayUrl).state,
        FeatureState::Unsupported,
        "AirPlay's own registration is unconditional"
    );

    atv.close().await.expect("closing must succeed");
}

/// A tunnel that *fails* — as opposed to one the gate declines — must not take AirPlay with it.
///
/// The regression: `setup_protocol` propagated the tunnel's error with `?`, which discarded the
/// `AirPlay` registration it had already built two lines earlier. A receiver that refuses the
/// remote-control `SETUP` therefore lost `play_url` as well, even though the AirPlay half had
/// connected fine and needs nothing from the tunnel. Upstream cannot hit this: its `setup()` is a
/// generator, so the first `yield` has already escaped by the time the second one raises.
#[tokio::test]
async fn a_refused_tunnel_setup_leaves_airplay_registered() {
    let device = FakeAppleTv::start_without_a_tunnel().await;
    let atv = device.connect().await;

    assert!(
        atv.metadata().is_none(),
        "the tunnel was refused, so nothing registers Metadata"
    );
    assert_ne!(
        atv.features().get_feature(FeatureName::PlayUrl).state,
        FeatureState::Unsupported,
        "AirPlay's own registration must survive the tunnel's failure"
    );
    assert_ne!(
        atv.features().get_feature(FeatureName::AppList).state,
        FeatureState::Unsupported,
        "and so must Companion's"
    );

    atv.close().await.expect("closing must succeed");
}

/// When the *device* ends the session, the AirPlay keepalive stops too.
///
/// MRP notices first — its reader sees the tunnelled data channel close — and reports it through
/// the `DeviceListener` path. Nothing downstream of that used to close the AirPlay half, so the
/// `/feedback` poster went on talking to a receiver that had already hung up, for the rest of the
/// process's life. The listener must also hear about it exactly once, as a *loss* rather than an
/// orderly close.
#[tokio::test]
async fn a_device_initiated_close_tears_the_airplay_session_down() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let listener = Arc::new(CountingListener::default());
    atv.add_listener(&(Arc::clone(&listener) as Arc<dyn DeviceListener>));

    // Prove the tunnel is live first, so a passing test cannot be one that never came up.
    atv.metadata()
        .expect("MRP must be registered")
        .playing()
        .await
        .expect("playing() must not fail while connected");

    let airplay_state = device.airplay.state();
    until("the keepalive to post at least once", || {
        (airplay_state.feedbacks.load(Ordering::SeqCst) > 0).then_some(())
    })
    .await;

    // The device hangs up, without anyone calling `close()`.
    device.mrp.kill_connections();

    until("the caller to be told the connection ended", || {
        (listener.lost.load(Ordering::SeqCst) + listener.closed.load(Ordering::SeqCst) > 0)
            .then_some(())
    })
    .await;

    // Give the spawned teardown a moment, then confirm the keepalive really has stopped rather
    // than merely paused between posts.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let feedbacks = airplay_state.feedbacks.load(Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    assert_eq!(
        airplay_state.feedbacks.load(Ordering::SeqCst),
        feedbacks,
        "the AirPlay keepalive must stop when the device ends the session"
    );
}

/// Streaming and video-playing coexist on one device, each reaching the right protocol.
///
/// This is the case per-trait relaying gets wrong. `AirPlay` and RAOP both register a `Stream`;
/// `AirPlay` outranks RAOP (`pyatv/core/facade.py:37-43`) and implements only `play_url`, RAOP only
/// `stream_file` — so a facade that picks one instance for the whole trait makes `stream_file`
/// unreachable on every device that advertises both, which is every modern Apple TV. Upstream
/// resolves it per method in `Relayer._find_instance` (`pyatv/core/relayer.py:96-115`).
///
/// The third assertion is the RAOP takeover (`pyatv/protocols/raop/__init__.py:350-352`): while the
/// stream runs, `metadata()` must describe the track being streamed rather than whatever MRP was
/// showing before.
#[tokio::test(flavor = "multi_thread")]
async fn stream_file_reaches_raop_while_play_url_reaches_airplay() {
    let device = FakeAppleTv::start_with_raop().await;
    device.arrange_mrp(|state| state.example_video());

    let atv = device.connect().await;
    let raop_state = device
        .raop
        .as_ref()
        .expect("the harness started a RAOP receiver")
        .state();

    assert_eq!(
        atv.features().get_feature(FeatureName::StreamFile).state,
        FeatureState::Available,
        "RAOP must declare StreamFile or the relayer has nowhere to send it"
    );

    let stream = atv.stream().expect("a stream is registered");

    // ---- stream_file: RAOP, despite AirPlay outranking it ----
    let source = pyatv::MediaSource::Bytes(support::sine_wav(0.2));
    let metadata = pyatv::MediaMetadata {
        title: Some("Ported Track".to_owned()),
        artist: Some("pyatv-rs".to_owned()),
        ..pyatv::MediaMetadata::default()
    };

    let streaming = {
        let stream = Arc::clone(&stream);
        let metadata = metadata.clone();
        tokio::spawn(async move { stream.stream_file(&source, Some(&metadata), false).await })
    };

    // While the stream is running the RAOP takeover holds Metadata, so `playing()` describes the
    // track being streamed — not MRP's "dummy" video.
    let title = until_async("the streamed track to be reported", || async {
        let playing = atv.metadata()?.playing().await.ok()?;
        (playing.title.as_deref() == Some("Ported Track")).then_some(playing.title)
    })
    .await;
    assert_eq!(title.as_deref(), Some("Ported Track"));

    streaming
        .await
        .expect("the stream task must not panic")
        .expect("the file must stream");

    assert_eq!(
        raop_state.records.load(Ordering::SeqCst),
        1,
        "the RAOP receiver must have accepted exactly one RECORD"
    );
    assert_eq!(raop_state.teardowns.load(Ordering::SeqCst), 1);

    // Once the stream has finished the takeover is released and MRP answers again.
    until_async("MRP metadata to come back", || async {
        let playing = atv.metadata()?.playing().await.ok()?;
        (playing.title.as_deref() == Some("dummy")).then_some(())
    })
    .await;

    // ---- play_url: AirPlay, on the same handle ----
    device
        .airplay
        .state()
        .play
        .queue([
            pyatv_proto_airplay::test_support::fake_play::PlaybackAnswer::playing(0.1),
            pyatv_proto_airplay::test_support::fake_play::PlaybackAnswer::idle(),
        ])
        .await;

    stream
        .play_url("http://example.invalid/v.mp4")
        .await
        .expect("AirPlay must accept the play");
    assert_eq!(
        device.airplay.state().play.plays.load(Ordering::SeqCst),
        1,
        "the AirPlay receiver must have seen the /play"
    );
}
