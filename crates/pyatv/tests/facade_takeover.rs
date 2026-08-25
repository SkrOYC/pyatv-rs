//! Interface takeover across a whole connected device.
//!
//! `pyatv/core/facade.py:804-830` and `pyatv/core/relayer.py:117-127` exist for one concrete
//! reason: an AirPlay `play_url` holds the playback open on one HTTP connection, and the only way
//! to end it is to close that connection. So while a URL is playing, `remote_control().stop()` has
//! to reach AirPlay — even though MRP outranks it everywhere else
//! (`pyatv/protocols/airplay/__init__.py:125,139`).
//!
//! Everything below runs against the hermetic device in [`support`]: real sockets, real
//! pair-verify, a real `/play` and `/playback-info` poll. The MRP side is the tunnelled one, so a
//! button that lands there really crossed the AirPlay data channel.

mod support;

use std::sync::atomic::Ordering;
use std::time::Duration;

use pyatv::{FeatureName, FeatureState};
use pyatv_core::consts::Protocol;
use pyatv_core::facade::{FacadeAppleTV, Interface, SetupData};
use pyatv_core::models::BaseService;
use pyatv_proto_airplay::test_support::fake_play::PlaybackAnswer;

use support::{FakeAppleTv, until, until_async};

/// How many `playing` answers to queue: each one costs a one-second poll, and the test only needs
/// the playback to still be running when it presses stop.
const PLAYING_ANSWERS: usize = 30;

/// `stop()` reaches AirPlay while a URL is playing, and MRP once it is not.
///
/// The two halves are the same call on the same handle, taken once before either happens — which is
/// what makes this a test of the takeover rather than of `atv.remote_control()` being re-resolved.
#[tokio::test(flavor = "multi_thread")]
async fn stop_goes_to_airplay_during_play_url_and_to_mrp_after_it() {
    let device = FakeAppleTv::start().await;
    device.arrange_mrp(|state| state.example_video());
    device
        .airplay
        .state()
        .play
        .queue(
            std::iter::once(PlaybackAnswer::idle())
                .chain(std::iter::repeat_n(
                    PlaybackAnswer::playing(600.0),
                    PLAYING_ANSWERS,
                ))
                .collect::<Vec<_>>(),
        )
        .await;

    let atv = device.connect().await;
    assert_eq!(
        atv.features().get_feature(FeatureName::PlayUrl).state,
        FeatureState::Available,
        "the AirPlay feature bits must make play_url available or the facade gate refuses it"
    );

    // Taken *before* the takeover happens, exactly as `test_takeover_and_release`
    // (`tests/core/test_facade.py:544-566`) takes `facade_dummy.audio` before it.
    let remote = atv
        .remote_control()
        .expect("MRP and AirPlay both register a remote control");
    let stream = atv.stream().expect("AirPlay registers a stream");

    let airplay_state = device.airplay.state();
    let mrp_state = device.mrp.state();
    mrp_state.update(|inner| inner.last_button_pressed = None);

    let playing =
        tokio::spawn(async move { stream.play_url("http://example.invalid/v.mp4").await });

    // Wait until the receiver has actually accepted the `/play`, so the takeover is in force.
    until("the receiver to accept /play", || {
        (airplay_state.play.plays.load(Ordering::SeqCst) == 1).then_some(())
    })
    .await;

    // ---- During the playback: AirPlay ----
    remote.stop().await.expect("stop must succeed");

    // AirPlay's `stop()` is `self.stream.stop()` and sends nothing on the wire
    // (`airplay/__init__.py:175-177`) — the observable effect is that the play call returns.
    tokio::time::timeout(Duration::from_secs(10), playing)
        .await
        .expect("stop must end the playback")
        .expect("the play task must not panic")
        .expect("a stopped playback is not an error");

    assert_eq!(
        mrp_state.with(|inner| inner.last_button_pressed.clone()),
        None,
        "MRP must not have seen the stop that belonged to AirPlay"
    );

    // ---- After it: back to MRP, on the same handle ----
    remote.stop().await.expect("stop must succeed");
    let pressed = until("MRP to record the stop", || {
        mrp_state.with(|inner| inner.last_button_pressed.clone())
    })
    .await;
    assert_eq!(pressed, "stop");
}

/// `metadata()` follows the RAOP takeover on a handle taken before the stream started.
///
/// RAOP claims `Audio`, `Metadata`, `PushUpdater` and `RemoteControl` for the length of a
/// `stream_file` (`pyatv/protocols/raop/__init__.py:350-352`) so that the reported track is the one
/// being streamed. Making that visible on an already-held handle is what
/// `pyatv_core::facade::FacadeMetadata` is for: `metadata()` used to hand out the highest-priority
/// protocol's own object, which is a snapshot — a caller who read it once, as `atvremote` and any
/// long-lived application does, went on talking to MRP for the whole stream.
#[tokio::test(flavor = "multi_thread")]
async fn metadata_follows_the_raop_takeover_on_a_handle_taken_earlier() {
    let device = FakeAppleTv::start_with_raop().await;
    device.arrange_mrp(|state| state.example_video());

    let atv = device.connect().await;

    // Taken before anything streams, and never re-read below.
    let metadata = atv.metadata().expect("MRP and RAOP both register metadata");
    let title = || {
        let metadata = std::sync::Arc::clone(&metadata);
        async move { metadata.playing().await.ok().and_then(|it| it.title) }
    };

    assert_eq!(
        title().await.as_deref(),
        Some("dummy"),
        "MRP outranks RAOP until the takeover"
    );

    let stream = atv.stream().expect("RAOP registers a stream");
    let streaming = tokio::spawn(async move {
        stream
            .stream_file(
                &pyatv::MediaSource::Bytes(support::sine_wav(0.2)),
                Some(&pyatv::MediaMetadata {
                    title: Some("Taken Over".to_owned()),
                    ..pyatv::MediaMetadata::default()
                }),
                false,
            )
            .await
    });

    until_async("the streamed track on the handle taken earlier", || async {
        (title().await.as_deref() == Some("Taken Over")).then_some(())
    })
    .await;

    // ...but only `playing` moves. `RaopMetadata` overrides nothing else upstream
    // (`raop/__init__.py:181-206`), and RAOP declares none of the metadata features here, so the
    // accessors that carry no feature still fall through to MRP rather than reporting `None` for
    // the length of the stream.
    assert_eq!(
        metadata.device_id().as_deref(),
        Some(support::DEVICE_IDENTIFIER),
        "device_id must not vanish during a RAOP takeover"
    );

    streaming
        .await
        .expect("the stream task must not panic")
        .expect("the file must stream");

    // Releasing the takeover puts MRP back, on that same handle.
    until_async("MRP metadata to come back", || async {
        (title().await.as_deref() == Some("dummy")).then_some(())
    })
    .await;

    atv.close().await.expect("closing must succeed");
}

/// A second protocol cannot claim an interface the first one holds, and the refusal is total.
///
/// `test_takeover_failure_restores` (`tests/core/test_facade.py:575-596`): the partial claim is
/// rolled back, so the interface that was taken first is released again and normal priority
/// resumes. Driven against a bare facade rather than a live device because it is about the registry
/// and nothing else.
#[test]
fn a_conflicting_takeover_is_refused_and_rolled_back() {
    let mut facade = FacadeAppleTV::new(BaseService::new(Protocol::AirPlay, 7000));
    facade.add_protocol(SetupData {
        protocol: Some(Protocol::Mrp),
        ..SetupData::default()
    });

    let held = facade
        .takeover(Protocol::AirPlay, &[Interface::Audio])
        .expect("nothing is claimed yet");

    let error = facade
        .takeover(Protocol::Raop, &[Interface::Stream, Interface::Audio])
        .expect_err("Audio is already claimed by AirPlay");
    assert!(
        matches!(error, pyatv::Error::InvalidState(_)),
        "expected InvalidState, got {error}"
    );

    // The rollback freed `Stream`, so a claim on it alone now succeeds.
    let stream_only = facade.takeover(Protocol::Raop, &[Interface::Stream]);
    assert!(stream_only.is_ok(), "Stream must have been rolled back");

    drop(held);
    let audio_again = facade.takeover(Protocol::Raop, &[Interface::Audio]);
    assert!(audio_again.is_ok(), "dropping the guard releases Audio");
}
