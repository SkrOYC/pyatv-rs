//! `play_url` end to end against the hermetic receiver, on both protocol versions.
//!
//! These mirror `tests/protocols/airplay/test_airplay_player.py` — the same four scenarios, the
//! same assertions on what the receiver recorded — and add the ones upstream has no fixture for:
//! the `AirPlay` 2 header set and `SETUP`/`RECORD` sequence, `skipRecord`, a receiver-reported
//! playback error, and stopping mid-play (`docs/research/airplay-playurl-raop-port-spec.md` §12.2
//! and §12.3).
//!
//! Every test drives real sockets: pair-setup, pair-verify, the HAP-encrypted control connection,
//! the event channel and the `/playback-info` poll all actually happen. Only the intervals are
//! shortened, which is what pyatv achieves by stubbing `asyncio.sleep`.

mod play_support;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use pyatv_core::interface::RemoteControl as _;
use pyatv_proto_airplay::Error;
use pyatv_proto_airplay::setup::AirPlayRemoteControl;
use pyatv_proto_airplay::test_support::fake_airplay::FakeOptions;
use pyatv_proto_airplay::test_support::fake_play::PlaybackAnswer;
use tokio::sync::Notify;

use play_support::{START_POSITION, URL, ap1, ap2, ap2_stream};

/// `test_play_video` on `AirPlay` 2: idle, playing, idle, and the call returns.
///
/// The whole sequence really runs — pair-verify, the fifteen-key base `SETUP`, the event channel,
/// `RECORD`, the twenty-one-key `/play` — and the receiver's assertions on the `AirPlay` 2 header
/// set fire inside `/play` rather than here.
#[tokio::test]
async fn an_airplay_2_play_runs_to_the_end_of_the_media() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state
        .play
        .queue([
            PlaybackAnswer::idle(),
            PlaybackAnswer::playing(0.8),
            PlaybackAnswer::idle(),
        ])
        .await;

    player
        .play_url(URL, START_POSITION, &Notify::new())
        .await
        .expect("the media should play to its end");

    assert_eq!(state.play.plays.load(Ordering::SeqCst), 1);
    assert_eq!(state.play.url.lock().await.as_deref(), Some(URL));
    assert_eq!(*state.play.position.lock().await, Some(START_POSITION));
    assert!(
        state
            .play
            .session_id
            .lock()
            .await
            .as_deref()
            .is_some_and(|id| !id.is_empty()),
        "the body carries a uuid"
    );

    // Exactly three polls: the loop exits on the third answer without sleeping again, which is
    // what `math.isclose(total_sleep_time(), 2.0)` pins upstream (`test_airplay_player.py:40`).
    assert_eq!(state.play.polls.load(Ordering::SeqCst), 3);

    // `RECORD` was sent, since this receiver did not ask for it to be skipped.
    assert_eq!(state.records.load(Ordering::SeqCst), 1);

    // And the five fire-and-forget calls followed the play, `/rate` among them.
    assert_eq!(state.play.rates.load(Ordering::SeqCst), 1);
    let properties = state.play.properties.lock().await;
    let paths: Vec<&str> = properties.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "/setProperty?isInterestedInDateRange",
            "/setProperty?actionAtItemEnd",
            "/setProperty?forwardEndTime",
            "/setProperty?reverseEndTime",
        ]
    );

    // `/rate` is not appended after the four: upstream sends it *between* the second and the third
    // `setProperty` (`airplayv2.py:246-272`, where the `POST` sits at line 252 in the middle of the
    // block). The counter above only proves it was sent at all, so the interleaving is pinned here.
    let calls = state.play.calls.lock().await;
    assert_eq!(
        calls.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "/setProperty?isInterestedInDateRange",
            "/setProperty?actionAtItemEnd",
            "/rate?value=1.000000",
            "/setProperty?forwardEndTime",
            "/setProperty?reverseEndTime",
        ]
    );
}

/// `test_play_video` on `AirPlay` 1 — one `POST /play` and nothing else on the wire.
#[tokio::test]
async fn an_airplay_1_play_sends_one_request_and_polls() {
    let (device, mut player) = ap1().await;
    let state = device.state();
    state
        .play
        .queue([PlaybackAnswer::playing(0.8), PlaybackAnswer::idle()])
        .await;

    player
        .play_url(URL, START_POSITION, &Notify::new())
        .await
        .expect("the media should play to its end");

    assert_eq!(state.play.plays.load(Ordering::SeqCst), 1);
    assert_eq!(state.play.url.lock().await.as_deref(), Some(URL));
    assert_eq!(*state.play.position.lock().await, Some(START_POSITION));

    // No `SETUP`, no `RECORD`, no event channel, no keepalive.
    assert_eq!(state.records.load(Ordering::SeqCst), 0);
    assert_eq!(state.feedbacks.load(Ordering::SeqCst), 0);
    assert!(state.event_setup.lock().await.is_none());
    assert_eq!(state.play.rates.load(Ordering::SeqCst), 0);
}

/// An `error` key in `/playback-info` aborts the wait (`player.py:96-102`).
#[tokio::test]
async fn a_reported_playback_error_fails_the_call() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    device
        .state()
        .play
        .queue([
            PlaybackAnswer::playing(12.0),
            PlaybackAnswer::failed(-12_345, "NSURLErrorDomain"),
        ])
        .await;

    let error = player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect_err("the receiver reported an error");

    assert!(
        matches!(&error, Error::Playback(message)
            if message == "got error -12345 (NSURLErrorDomain) when playing video"),
        "{error}"
    );
}

/// `test_play_with_retries`: two `500`s then success, three requests in total
/// (`test_airplay_player.py:49-57`).
#[tokio::test]
async fn a_500_is_retried_and_the_third_attempt_succeeds() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state.play.fail_plays(2);
    state
        .play
        .queue([PlaybackAnswer::playing(0.8), PlaybackAnswer::idle()])
        .await;

    player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect("the third attempt should be accepted");

    assert_eq!(state.play.plays.load(Ordering::SeqCst), 3);
}

/// `test_play_with_too_many_retries`: more failures than attempts, and the driver gives up
/// (`test_airplay_player.py:60-67`).
#[tokio::test]
async fn too_many_500s_exhaust_the_retries() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state.play.fail_plays(10);

    let error = player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect_err("every attempt was refused");

    assert!(
        matches!(&error, Error::Playback(message) if message == "Max retries exceeded"),
        "{error}"
    );
    assert_eq!(state.play.plays.load(Ordering::SeqCst), 3);
}

/// Any other `4xx`/`5xx` is an authentication error on the first answer, with no retry — upstream's
/// own coarse mapping (`player.py:63-65`).
#[tokio::test]
async fn a_4xx_is_an_authentication_error_and_is_not_retried() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state.play.refuse_plays(403);

    let error = player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect_err("the receiver refused the play");

    assert!(
        matches!(error, Error::NotAuthenticated { status: 403 }),
        "{error}"
    );
    assert_eq!(state.play.plays.load(Ordering::SeqCst), 1);
}

/// A `403` on `/playback-info` propagates rather than being read as an empty body.
///
/// This is what `test_play_video_no_permission` actually exercises: the poll is sent without
/// `allow_error`, so a non-`2xx` raises before either key is looked at
/// (`player.py:84`, `pyatv/support/http.py:482-489`).
#[tokio::test]
async fn a_forbidden_playback_info_fails_the_call() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    device
        .state()
        .play
        .queue([PlaybackAnswer::forbidden()])
        .await;

    let error = player
        .play_url(URL, START_POSITION, &Notify::new())
        .await
        .expect_err("the poll was refused");

    assert!(
        matches!(error, Error::NotAuthenticated { status: 403 }),
        "{error}"
    );
}

/// Nothing ever reports a duration, so the driver gives up after `WAIT_RETRIES` polls — quietly,
/// which is upstream's behaviour and not obviously the intended one (`player.py:104-116`).
#[tokio::test]
async fn a_play_that_never_starts_returns_after_five_polls() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();

    player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect("a media that never starts is not an error upstream");

    // Five decrements from 5 to -1, so six polls before `attempts < 0` holds with no duration.
    assert_eq!(state.play.polls.load(Ordering::SeqCst), 6);
}

/// Stopping mid-play ends the call, and sends nothing at all while doing it.
#[tokio::test]
async fn stopping_ends_the_call_without_a_request() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();

    // Enough "still playing" answers that the poll would otherwise never end.
    state
        .play
        .queue((0..200).map(|_| PlaybackAnswer::playing(600.0)))
        .await;

    // The stop is raised once the poll loop has demonstrably started, not after a fixed delay: a
    // sleep long enough to be reliable on a loaded machine is a sleep this suite pays on every run,
    // and a short one makes the `polls > 0` assertion below a race. Waiting on the receiver's own
    // counter is both instant and certain.
    let stop = Arc::new(Notify::new());
    let signal = Arc::clone(&stop);
    let polling = Arc::clone(&state);
    tokio::spawn(async move {
        while polling.play.polls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        signal.notify_one();
    });

    tokio::time::timeout(Duration::from_secs(5), player.play_url(URL, 0.0, &stop))
        .await
        .expect("the stop must end the call")
        .expect("a stopped playback is not a failure");

    assert_eq!(
        state.play.stops.load(Ordering::SeqCst),
        0,
        "there is no /stop request in pyatv's play path"
    );
    assert!(state.play.polls.load(Ordering::SeqCst) > 0);
}

/// A stop raised before the poll even starts is still seen, because the signal is a stored permit
/// rather than a broadcast.
#[tokio::test]
async fn a_stop_raised_early_is_not_lost() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state
        .play
        .queue((0..200).map(|_| PlaybackAnswer::playing(600.0)))
        .await;

    let stop = Notify::new();
    stop.notify_one();

    tokio::time::timeout(Duration::from_secs(5), player.play_url(URL, 0.0, &stop))
        .await
        .expect("the stop must end the call")
        .expect("a stopped playback is not a failure");
}

/// The tvOS 27 divergence, on the play path this time: `skipRecord: true` suppresses the `RECORD`
/// and the rest of the sequence carries on unchanged.
#[tokio::test]
async fn skip_record_is_honoured_on_the_play_path() {
    let (device, mut player) = ap2(FakeOptions {
        skip_record: Some(true),
        ..FakeOptions::default()
    })
    .await;
    let state = device.state();
    state
        .play
        .queue([PlaybackAnswer::playing(0.8), PlaybackAnswer::idle()])
        .await;

    player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect("the media should play to its end");

    assert_eq!(state.records.load(Ordering::SeqCst), 0);
    assert_eq!(state.play.plays.load(Ordering::SeqCst), 1);
}

/// `skipRecord: false` is not an absent key: it means "do send it".
#[tokio::test]
async fn an_explicit_false_skip_record_still_records() {
    let (device, mut player) = ap2(FakeOptions {
        skip_record: Some(false),
        ..FakeOptions::default()
    })
    .await;
    let state = device.state();
    state
        .play
        .queue([PlaybackAnswer::playing(0.8), PlaybackAnswer::idle()])
        .await;

    player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect("the media should play to its end");

    assert_eq!(state.records.load(Ordering::SeqCst), 1);
}

/// The keepalive really runs for the duration of an `AirPlay` 2 play, and stops with the session.
#[tokio::test]
async fn the_feedback_loop_runs_while_the_media_plays() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state
        .play
        .queue((0..40).map(|_| PlaybackAnswer::playing(600.0)))
        .await;

    let stop = Arc::new(Notify::new());
    let signal = Arc::clone(&stop);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        signal.notify_one();
    });

    player
        .play_url(URL, 0.0, &stop)
        .await
        .expect("stopping is not a failure");
    player.close().await.expect("closing should succeed");

    let during = state.feedbacks.load(Ordering::SeqCst);
    assert!(during >= 1, "expected a keepalive, got {during}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        state.feedbacks.load(Ordering::SeqCst),
        during,
        "closing the session must stop the keepalive"
    );
}

/// The whole `/play` body reaches the receiver intact, with the values upstream sends.
#[tokio::test]
async fn the_play_body_reaches_the_receiver_intact() {
    let (device, mut player) = ap2(FakeOptions::default()).await;
    let state = device.state();
    state
        .play
        .queue([PlaybackAnswer::playing(0.8), PlaybackAnswer::idle()])
        .await;

    player
        .play_url(URL, 0.0, &Notify::new())
        .await
        .expect("the media should play to its end");

    let body = state.play.body.lock().await.clone().expect("a play body");
    let dictionary = body.as_dictionary().expect("a dictionary");

    assert_eq!(dictionary.len(), 21);
    assert_eq!(dictionary["Content-Location"].as_string(), Some(URL));
    // The facade's route truncates, so a whole position arrives as a plist integer.
    assert_eq!(
        dictionary["Start-Position-Seconds"].as_signed_integer(),
        Some(0)
    );
    assert_eq!(dictionary["mediaType"].as_string(), Some("file"));
    assert_eq!(dictionary["rate"].as_real(), Some(1.0));
    assert_eq!(
        dictionary["clientBundleID"].as_string(),
        Some("dev.pyatv.GPU")
    );

    // And the base `SETUP` was the play path's, not the tunnel's.
    let setup = state
        .event_setup
        .lock()
        .await
        .clone()
        .expect("a SETUP body");
    let setup = setup.as_dictionary().expect("a dictionary");
    assert_eq!(setup.len(), 15);
    assert_eq!(setup["timingProtocol"].as_string(), Some("NTP"));
    assert_eq!(setup["sourceVersion"].as_string(), Some("690.7.1"));
    assert!(!setup.contains_key("isRemoteControlOnly"));
    assert!(
        setup["timingPort"]
            .as_signed_integer()
            .is_some_and(|port| port > 0),
        "a real UDP timing socket is bound and its port is quoted"
    );
}

/// The facade's `Stream`, end to end: a stop raised with nothing playing is a no-op, and the play
/// that follows still runs to the end.
///
/// The signal only exists while a playback does, so a stray `stop()` cannot leave a permit behind
/// for the next call to consume — which is what would make the *following* `play_url` return
/// immediately and look like it had played.
#[tokio::test]
async fn a_stop_with_nothing_playing_does_not_affect_the_next_play() {
    let (device, stream) = ap2_stream(FakeOptions::default()).await;
    let state = device.state();

    stream.stop();
    stream.stop();

    state
        .play
        .queue([PlaybackAnswer::playing(0.8), PlaybackAnswer::idle()])
        .await;
    stream
        .play_url_at(URL, START_POSITION)
        .await
        .expect("the media should play to its end");

    assert_eq!(state.play.plays.load(Ordering::SeqCst), 1);
    assert!(state.play.polls.load(Ordering::SeqCst) >= 2);
}

/// `AirPlayRemoteControl::stop` reaches the playback the `Stream` started, which is the whole of
/// what upstream's `AirPlayRemoteControl` does (`__init__.py:168-177`).
#[tokio::test]
async fn the_remote_controls_stop_ends_the_facades_playback() {
    let (device, stream) = ap2_stream(FakeOptions::default()).await;
    let state = device.state();
    state
        .play
        .queue((0..200).map(|_| PlaybackAnswer::playing(600.0)))
        .await;

    let remote = AirPlayRemoteControl::new(stream.clone());
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(60)).await;
        remote.stop().await.expect("stopping never fails");
    });

    tokio::time::timeout(Duration::from_secs(5), stream.play_url_at(URL, 0.0))
        .await
        .expect("the stop must end the call")
        .expect("a stopped playback is not a failure");

    assert_eq!(state.play.stops.load(Ordering::SeqCst), 0);
}
