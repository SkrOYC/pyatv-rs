//! MRP's metadata and push-update surface, end to end against a hermetic device.
//!
//! Counterpart of the now-playing half of `tests/protocols/mrp/test_mrp_functional.py`; the button,
//! volume, power and artwork half is in `mrp_control.rs`. Everything runs over a real loopback
//! socket through the real pair-verify, the real ChaCha20 framing and the real protobuf extension
//! layer, so a failure here means the bytes are wrong rather than that a mock disagreed.

use pyatv_proto_mrp::test_support as support;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyatv_core::consts::{DeviceState, MediaType, RepeatState, ShuffleState};
use pyatv_core::interface::PlaybackListener;
use pyatv_core::models::Playing;
use pyatv_core::{FeatureName, FeatureState};
use pyatv_pairing::server::PIN_CODE;

use support::fake_mrp::FakeMrpDevice;
use support::fake_state::{APP_NAME, PLAYER_IDENTIFIER, PlayingState};
use support::harness::{connect, feature, playing, until};

// --- Metadata ---------------------------------------------------------------

#[tokio::test]
async fn metadata_for_a_paused_video() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video();
    let data = connect(&device).await;

    let snapshot = playing(&data, "the example video", |it| {
        it.title.as_deref() == Some("dummy")
    })
    .await;

    assert_eq!(snapshot.media_type, MediaType::Video);
    assert_eq!(snapshot.device_state, DeviceState::Paused);
    assert_eq!(snapshot.total_time, Some(123));
    assert_eq!(
        snapshot.position,
        Some(3),
        "paused means the raw elapsed time, never extrapolated"
    );
    assert_eq!(feature(&data, FeatureName::Title), FeatureState::Available);
    assert_eq!(
        feature(&data, FeatureName::Artist),
        FeatureState::Unavailable,
        "a video has no artist"
    );
}

#[tokio::test]
async fn metadata_for_music() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_music();
    let data = connect(&device).await;

    let snapshot = playing(&data, "the example music", |it| {
        it.title.as_deref() == Some("music")
    })
    .await;

    assert_eq!(snapshot.media_type, MediaType::Music);
    assert_eq!(snapshot.artist.as_deref(), Some("artist"));
    assert_eq!(snapshot.album.as_deref(), Some("album"));
    assert_eq!(snapshot.genre.as_deref(), Some("genre"));
    assert_eq!(snapshot.total_time, Some(49));
    assert_eq!(snapshot.position, Some(22));

    for name in [
        FeatureName::Title,
        FeatureName::Artist,
        FeatureName::Album,
        FeatureName::Genre,
        FeatureName::TotalTime,
        FeatureName::Position,
    ] {
        assert_eq!(feature(&data, name), FeatureState::Available, "{name:?}");
    }
}

#[tokio::test]
async fn metadata_for_tv_content() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().tv_playing(
        false,
        "tv",
        40.0,
        10.0,
        12,
        4,
        &PlayingState {
            content_identifier: Some("identifier".to_owned()),
            itunes_store_identifier: Some(123_456_789),
            ..PlayingState::default()
        },
    );
    let data = connect(&device).await;

    let snapshot = playing(&data, "the tv episode", |it| {
        it.series_name.as_deref() == Some("tv")
    })
    .await;

    assert_eq!(snapshot.media_type, MediaType::Video);
    assert_eq!(snapshot.device_state, DeviceState::Playing);
    assert_eq!(snapshot.total_time, Some(40));
    assert_eq!(snapshot.season_number, Some(12));
    assert_eq!(snapshot.episode_number, Some(4));
    assert_eq!(snapshot.content_identifier.as_deref(), Some("identifier"));
    assert_eq!(snapshot.itunes_store_identifier, Some(123_456_789));

    // Playing at rate 1, so the position is extrapolated from the device's own timestamp; the
    // fixture stamps "now", so the drift is however long the round trip took.
    let position = snapshot.position.expect("a position must be reported");
    assert!(
        (10..=12).contains(&position),
        "extrapolated position {position} is not close to 10"
    );
}

#[tokio::test]
async fn an_idle_device_reports_idle() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video();
    let data = connect(&device).await;
    playing(&data, "the example video", |it| {
        it.title.as_deref() == Some("dummy")
    })
    .await;

    device.state().nothing_playing();

    let snapshot = playing(&data, "the idle state", |it| {
        it.device_state == DeviceState::Idle
    })
    .await;
    assert_eq!(snapshot.media_type, MediaType::Unknown);
    assert_eq!(snapshot.title, None);
}

#[tokio::test]
async fn a_loading_device_reports_loading() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().media_is_loading();
    let data = connect(&device).await;

    playing(&data, "the loading state", |it| {
        it.device_state == DeviceState::Loading
    })
    .await;
}

/// `UPDATE_CONTENT_ITEM_MESSAGE` merges into the tracked item rather than replacing it.
#[tokio::test]
async fn a_content_item_update_merges_into_the_current_item() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_music();
    let data = connect(&device).await;
    playing(&data, "the example music", |it| {
        it.title.as_deref() == Some("music")
    })
    .await;

    device.state().change_metadata(&PlayingState {
        title: Some("foobar".to_owned()),
        ..PlayingState::default()
    });

    let snapshot = playing(&data, "the merged title", |it| {
        it.title.as_deref() == Some("foobar")
    })
    .await;
    assert_eq!(
        snapshot.artist.as_deref(),
        Some("artist"),
        "the untouched fields must survive the merge"
    );
    assert_eq!(snapshot.album.as_deref(), Some("album"));
}

#[tokio::test]
async fn shuffle_and_repeat_are_read_off_their_command_entries() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video_with(&PlayingState {
        shuffle: Some(ShuffleState::Songs),
        repeat: Some(RepeatState::All),
        ..PlayingState::default()
    });
    let data = connect(&device).await;

    let snapshot = playing(&data, "the example video", |it| {
        it.title.as_deref() == Some("dummy")
    })
    .await;
    assert_eq!(snapshot.shuffle, Some(ShuffleState::Songs));
    assert_eq!(snapshot.repeat, Some(RepeatState::All));
}

#[tokio::test]
async fn the_app_comes_from_the_active_client() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video();
    let data = connect(&device).await;
    playing(&data, "the example video", |it| {
        it.title.as_deref() == Some("dummy")
    })
    .await;

    let metadata = data.metadata.as_ref().expect("Metadata is registered");
    let app = until("the app", || metadata.app()).await;
    assert_eq!(app.identifier, PLAYER_IDENTIFIER);
    assert_eq!(app.name, APP_NAME);

    device
        .state()
        .update_client(Some("Demo App"), PLAYER_IDENTIFIER);
    until("the renamed app", || {
        metadata.app().filter(|app| app.name == "Demo App")
    })
    .await;
}

// --- Push updates -----------------------------------------------------------

/// A listener that records every snapshot it is handed.
#[derive(Debug, Default)]
struct Recorder {
    updates: Mutex<Vec<Playing>>,
    errors: Mutex<usize>,
}

impl Recorder {
    fn titles(&self) -> Vec<Option<String>> {
        self.updates
            .lock()
            .map(|updates| updates.iter().map(|it| it.title.clone()).collect())
            .unwrap_or_default()
    }
}

impl PlaybackListener for Recorder {
    fn playstatus_update(&self, playing: &Playing) {
        if let Ok(mut updates) = self.updates.lock() {
            updates.push(playing.clone());
        }
    }

    fn playstatus_error(&self, _error: &pyatv_core::Error) {
        if let Ok(mut errors) = self.errors.lock() {
            *errors += 1;
        }
    }
}

#[tokio::test]
async fn push_updates_deliver_every_state_change() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video();
    let data = connect(&device).await;

    let recorder = Arc::new(Recorder::default());
    let updater = data
        .push_updater
        .as_ref()
        .expect("PushUpdater is registered");
    updater.set_listener(&(Arc::clone(&recorder) as Arc<dyn PlaybackListener>));
    updater.start(0).await.expect("starting must succeed");
    assert!(updater.active());

    // `start()` posts one snapshot immediately, without waiting for the device.
    until("the initial push", || {
        (!recorder.titles().is_empty()).then_some(())
    })
    .await;

    device.state().change_state(&PlayingState {
        title: Some("second".to_owned()),
        ..PlayingState::default()
    });
    until("the pushed change", || {
        recorder
            .titles()
            .contains(&Some("second".to_owned()))
            .then_some(())
    })
    .await;

    updater.stop();
    assert!(!updater.active());
}

/// A listener that blocks for a long time on every update.
///
/// Blocking rather than sleeping asynchronously on purpose: `PlaybackListener` is a synchronous
/// trait, so this is what a caller doing real work — writing to a terminal, updating a UI — looks
/// like from the protocol's point of view.
#[derive(Debug)]
struct SleepingListener {
    delay: Duration,
    seen: Mutex<usize>,
}

impl PlaybackListener for SleepingListener {
    fn playstatus_update(&self, _playing: &Playing) {
        std::thread::sleep(self.delay);
        if let Ok(mut seen) = self.seen.lock() {
            *seen += 1;
        }
    }

    fn playstatus_error(&self, _error: &pyatv_core::Error) {}
}

/// A listener that blocks must not hold up an unrelated request.
///
/// The regression this guards: callbacks used to run inside the protocol actor's `select!` loop,
/// which is the only thing that writes to the transport. A listener that took a second per update
/// therefore added a second per update to every command — and on a tunnelled connection it also
/// stopped the data channel's `rply` acknowledgements for that long, which is what makes a real
/// receiver decide the tunnel is dead.
///
/// Two worker threads are required, not incidental: the listener blocks the thread the notifier
/// task is running on, and the assertion is precisely that the actor is somewhere else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocking_listener_does_not_hold_up_a_request() {
    /// One callback has to outlast the bound on its own. The actor's `select!` is `biased`
    /// towards requests, so under the old behaviour a request queued mid-callback was served as
    /// soon as that *one* callback returned — the delay to beat is `DELAY`, not `CHANGES * DELAY`.
    const DELAY: Duration = Duration::from_millis(1_200);
    /// Enough queued work that a callback is certainly in flight when the request is issued.
    const CHANGES: usize = 3;
    /// Comfortably under [`DELAY`], comfortably over a loopback round trip.
    const BOUND: Duration = Duration::from_millis(600);

    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video();
    let data = connect(&device).await;

    let listener = Arc::new(SleepingListener {
        delay: DELAY,
        seen: Mutex::new(0),
    });
    let updater = data
        .push_updater
        .as_ref()
        .expect("PushUpdater is registered");
    updater.set_listener(&(Arc::clone(&listener) as Arc<dyn PlaybackListener>));
    updater.start(0).await.expect("starting must succeed");

    for index in 0..CHANGES {
        device.state().change_state(&PlayingState {
            title: Some(format!("track {index}")),
            ..PlayingState::default()
        });
    }

    // Wait until the listener is definitely occupied before timing anything, so the measurement
    // cannot land in a gap between updates.
    until("the listener to start blocking", || {
        (*listener
            .seen
            .lock()
            .expect("the recorder must not be poisoned")
            >= 1)
            .then_some(())
    })
    .await;

    let remote = data
        .remote_control
        .as_ref()
        .expect("MRP registers a RemoteControl implementation");

    let started = std::time::Instant::now();
    remote
        .select(pyatv_core::consts::InputAction::SingleTap)
        .await
        .expect("select must reach the device");
    let elapsed = started.elapsed();

    assert!(
        elapsed < BOUND,
        "a blocking listener delayed an unrelated request by {elapsed:?}, over the {BOUND:?} bound"
    );
}
