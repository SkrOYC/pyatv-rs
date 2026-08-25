//! DMAP's session, metadata, feature and push-update behaviour, end to end.
//!
//! Counterpart of `tests/protocols/dmap/test_dmap_functional.py`. The buttons and the seek
//! arithmetic live next door in `dmap_control`; the shared harness is in [`support`].

mod support;

use std::sync::Arc;

use pyatv_core::interface::{AppleTV, DeviceListener, PlaybackListener};
use pyatv_core::{
    DeviceState, FeatureName, FeatureState, MediaType, OperatingSystem, RepeatState, ShuffleState,
};
use pyatv_proto_dmap::test_support::fake_dmap::FakeDmapDevice;
use pyatv_proto_dmap::test_support::fake_state::{HSGID, PAIRING_GUID, PlayingResponse};

use support::{
    RecordingDeviceListener, RecordingPushListener, connect, connect_with_listener, playing, until,
};

// ---- Login (`test_dmap_functional.py:96-138`) ----

/// Bring-up is `login` then one immediate `playstatusupdate` (`__init__.py:684-689`).
#[tokio::test]
async fn connecting_logs_in_and_primes_the_play_status() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();

    let atv = connect(&device, HSGID).await;
    assert_eq!(playing(&atv).await.title.as_deref(), Some("dummy"));

    let requests = use_cases.requests();
    assert!(
        requests[0].starts_with("/login?hsgid="),
        "the first request must be a login, was {:?}",
        requests[0]
    );
    assert!(
        requests[1].starts_with("/ctrl-int/1/playstatusupdate?session-id="),
        "the second must prime the play status, was {:?}",
        requests[1]
    );
    use_cases.assert_no_protocol_errors();
}

/// `test_login_with_pairing_guid_succeed` (`:134-138`): the other credential form works too, and
/// goes out as `pairing-guid=` rather than `hsgid=`.
#[tokio::test]
async fn a_pairing_guid_logs_in_as_well_as_a_home_sharing_id() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();

    let _atv = connect(&device, PAIRING_GUID).await;

    let requests = use_cases.requests();
    assert!(
        requests[0].starts_with(&format!("/login?pairing-guid={PAIRING_GUID}")),
        "was {:?}",
        requests[0]
    );
    use_cases.assert_no_protocol_errors();
}

/// `test_connect_failed` (`:96-102`): "twice since the client will retry one time".
#[tokio::test]
async fn a_login_that_keeps_failing_reports_authentication() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.make_login_fail();

    let error = connect_with_listener(&device, HSGID, None)
        .await
        .expect_err("a device that refuses the credential must not connect");

    assert!(
        matches!(error, pyatv_proto_dmap::Error::Authentication(503)),
        "expected an authentication failure, got {error:?}"
    );
    assert_eq!(
        use_cases.requests().len(),
        2,
        "the login must be attempted exactly twice"
    );
}

/// `test_relogin_if_session_expired` (`:106-116`), pyatv issue #2.
///
/// Upstream's version cannot actually fail: `force_relogin` only changes what the *next* login
/// hands out, and the 403 it arranges is then overwritten by `change_artwork`. The fixture here
/// invalidates the session for real (see `test_support`'s module documentation), so the client
/// genuinely sees a 403, re-logs in, and retries.
#[tokio::test]
async fn an_expired_session_is_re_logged_in_and_the_request_retried() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();

    let atv = connect(&device, HSGID).await;

    use_cases.force_relogin(1234);
    use_cases.change_artwork(b"1234");

    let artwork = atv
        .metadata()
        .expect("DMAP provides Metadata")
        .artwork(None, None)
        .await
        .expect("artwork must survive a session expiry")
        .expect("the device has artwork");
    assert_eq!(artwork.bytes, b"1234");

    let requests = use_cases.requests();
    let logins = requests
        .iter()
        .filter(|target| target.starts_with("/login"))
        .count();
    assert_eq!(logins, 2, "the expiry must have forced a second login");
    assert!(
        requests
            .last()
            .is_some_and(|last| last.contains("session-id=1234")),
        "the retry must carry the new session id, requests were {requests:?}"
    );
}

// ---- Metadata (`test_dmap_functional.py:92-94,118-132`) ----

/// `test_metadata_artwork_size` (`:118-132`): the requested dimensions reach the device.
///
/// **Divergence:** upstream reports `width == -1` and `height == -1` because DMAP does not say what
/// size it returned; this reports `None`, which says the same thing without a sentinel.
#[tokio::test]
async fn artwork_asks_for_the_requested_size_and_reports_unknown_dimensions() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();
    use_cases.change_artwork(b"1234");

    let atv = connect(&device, HSGID).await;
    let artwork = atv
        .metadata()
        .expect("DMAP provides Metadata")
        .artwork(Some(123), Some(456))
        .await
        .expect("artwork must be readable")
        .expect("the device has artwork");

    assert_eq!(artwork.bytes, b"1234");
    assert_eq!(artwork.mimetype, "image/png");
    assert_eq!(artwork.width, None);
    assert_eq!(artwork.height, None);

    let state = use_cases.state();
    assert_eq!(state.last_artwork_width, Some(123));
    assert_eq!(state.last_artwork_height, Some(456));
}

/// An empty artwork body is "nothing playing has artwork", not an error.
#[tokio::test]
async fn no_artwork_is_reported_as_none() {
    let device = FakeDmapDevice::start().await;
    device.use_cases().example_video();

    let atv = connect(&device, HSGID).await;
    let artwork = atv
        .metadata()
        .expect("DMAP provides Metadata")
        .artwork(None, None)
        .await
        .expect("an empty body must not be an error");

    assert!(artwork.is_none());
}

/// `test_app_not_supported` (`:92-94`): DMAP has no notion of a foreground app.
#[tokio::test]
async fn there_is_no_app_information() {
    let device = FakeDmapDevice::start().await;
    let atv = connect(&device, HSGID).await;

    assert!(
        atv.metadata()
            .expect("DMAP provides Metadata")
            .app()
            .is_none()
    );
}

/// `test_basic_device_info` (`:194-195`).
#[tokio::test]
async fn the_device_is_reported_as_legacy() {
    let device = FakeDmapDevice::start().await;
    let atv = connect(&device, HSGID).await;

    assert_eq!(
        atv.device_info().operating_system(),
        OperatingSystem::Legacy
    );
}

/// The full now-playing mapping for a music track, which exercises every string tag and the
/// `cant` -> position subtraction at once (`common_functional_tests.py::test_metadata_music`).
#[tokio::test]
async fn a_music_track_maps_every_field() {
    let device = FakeDmapDevice::start().await;
    device.use_cases().example_music();

    let atv = connect(&device, HSGID).await;
    let playing = playing(&atv).await;

    assert_eq!(playing.media_type, MediaType::Music);
    assert_eq!(playing.device_state, DeviceState::Paused);
    assert_eq!(playing.title.as_deref(), Some("music"));
    assert_eq!(playing.artist.as_deref(), Some("artist"));
    assert_eq!(playing.album.as_deref(), Some("album"));
    assert_eq!(playing.genre.as_deref(), Some("genre"));
    assert_eq!(playing.total_time, Some(49));
    assert_eq!(playing.position, Some(22));
}

// ---- Features (`test_dmap_functional.py:197-258`) ----

/// `test_always_available_features` and `test_always_unknown_features` (`:197-237`), through the
/// facade rather than against the constant tables.
#[tokio::test]
async fn the_static_feature_groups_report_through_the_facade() {
    let device = FakeDmapDevice::start().await;
    let atv = connect(&device, HSGID).await;
    let features = atv.features();

    for feature in [
        FeatureName::Down,
        FeatureName::Left,
        FeatureName::Menu,
        FeatureName::Right,
        FeatureName::Select,
        FeatureName::TopMenu,
        FeatureName::Up,
    ] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Available,
            "{feature}"
        );
    }

    for feature in [
        FeatureName::Artwork,
        FeatureName::Next,
        FeatureName::Pause,
        FeatureName::Play,
        FeatureName::PlayPause,
        FeatureName::Previous,
        FeatureName::SetPosition,
        FeatureName::SetRepeat,
        FeatureName::SetShuffle,
        FeatureName::Stop,
        FeatureName::SkipForward,
        FeatureName::SkipBackward,
    ] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Unknown,
            "{feature}"
        );
    }

    for feature in [
        FeatureName::Home,
        FeatureName::HomeHold,
        FeatureName::Suspend,
        FeatureName::WakeUp,
        FeatureName::PowerState,
        FeatureName::TurnOn,
        FeatureName::TurnOff,
        FeatureName::App,
    ] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Unsupported,
            "{feature}"
        );
    }
}

/// `test_features_shuffle_repeat` (`:239-258`): the field-gated features follow the last response.
#[tokio::test]
async fn field_gated_features_follow_the_latest_play_status() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.nothing_playing();

    let atv = connect(&device, HSGID).await;
    let features = atv.features();

    for feature in [FeatureName::Shuffle, FeatureName::Repeat] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Unavailable,
            "{feature} with nothing playing"
        );
    }

    use_cases.music_playing(PlayingResponse {
        shuffle: Some(ShuffleState::Albums),
        repeat: Some(RepeatState::Track),
        ..PlayingResponse::example_music()
    });
    assert_eq!(playing(&atv).await.title.as_deref(), Some("music"));

    for feature in [FeatureName::Shuffle, FeatureName::Repeat] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Available,
            "{feature} while a track is playing"
        );
    }
}

/// `cavc` decides whether the volume buttons are usable (`__init__.py:640-651`).
#[tokio::test]
async fn the_volume_buttons_follow_the_devices_volume_control_flag() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();
    use_cases.change_volume_control(Some(true));

    let atv = connect(&device, HSGID).await;
    let features = atv.features();
    for feature in [FeatureName::VolumeUp, FeatureName::VolumeDown] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Available,
            "{feature}"
        );
    }

    use_cases.change_volume_control(Some(false));
    assert_eq!(playing(&atv).await.title.as_deref(), Some("dummy"));
    for feature in [FeatureName::VolumeUp, FeatureName::VolumeDown] {
        assert_eq!(
            features.get_feature(feature).state,
            FeatureState::Unavailable,
            "{feature}"
        );
    }
}

// ---- Push updates (`test_dmap_functional.py:140-151,284-316`) ----

/// `test_reset_revision_if_push_updates_fail` (`:284-316`).
///
/// The updater polls revision 0, gets the video, then polls revision 1 — for which the device has
/// nothing and answers 500. That must reset the revision to zero rather than wedge the loop, so the
/// content the error handler installs for revision 0 is picked up on the next pass.
#[tokio::test]
async fn a_push_error_resets_the_revision() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.video_playing(PlayingResponse {
        title: Some("video1".to_owned()),
        ..PlayingResponse::example_video()
    });

    let (atv, updater) = connect_with_listener(&device, HSGID, None)
        .await
        .expect("connecting must succeed");
    assert!(
        atv.push_updater().is_some(),
        "the facade must offer a push updater once DMAP has registered one"
    );

    let listener: Arc<RecordingPushListener> = Arc::new(RecordingPushListener::default());
    updater.set_listener(&(Arc::clone(&listener) as Arc<dyn PlaybackListener>));
    updater.start(0).await.expect("starting must succeed");

    until("the first push update", || {
        listener.latest_title().as_deref() == Some("video1")
    })
    .await;

    until("an error from the revision-1 poll", || {
        listener.error_count() > 0
    })
    .await;

    use_cases.video_playing(PlayingResponse {
        title: Some("video2".to_owned()),
        ..PlayingResponse::example_video()
    });
    until("the recovered push update", || {
        listener.latest_title().as_deref() == Some("video2")
    })
    .await;

    updater.stop();
    assert!(!updater.active());
}

/// `test_connection_lost` (`:140-151`): a device that hangs up mid-poll stops the loop and tells
/// the device listener, rather than reporting a playback error and spinning.
#[tokio::test]
async fn a_dropped_connection_stops_the_loop_and_reports_it() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();

    let device_listener: Arc<RecordingDeviceListener> =
        Arc::new(RecordingDeviceListener::default());
    let (_atv, updater) = connect_with_listener(
        &device,
        HSGID,
        Some(Arc::clone(&device_listener) as Arc<dyn DeviceListener>),
    )
    .await
    .expect("connecting must succeed");

    use_cases.server_closes_connection();

    let listener: Arc<RecordingPushListener> = Arc::new(RecordingPushListener::default());
    updater.set_listener(&(Arc::clone(&listener) as Arc<dyn PlaybackListener>));
    updater.start(0).await.expect("starting must succeed");

    until("connection_lost", || device_listener.lost_count() > 0).await;
    until("the poll loop to end", || !updater.active()).await;
    assert_eq!(
        listener.error_count(),
        0,
        "a transport loss is not a playback error"
    );
}
