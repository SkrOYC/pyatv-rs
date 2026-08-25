//! MRP's control surface, end to end against a hermetic device.
//!
//! The button, volume, power and artwork half of the counterpart to
//! `tests/protocols/mrp/test_mrp_functional.py`; the metadata and push-update half is in
//! `mrp_functional.rs`. Everything runs over a real loopback socket through the real pair-verify,
//! the real ChaCha20 framing and the real protobuf extension layer.

mod support;

use std::sync::{Arc, Mutex};

use pyatv_core::consts::{InputAction, PowerState, RepeatState, ShuffleState};
use pyatv_core::interface::PowerListener;
use pyatv_core::{FeatureName, FeatureState, Protocol};
use pyatv_pairing::server::PIN_CODE;
use pyatv_proto_mrp::protobuf::Command;

use support::fake_mrp::FakeMrpDevice;
use support::fake_state::{DEVICE_UID, INITIAL_VOLUME, PlayingState, VOLUME_STEP};
use support::harness::{connect, connect_with, feature, open, playing, pressed, until};

// --- Buttons ----------------------------------------------------------------

#[tokio::test]
async fn every_hid_button_reaches_the_device() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;
    let remote = data
        .remote_control
        .as_ref()
        .expect("RemoteControl is registered");
    let state = device.state();

    remote.up(InputAction::SingleTap).await.expect("up");
    pressed(&state, "up").await;
    remote.down(InputAction::SingleTap).await.expect("down");
    pressed(&state, "down").await;
    remote.left(InputAction::SingleTap).await.expect("left");
    pressed(&state, "left").await;
    remote.right(InputAction::SingleTap).await.expect("right");
    pressed(&state, "right").await;
    remote.select(InputAction::SingleTap).await.expect("select");
    pressed(&state, "select").await;
    remote.menu(InputAction::SingleTap).await.expect("menu");
    pressed(&state, "menu").await;
    remote.home(InputAction::SingleTap).await.expect("home");
    pressed(&state, "home").await;
    remote.top_menu().await.expect("top_menu");
    pressed(&state, "top_menu").await;
}

#[tokio::test]
async fn a_double_tap_and_a_hold_are_distinguishable() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;
    let remote = data
        .remote_control
        .as_ref()
        .expect("RemoteControl is registered");
    let state = device.state();

    remote.select(InputAction::SingleTap).await.expect("select");
    pressed(&state, "select").await;
    assert_eq!(
        state.with(|inner| inner.last_button_action),
        Some(InputAction::SingleTap)
    );

    remote.select(InputAction::DoubleTap).await.expect("select");
    until("the double tap", || {
        state
            .with(|inner| inner.last_button_action)
            .filter(|action| *action == InputAction::DoubleTap)
    })
    .await;

    remote.menu(InputAction::Hold).await.expect("menu");
    until("the hold", || {
        state
            .with(|inner| inner.last_button_action)
            .filter(|action| *action == InputAction::Hold)
    })
    .await;
}

#[tokio::test]
async fn the_playback_commands_reach_the_device() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video_with(&PlayingState {
        supported_commands: vec![
            Command::Play,
            Command::Pause,
            Command::Stop,
            Command::NextTrack,
            Command::PreviousTrack,
            Command::TogglePlayPause,
        ],
        ..PlayingState::default()
    });
    let data = connect(&device).await;
    let remote = data
        .remote_control
        .as_ref()
        .expect("RemoteControl is registered");
    let state = device.state();

    remote.play().await.expect("play");
    pressed(&state, "play").await;
    remote.pause().await.expect("pause");
    pressed(&state, "pause").await;
    remote.stop().await.expect("stop");
    pressed(&state, "stop").await;
    remote.next().await.expect("next");
    pressed(&state, "nextitem").await;
    remote.previous().await.expect("previous");
    pressed(&state, "previtem").await;
    remote.play_pause().await.expect("play_pause");
    pressed(&state, "playpause").await;
}

#[tokio::test]
async fn skipping_moves_the_position_by_the_requested_interval() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video_with(&PlayingState {
        supported_commands: vec![Command::SkipForward, Command::SkipBackward],
        skip_time: Some(12.0),
        position: Some(20.0),
        ..PlayingState::default()
    });
    let data = connect(&device).await;
    let remote = data
        .remote_control
        .as_ref()
        .expect("RemoteControl is registered");

    playing(&data, "the initial position", |it| it.position == Some(20)).await;

    // No interval given, so the device's advertised preferred interval is used.
    remote.skip_forward(0.0).await.expect("skip_forward");
    playing(&data, "the forward skip", |it| it.position == Some(32)).await;

    remote.skip_backward(0.0).await.expect("skip_backward");
    playing(&data, "the backward skip", |it| it.position == Some(20)).await;

    // An explicit interval overrides it.
    remote.skip_forward(17.0).await.expect("skip_forward");
    playing(&data, "the explicit skip", |it| it.position == Some(37)).await;
}

#[tokio::test]
async fn seeking_sets_an_absolute_position() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video_with(&PlayingState {
        supported_commands: vec![Command::SeekToPlaybackPosition],
        ..PlayingState::default()
    });
    let data = connect(&device).await;
    let remote = data
        .remote_control
        .as_ref()
        .expect("RemoteControl is registered");

    remote.set_position(60.0).await.expect("set_position");
    playing(&data, "the seek", |it| it.position == Some(60)).await;
}

#[tokio::test]
async fn shuffle_and_repeat_can_be_set() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    // Deliberately *not* listing `ChangeShuffleMode`/`ChangeRepeatMode` in `supported_commands`:
    // the device reports the current mode by appending its own `CommandInfo` for that command, and
    // `command_info` returns the first match, so a plain capability entry would shadow it. pyatv's
    // own fixtures set the mode the same way.
    device.state().example_video_with(&PlayingState {
        shuffle: Some(ShuffleState::Off),
        repeat: Some(RepeatState::Off),
        ..PlayingState::default()
    });
    let data = connect(&device).await;
    let remote = data
        .remote_control
        .as_ref()
        .expect("RemoteControl is registered");

    remote
        .set_shuffle(ShuffleState::Songs)
        .await
        .expect("set_shuffle");
    playing(&data, "shuffle on", |it| {
        it.shuffle == Some(ShuffleState::Songs)
    })
    .await;

    remote
        .set_repeat(RepeatState::Track)
        .await
        .expect("set_repeat");
    playing(&data, "repeat on", |it| {
        it.repeat == Some(RepeatState::Track)
    })
    .await;
}

/// A command the device does not implement comes back as `NoCommandHandlers` and must surface.
///
/// No `RemoteControl` method reaches that branch — every one of them maps onto a command the
/// fixture implements — so this drives [`pyatv_proto_mrp::facade::remote::send_command`] directly,
/// which is the shared helper all of them funnel through.
#[tokio::test]
async fn an_unhandled_command_is_reported_as_an_error() {
    use pyatv_proto_mrp::facade::remote::send_command;

    let device = FakeMrpDevice::start(PIN_CODE).await;
    let protocol = open(&device).await;
    protocol.start().await.expect("bring-up must succeed");

    let outcome = send_command(&protocol, Command::NextChapter, None).await;
    let error = outcome.expect_err("an unhandled command must not report success");
    let rendered = error.to_string();
    assert!(
        rendered.contains("NoCommandHandlers"),
        "the SendError name must be in the message: {rendered}"
    );

    protocol.close().await.expect("closing must succeed");
}

// --- Volume -----------------------------------------------------------------

#[tokio::test]
async fn volume_is_unavailable_until_the_device_says_otherwise() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;

    assert_eq!(
        feature(&data, FeatureName::Volume),
        FeatureState::Unavailable
    );
    assert_eq!(
        feature(&data, FeatureName::SetVolume),
        FeatureState::Unavailable
    );

    device.state().volume_control(true, true, true);
    device.state().set_volume(INITIAL_VOLUME, DEVICE_UID);

    until("volume to become available", || {
        (feature(&data, FeatureName::Volume) == FeatureState::Available).then_some(())
    })
    .await;

    let audio = data.audio.as_ref().expect("Audio is registered");
    assert!((audio.volume() - 50.0).abs() < 0.01, "{}", audio.volume());
}

#[tokio::test]
async fn setting_the_volume_round_trips() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;
    device.state().volume_control(true, true, true);
    device.state().set_volume(INITIAL_VOLUME, DEVICE_UID);
    until("volume to become available", || {
        (feature(&data, FeatureName::Volume) == FeatureState::Available).then_some(())
    })
    .await;

    let audio = data.audio.as_ref().expect("Audio is registered");
    audio.set_volume(20.0).await.expect("set_volume");
    assert!((audio.volume() - 20.0).abs() < 0.01, "{}", audio.volume());
    assert!(
        (device.state().with(|inner| inner.volume) - 0.2).abs() < 0.001,
        "the device stores a 0..1 fraction"
    );
}

/// Relative stepping goes out as HID volume keys, and the device answers with the new level.
#[tokio::test]
async fn stepping_the_volume_uses_the_hid_keys() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;
    // Relative-only: `Volume` and `SetVolume` stay unavailable, `VolumeUp`/`VolumeDown` do not.
    device.state().volume_control(true, false, true);
    device.state().set_volume(INITIAL_VOLUME, DEVICE_UID);
    until("relative volume to become available", || {
        (feature(&data, FeatureName::VolumeUp) == FeatureState::Available).then_some(())
    })
    .await;
    assert_eq!(
        feature(&data, FeatureName::SetVolume),
        FeatureState::Unavailable,
        "without absolute support there is no SetVolume"
    );

    let audio = data.audio.as_ref().expect("Audio is registered");
    audio.volume_up().await.expect("volume_up");
    let expected = INITIAL_VOLUME + VOLUME_STEP;
    until("the stepped volume", || {
        ((device.state().with(|inner| inner.volume) - expected).abs() < 0.001).then_some(())
    })
    .await;
    assert_eq!(
        device
            .state()
            .with(|inner| inner.last_button_pressed.clone()),
        Some("volumeup".to_owned())
    );

    audio.volume_down().await.expect("volume_down");
    until("the stepped volume", || {
        ((device.state().with(|inner| inner.volume) - INITIAL_VOLUME).abs() < 0.001).then_some(())
    })
    .await;
}

#[tokio::test]
async fn output_devices_can_be_added_removed_and_set() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;
    let audio = data.audio.as_ref().expect("Audio is registered");

    audio
        .add_output_devices(&["DEVICE-A".to_owned()])
        .await
        .expect("add_output_devices");
    until("the added device", || {
        device
            .state()
            .with(|inner| inner.output_devices.contains(&"DEVICE-A".to_owned()))
            .then_some(())
    })
    .await;

    audio
        .set_output_devices(&["DEVICE-B".to_owned()])
        .await
        .expect("set_output_devices");
    until("the replaced device list", || {
        device
            .state()
            .with(|inner| inner.output_devices == vec!["DEVICE-B".to_owned()])
            .then_some(())
    })
    .await;

    audio
        .remove_output_devices(&["DEVICE-B".to_owned()])
        .await
        .expect("remove_output_devices");
    until("the emptied device list", || {
        device
            .state()
            .with(|inner| inner.output_devices.is_empty())
            .then_some(())
    })
    .await;
}

// --- Power ------------------------------------------------------------------

/// Records every power transition the facade reports.
#[derive(Debug, Default)]
struct PowerRecorder {
    states: Mutex<Vec<PowerState>>,
}

impl PowerListener for PowerRecorder {
    fn power_state_changed(&self, _old: PowerState, new: PowerState) {
        if let Ok(mut states) = self.states.lock() {
            states.push(new);
        }
    }
}

#[tokio::test]
async fn power_state_follows_the_devices_logical_device_count() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let recorder = Arc::new(PowerRecorder::default());
    let data = connect_with(
        &device,
        Some(Arc::clone(&recorder) as Arc<dyn PowerListener>),
    )
    .await;

    let power = data.power.as_ref().expect("Power is registered");
    assert_eq!(power.power_state(), PowerState::On);

    // `turn_off` is Home-hold-then-Select, which the fixture recognises as a power-off.
    power.turn_off(true).await.expect("turn_off");
    until("the device to power off", || {
        (power.power_state() == PowerState::Off).then_some(())
    })
    .await;

    power.turn_on(true).await.expect("turn_on");
    until("the device to power on", || {
        (power.power_state() == PowerState::On).then_some(())
    })
    .await;

    let seen = recorder
        .states
        .lock()
        .map(|states| states.clone())
        .unwrap_or_default();
    assert!(
        seen.contains(&PowerState::Off) && seen.contains(&PowerState::On),
        "the listener saw {seen:?}"
    );
}

// --- Artwork ----------------------------------------------------------------

#[tokio::test]
async fn artwork_is_fetched_through_the_playback_queue() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    device.state().example_video();
    device
        .state()
        .change_artwork(b"1234", "image/png", "artwork_id1");
    let data = connect(&device).await;

    let metadata = data.metadata.as_ref().expect("Metadata is registered");
    playing(&data, "the example video", |it| {
        it.title.as_deref() == Some("dummy")
    })
    .await;

    until("the artwork identifier", || {
        metadata
            .artwork_id()
            .filter(|id| id.contains("artwork_id1"))
    })
    .await;

    let artwork = metadata
        .artwork(None, None)
        .await
        .expect("artwork() must not fail")
        .expect("artwork must be present");
    assert_eq!(artwork.bytes.as_slice(), b"1234");
    assert_eq!(artwork.mimetype, "image/png");
    assert_eq!(artwork.width, Some(456));
    assert_eq!(artwork.height, Some(789));
}

// --- Bring-up ---------------------------------------------------------------

#[tokio::test]
async fn the_bring_up_sequence_authenticates_and_connects() {
    let device = FakeMrpDevice::start(PIN_CODE).await;
    let data = connect(&device).await;

    assert_eq!(data.protocol, Some(Protocol::Mrp));
    let state = device.state();
    assert!(
        state.with(|inner| inner.has_authenticated),
        "pair-verify must have run"
    );
    assert_eq!(
        state.with(|inner| inner.connection_state),
        Some(2),
        "SET_CONNECTION_STATE must carry Connected"
    );
    assert_eq!(
        data.device_info.build_number(),
        Some(support::fake_state::BUILD_NUMBER)
    );
}
