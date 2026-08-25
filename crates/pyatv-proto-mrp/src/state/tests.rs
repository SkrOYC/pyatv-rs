//! Unit tests for the shared state's message handling.

use std::sync::{Arc, Mutex};

use pyatv_core::consts::{DeviceState, PowerState};
use pyatv_core::interface::{PlaybackListener, PowerListener};
use pyatv_core::models::Playing;

use super::MrpState;
use crate::message::MrpMessage;
use crate::messages::envelope;
use crate::protobuf::{
    ContentItem, ContentItemMetadata, DeviceInfoMessage, NowPlayingClient, NowPlayingPlayer,
    PlaybackQueue, PlayerPath, SetNowPlayingClientMessage, SetStateMessage,
    VolumeControlAvailabilityMessage, VolumeDidChangeMessage, extensions, playback_state,
    protocol_message::Type, volume_capabilities,
};

/// Records everything pushed to it.
#[derive(Debug, Default)]
struct Recorder {
    updates: Mutex<Vec<Playing>>,
}

impl PlaybackListener for Recorder {
    fn playstatus_update(&self, playing: &Playing) {
        if let Ok(mut updates) = self.updates.lock() {
            updates.push(playing.clone());
        }
    }

    fn playstatus_error(&self, _error: &pyatv_core::Error) {}
}

/// Records power transitions.
#[derive(Debug, Default)]
struct PowerRecorder {
    transitions: Mutex<Vec<(PowerState, PowerState)>>,
}

impl PowerListener for PowerRecorder {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        if let Ok(mut transitions) = self.transitions.lock() {
            transitions.push((old_state, new_state));
        }
    }
}

fn device_info(logical_device_count: u32) -> MrpMessage {
    MrpMessage::with_extension(
        envelope(Type::DeviceInfoMessage),
        &extensions::DEVICE_INFO_MESSAGE,
        &DeviceInfoMessage {
            name: "Fake".to_owned(),
            device_uid: Some("UID".to_owned()),
            logical_device_count: Some(logical_device_count),
            ..DeviceInfoMessage::default()
        },
    )
    .unwrap()
}

fn player_path(bundle: &str) -> PlayerPath {
    PlayerPath {
        client: Some(NowPlayingClient {
            bundle_identifier: Some(bundle.to_owned()),
            ..NowPlayingClient::default()
        }),
        player: Some(NowPlayingPlayer {
            identifier: Some(crate::player_state::DEFAULT_PLAYER_ID.to_owned()),
            ..NowPlayingPlayer::default()
        }),
        origin: None,
    }
}

fn set_state(bundle: &str, title: &str) -> MrpMessage {
    MrpMessage::with_extension(
        envelope(Type::SetStateMessage),
        &extensions::SET_STATE_MESSAGE,
        &SetStateMessage {
            playback_state: Some(playback_state::Enum::Playing as i32),
            playback_queue: Some(PlaybackQueue {
                location: Some(0),
                content_items: vec![ContentItem {
                    identifier: Some("item".to_owned()),
                    metadata: Some(ContentItemMetadata {
                        title: Some(title.to_owned()),
                        ..ContentItemMetadata::default()
                    }),
                    ..ContentItem::default()
                }],
                ..PlaybackQueue::default()
            }),
            player_path: Some(player_path(bundle)),
            ..SetStateMessage::default()
        },
    )
    .unwrap()
}

fn set_now_playing_client(bundle: &str) -> MrpMessage {
    MrpMessage::with_extension(
        envelope(Type::SetNowPlayingClientMessage),
        &extensions::SET_NOW_PLAYING_CLIENT_MESSAGE,
        &SetNowPlayingClientMessage {
            client: Some(NowPlayingClient {
                bundle_identifier: Some(bundle.to_owned()),
                display_name: Some("Test app".to_owned()),
                ..NowPlayingClient::default()
            }),
        },
    )
    .unwrap()
}

#[test]
fn a_set_state_for_the_active_client_reaches_the_listener() {
    let state = MrpState::new();
    let recorder = Arc::new(Recorder::default());
    state.add_push_listener(Arc::clone(&recorder) as Arc<dyn PlaybackListener>);
    state.set_push_active(true);

    state.handle(&set_now_playing_client("app")).unwrap();
    state.handle(&set_state("app", "Track")).unwrap();

    let updates = recorder.updates.lock().unwrap();
    assert!(
        updates.len() >= 2,
        "client switch and state change both push"
    );
    assert_eq!(updates.last().unwrap().title.as_deref(), Some("Track"));
    assert_eq!(updates.last().unwrap().device_state, DeviceState::Playing);
}

#[test]
fn nothing_is_pushed_while_the_updater_is_stopped() {
    let state = MrpState::new();
    let recorder = Arc::new(Recorder::default());
    state.add_push_listener(Arc::clone(&recorder) as Arc<dyn PlaybackListener>);

    state.handle(&set_now_playing_client("app")).unwrap();
    state.handle(&set_state("app", "Track")).unwrap();

    assert!(recorder.updates.lock().unwrap().is_empty());
}

#[test]
fn the_app_comes_from_the_active_client() {
    let state = MrpState::new();
    assert!(state.app().is_none());

    state
        .handle(&set_now_playing_client("com.example.app"))
        .unwrap();
    let app = state.app().unwrap();
    assert_eq!(app.identifier, "com.example.app");
    assert_eq!(app.name, "Test app");
}

#[test]
fn power_state_follows_the_logical_device_count() {
    let state = MrpState::new();
    let recorder = Arc::new(PowerRecorder::default());
    state.set_power_listener(Some(Arc::clone(&recorder) as Arc<dyn PowerListener>));

    assert_eq!(state.power_state(), PowerState::Unknown);

    state.handle(&device_info(1)).unwrap();
    assert_eq!(state.power_state(), PowerState::On);

    state.handle(&device_info(0)).unwrap();
    assert_eq!(state.power_state(), PowerState::Off);

    assert_eq!(
        *recorder.transitions.lock().unwrap(),
        vec![
            (PowerState::Unknown, PowerState::On),
            (PowerState::On, PowerState::Off)
        ]
    );
}

#[test]
fn volume_is_tracked_only_for_our_own_output_device() {
    let state = MrpState::new();
    state.handle(&device_info(1)).unwrap();

    let availability = MrpMessage::with_extension(
        envelope(Type::VolumeControlAvailabilityMessage),
        &extensions::VOLUME_CONTROL_AVAILABILITY_MESSAGE,
        &VolumeControlAvailabilityMessage {
            volume_control_available: Some(true),
            volume_capabilities: Some(volume_capabilities::Enum::Both as i32),
        },
    )
    .unwrap();
    state.handle(&availability).unwrap();

    let volume = state.volume();
    assert!(volume.available && volume.absolute && volume.relative);
    assert!(state.volume_available());

    let ours = MrpMessage::with_extension(
        envelope(Type::VolumeDidChangeMessage),
        &extensions::VOLUME_DID_CHANGE_MESSAGE,
        &VolumeDidChangeMessage {
            volume: Some(0.42),
            output_device_uid: Some("UID".to_owned()),
            endpoint_uid: None,
        },
    )
    .unwrap();
    state.handle(&ours).unwrap();
    assert!((state.volume().level - 42.0).abs() < 0.05);

    let theirs = MrpMessage::with_extension(
        envelope(Type::VolumeDidChangeMessage),
        &extensions::VOLUME_DID_CHANGE_MESSAGE,
        &VolumeDidChangeMessage {
            volume: Some(0.9),
            output_device_uid: Some("SOMEONE-ELSE".to_owned()),
            endpoint_uid: None,
        },
    )
    .unwrap();
    state.handle(&theirs).unwrap();
    assert!(
        (state.volume().level - 42.0).abs() < 0.05,
        "another device's volume must not overwrite ours"
    );
}

#[test]
fn an_unhandled_message_type_is_ignored() {
    let state = MrpState::new();
    let message = MrpMessage::bare(envelope(Type::UnknownMessage));
    assert!(state.handle(&message).is_ok());
}
