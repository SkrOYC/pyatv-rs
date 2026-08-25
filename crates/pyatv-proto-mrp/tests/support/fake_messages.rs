//! Device-to-client message builders for the fake MRP device.
//!
//! Port of the module-level helpers in `tests/fake_device/mrp.py` — `_fill_item` (`mrp.py:84-122`),
//! `_set_state_message` (`mrp.py:125-169`) and the one-off `messages.create(...)` bodies scattered
//! through `FakeMrpState` (`mrp.py:243-348`).
//!
//! These are the *device* side of the wire, so they are written against the generated protobuf
//! types directly rather than through [`pyatv_proto_mrp::messages`], which only knows how to build
//! what a controller sends.

use pyatv_core::consts::{RepeatState, ShuffleState};
use pyatv_proto_mrp::MrpMessage;
use pyatv_proto_mrp::messages::envelope;
use pyatv_proto_mrp::protobuf::{
    Command, CommandInfo, ContentItem, ContentItemMetadata, DeviceInfoMessage, KeyboardMessage,
    NowPlayingClient, NowPlayingPlayer, PlaybackQueue, PlayerPath, SendCommandResultMessage,
    SetDefaultSupportedCommandsMessage, SetNowPlayingClientMessage, SetStateMessage,
    SupportedCommands, UpdateClientMessage, UpdateContentItemMessage,
    VolumeControlAvailabilityMessage, VolumeControlCapabilitiesDidChangeMessage,
    VolumeDidChangeMessage, content_item_metadata, extensions, playback_state, protocol_message,
    repeat_mode, shuffle_mode, volume_capabilities,
};

use super::fake_state::{
    DEFAULT_PLAYER_ID, DEFAULT_PLAYER_NAME, DEVICE_MODEL, DEVICE_NAME, DEVICE_UID, PlayingState,
};

/// `ProtocolMessage.Type`, spelled out once so the builders below read like pyatv's.
type Type = protocol_message::Type;

/// Seconds from the Unix epoch to Apple's `NSDate` epoch.
///
/// pyatv's fake sends `_COCOA_BASE` (`mrp.py:65`), which maps to Unix time zero, and the tests then
/// freeze the clock at zero with `faketime("pyatv", 0)` so the position extrapolation contributes
/// nothing. Freezing the process clock is not available here, so the fixture instead stamps the
/// item with the *current* Cocoa time — the same net effect, and closer to what real hardware
/// sends. See [`cocoa_now`].
pub const COCOA_EPOCH_OFFSET: f64 = 978_307_200.0;

/// Now, in Apple's `NSDate` epoch.
#[must_use]
pub fn cocoa_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0.0, |it| it.as_secs_f64())
        - COCOA_EPOCH_OFFSET
}

/// Build an envelope of `message_type`, optionally correlated to a request.
#[must_use]
pub fn bare(message_type: Type, identifier: Option<&str>) -> MrpMessage {
    let mut message = MrpMessage::bare(envelope(message_type));
    if let Some(identifier) = identifier {
        message
            .set_identifier(identifier)
            .expect("stamping an identifier on a bare envelope must succeed");
    }
    message
}

/// Build a message of `message_type` carrying `inner`, optionally correlated to a request.
fn with<M: pyatv_proto_mrp::protobuf::Message + Default>(
    message_type: Type,
    extension: &extensions::MessageExtension<M>,
    inner: &M,
    identifier: Option<&str>,
) -> MrpMessage {
    let mut message = MrpMessage::with_extension(envelope(message_type), extension, inner)
        .expect("the fixture's own messages must serialise");
    if let Some(identifier) = identifier {
        message
            .set_identifier(identifier)
            .expect("stamping an identifier must succeed");
    }
    message
}

/// `_fill_item` (`mrp.py:84-122`): one `ContentItem` describing what is playing.
#[must_use]
pub fn fill_item(state: &PlayingState) -> ContentItem {
    ContentItem {
        identifier: state.identifier.clone(),
        metadata: Some(ContentItemMetadata {
            elapsed_time_timestamp: Some(cocoa_now()),
            track_artist_name: state.artist.clone(),
            album_name: state.album.clone(),
            title: state.title.clone(),
            genre: state.genre.clone(),
            duration: state.total_time,
            elapsed_time: state.position,
            playback_rate: state.playback_rate,
            media_type: state.media_type.map(|it| it as i32),
            artwork_available: state.artwork_mimetype.as_ref().map(|_| true),
            artwork_mime_type: state.artwork_mimetype.clone(),
            artwork_url: state.artwork_url.clone(),
            artwork_identifier: state.artwork_identifier.clone(),
            series_name: state.series_name.clone(),
            season_number: state.season_number,
            episode_number: state.episode_number,
            content_identifier: state.content_identifier.clone(),
            i_tunes_store_identifier: state.itunes_store_identifier,
            ..ContentItemMetadata::default()
        }),
        ..ContentItem::default()
    }
}

/// The `supportedCommands` list a `SET_STATE_MESSAGE` carries (`mrp.py:133-154`).
///
/// `ChangeRepeatMode` and `ChangeShuffleMode` are appended as *modes*, not as capabilities: the
/// current repeat/shuffle setting has no field of its own and is read back off these entries.
fn supported_commands(state: &PlayingState) -> SupportedCommands {
    let mut commands: Vec<CommandInfo> = state
        .supported_commands
        .iter()
        .map(|command| CommandInfo {
            command: Some(*command as i32),
            enabled: Some(true),
            preferred_intervals: match (command, state.skip_time) {
                (Command::SkipForward | Command::SkipBackward, Some(interval)) => vec![interval],
                _ => Vec::new(),
            },
            ..CommandInfo::default()
        })
        .collect();

    if let Some(repeat) = state.repeat {
        commands.push(CommandInfo {
            command: Some(Command::ChangeRepeatMode as i32),
            repeat_mode: Some(repeat_mode_of(repeat) as i32),
            ..CommandInfo::default()
        });
    }
    if let Some(shuffle) = state.shuffle {
        commands.push(CommandInfo {
            command: Some(Command::ChangeShuffleMode as i32),
            shuffle_mode: Some(shuffle_mode_of(shuffle) as i32),
            ..CommandInfo::default()
        });
    }

    SupportedCommands {
        supported_commands: commands,
    }
}

/// `_REPEAT_LOOKUP` (`mrp.py:53-57`).
#[must_use]
pub const fn repeat_mode_of(state: RepeatState) -> repeat_mode::Enum {
    match state {
        RepeatState::Off => repeat_mode::Enum::Off,
        RepeatState::Track => repeat_mode::Enum::One,
        RepeatState::All => repeat_mode::Enum::All,
    }
}

/// The inverse of [`repeat_mode_of`] (`mrp.py:557-561`).
#[must_use]
pub fn repeat_state_of(mode: Option<i32>) -> RepeatState {
    match mode {
        Some(value) if value == repeat_mode::Enum::One as i32 => RepeatState::Track,
        Some(value) if value == repeat_mode::Enum::All as i32 => RepeatState::All,
        _ => RepeatState::Off,
    }
}

/// `_SHUFFLE_LOOKUP` (`mrp.py:59-63`).
#[must_use]
pub const fn shuffle_mode_of(state: ShuffleState) -> shuffle_mode::Enum {
    match state {
        ShuffleState::Off => shuffle_mode::Enum::Off,
        ShuffleState::Albums => shuffle_mode::Enum::Albums,
        ShuffleState::Songs => shuffle_mode::Enum::Songs,
    }
}

/// The inverse of [`shuffle_mode_of`] (`mrp.py:565-569`).
#[must_use]
pub fn shuffle_state_of(mode: Option<i32>) -> ShuffleState {
    match mode {
        Some(value) if value == shuffle_mode::Enum::Albums as i32 => ShuffleState::Albums,
        Some(value) if value == shuffle_mode::Enum::Songs as i32 => ShuffleState::Songs,
        _ => ShuffleState::Off,
    }
}

/// The player path every message from this fixture carries (`mrp.py:160-168`).
fn player_path(bundle_identifier: &str, app_name: Option<&str>) -> PlayerPath {
    PlayerPath {
        client: Some(NowPlayingClient {
            process_identifier: Some(123),
            bundle_identifier: Some(bundle_identifier.to_owned()),
            display_name: app_name.map(str::to_owned),
            ..NowPlayingClient::default()
        }),
        player: Some(NowPlayingPlayer {
            identifier: Some(DEFAULT_PLAYER_ID.to_owned()),
            display_name: Some(DEFAULT_PLAYER_NAME.to_owned()),
            ..NowPlayingPlayer::default()
        }),
        ..PlayerPath::default()
    }
}

/// `_set_state_message` (`mrp.py:125-169`).
#[must_use]
pub fn set_state(state: &PlayingState, bundle_identifier: &str) -> MrpMessage {
    with(
        Type::SetStateMessage,
        &extensions::SET_STATE_MESSAGE,
        &SetStateMessage {
            playback_state: state.playback_state.map(|it| it as i32),
            display_name: Some("Fake Player".to_owned()),
            supported_commands: Some(supported_commands(state)),
            playback_queue: Some(PlaybackQueue {
                location: Some(0),
                content_items: vec![fill_item(state)],
                ..PlaybackQueue::default()
            }),
            player_path: Some(player_path(bundle_identifier, state.app_name.as_deref())),
            ..SetStateMessage::default()
        },
        None,
    )
}

/// `FakeMrpState.item_update` (`mrp.py:254-273`).
#[must_use]
pub fn item_update(change: &PlayingState, bundle_identifier: &str) -> MrpMessage {
    with(
        Type::UpdateContentItemMessage,
        &extensions::UPDATE_CONTENT_ITEM_MESSAGE,
        &UpdateContentItemMessage {
            content_items: vec![fill_item(change)],
            player_path: Some(player_path(bundle_identifier, None)),
        },
        None,
    )
}

/// `FakeMrpState.set_active_player` (`mrp.py:243-252`); `None` means nothing is playing.
#[must_use]
pub fn set_now_playing_client(bundle_identifier: Option<&str>) -> MrpMessage {
    with(
        Type::SetNowPlayingClientMessage,
        &extensions::SET_NOW_PLAYING_CLIENT_MESSAGE,
        &SetNowPlayingClientMessage {
            client: Some(NowPlayingClient {
                bundle_identifier: bundle_identifier.map(str::to_owned),
                ..NowPlayingClient::default()
            }),
        },
        None,
    )
}

/// `FakeMrpState.update_client` (`mrp.py:275-281`).
#[must_use]
pub fn update_client(display_name: Option<&str>, bundle_identifier: &str) -> MrpMessage {
    with(
        Type::UpdateClientMessage,
        &extensions::UPDATE_CLIENT_MESSAGE,
        &UpdateClientMessage {
            client: Some(NowPlayingClient {
                bundle_identifier: Some(bundle_identifier.to_owned()),
                display_name: display_name.map(str::to_owned),
                ..NowPlayingClient::default()
            }),
        },
        None,
    )
}

/// The availability half of `FakeMrpState.volume_control` (`mrp.py:297-300`).
#[must_use]
pub fn volume_availability(
    available: bool,
    capabilities: Option<volume_capabilities::Enum>,
) -> MrpMessage {
    with(
        Type::VolumeControlAvailabilityMessage,
        &extensions::VOLUME_CONTROL_AVAILABILITY_MESSAGE,
        &VolumeControlAvailabilityMessage {
            volume_control_available: Some(available),
            volume_capabilities: capabilities.map(|it| it as i32),
        },
        None,
    )
}

/// The capabilities half of `FakeMrpState.volume_control` (`mrp.py:302-307`).
#[must_use]
pub fn volume_capabilities_changed(
    available: bool,
    capabilities: Option<volume_capabilities::Enum>,
) -> MrpMessage {
    with(
        Type::VolumeControlCapabilitiesDidChangeMessage,
        &extensions::VOLUME_CONTROL_CAPABILITIES_DID_CHANGE_MESSAGE,
        &VolumeControlCapabilitiesDidChangeMessage {
            capabilities: Some(VolumeControlAvailabilityMessage {
                volume_control_available: Some(available),
                volume_capabilities: capabilities.map(|it| it as i32),
            }),
            output_device_uid: Some(DEVICE_UID.to_owned()),
            ..VolumeControlCapabilitiesDidChangeMessage::default()
        },
        None,
    )
}

/// `FakeMrpState.set_volume` (`mrp.py:323-333`); the level travels as a 0..1 float.
#[must_use]
pub fn volume_did_change(volume: f32, device_uid: &str) -> MrpMessage {
    with(
        Type::VolumeDidChangeMessage,
        &extensions::VOLUME_DID_CHANGE_MESSAGE,
        &VolumeDidChangeMessage {
            volume: Some(volume),
            output_device_uid: Some(device_uid.to_owned()),
            ..VolumeDidChangeMessage::default()
        },
        None,
    )
}

/// `FakeMrpState.default_supported_commands` (`mrp.py:309-321`).
#[must_use]
pub fn default_supported_commands(commands: &[Command], bundle_identifier: &str) -> MrpMessage {
    with(
        Type::SetDefaultSupportedCommandsMessage,
        &extensions::SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE,
        &SetDefaultSupportedCommandsMessage {
            supported_commands: Some(SupportedCommands {
                supported_commands: commands
                    .iter()
                    .map(|command| CommandInfo {
                        command: Some(*command as i32),
                        enabled: Some(true),
                        ..CommandInfo::default()
                    })
                    .collect(),
            }),
            player_path: Some(PlayerPath {
                client: Some(NowPlayingClient {
                    bundle_identifier: Some(bundle_identifier.to_owned()),
                    ..NowPlayingClient::default()
                }),
                ..PlayerPath::default()
            }),
            ..SetDefaultSupportedCommandsMessage::default()
        },
        None,
    )
}

/// `FakeMrpService._send_device_info` (`mrp.py:419-442`).
///
/// `logicalDeviceCount` is the power signal: `1` when the device is on, `0` when it is off.
#[must_use]
pub fn device_info(
    powered_on: bool,
    cluster_id: Option<&str>,
    output_devices: &[String],
    identifier: Option<&str>,
    update: bool,
) -> MrpMessage {
    let message_type = if update {
        Type::DeviceInfoUpdateMessage
    } else {
        Type::DeviceInfoMessage
    };

    let inner = DeviceInfoMessage {
        unique_identifier: Some(DEVICE_UID.to_owned()),
        name: DEVICE_NAME.to_owned(),
        system_build_version: Some(super::fake_state::BUILD_NUMBER.to_owned()),
        logical_device_count: Some(u32::from(powered_on)),
        device_uid: Some(DEVICE_UID.to_owned()),
        cluster_id: cluster_id.map(str::to_owned),
        model_id: Some(DEVICE_MODEL.to_owned()),
        is_group_leader: Some(!output_devices.is_empty()),
        is_proxy_group_player: Some(
            !output_devices.is_empty() && !output_devices.iter().any(|it| it == DEVICE_UID),
        ),
        grouped_devices: output_devices
            .iter()
            .filter(|device| *device != DEVICE_UID)
            .map(|device| DeviceInfoMessage {
                name: format!("Device {}", &device[..2.min(device.len())]),
                device_uid: Some(device.clone()),
                ..DeviceInfoMessage::default()
            })
            .collect(),
        ..DeviceInfoMessage::default()
    };

    with(
        message_type,
        &extensions::DEVICE_INFO_MESSAGE,
        &inner,
        identifier,
    )
}

/// `messages.command_result` (`pyatv/protocols/mrp/messages.py:189-199`), the device's half.
#[must_use]
pub fn command_result(identifier: &str, send_error: Option<i32>) -> MrpMessage {
    with(
        Type::SendCommandResultMessage,
        &extensions::SEND_COMMAND_RESULT_MESSAGE,
        &SendCommandResultMessage {
            send_error,
            ..SendCommandResultMessage::default()
        },
        Some(identifier),
    )
}

/// The `KEYBOARD_MESSAGE` answer to `GET_KEYBOARD_SESSION_MESSAGE` (`mrp.py:489-494`).
#[must_use]
pub fn keyboard(identifier: &str) -> MrpMessage {
    with(
        Type::KeyboardMessage,
        &extensions::KEYBOARD_MESSAGE,
        &KeyboardMessage::default(),
        Some(identifier),
    )
}

/// The artwork answer to `PLAYBACK_QUEUE_REQUEST_MESSAGE` (`mrp.py:598-613`).
///
/// Artwork rides back in a `SET_STATE_MESSAGE`; there is no artwork-specific response type.
#[must_use]
pub fn artwork(identifier: &str, state: &PlayingState) -> MrpMessage {
    let queue = state.artwork.as_ref().map(|data| PlaybackQueue {
        location: Some(0),
        content_items: vec![ContentItem {
            artwork_data: Some(data.clone()),
            artwork_data_width: Some(state.artwork_width.unwrap_or(456)),
            artwork_data_height: Some(state.artwork_height.unwrap_or(789)),
            ..ContentItem::default()
        }],
        ..PlaybackQueue::default()
    });

    with(
        Type::SetStateMessage,
        &extensions::SET_STATE_MESSAGE,
        &SetStateMessage {
            playback_queue: queue,
            ..SetStateMessage::default()
        },
        Some(identifier),
    )
}

/// Whether a state counts as "playing" for the fixture's own bookkeeping.
#[must_use]
pub fn is_playing(state: &PlayingState) -> bool {
    state.playback_state == Some(playback_state::Enum::Playing)
}

/// `ContentItemMetadata.MediaType.Video`, spelled out for the use-case helpers.
pub const VIDEO: content_item_metadata::MediaType = content_item_metadata::MediaType::Video;
/// `ContentItemMetadata.MediaType.Audio`.
pub const MUSIC: content_item_metadata::MediaType = content_item_metadata::MediaType::Audio;
