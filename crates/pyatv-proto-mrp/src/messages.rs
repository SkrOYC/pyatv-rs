//! Every outbound message factory, ported field-for-field from `pyatv/protocols/mrp/messages.py`.
//!
//! The literals here are load-bearing: `docs/research/airplay-control-mrp-tunnel-port-spec.md` §9
//! reproduces the upstream source verbatim precisely because a device rejects a `DeviceInfoMessage`
//! that is missing a field, and the HID event payload is an opaque blob pyatv's own author never
//! decoded. Nothing in this module is a simplification of upstream; where a value looks arbitrary,
//! it is arbitrary upstream too.
//!
//! Each factory returns a [`MrpMessage`], i.e. the envelope *and* the extension payload — see that
//! type's documentation for why the two cannot be separated in a `prost` port.

use pyatv_core::consts::{RepeatState, ShuffleState};
use pyatv_core::storage::InfoSettings;
use uuid::Uuid;

use crate::hid;
use crate::message::MrpMessage;
use crate::protobuf::{
    ClientUpdatesConfigMessage, Command, CommandOptions, CryptoPairingMessage, DeviceInfoMessage,
    ModifyOutputContextRequestMessage, PlaybackQueueRequestMessage, ProtocolMessage,
    SendCommandMessage, SendHidEventMessage, SetConnectionStateMessage, SetVolumeMessage,
    device_class, extensions, modify_output_context_request_type, protocol_message::Type,
    repeat_mode, set_connection_state_message, shuffle_mode,
};
use crate::{Error, Result};

/// The bundle identifier pyatv impersonates (`messages.py:32`).
pub const APPLICATION_BUNDLE_IDENTIFIER: &str = "com.apple.TVRemote";
/// The bundle version pyatv impersonates (`messages.py:33`).
pub const APPLICATION_BUNDLE_VERSION: &str = "344.28";
/// The highest `ProtocolMessage.Type` pyatv claims to understand (`messages.py:34`).
pub const LAST_SUPPORTED_MESSAGE_TYPE: u32 = 108;
/// The model name pyatv impersonates; it always claims to be an iPhone (`messages.py:35`).
pub const LOCALIZED_MODEL_NAME: &str = "iPhone";
/// The media application pyatv claims to run (`messages.py:42`).
pub const SYSTEM_MEDIA_APPLICATION: &str = "com.apple.TVMusic";
/// The default skip interval when neither the caller nor the device names one
/// (`_DEFAULT_SKIP_TIME`, `pyatv/protocols/mrp/__init__.py:75`).
pub const DEFAULT_SKIP_TIME: f32 = 15.0;

/// Build a bare envelope: `type`, `errorCode` and a fresh `uniqueIdentifier`.
///
/// `messages.create` (`messages.py:13-21`). **Every** outbound message gets a fresh uppercase
/// UUID4 in `uniqueIdentifier` (field 85) — not to be confused with `identifier` (field 2), the
/// correlation key [`MrpMessage::set_identifier`] stamps later.
#[must_use]
pub fn envelope(message_type: Type) -> ProtocolMessage {
    ProtocolMessage {
        r#type: Some(message_type as i32),
        error_code: Some(0),
        unique_identifier: Some(Uuid::new_v4().to_string().to_uppercase()),
        ..ProtocolMessage::default()
    }
}

/// A message with only an envelope, no extension payload.
///
/// `messages.create(...)` used directly, as for `GENERIC_MESSAGE` heartbeats
/// (`protocol.py:202`) and `GET_KEYBOARD_SESSION_MESSAGE` (`messages.py:62-65`).
#[must_use]
pub fn create(message_type: Type) -> MrpMessage {
    MrpMessage::bare(envelope(message_type))
}

/// `DEVICE_INFO_MESSAGE`, or `DEVICE_INFO_UPDATE_MESSAGE` when `update` is set.
///
/// `messages.device_information` (`messages.py:24-48`). All fifteen fields are set, verbatim;
/// `identifier` is the *pairing* identifier and lands in `DeviceInfoMessage.uniqueIdentifier`
/// (field 1), a different field from the envelope's.
///
/// # Errors
///
/// Returns [`Error::WireFormat`] if the envelope cannot be re-scanned; see [`MrpMessage`].
pub fn device_information(
    info: &InfoSettings,
    identifier: &str,
    update: bool,
) -> Result<MrpMessage> {
    let message_type = if update {
        Type::DeviceInfoUpdateMessage
    } else {
        Type::DeviceInfoMessage
    };

    let inner = DeviceInfoMessage {
        unique_identifier: Some(identifier.to_owned()),
        name: info.name.clone(),
        localized_model_name: Some(LOCALIZED_MODEL_NAME.to_owned()),
        system_build_version: Some(info.os_build.clone()),
        application_bundle_identifier: Some(APPLICATION_BUNDLE_IDENTIFIER.to_owned()),
        application_bundle_version: Some(APPLICATION_BUNDLE_VERSION.to_owned()),
        protocol_version: Some(1),
        last_supported_message_type: Some(LAST_SUPPORTED_MESSAGE_TYPE),
        supports_system_pairing: Some(true),
        allows_pairing: Some(true),
        system_media_application: Some(SYSTEM_MEDIA_APPLICATION.to_owned()),
        supports_acl: Some(true),
        supports_shared_queue: Some(true),
        supports_extended_motion: Some(true),
        shared_queue_version: Some(2),
        device_class: Some(device_class::Enum::IPhone as i32),
        logical_device_count: Some(1),
        ..DeviceInfoMessage::default()
    };

    MrpMessage::with_extension(
        envelope(message_type),
        &extensions::DEVICE_INFO_MESSAGE,
        &inner,
    )
}

/// `WAKE_DEVICE_MESSAGE`, the only message `Power::turn_on` sends (`messages.py:51-53`).
///
/// It is **not** part of the connection bring-up sequence, contrary to a common misreading; its
/// sole caller upstream is `MrpPower.turn_on` (`__init__.py:659`).
///
/// `wake_device()` is a plain `create(WAKE_DEVICE_MESSAGE)`: the `wakeDeviceMessage` extension is
/// never touched, so nothing is emitted for field 45 and the envelope goes out bare. Setting an
/// empty `WakeDeviceMessage` instead would add three bytes pyatv never sends.
#[must_use]
pub fn wake_device() -> MrpMessage {
    create(Type::WakeDeviceMessage)
}

/// `SET_CONNECTION_STATE_MESSAGE` with `state = Connected` (`messages.py:56-60`).
///
/// pyatv jumps straight to `Connected`; it never sends `Connecting`.
///
/// # Errors
///
/// As [`device_information`].
pub fn set_connection_state() -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::SetConnectionStateMessage),
        &extensions::SET_CONNECTION_STATE_MESSAGE,
        &SetConnectionStateMessage {
            state: Some(set_connection_state_message::ConnectionState::Connected as i32),
        },
    )
}

/// `GET_KEYBOARD_SESSION_MESSAGE`, an envelope with no payload at all (`messages.py:63-65`).
///
/// Subscribing does not give MRP a keyboard: no MRP code path anywhere upstream produces a
/// `TEXT_INPUT_MESSAGE`. Text entry is Companion's job
/// (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §14).
#[must_use]
pub fn get_keyboard_session() -> MrpMessage {
    create(Type::GetKeyboardSessionMessage)
}

/// `CRYPTO_PAIRING_MESSAGE` carrying an already-encoded HAP TLV8 blob.
///
/// `messages.crypto_pairing` (`messages.py:68-79`). `state` is `2` only for pair-setup's very
/// first message and `0` for everything else including all of pair-verify; `isRetrying` and
/// `isUsingSystemPairing` are hardcoded `false` upstream, with a comment conceding the semantics
/// are not understood.
///
/// Unlike upstream this takes pre-encoded TLV8 rather than a tag→value map, because
/// [`pyatv_pairing`] hands the pairing state machines' output over as bytes already.
///
/// # Errors
///
/// As [`device_information`].
pub fn crypto_pairing(pairing_data: &[u8], is_pairing: bool) -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::CryptoPairingMessage),
        &extensions::CRYPTO_PAIRING_MESSAGE,
        &CryptoPairingMessage {
            pairing_data: Some(pairing_data.to_vec()),
            status: Some(0),
            is_retrying: Some(false),
            is_using_system_pairing: Some(false),
            state: Some(i32::from(is_pairing) * 2),
        },
    )
}

/// `CLIENT_UPDATES_CONFIG_MESSAGE` with pyatv's defaults (`messages.py:82-97`).
///
/// Artwork, volume, keyboard and output-device pushes on; now-playing pushes **off**, because
/// now-playing state arrives as `SET_STATE_MESSAGE` regardless. `MrpProtocol.start()` calls this
/// with no arguments, so these defaults are what actually goes on the wire (`protocol.py:164`).
///
/// # Errors
///
/// As [`device_information`].
pub fn client_updates_config() -> Result<MrpMessage> {
    client_updates_config_with(ClientUpdatesConfigMessage {
        artwork_updates: Some(true),
        now_playing_updates: Some(false),
        volume_updates: Some(true),
        keyboard_updates: Some(true),
        output_device_updates: Some(true),
    })
}

/// `CLIENT_UPDATES_CONFIG_MESSAGE` with an explicit subscription set.
///
/// # Errors
///
/// As [`device_information`].
pub fn client_updates_config_with(config: ClientUpdatesConfigMessage) -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::ClientUpdatesConfigMessage),
        &extensions::CLIENT_UPDATES_CONFIG_MESSAGE,
        &config,
    )
}

/// `PLAYBACK_QUEUE_REQUEST_MESSAGE`, which is also how artwork is fetched.
///
/// `messages.playback_queue_request` (`messages.py:100-109`). There is no separate artwork-fetch
/// message type: `_fetch_local_artwork` re-issues this with width/height and reads `artworkData`
/// off the returned content item (`__init__.py:583-598`).
///
/// # Errors
///
/// As [`device_information`].
pub fn playback_queue_request(location: i32, width: f64, height: f64) -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::PlaybackQueueRequestMessage),
        &extensions::PLAYBACK_QUEUE_REQUEST_MESSAGE,
        &PlaybackQueueRequestMessage {
            location: Some(location),
            length: Some(1),
            artwork_width: Some(width),
            artwork_height: Some(height),
            return_content_item_assets_in_user_completion: Some(true),
            ..PlaybackQueueRequestMessage::default()
        },
    )
}

/// `SEND_HID_EVENT_MESSAGE` for one press or release of a USB HID usage.
///
/// `messages.send_hid_event` (`messages.py:112-138`); the 60-byte payload layout is
/// [`hid::event_data`].
///
/// # Errors
///
/// As [`device_information`].
pub fn send_hid_event(usage_page: u16, usage: u16, down: bool) -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::SendHidEventMessage),
        &extensions::SEND_HID_EVENT_MESSAGE,
        &SendHidEventMessage {
            hid_event_data: Some(hid::event_data(usage_page, usage, down).to_vec()),
        },
    )
}

/// `SEND_COMMAND_MESSAGE` with no options.
///
/// `messages.command(cmd)` (`messages.py:151-158`). `playerPath` is never set, so the device
/// applies the command to whatever it considers the active player.
///
/// # Errors
///
/// As [`device_information`].
pub fn command(cmd: Command) -> Result<MrpMessage> {
    command_with(cmd, None)
}

/// `SEND_COMMAND_MESSAGE` with an explicit [`CommandOptions`].
///
/// # Errors
///
/// As [`device_information`].
pub fn command_with(cmd: Command, options: Option<CommandOptions>) -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::SendCommandMessage),
        &extensions::SEND_COMMAND_MESSAGE,
        &SendCommandMessage {
            command: Some(cmd as i32),
            options,
            player_path: None,
        },
    )
}

/// `SEND_COMMAND_MESSAGE` for `SkipForward`/`SkipBackward` with an interval.
///
/// `_skip_command` (`__init__.py:455-467`) resolves the interval before calling; this just carries
/// it in `options.skipInterval`.
///
/// # Errors
///
/// As [`device_information`].
pub fn skip_command(cmd: Command, interval: f32) -> Result<MrpMessage> {
    command_with(
        cmd,
        Some(CommandOptions {
            skip_interval: Some(interval),
            ..CommandOptions::default()
        }),
    )
}

/// `SEND_COMMAND_MESSAGE` for `ChangeRepeatMode` (`messages.py:170-182`).
///
/// `options.sendOptions` is zeroed first — an undocumented flags field pyatv always sets to `0`
/// on both this and [`shuffle`], and never sets anywhere else.
///
/// # Errors
///
/// As [`device_information`].
pub fn repeat(mode: RepeatState) -> Result<MrpMessage> {
    let repeat_mode = match mode {
        RepeatState::Off => repeat_mode::Enum::Off,
        RepeatState::Track => repeat_mode::Enum::One,
        RepeatState::All => repeat_mode::Enum::All,
    };

    command_with(
        Command::ChangeRepeatMode,
        Some(CommandOptions {
            send_options: Some(0),
            repeat_mode: Some(repeat_mode as i32),
            ..CommandOptions::default()
        }),
    )
}

/// `SEND_COMMAND_MESSAGE` for `ChangeShuffleMode` (`messages.py:185-195`).
///
/// # Errors
///
/// As [`device_information`].
pub fn shuffle(state: ShuffleState) -> Result<MrpMessage> {
    let shuffle_mode = match state {
        ShuffleState::Off => shuffle_mode::Enum::Off,
        ShuffleState::Albums => shuffle_mode::Enum::Albums,
        ShuffleState::Songs => shuffle_mode::Enum::Songs,
    };

    command_with(
        Command::ChangeShuffleMode,
        Some(CommandOptions {
            send_options: Some(0),
            shuffle_mode: Some(shuffle_mode as i32),
            ..CommandOptions::default()
        }),
    )
}

/// `SEND_COMMAND_MESSAGE` for `SeekToPlaybackPosition` (`messages.py:198-203`).
///
/// Unlike [`repeat`] and [`shuffle`] this does **not** zero `sendOptions`.
///
/// # Errors
///
/// As [`device_information`].
pub fn seek_to_position(position: f64) -> Result<MrpMessage> {
    command_with(
        Command::SeekToPlaybackPosition,
        Some(CommandOptions {
            playback_position: Some(position),
            ..CommandOptions::default()
        }),
    )
}

/// `SET_VOLUME_MESSAGE` (`messages.py:206-212`).
///
/// `volume` is a `0.0..=1.0` fraction; the facade divides the caller's `0..=100` percentage by
/// 100 before getting here (`__init__.py:875-883`). There is no response to this message — the
/// only confirmation is the next `VOLUME_DID_CHANGE_MESSAGE` push.
///
/// # Errors
///
/// As [`device_information`].
pub fn set_volume(device_uid: &str, volume: f32) -> Result<MrpMessage> {
    MrpMessage::with_extension(
        envelope(Type::SetVolumeMessage),
        &extensions::SET_VOLUME_MESSAGE,
        &SetVolumeMessage {
            volume: Some(volume),
            output_device_uid: Some(device_uid.to_owned()),
        },
    )
}

/// Which of the three parallel field pairs a `MODIFY_OUTPUT_CONTEXT_REQUEST_MESSAGE` fills in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputDeviceChange {
    /// `addingDevices` + `clusterAwareAddingDevices` (`messages.py:215-223`).
    Add,
    /// `removingDevices` + `clusterAwareRemovingDevices` (`messages.py:226-234`).
    Remove,
    /// `settingDevices` + `clusterAwareSettingDevices` (`messages.py:237-245`).
    Set,
}

/// `MODIFY_OUTPUT_CONTEXT_REQUEST_MESSAGE` for one speaker-group change.
///
/// Each operation populates **two** parallel repeated fields with the same identifiers — the
/// plain one and its `clusterAware` twin. Writing only one leaves the device partially applying
/// the change (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §9.10).
///
/// # Errors
///
/// As [`device_information`].
pub fn modify_output_context(
    change: OutputDeviceChange,
    device_uids: &[String],
) -> Result<MrpMessage> {
    let uids = device_uids.to_vec();
    let mut inner = ModifyOutputContextRequestMessage {
        r#type: Some(modify_output_context_request_type::Enum::SharedAudioPresentation as i32),
        ..ModifyOutputContextRequestMessage::default()
    };

    match change {
        OutputDeviceChange::Add => {
            inner.adding_devices.clone_from(&uids);
            inner.cluster_aware_adding_devices = uids;
        }
        OutputDeviceChange::Remove => {
            inner.removing_devices.clone_from(&uids);
            inner.cluster_aware_removing_devices = uids;
        }
        OutputDeviceChange::Set => {
            inner.setting_devices.clone_from(&uids);
            inner.cluster_aware_setting_devices = uids;
        }
    }

    MrpMessage::with_extension(
        envelope(Type::ModifyOutputContextRequestMessage),
        &extensions::MODIFY_OUTPUT_CONTEXT_REQUEST_MESSAGE,
        &inner,
    )
}

/// Map a device's `SendError`/`HandlerReturnStatus` pair onto this crate's error.
///
/// `MrpRemoteControl._send_command`'s failure branch (`__init__.py:347-354`), which bakes both
/// enum *names* into the message. Both enums are sparse, so an unknown value is rendered
/// numerically rather than being coerced to a neighbouring variant.
#[must_use]
pub fn command_error(cmd: Command, send_error: i32, handler_status: i32) -> Error {
    use crate::protobuf::{handler_return_status, send_error as send_error_enum};

    let send = send_error_enum::Enum::try_from(send_error)
        .map_or_else(|_| send_error.to_string(), |it| it.as_str_name().to_owned());
    let handler = handler_return_status::Enum::try_from(handler_status).map_or_else(
        |_| handler_status.to_string(),
        |it| it.as_str_name().to_owned(),
    );

    Error::Command(format!(
        "{} failed: SendError={send}, HandlerReturnStatus={handler}",
        cmd.as_str_name()
    ))
}

#[cfg(test)]
mod tests;
