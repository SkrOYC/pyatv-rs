//! Known-answer tests for the proto2 extension layer, against pyatv's own protobuf runtime.
//!
//! Each vector in `kat/mrp_extension_kat.json` is a `ProtocolMessage` that pyatv serialised, most
//! of them through pyatv's own `pyatv/protocols/mrp/messages.py` helpers. For every one the test
//! does the full round trip that the MRP transport will do at Step 4:
//!
//! 1. decode the envelope with `prost`, which sees the seven declared fields and drops everything
//!    else — including the extension;
//! 2. pull the extension payload off the same bytes with the extractor and decode it as its own
//!    message type;
//! 3. re-encode envelope plus payload and compare with the original buffer **byte for byte**.
//!
//! Step 3 is the strong claim: it says this crate emits exactly the bytes the reference
//! implementation emits, field order included, so a device cannot tell the two apart.

mod kat;

use kat::Vector;
use pyatv_proto_mrp::protobuf::{
    CryptoPairingMessage, DeviceInfoMessage, Message, ProtocolMessage, RegisterHidDeviceMessage,
    SendCommandMessage, SetStateMessage, extensions, extensions::MessageExtension,
};

/// Decode the envelope's declared fields, checking them against the vector.
fn envelope(vector: &Vector) -> ProtocolMessage {
    let message = ProtocolMessage::decode(vector.protocol_message.as_slice())
        .unwrap_or_else(|error| panic!("{}: envelope did not decode: {error}", vector.name));

    assert_eq!(
        message.r#type,
        Some(vector.message_type),
        "{}: wrong type ({})",
        vector.name,
        vector.type_name
    );
    assert_eq!(
        message.unique_identifier.as_deref(),
        Some(vector.unique_identifier.as_str()),
        "{}: wrong uniqueIdentifier",
        vector.name
    );

    message
}

/// Extract, decode and re-encode one message-typed extension.
///
/// Returns the decoded payload so the caller can assert on its fields.
fn round_trip<M>(vector: &Vector, extension: &MessageExtension<M>) -> M
where
    M: Message + Default,
{
    assert_eq!(
        Some(extension.name().to_owned()),
        vector.extension_name,
        "{}: wrong extension handle",
        vector.name
    );
    assert_eq!(
        Some(extension.number()),
        vector.extension_number,
        "{}: {} has the wrong field number",
        vector.name,
        extension.name()
    );
    assert_eq!(
        extensions::number_for_type(vector.message_type),
        vector.extension_number,
        "{}: type {} does not map to its extension ({})",
        vector.name,
        vector.type_name,
        vector.note
    );

    let raw = extensions::raw_for_type(&vector.protocol_message, vector.message_type)
        .unwrap_or_else(|error| panic!("{}: extraction failed: {error}", vector.name))
        .unwrap_or_else(|| panic!("{}: extension field is absent", vector.name));
    assert_eq!(
        Some(raw.to_vec()),
        vector.inner,
        "{}: extracted payload differs from pyatv's",
        vector.name
    );

    let payload = extension
        .decode(&vector.protocol_message)
        .unwrap_or_else(|error| panic!("{}: payload did not decode: {error}", vector.name))
        .unwrap_or_else(|| panic!("{}: payload is absent", vector.name));

    let reencoded = extension
        .encode(&envelope(vector), &payload)
        .unwrap_or_else(|error| panic!("{}: re-encode failed: {error}", vector.name));
    assert_eq!(
        hex::encode(&reencoded),
        hex::encode(&vector.protocol_message),
        "{}: re-encoded bytes differ from pyatv's",
        vector.name
    );

    payload
}

/// Find one vector by name; a rename in the generator must fail the test, not skip it.
fn vector(name: &str) -> Vector {
    kat::load()
        .into_iter()
        .find(|vector| vector.name == name)
        .unwrap_or_else(|| panic!("no vector named `{name}`"))
}

/// Every vector round-trips, whatever it is. The per-message tests below then check the fields.
#[test]
fn every_vector_round_trips_byte_for_byte() {
    let vectors = kat::load();
    assert_eq!(
        vectors.len(),
        26,
        "vector count changed; review the new ones"
    );

    for vector in &vectors {
        let message = envelope(vector);
        assert_eq!(
            message.error_code,
            Some(0),
            "{}: unexpected errorCode",
            vector.name
        );

        let Some(number) = vector.extension_number else {
            // A bare envelope: `get_keyboard_session()` and the `GENERIC_MESSAGE` heartbeat carry
            // no payload, so there is nothing to extract.
            assert!(
                extensions::raw_for_type(&vector.protocol_message, vector.message_type)
                    .is_ok_and(|payload| payload.is_none()),
                "{}: a bare envelope must have no extension payload",
                vector.name
            );
            continue;
        };
        assert_eq!(
            extensions::number_for_type(vector.message_type),
            Some(number),
            "{}: {}",
            vector.name,
            vector.note
        );

        let raw = extensions::raw_for_type(&vector.protocol_message, vector.message_type)
            .unwrap_or_else(|error| panic!("{}: extraction failed: {error}", vector.name))
            .unwrap_or_else(|| panic!("{}: extension field is absent", vector.name));

        let payload = vector
            .inner
            .clone()
            .or_else(|| vector.inner_string.clone().map(String::into_bytes))
            .unwrap_or_else(|| panic!("{}: vector carries no payload", vector.name));
        assert_eq!(raw, payload.as_slice(), "{}: wrong payload", vector.name);
    }
}

/// `prost` alone cannot see the extension: this is the gap the extractor exists to close.
#[test]
fn prost_drops_the_extension_field() {
    let vector = vector("send_command_play");
    let message = envelope(&vector);

    // Round-tripping through prost alone silently loses 4 bytes of payload.
    assert!(message.encode_to_vec().len() < vector.protocol_message.len());
    assert_eq!(
        hex::encode(message.encode_to_vec()),
        "08012000aa052431313131313131312d323232322d343333332d383434342d353535353535353535353030"
    );
}

#[test]
fn send_command_message() {
    let vector = vector("send_command_play");
    let payload: SendCommandMessage = round_trip(&vector, &extensions::SEND_COMMAND_MESSAGE);

    assert_eq!(payload.command, Some(1)); // CommandInfo.Command.Play
    assert!(payload.options.is_none());
}

/// The same extension carrying a nested submessage, to prove the payload is handed to `prost`
/// whole rather than re-parsed field by field.
#[test]
fn send_command_message_with_options() {
    let vector = vector("send_command_seek");
    let payload: SendCommandMessage = round_trip(&vector, &extensions::SEND_COMMAND_MESSAGE);

    assert_eq!(payload.command, Some(45)); // SeekToPlaybackPosition
    assert_eq!(
        payload
            .options
            .as_ref()
            .and_then(|options| options.playback_position),
        Some(90.0)
    );
}

#[test]
fn set_state_message() {
    let vector = vector("set_state");
    let payload: SetStateMessage = round_trip(&vector, &extensions::SET_STATE_MESSAGE);

    assert_eq!(payload.display_name.as_deref(), Some("Music"));
    assert_eq!(payload.playback_state, Some(1)); // PlaybackState.Playing
    assert_eq!(payload.playback_state_timestamp, Some(1234.5));

    let now_playing = payload.now_playing_info.expect("nowPlayingInfo is missing");
    assert_eq!(
        now_playing.title.as_deref(),
        Some("Never Gonna Give You Up")
    );
    assert_eq!(now_playing.artist.as_deref(), Some("Rick Astley"));
    assert_eq!(now_playing.duration, Some(213.0));

    let player_path = payload.player_path.expect("playerPath is missing");
    assert_eq!(
        player_path
            .client
            .and_then(|client| client.bundle_identifier),
        Some("com.apple.TVMusic".to_owned())
    );
}

/// The first message on every direct MRP socket; the device refuses anything else.
#[test]
fn device_info_message() {
    let vector = vector("device_info");
    let payload: DeviceInfoMessage = round_trip(&vector, &extensions::DEVICE_INFO_MESSAGE);

    assert_eq!(
        payload.application_bundle_identifier.as_deref(),
        Some("com.apple.TVRemote")
    );
    assert_eq!(
        payload.application_bundle_version.as_deref(),
        Some("344.28")
    );
    assert_eq!(payload.localized_model_name.as_deref(), Some("iPhone"));
    assert_eq!(payload.protocol_version, Some(1));
    assert_eq!(payload.allows_pairing, Some(true));
    assert_eq!(
        payload.unique_identifier.as_deref(),
        Some("89B3D2B7-9D62-4A5C-9E48-2C4F2A0B1D33")
    );
}

/// Two `Type` values, one extension field: the alias pyatv keeps in `REUSED_MESSAGES`.
#[test]
fn device_info_update_reuses_the_device_info_extension() {
    let vector = vector("device_info_update");
    assert_eq!(vector.message_type, 37);
    assert_eq!(vector.extension_number, Some(20));

    let payload: DeviceInfoMessage = round_trip(&vector, &extensions::DEVICE_INFO_MESSAGE);
    assert_eq!(payload.protocol_version, Some(1));
}

#[test]
fn crypto_pairing_message() {
    let vector = vector("crypto_pairing");
    let payload: CryptoPairingMessage = round_trip(&vector, &extensions::CRYPTO_PAIRING_MESSAGE);

    // HAP TLV8: Method(0x00) = 0x00, SeqNo(0x06) = 0x01.
    assert_eq!(
        payload.pairing_data.as_deref(),
        Some(&[0x00, 0x01, 0x00, 0x06, 0x01, 0x01][..])
    );
    assert_eq!(payload.status, Some(0));
    assert_eq!(payload.state, Some(2));
    assert_eq!(payload.is_retrying, Some(false));
}

/// The acronym case: pyatv writes `registerHIDDeviceMessage`, `prost` renames the message type to
/// `RegisterHidDeviceMessage`, and the generated handle has to bridge the two.
#[test]
fn register_hid_device_message() {
    let vector = vector("register_hid_device");
    let payload: RegisterHidDeviceMessage =
        round_trip(&vector, &extensions::REGISTER_HID_DEVICE_MESSAGE);

    assert_eq!(
        extensions::REGISTER_HID_DEVICE_MESSAGE.name(),
        "registerHIDDeviceMessage"
    );

    let descriptor = payload.device_descriptor.expect("deviceDescriptor missing");
    assert_eq!(descriptor.absolute, Some(false));
    assert_eq!(descriptor.screen_size_width, Some(1000.0));
    assert_eq!(descriptor.screen_size_height, Some(1000.0));
}

/// The corpus' only scalar extension takes the other code path.
#[test]
fn string_extension() {
    let vector = vector("get_keyboard_session_string");
    let message = envelope(&vector);

    assert_eq!(extensions::GET_KEYBOARD_SESSION_MESSAGE.number(), 29);
    assert_eq!(
        extensions::GET_KEYBOARD_SESSION_MESSAGE
            .decode(&vector.protocol_message)
            .expect("decode failed"),
        vector.inner_string
    );

    let reencoded = extensions::GET_KEYBOARD_SESSION_MESSAGE
        .encode(
            &message,
            vector.inner_string.as_deref().expect("no string payload"),
        )
        .expect("encode failed");
    assert_eq!(
        hex::encode(reencoded),
        hex::encode(&vector.protocol_message)
    );
}

/// An extension that is simply not present decodes to `None` rather than failing.
#[test]
fn absent_extension_decodes_to_none() {
    let vector = vector("send_command_play");

    assert_eq!(
        extensions::SET_STATE_MESSAGE
            .decode(&vector.protocol_message)
            .expect("decode failed"),
        None
    );
}
