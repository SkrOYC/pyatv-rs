//! Known-answer tests for the AirPlay 2 tunnel's wire format, against vectors generated from pyatv.
//!
//! pyatv has **no** automated coverage of this path at all
//! (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §16.2), so agreeing with a reading of
//! its source is not enough: `tests/kat/gen_airplay_tunnel_kat.py` runs pyatv's own encoders and
//! pins what they produce, and everything below compares against that file rather than against this
//! port's own expectations.
//!
//! The key-derivation vectors come from `crates/pyatv-pairing/tests/kat/hap_srp_kat.json`, which
//! already pins the AirPlay salts and info strings including the event channel's read/write swap
//! and the data channel's seeded salt.

use std::sync::LazyLock;

use pyatv_proto_airplay::ap2::data_stream::{frame, payload};
use pyatv_proto_airplay::ap2::{
    InfoSettings, data_stream::DataStreamRequest, data_stream::data_stream_key_spec,
    event_channel::event_channel_key_spec, remote_control_setup_body,
};
use pyatv_proto_airplay::rtsp::{decode_plist, encode_plist};

/// The vectors generated from pyatv b277a4c.
static KAT: LazyLock<serde_json::Value> = LazyLock::new(|| {
    let raw = include_str!("kat/airplay_tunnel_kat.json");
    serde_json::from_str(raw).expect("the vector file must be valid JSON")
});

/// The HAP pairing vectors, which already carry the AirPlay transport rows.
static PAIRING_KAT: LazyLock<serde_json::Value> = LazyLock::new(|| {
    let raw = include_str!("../../pyatv-pairing/tests/kat/hap_srp_kat.json");
    serde_json::from_str(raw).expect("the pairing vector file must be valid JSON")
});

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16).expect("the vector must be hex")
        })
        .collect()
}

fn vector(path: &[&str]) -> String {
    let mut node = &*KAT;
    for key in path {
        node = node
            .get(key)
            .unwrap_or_else(|| panic!("no vector at {key}"));
    }
    node.as_str().expect("a string vector").to_owned()
}

fn session_uuid() -> String {
    vector(&["session", "session_uuid"])
}

fn info_settings() -> InfoSettings {
    let node = &KAT["info_settings"];
    let field = |name: &str| node[name].as_str().expect("a string field").to_owned();

    InfoSettings {
        name: field("name"),
        mac: field("mac"),
        device_id: field("device_id"),
        model: field("model"),
        os_name: field("os_name"),
        os_build: field("os_build"),
        os_version: field("os_version"),
    }
}

/// The `InfoSettings` defaults this port ships are the ones pyatv would send.
///
/// A device that remembers a controller by `deviceID` or `macAddress` would treat a different value
/// as a different controller, so this is behaviour, not cosmetics.
#[test]
fn the_default_controller_identity_matches_pyatvs() {
    assert_eq!(InfoSettings::default(), info_settings());
}

/// The whole outbound MRP frame, byte for byte against `BaseDataStreamChannel.encode_message`.
///
/// This is the strongest single check in the suite: it covers the 32-byte big-endian header layout,
/// the `sync`/`comm` tags, the zero padding, the `size` arithmetic and the exact payload bytes all
/// at once.
#[test]
fn a_sync_frame_matches_pyatvs_encoder() {
    let seqno = KAT["session"]["seqno"].as_u64().expect("a seqno");
    let message = hex(&vector(&["session", "message"]));

    let envelope = payload::encode_envelope(payload::encode_messages(&[&message]))
        .expect("the envelope must encode");
    let wire = frame::encode_sync(seqno, &envelope);
    let expected = hex(&vector(&["data_frames", "sync"]));

    // The header is compared byte for byte; the payload is compared after decoding, because two
    // conforming `bplist00` writers legally differ in their offset tables.
    assert_eq!(
        &wire[..frame::HEADER_LEN],
        &expected[..frame::HEADER_LEN],
        "the 32-byte header must match pyatv exactly"
    );
    assert_eq!(
        decode_plist(&wire[frame::HEADER_LEN..]).expect("ours decodes"),
        decode_plist(&expected[frame::HEADER_LEN..]).expect("pyatv's decodes")
    );
}

/// An acknowledgement is header-only and carries the incoming seqno, byte for byte.
#[test]
fn a_reply_frame_matches_pyatvs_encoder_byte_for_byte() {
    let seqno = KAT["session"]["seqno"].as_u64().expect("a seqno");

    assert_eq!(
        frame::encode_reply(seqno),
        hex(&vector(&["data_frames", "reply"]))
    );
}

/// pyatv's own frames decode back to the payload it put in them.
#[test]
fn pyatvs_sync_frame_decodes_to_the_message_it_carried() {
    let mut buffer = bytes::BytesMut::from(&hex(&vector(&["data_frames", "sync"]))[..]);

    let decoded = frame::decode(&mut buffer)
        .expect("pyatv's frame must decode")
        .expect("a whole frame");

    assert!(decoded.header.wants_reply());
    assert_eq!(decoded.header.message_type, frame::MESSAGE_TYPE_SYNC);
    assert_eq!(decoded.header.command, frame::COMMAND_COMM);
    assert_eq!(decoded.header.padding, frame::PADDING);
    assert!(buffer.is_empty(), "the frame must be consumed exactly");

    let data = payload::decode_envelope(&decoded.payload).expect("params.data must be there");
    let messages = payload::decode_messages(&data).expect("the messages must split");

    assert_eq!(messages.len(), 1);
    assert_eq!(&messages[0][..], &hex(&vector(&["session", "message"]))[..]);
}

/// Every varint pyatv writes, byte for byte.
#[test]
fn varints_match_pyatvs_write_variant() {
    let variants = KAT["variants"].as_object().expect("a table of variants");

    for (value, expected) in variants {
        let value: u64 = value.parse().expect("a decimal key");
        assert_eq!(
            payload::write_variant(value),
            hex(expected.as_str().expect("a hex string")),
            "write_variant({value})"
        );
    }
}

/// The `{"params": {"data": …}}` envelope decodes to the same structure pyatv's does.
#[test]
fn the_envelope_matches_pyatvs() {
    let message = hex(&vector(&["session", "message"]));

    let ours = payload::encode_envelope(payload::encode_messages(&[&message])).expect("encodes");
    let theirs = hex(&vector(&["plists", "envelope"]));

    assert_eq!(
        decode_plist(&ours).expect("ours decodes"),
        decode_plist(&theirs).expect("pyatv's decodes")
    );
    // And pyatv's own bytes have to survive this port's decoder.
    assert_eq!(
        payload::decode_envelope(&theirs).expect("params.data"),
        payload::encode_messages(&[&message])
    );
}

/// The eleven-key event-channel `SETUP` body, compared against pyatv's dictionary.
#[test]
fn the_event_setup_body_matches_pyatvs() {
    let ours = remote_control_setup_body(&info_settings(), &session_uuid());
    let theirs = decode_plist(&hex(&vector(&["plists", "event_setup_body"]))).expect("decodes");

    assert_eq!(ours, theirs);
    // The encoder this port ships has to produce something pyatv's parser would accept, too.
    assert_eq!(
        decode_plist(&encode_plist(&ours).expect("encodes")).expect("decodes"),
        theirs
    );
}

/// The single-stream data-channel `SETUP` body, compared against pyatv's dictionary.
#[test]
fn the_data_setup_body_matches_pyatvs() {
    let request = DataStreamRequest {
        seed: KAT["session"]["seed"].as_u64().expect("a seed"),
        channel_id: vector(&["session", "channel_id"]),
        client_uuid: vector(&["session", "client_uuid"]),
    };

    let theirs = decode_plist(&hex(&vector(&["plists", "data_setup_body"]))).expect("decodes");

    assert_eq!(request.body(), theirs);
}

/// Look up one channel row in the pairing vectors.
fn transport_row(channel: &str) -> &'static serde_json::Value {
    PAIRING_KAT["transport_keys"]["channels"]
        .as_array()
        .expect("an array of channels")
        .iter()
        .find(|row| row["channel"] == channel)
        .unwrap_or_else(|| panic!("no {channel} row"))
}

/// The event channel's swap, checked against a vector pyatv produced.
///
/// Getting this backwards decrypts garbage in exactly one direction, which is the failure mode the
/// research reports flag hardest.
#[test]
fn the_event_channel_derives_with_the_swapped_info_strings() {
    let row = transport_row("airplay_events");
    let (salt, output_info, input_info) = event_channel_key_spec();

    assert_eq!(salt, row["salt"].as_str().expect("a salt"));
    assert_eq!(output_info, row["output_info"].as_str().expect("an info"));
    assert_eq!(input_info, row["input_info"].as_str().expect("an info"));

    // And the strings really do produce the pinned keys.
    let ikm = hex(PAIRING_KAT["transport_keys"]["pair_verify_ikm"]
        .as_str()
        .expect("the shared secret"));
    assert_eq!(
        pyatv_pairing::hkdf_derive::expand(salt, output_info, &ikm).expect("derives")[..],
        hex(row["output_key"].as_str().expect("a key"))[..]
    );
    assert_eq!(
        pyatv_pairing::hkdf_derive::expand(salt, input_info, &ikm).expect("derives")[..],
        hex(row["input_key"].as_str().expect("a key"))[..]
    );
}

/// The data channel's seeded salt and its *unswapped* argument order.
#[test]
fn the_data_channel_derives_with_the_seeded_salt() {
    let row = transport_row("airplay_data_stream");
    // The seed the pairing vectors were generated with, the same one this crate's own vectors use.
    let (salt, output_info, input_info) = data_stream_key_spec(3_141_592_653_589_793);

    assert_eq!(salt, row["salt"].as_str().expect("a salt"));
    assert_eq!(salt, "DataStream-Salt3141592653589793");
    assert_eq!(output_info, row["output_info"].as_str().expect("an info"));
    assert_eq!(input_info, row["input_info"].as_str().expect("an info"));

    let ikm = hex(PAIRING_KAT["transport_keys"]["pair_verify_ikm"]
        .as_str()
        .expect("the shared secret"));
    assert_eq!(
        pyatv_pairing::hkdf_derive::expand(&salt, output_info, &ikm).expect("derives")[..],
        hex(row["output_key"].as_str().expect("a key"))[..]
    );
    assert_eq!(
        pyatv_pairing::hkdf_derive::expand(&salt, input_info, &ikm).expect("derives")[..],
        hex(row["input_key"].as_str().expect("a key"))[..]
    );
}
