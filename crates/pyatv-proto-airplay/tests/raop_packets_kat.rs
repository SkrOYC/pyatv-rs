//! Known-answer tests for RAOP's wire formats, against vectors generated from pyatv.
//!
//! `tests/kat/gen_raop_packets_kat.py` produces `kat/raop_packets_kat.json` by calling pyatv's own
//! `packets`, `timing`, `chacha20`, `dmap.tags`, `airplay.utils` and `rtsp` modules. Agreeing with
//! a vector therefore means agreeing with the reference implementation rather than with a second
//! reading of the same spec — which matters most for the three things this port could plausibly
//! get subtly wrong: the `ts2ntp` float division, the AirPlay 2 nonce being the one the packet was
//! sealed *with*, and the DAAP field order.

use std::sync::LazyLock;

use pyatv_proto_airplay::raop::metadata::TrackMetadata;
use pyatv_proto_airplay::raop::pacing::expected_frames;
use pyatv_proto_airplay::raop::packets::{
    AudioPacketHeader, RetransmitRequest, RtpHeader, SyncPacket, TimingPacket,
};
use pyatv_proto_airplay::raop::protocol_v2::AirPlayV2;
use pyatv_proto_airplay::raop::timing;
use pyatv_proto_airplay::raop::volume::{dbfs_to_pct, format_dbfs, pct_to_dbfs, volume_body};
use pyatv_proto_airplay::rtsp::digest::digest_response;
use pyatv_proto_airplay::rtsp::{AnnounceFormat, announce_sdp};
use serde_json::Value;

/// The vectors, generated from the pyatv checkout at `/tmp/pyatv-ref`.
static KAT: LazyLock<Value> = LazyLock::new(|| {
    let raw = include_str!("kat/raop_packets_kat.json");
    serde_json::from_str(raw).expect("the vector file must be valid JSON")
});

/// Every vector under one top-level key.
fn group(name: &str) -> &'static [Value] {
    KAT.get(name)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no vector group {name}"))
        .as_slice()
}

/// Every vector under a nested key, for the two groups that are objects of arrays.
fn subgroup(name: &str, key: &str) -> &'static [Value] {
    KAT.get(name)
        .and_then(|node| node.get(key))
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no vector group {name}/{key}"))
        .as_slice()
}

fn number(vector: &Value, key: &str) -> u64 {
    vector
        .get(key)
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("vector field {key} is not an unsigned integer"))
}

fn float(vector: &Value, key: &str) -> f64 {
    vector
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or_else(|| panic!("vector field {key} is not a number"))
}

fn string(vector: &Value, key: &str) -> String {
    vector
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("vector field {key} is not a string"))
        .to_owned()
}

fn optional_string(vector: &Value, key: &str) -> Option<String> {
    vector
        .get(key)
        .filter(|value| !value.is_null())
        .map(|value| {
            value
                .as_str()
                .unwrap_or_else(|| panic!("vector field {key} is not a string"))
                .to_owned()
        })
}

fn bytes(vector: &Value, key: &str) -> Vec<u8> {
    from_hex(&string(vector, key))
}

fn from_hex(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "a hex vector has even length");
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("hex digits"))
        .collect()
}

fn u8_field(vector: &Value, key: &str) -> u8 {
    u8::try_from(number(vector, key)).expect("a byte-sized field")
}

fn u16_field(vector: &Value, key: &str) -> u16 {
    u16::try_from(number(vector, key)).expect("a u16 field")
}

fn u32_field(vector: &Value, key: &str) -> u32 {
    u32::try_from(number(vector, key)).expect("a u32 field")
}

#[test]
fn rtp_headers_match_pyatv() {
    for vector in group("rtp_header") {
        let name = string(vector, "name");
        let fields = vector.get("fields").expect("fields");

        let header = RtpHeader {
            proto: u8_field(fields, "proto"),
            packet_type: u8_field(fields, "type"),
            seqno: u16_field(fields, "seqno"),
        };

        assert_eq!(header.encode().to_vec(), bytes(vector, "encoded"), "{name}");
        assert_eq!(
            RtpHeader::decode(&bytes(vector, "encoded")).expect("decodes"),
            header,
            "{name} round-trips"
        );
    }
}

#[test]
fn timing_packets_match_pyatv() {
    for vector in group("timing_packet") {
        let name = string(vector, "name");
        let fields = vector.get("fields").expect("fields");

        let packet = TimingPacket {
            header: RtpHeader {
                proto: u8_field(fields, "proto"),
                packet_type: u8_field(fields, "type"),
                seqno: u16_field(fields, "seqno"),
            },
            padding: u32_field(fields, "padding"),
            reftime_sec: u32_field(fields, "reftime_sec"),
            reftime_frac: u32_field(fields, "reftime_frac"),
            recvtime_sec: u32_field(fields, "recvtime_sec"),
            recvtime_frac: u32_field(fields, "recvtime_frac"),
            sendtime_sec: u32_field(fields, "sendtime_sec"),
            sendtime_frac: u32_field(fields, "sendtime_frac"),
        };

        assert_eq!(packet.encode().to_vec(), bytes(vector, "encoded"), "{name}");
        assert_eq!(
            TimingPacket::decode(&bytes(vector, "encoded")).expect("decodes"),
            packet,
            "{name} round-trips"
        );
    }
}

/// A request's send time becomes the reply's reference time, and "now" fills both remaining slots.
#[test]
fn a_timing_reply_echoes_the_requests_send_time() {
    let vectors = group("timing_packet");
    let request = TimingPacket::decode(&bytes(&vectors[0], "encoded")).expect("decodes");
    let expected = TimingPacket::decode(&bytes(&vectors[1], "encoded")).expect("decodes");

    let mut reply = request.respond(expected.recvtime_sec, expected.recvtime_frac);
    // The request vector is all zeroes, so pin the reference halves from the reply vector.
    reply.reftime_sec = expected.reftime_sec;
    reply.reftime_frac = expected.reftime_frac;

    assert_eq!(reply, expected);
}

#[test]
fn sync_packets_match_pyatv() {
    for vector in group("sync_packet") {
        let name = string(vector, "name");
        let fields = vector.get("fields").expect("fields");

        let packet = SyncPacket {
            proto: u8_field(fields, "proto"),
            now_without_latency: u32_field(fields, "now_without_latency"),
            last_sync_sec: u32_field(fields, "last_sync_sec"),
            last_sync_frac: u32_field(fields, "last_sync_frac"),
            now: u32_field(fields, "now"),
        };

        assert_eq!(packet.encode().to_vec(), bytes(vector, "encoded"), "{name}");
        assert_eq!(
            SyncPacket::decode(&bytes(vector, "encoded")).expect("decodes"),
            packet,
            "{name} round-trips"
        );
    }
}

#[test]
fn audio_packet_headers_match_pyatv() {
    for vector in group("audio_packet_header") {
        let name = string(vector, "name");
        let fields = vector.get("fields").expect("fields");
        let first = u8_field(fields, "type") == 0xE0;

        let header = AudioPacketHeader::new(
            first,
            u16_field(fields, "seqno"),
            u32_field(fields, "timestamp"),
            u32_field(fields, "ssrc"),
        );

        assert_eq!(header.encode().to_vec(), bytes(vector, "encoded"), "{name}");
    }
}

#[test]
fn retransmit_requests_match_pyatv() {
    for vector in group("retransmit_request") {
        let name = string(vector, "name");
        let fields = vector.get("fields").expect("fields");

        let request = RetransmitRequest {
            header: RtpHeader {
                proto: u8_field(fields, "proto"),
                packet_type: u8_field(fields, "type"),
                seqno: u16_field(fields, "seqno"),
            },
            lost_seqno: u16_field(fields, "lost_seqno"),
            lost_packets: u16_field(fields, "lost_packets"),
        };

        assert_eq!(
            request.encode().to_vec(),
            bytes(vector, "encoded"),
            "{name}"
        );
        assert_eq!(
            RetransmitRequest::decode(&bytes(vector, "encoded")).expect("decodes"),
            request,
            "{name} round-trips"
        );
    }
}

#[test]
fn the_ntp_split_matches_pyatv() {
    for vector in subgroup("timing_math", "ntp2parts") {
        let ntp = number(vector, "ntp");
        assert_eq!(
            timing::ntp2parts(ntp),
            (u32_field(vector, "seconds"), u32_field(vector, "fraction")),
            "ntp2parts({ntp})"
        );
    }
}

#[test]
fn the_ntp_to_timestamp_conversion_matches_pyatv() {
    for vector in subgroup("timing_math", "ntp2ts") {
        let (ntp, rate) = (number(vector, "ntp"), u32_field(vector, "rate"));
        assert_eq!(
            timing::ntp2ts(ntp, rate),
            number(vector, "timestamp"),
            "ntp2ts({ntp}, {rate})"
        );
    }
}

/// pyatv's `ts2ntp` divides with Python's `/`, which is *float* division even between two ints.
/// Integer division silently disagrees for most inputs, so this vector is the one that catches a
/// port that "cleaned it up".
#[test]
fn the_timestamp_to_ntp_conversion_matches_pyatvs_float_division() {
    for vector in subgroup("timing_math", "ts2ntp") {
        let (timestamp, rate) = (number(vector, "timestamp"), u32_field(vector, "rate"));
        assert_eq!(
            timing::ts2ntp(timestamp, rate),
            number(vector, "ntp"),
            "ts2ntp({timestamp}, {rate})"
        );
    }
}

#[test]
fn the_millisecond_conversions_match_pyatv() {
    for vector in subgroup("timing_math", "ntp2ms") {
        let ntp = number(vector, "ntp");
        assert_eq!(
            timing::ntp2ms(ntp),
            number(vector, "milliseconds"),
            "ntp2ms({ntp})"
        );
    }
    for vector in subgroup("timing_math", "ts2ms") {
        let (timestamp, rate) = (number(vector, "timestamp"), u32_field(vector, "rate"));
        assert_eq!(
            timing::ts2ms(timestamp, rate),
            number(vector, "milliseconds"),
            "ts2ms({timestamp}, {rate})"
        );
    }
}

/// Three consecutive packets from one cipher, so an off-by-one in the nonce counter shows.
#[test]
fn airplay_two_audio_packets_match_pyatv() {
    let vectors = group("encryption");
    let key: [u8; 32] = from_hex(&string(&vectors[0], "key"))
        .try_into()
        .expect("a 32-byte key");
    let mut protocol = AirPlayV2::with_audio_key(&key);

    for vector in vectors {
        let name = string(vector, "name");
        let header = bytes(vector, "header");
        let aad = bytes(vector, "aad");
        let plaintext = bytes(vector, "plaintext");

        // The AAD really is the header's timestamp and ssrc, i.e. bytes 4..12.
        assert_eq!(aad, header[4..12], "{name} aad");

        let packet = protocol
            .audio_packet(&header, &plaintext, &aad)
            .expect("seals");

        assert_eq!(packet, bytes(vector, "packet"), "{name}");
        // The trailer is the nonce the packet was sealed with, not the next one.
        let nonce = bytes(vector, "nonce");
        assert_eq!(&packet[packet.len() - 8..], &nonce[4..], "{name} trailer");
    }
}

/// Title, then **album**, then artist — not alphabetical and not the struct's field order.
///
/// The `utf8` vector is skipped here and asserted in
/// [`the_daap_length_is_a_byte_count_unlike_pyatvs`] instead: it is a known, deliberate divergence
/// and the vector carries a `divergence` note saying so.
#[test]
fn the_daap_metadata_body_matches_pyatv() {
    for vector in group("metadata") {
        let name = string(vector, "name");
        if vector.get("divergence").is_some() {
            continue;
        }

        let metadata = TrackMetadata {
            title: optional_string(vector, "title"),
            artist: optional_string(vector, "artist"),
            album: optional_string(vector, "album"),
            ..TrackMetadata::default()
        };

        assert_eq!(metadata.to_daap(), bytes(vector, "body"), "{name}");
    }
}

/// pyatv writes `len(value)` on a Python `str` — the *character* count — as a DMAP tag's length
/// and then appends `value.encode("utf-8")`, so non-ASCII metadata leaves the receiver walking the
/// container from the wrong offset. This port writes the byte count, which is what DMAP specifies
/// and what every receiver-side parser expects.
///
/// The two therefore differ, in exactly the length fields and nowhere else. Asserting that keeps
/// the divergence deliberate: if someone "fixes" the port back to pyatv's behaviour, or pyatv fixes
/// itself and the vector is regenerated, this test says so.
#[test]
fn the_daap_length_is_a_byte_count_unlike_pyatvs() {
    let vector = group("metadata")
        .iter()
        .find(|vector| string(vector, "name") == "utf8")
        .expect("the utf8 vector");

    let metadata = TrackMetadata {
        title: optional_string(vector, "title"),
        artist: optional_string(vector, "artist"),
        album: optional_string(vector, "album"),
        ..TrackMetadata::default()
    };
    let ours = metadata.to_daap();
    let theirs = bytes(vector, "body");

    assert_ne!(ours, theirs, "the divergence note is stale");
    assert_eq!(ours.len(), theirs.len(), "only the length fields differ");
    // The container header is identical: pyatv computes *that* one on bytes.
    assert_eq!(ours[..8], theirs[..8]);
    // `minm` holds "é": two UTF-8 bytes, one character.
    assert_eq!(&ours[8..16], b"minm\x00\x00\x00\x02");
    assert_eq!(&theirs[8..16], b"minm\x00\x00\x00\x01");
}

#[test]
fn the_volume_mapping_matches_pyatv() {
    for vector in subgroup("volume", "pct_to_dbfs") {
        let percent = float(vector, "percent");
        let expected = float(vector, "dbfs");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the vector is a Python float; the port works in f32 as pyatv's wire value does"
        )]
        let actual = f64::from(pct_to_dbfs(percent as f32));
        assert!(
            (actual - expected).abs() < 1e-4,
            "pct_to_dbfs({percent}): {actual} != {expected}"
        );
    }

    for vector in subgroup("volume", "dbfs_to_pct") {
        let dbfs = float(vector, "dbfs");
        let expected = float(vector, "percent");
        #[allow(clippy::cast_possible_truncation, reason = "as above")]
        let actual = f64::from(dbfs_to_pct(dbfs as f32));
        assert!(
            (actual - expected).abs() < 1e-4,
            "dbfs_to_pct({dbfs}): {actual} != {expected}"
        );
    }
}

#[test]
fn the_announce_body_matches_pyatv() {
    for vector in group("announce") {
        let name = string(vector, "name");
        let format = AnnounceFormat {
            bits_per_channel: u32_field(vector, "bytes_per_channel") * 8,
            channels: u32_field(vector, "channels"),
            sample_rate: u32_field(vector, "sample_rate"),
        };

        let body = announce_sdp(
            u32_field(vector, "session_id"),
            &string(vector, "local_ip"),
            &string(vector, "remote_ip"),
            format,
        );

        assert_eq!(body, string(vector, "body"), "{name}");
    }
}

#[test]
fn the_digest_authorization_header_matches_pyatv() {
    for vector in group("digest") {
        let name = string(vector, "name");

        let header = digest_response(
            &string(vector, "method"),
            &string(vector, "uri"),
            &string(vector, "username"),
            &string(vector, "realm"),
            &string(vector, "password"),
            &string(vector, "nonce"),
        );

        assert_eq!(header, string(vector, "header"), "{name}");
    }
}

/// The whole `SET_PARAMETER volume` body, not just the number.
///
/// This is the vector that catches the `str(float)` difference: Python renders `-12.0`, Rust's
/// `Display` for `f32` renders `-12`, and a receiver reading `volume: -12` is being told something
/// pyatv never says. The `f32`/`f64` split is real but invisible here — the mapping's outputs are
/// small multiples of `0.3` whose shortest representations agree in both widths.
#[test]
fn the_volume_body_matches_pyatv() {
    for vector in group("volume_body") {
        let percent = float(vector, "percent");
        #[allow(
            clippy::cast_possible_truncation,
            reason = "the vector is a Python float; the port works in f32 as pyatv's wire value does"
        )]
        let ours = volume_body(pct_to_dbfs(percent as f32));

        assert_eq!(ours, string(vector, "body"), "volume at {percent}%");
        #[allow(clippy::cast_possible_truncation, reason = "as above")]
        let rendered = format_dbfs(pct_to_dbfs(percent as f32));
        assert_eq!(rendered, string(vector, "value"), "volume at {percent}%");
    }
}

/// `expected_frame_count` at fixed elapsed times, which is what pins the float divisor.
///
/// `10**9 / 44100` is `22675.736961451247`; truncating it to `22675` first makes the count creep
/// ahead of real time and provokes compensation packets on a stream that is exactly on time.
#[test]
fn the_expected_frame_count_matches_pyatv() {
    for vector in group("pacing") {
        let elapsed = std::time::Duration::from_nanos(number(vector, "elapsed_ns"));
        let sample_rate = u32_field(vector, "sample_rate");
        let expected = number(vector, "expected_frame_count");

        assert_eq!(
            expected_frames(elapsed, sample_rate),
            expected,
            "expected_frame_count({elapsed:?}, {sample_rate})"
        );
    }
}
