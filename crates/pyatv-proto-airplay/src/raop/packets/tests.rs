//! Packet-layout unit tests, checked against `struct.pack` byte strings.
//!
//! In a child module rather than at the bottom of the parent so the layouts and the vectors that
//! pin them are each one file's worth of one thing.

use super::{
    AUDIO_HEADER_LEN, AudioPacketHeader, PAYLOAD_TYPE_AUDIO, PAYLOAD_TYPE_AUDIO_FIRST,
    PROTO_MARKER, PROTO_NORMAL, RetransmitRequest, RtpHeader, SYNC_PACKET_LEN, SyncPacket,
    TIMING_PACKET_LEN, TimingPacket, retransmit_response,
};

/// `struct.pack(">BBH", 0x80, 0x60, 0x1234)`.
#[test]
fn the_rtp_header_is_four_big_endian_bytes() {
    let header = RtpHeader {
        proto: PROTO_NORMAL,
        packet_type: PAYLOAD_TYPE_AUDIO,
        seqno: 0x1234,
    };

    assert_eq!(header.encode(), [0x80, 0x60, 0x12, 0x34]);
    assert_eq!(
        RtpHeader::decode(&header.encode()).expect("decodes"),
        header
    );
}

/// The first audio packet sets the marker bit on the payload type, and only there.
#[test]
fn the_first_audio_packet_sets_the_marker_bit() {
    let first = AudioPacketHeader::new(true, 1, 2, 3);
    let rest = AudioPacketHeader::new(false, 1, 2, 3);

    assert_eq!(first.header.packet_type, PAYLOAD_TYPE_AUDIO_FIRST);
    assert_eq!(rest.header.packet_type, PAYLOAD_TYPE_AUDIO);
    assert_eq!(first.header.proto, PROTO_NORMAL);
    assert_eq!(first.header.masked_type(), PAYLOAD_TYPE_AUDIO);
}

/// Twelve bytes, timestamp then SSRC, both big-endian.
#[test]
fn an_audio_header_is_twelve_bytes() {
    let encoded = AudioPacketHeader::new(false, 0xABCD, 0x1122_3344, 0x5566_7788).encode();

    assert_eq!(encoded.len(), AUDIO_HEADER_LEN);
    assert_eq!(
        encoded,
        [
            0x80, 0x60, 0xAB, 0xCD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
        ]
    );
}

/// The associated data is bytes 4..12 — timestamp and SSRC, never the sequence number.
#[test]
fn the_associated_data_omits_the_sequence_number() {
    let header = AudioPacketHeader::new(true, 0xABCD, 0x1122_3344, 0x5566_7788);

    assert_eq!(
        header.additional_data(),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    );
}

/// Twenty bytes, and the fixed seqno `7` regardless of how many have been sent.
#[test]
fn a_sync_packet_carries_the_fixed_sequence_number() {
    let packet = SyncPacket {
        proto: PROTO_MARKER,
        now_without_latency: 0x0000_0001,
        last_sync_sec: 0x0000_0002,
        last_sync_frac: 0x0000_0003,
        now: 0x0000_0004,
    };
    let encoded = packet.encode();

    assert_eq!(encoded.len(), SYNC_PACKET_LEN);
    assert_eq!(&encoded[..4], &[0x90, 0xD4, 0x00, 0x07]);
    assert_eq!(SyncPacket::decode(&encoded).expect("decodes"), packet);
}

/// The reply echoes the request's `proto`, answers `0xD3`, and puts one "now" in both slots.
#[test]
fn a_timing_reply_mirrors_the_request() {
    let request = TimingPacket {
        header: RtpHeader {
            proto: 0x80,
            packet_type: 0x52,
            seqno: 0,
        },
        padding: 0,
        reftime_sec: 1,
        reftime_frac: 2,
        recvtime_sec: 3,
        recvtime_frac: 4,
        sendtime_sec: 5,
        sendtime_frac: 6,
    };

    let reply = request.respond(100, 200);

    assert_eq!(reply.header.proto, 0x80);
    assert_eq!(reply.header.packet_type, 0xD3);
    assert_eq!(reply.header.seqno, 7);
    assert_eq!(reply.padding, 0);
    assert_eq!((reply.reftime_sec, reply.reftime_frac), (5, 6));
    assert_eq!((reply.recvtime_sec, reply.recvtime_frac), (100, 200));
    assert_eq!((reply.sendtime_sec, reply.sendtime_frac), (100, 200));
    assert_eq!(reply.encode().len(), TIMING_PACKET_LEN);
    assert_eq!(
        TimingPacket::decode(&reply.encode()).expect("decodes"),
        reply
    );
}

/// A receiver asks with the marker bit set; the sender matches on the masked value.
#[test]
fn a_retransmit_request_round_trips() {
    let request = RetransmitRequest {
        header: RtpHeader {
            proto: 0x80,
            packet_type: 0xD5,
            seqno: 0,
        },
        lost_seqno: 0x0102,
        lost_packets: 3,
    };

    assert_eq!(
        request.encode(),
        [0x80, 0xD5, 0x00, 0x00, 0x01, 0x02, 0x00, 0x03]
    );
    assert_eq!(request.header.masked_type(), 0x55);
    assert_eq!(
        RetransmitRequest::decode(&request.encode()).expect("decodes"),
        request
    );
}

/// The response repeats the sequence number outside the cached packet as well as inside it.
#[test]
fn a_retransmit_response_prefixes_the_cached_packet() {
    let cached = [0x80, 0x60, 0x12, 0x34, 0xAA, 0xBB];

    let response = retransmit_response(&cached).expect("wraps");

    assert_eq!(&response[..4], &[0x80, 0xD6, 0x12, 0x34]);
    assert_eq!(&response[4..], &cached);
}

#[test]
fn a_truncated_packet_is_an_error_not_a_panic() {
    assert!(RtpHeader::decode(&[0x80, 0x60]).is_err());
    assert!(SyncPacket::decode(&[0u8; 19]).is_err());
    assert!(TimingPacket::decode(&[0u8; 31]).is_err());
    assert!(RetransmitRequest::decode(&[0u8; 7]).is_err());
    assert!(retransmit_response(&[0x80, 0x60]).is_err());
}
