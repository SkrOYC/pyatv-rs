//! The RTP packet layouts RAOP uses on its three UDP channels.
//!
//! Full port of `pyatv/protocols/raop/packets.py` and the `defpacket` codec generator it is built
//! on (`pyatv/support/packet.py`). Every layout is a fixed-width big-endian struct — `defpacket`
//! always prefixes its `struct` format with `">"` — and every one begins with the same four-byte
//! `RtpHeader`, because `.extend()` spreads the base fields first and appends the new ones after
//! (`packet.py:29-30`).
//!
//! Sans-io by construction: nothing here touches a socket. [`super::net`] owns the sockets.
//!
//! ```text
//! RtpHeader          proto:u8  type:u8  seqno:u16                                  4 bytes
//! TimingPacket       RtpHeader padding:u32 reftime:u64 recvtime:u64 sendtime:u64   32 bytes
//! SyncPacket         RtpHeader now_without_latency:u32 last_sync:u64 now:u32       20 bytes
//! AudioPacketHeader  RtpHeader timestamp:u32 ssrc:u32                              12 bytes
//! RetransmitRequest  RtpHeader lost_seqno:u16 lost_packets:u16                      8 bytes
//! ```

use crate::{Error, Result};

/// Length of the four-byte RTP header every RAOP packet starts with.
pub const RTP_HEADER_LEN: usize = 4;

/// Length of an [`AudioPacketHeader`], which the audio payload is appended to by the caller.
pub const AUDIO_HEADER_LEN: usize = 12;

/// Length of a [`TimingPacket`].
pub const TIMING_PACKET_LEN: usize = 32;

/// Length of a [`SyncPacket`].
pub const SYNC_PACKET_LEN: usize = 20;

/// Length of a [`RetransmitRequest`].
pub const RETRANSMIT_REQUEST_LEN: usize = 8;

/// `proto` byte on every ordinary packet this port sends.
pub const PROTO_NORMAL: u8 = 0x80;

/// `proto` byte on the first sync packet of a stream, i.e. [`PROTO_NORMAL`] with the RTP marker
/// bit set (`stream_client.py:105`).
pub const PROTO_MARKER: u8 = 0x90;

/// RTP payload type for RAOP audio, matching `a=rtpmap:96 L16/44100/2` in the SDP.
pub const PAYLOAD_TYPE_AUDIO: u8 = 0x60;

/// `type` byte on the first audio packet of a session: [`PAYLOAD_TYPE_AUDIO`] with the RTP marker
/// bit, the standard "first packet of a talkspurt" convention (`stream_client.py:583`).
pub const PAYLOAD_TYPE_AUDIO_FIRST: u8 = 0xE0;

/// `type` byte on a timing response (`0x53 | 0x80`, `protocols/__init__.py:130`).
pub const PAYLOAD_TYPE_TIMING_RESPONSE: u8 = 0xD3;

/// `type` byte on a sync packet (`stream_client.py:106`).
pub const PAYLOAD_TYPE_SYNC: u8 = 0xD4;

/// `type` byte a retransmit *request* carries, once the marker bit is masked off
/// (`stream_client.py:141-144`).
pub const PAYLOAD_TYPE_RETRANSMIT_REQUEST: u8 = 0x55;

/// The two leading bytes of a retransmit *response* (`stream_client.py:167`).
pub const RETRANSMIT_RESPONSE_PREFIX: [u8; 2] = [0x80, 0xD6];

/// `seqno` every sync packet carries. Fixed, never incremented (`stream_client.py:107`).
pub const SYNC_SEQNO: u16 = 0x0007;

/// `seqno` every timing response carries (`protocols/__init__.py:132`).
pub const TIMING_RESPONSE_SEQNO: u16 = 7;

/// The four-byte header shared by every RAOP RTP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    /// Protocol byte: [`PROTO_NORMAL`], or [`PROTO_MARKER`] on a first sync packet.
    pub proto: u8,
    /// Payload type, with the RTP marker bit folded in on some packets.
    pub packet_type: u8,
    /// Sequence number.
    pub seqno: u16,
}

impl RtpHeader {
    /// Serialise to the four wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; RTP_HEADER_LEN] {
        let [high, low] = self.seqno.to_be_bytes();
        [self.proto, self.packet_type, high, low]
    }

    /// Read a header off the front of `data`, ignoring anything after it.
    ///
    /// `RtpHeader.decode(data, allow_excessive=True)` (`tests/fake_device/raop.py:217`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `data` is shorter than four bytes.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let bytes: [u8; RTP_HEADER_LEN] = data
            .get(..RTP_HEADER_LEN)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| Error::Malformed("RTP packet is shorter than its header".to_owned()))?;

        Ok(Self {
            proto: bytes[0],
            packet_type: bytes[1],
            seqno: u16::from_be_bytes([bytes[2], bytes[3]]),
        })
    }

    /// The payload type with the RTP marker bit masked off.
    ///
    /// Both the sender's control-channel dispatch (`stream_client.py:139`) and the fake receiver's
    /// audio dispatch (`tests/fake_device/raop.py:218`) branch on this rather than on the raw byte.
    #[must_use]
    pub const fn masked_type(&self) -> u8 {
        self.packet_type & 0x7F
    }
}

/// An audio packet's fixed 12-byte header. The payload is appended by the caller.
///
/// `AudioPacketHeader` (`packets.py:26-31`), built at `stream_client.py:581-587`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AudioPacketHeader {
    /// The shared RTP header.
    pub header: RtpHeader,
    /// RTP timestamp, advancing by each packet's frame count.
    pub timestamp: u32,
    /// Synchronisation source — literally the RTSP session identifier, not a separate draw
    /// (`stream_client.py:586`).
    pub ssrc: u32,
}

impl AudioPacketHeader {
    /// The header for one audio packet.
    ///
    /// `first` selects [`PAYLOAD_TYPE_AUDIO_FIRST`] over [`PAYLOAD_TYPE_AUDIO`].
    #[must_use]
    pub const fn new(first: bool, seqno: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            header: RtpHeader {
                proto: PROTO_NORMAL,
                packet_type: if first {
                    PAYLOAD_TYPE_AUDIO_FIRST
                } else {
                    PAYLOAD_TYPE_AUDIO
                },
                seqno,
            },
            timestamp,
            ssrc,
        }
    }

    /// Serialise to the twelve wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; AUDIO_HEADER_LEN] {
        let mut out = [0u8; AUDIO_HEADER_LEN];
        out[..RTP_HEADER_LEN].copy_from_slice(&self.header.encode());
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        out
    }

    /// The bytes an AirPlay 2 audio packet authenticates but does not encrypt.
    ///
    /// `aad = rtp_header[4:12]` — the timestamp and SSRC only, never the proto/type/seqno
    /// (`airplayv2.py:194`).
    #[must_use]
    pub fn additional_data(&self) -> [u8; 8] {
        let encoded = self.encode();
        let mut aad = [0u8; 8];
        aad.copy_from_slice(&encoded[4..12]);
        aad
    }
}

/// A sync packet, pushed to the receiver's control port once a second.
///
/// `SyncPacket` (`packets.py:18-24`), built at `stream_client.py:104-112`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncPacket {
    /// `0x90` on the first packet of a stream, `0x80` afterwards.
    pub proto: u8,
    /// `rtptime - latency`, the position without the look-ahead offset.
    pub now_without_latency: u32,
    /// The NTP seconds half of the moment this packet was built.
    ///
    /// Named "last sync" upstream, but recomputed fresh for every packet — it is not a previous
    /// packet's timestamp.
    pub last_sync_sec: u32,
    /// The NTP fraction half of the same moment.
    pub last_sync_frac: u32,
    /// `rtptime`, the latency-inclusive RTP timestamp.
    pub now: u32,
}

impl SyncPacket {
    /// Serialise to the twenty wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; SYNC_PACKET_LEN] {
        let mut out = [0u8; SYNC_PACKET_LEN];
        out[..RTP_HEADER_LEN].copy_from_slice(
            &RtpHeader {
                proto: self.proto,
                packet_type: PAYLOAD_TYPE_SYNC,
                seqno: SYNC_SEQNO,
            }
            .encode(),
        );
        out[4..8].copy_from_slice(&self.now_without_latency.to_be_bytes());
        out[8..12].copy_from_slice(&self.last_sync_sec.to_be_bytes());
        out[12..16].copy_from_slice(&self.last_sync_frac.to_be_bytes());
        out[16..20].copy_from_slice(&self.now.to_be_bytes());
        out
    }

    /// Read a sync packet, as a receiver-side fixture does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `data` is not twenty bytes long.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let bytes: [u8; SYNC_PACKET_LEN] = data.try_into().map_err(|_| {
            Error::Malformed(format!("a sync packet is 20 bytes, got {}", data.len()))
        })?;

        Ok(Self {
            proto: bytes[0],
            now_without_latency: read_u32(&bytes, 4),
            last_sync_sec: read_u32(&bytes, 8),
            last_sync_frac: read_u32(&bytes, 12),
            now: read_u32(&bytes, 16),
        })
    }
}

/// A timing packet, in either direction.
///
/// `TimingPacket` (`packets.py:7-16`). The receiver sends a request; the controller answers with
/// [`TimingPacket::respond`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimingPacket {
    /// The shared RTP header.
    pub header: RtpHeader,
    /// Always zero.
    pub padding: u32,
    /// Reference time, seconds half.
    pub reftime_sec: u32,
    /// Reference time, fraction half.
    pub reftime_frac: u32,
    /// Receive time, seconds half.
    pub recvtime_sec: u32,
    /// Receive time, fraction half.
    pub recvtime_frac: u32,
    /// Send time, seconds half.
    pub sendtime_sec: u32,
    /// Send time, fraction half.
    pub sendtime_frac: u32,
}

impl TimingPacket {
    /// Serialise to the thirty-two wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; TIMING_PACKET_LEN] {
        let mut out = [0u8; TIMING_PACKET_LEN];
        out[..RTP_HEADER_LEN].copy_from_slice(&self.header.encode());
        for (index, value) in [
            self.padding,
            self.reftime_sec,
            self.reftime_frac,
            self.recvtime_sec,
            self.recvtime_frac,
            self.sendtime_sec,
            self.sendtime_frac,
        ]
        .into_iter()
        .enumerate()
        {
            let offset = RTP_HEADER_LEN + index * 4;
            out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    /// Parse a timing packet.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `data` is not thirty-two bytes long.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let bytes: [u8; TIMING_PACKET_LEN] = data.try_into().map_err(|_| {
            Error::Malformed(format!("a timing packet is 32 bytes, got {}", data.len()))
        })?;

        Ok(Self {
            header: RtpHeader::decode(&bytes)?,
            padding: read_u32(&bytes, 4),
            reftime_sec: read_u32(&bytes, 8),
            reftime_frac: read_u32(&bytes, 12),
            recvtime_sec: read_u32(&bytes, 16),
            recvtime_frac: read_u32(&bytes, 20),
            sendtime_sec: read_u32(&bytes, 24),
            sendtime_frac: read_u32(&bytes, 28),
        })
    }

    /// Build the answer to a received timing request.
    ///
    /// `TimingServer.datagram_received` (`protocols/__init__.py:125-140`): the request's `proto`
    /// byte is echoed, the type becomes [`PAYLOAD_TYPE_TIMING_RESPONSE`], the seqno is the literal
    /// `7`, the request's *send* time becomes this reply's *reference* time, and one single "now"
    /// reading fills both the receive and send slots — upstream does not distinguish when it read
    /// the request from when it answered.
    #[must_use]
    pub fn respond(&self, now_sec: u32, now_frac: u32) -> Self {
        Self {
            header: RtpHeader {
                proto: self.header.proto,
                packet_type: PAYLOAD_TYPE_TIMING_RESPONSE,
                seqno: TIMING_RESPONSE_SEQNO,
            },
            padding: 0,
            reftime_sec: self.sendtime_sec,
            reftime_frac: self.sendtime_frac,
            recvtime_sec: now_sec,
            recvtime_frac: now_frac,
            sendtime_sec: now_sec,
            sendtime_frac: now_frac,
        }
    }
}

/// A receiver's request to have packets resent.
///
/// `RetransmitReqeust` (`packets.py:33-35` — the misspelling is upstream's class name; it is not
/// carried into this port, only cited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetransmitRequest {
    /// The shared RTP header.
    pub header: RtpHeader,
    /// Sequence number of the first missing packet.
    pub lost_seqno: u16,
    /// How many consecutive packets are missing.
    pub lost_packets: u16,
}

impl RetransmitRequest {
    /// Serialise to the eight wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; RETRANSMIT_REQUEST_LEN] {
        let mut out = [0u8; RETRANSMIT_REQUEST_LEN];
        out[..RTP_HEADER_LEN].copy_from_slice(&self.header.encode());
        out[4..6].copy_from_slice(&self.lost_seqno.to_be_bytes());
        out[6..8].copy_from_slice(&self.lost_packets.to_be_bytes());
        out
    }

    /// Parse a retransmit request.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `data` is not eight bytes long.
    pub fn decode(data: &[u8]) -> Result<Self> {
        let bytes: [u8; RETRANSMIT_REQUEST_LEN] = data.try_into().map_err(|_| {
            Error::Malformed(format!(
                "a retransmit request is 8 bytes, got {}",
                data.len()
            ))
        })?;

        Ok(Self {
            header: RtpHeader::decode(&bytes)?,
            lost_seqno: u16::from_be_bytes([bytes[4], bytes[5]]),
            lost_packets: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}

/// Wrap a cached audio packet as a retransmit response.
///
/// `b"\x80\xd6" + original_seqno + packet` (`stream_client.py:166-167`), where `original_seqno` is
/// re-read out of the cached packet's own RTP header rather than recomputed — so the sequence
/// number appears twice, once in the four-byte retransmission prefix and again inside the payload
/// the receiver strips it from (`tests/fake_device/raop.py:240-242`).
///
/// # Errors
///
/// Returns [`Error::Malformed`] if `packet` is too short to carry an RTP header.
pub fn retransmit_response(packet: &[u8]) -> Result<Vec<u8>> {
    let seqno = packet
        .get(2..4)
        .ok_or_else(|| Error::Malformed("cached packet has no sequence number".to_owned()))?;

    let mut out = Vec::with_capacity(RTP_HEADER_LEN + packet.len());
    out.extend_from_slice(&RETRANSMIT_RESPONSE_PREFIX);
    out.extend_from_slice(seqno);
    out.extend_from_slice(packet);
    Ok(out)
}

/// Read a big-endian `u32` at `offset`, which the fixed-width layouts above always have room for.
fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut field = [0u8; 4];
    field.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(field)
}

#[cfg(test)]
mod tests {
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
}
