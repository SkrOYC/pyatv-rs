//! RTP packet layouts for the RAOP audio, timing and control channels.
//!
//! Layouts are in `docs/research/airplay-raop-dmap.md`. All RTP headers are big-endian.

/// RTP payload type for the audio stream, matching `m=audio 0 RTP/AVP 96` in the SDP.
pub const PAYLOAD_TYPE_AUDIO: u8 = 96;

/// Length of the fixed RTP header, before any RAOP-specific extension.
pub const RTP_HEADER_LEN: usize = 12;

/// An outgoing audio packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket {
    /// Sequence number, incrementing per packet and wrapping at 16 bits.
    pub sequence: u16,
    /// RTP timestamp, advancing by the frame count of each packet.
    pub timestamp: u32,
    /// Synchronisation source identifier for this session.
    pub ssrc: u32,
    /// Encoded audio payload.
    pub payload: Vec<u8>,
}

impl AudioPacket {
    /// Serialise to the wire.
    // TODO(step-1): write the 12-byte big-endian RTP header then the payload. See
    // docs/research/airplay-raop-dmap.md for the exact marker/version bits RAOP sets.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        todo!("AudioPacket::encode")
    }
}

/// A timing or control channel packet.
// TODO(step-1): model the NTP-style timing request/response and the retransmit request the control
// channel carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPacket {
    /// Packet type from the RTP header.
    pub packet_type: u8,
    /// Raw body, pending a typed model.
    pub body: Vec<u8>,
}
