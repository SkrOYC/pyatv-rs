//! AirPlay-tunnel transport: MRP protobufs inside binary plists on an AirPlay 2 data channel.
//!
//! Mandatory on tvOS 15 and later, where the `_mediaremotetv._tcp` service is no longer offered.
//! See `docs/research/mrp-companion.md` §3.4.
//!
//! The framing is a 32-byte big-endian header followed by a binary plist body shaped
//! `{"params": {"data": <concatenated framed protobufs>}}`. The header fields are `size: u32`
//! (total frame size including the header), `message_type: [u8; 12]`, `command: [u8; 4]`,
//! `seqno: u64` and four bytes of padding.
//!
//! Two behaviours here are reverse-engineered rather than designed, and both must be reproduced
//! rather than tidied:
//!
//! 1. **The unprefixed-message heuristic.** Messages inside `data` are normally varint-prefixed,
//!    but `ConfigureConnectionMessage` arrives without a prefix. pyatv detects this by peeking the
//!    first byte: `0x08` is the protobuf wire tag for field 1 (`type`), and since the minimum real
//!    message length is around 40 bytes, a leading `0x08` cannot be a valid length varint. If it is
//!    `0x08`, consume the whole buffer as one message.
//! 2. **The `sync`/`rply` acknowledgement.** Any inbound frame whose `message_type` starts with
//!    `sync` must be answered with a `rply` frame — same header shape, zeroed `command`, the same
//!    `seqno` echoed back, and an empty payload. This is a data-channel-level keepalive, separate
//!    from the RTSP `FEEDBACK` heartbeat.

use bytes::Bytes;

use crate::Result;
use crate::transport::MrpTransport;

/// Total length of the data-channel frame header, `4 + 12 + 4 + 8 + 4`.
pub const DATA_HEADER_LEN: usize = 32;

/// Marks an inbound frame that must be acknowledged.
pub const MESSAGE_TYPE_SYNC: &[u8; 4] = b"sync";

/// The acknowledgement sent in reply to a `sync` frame.
pub const MESSAGE_TYPE_REPLY: &[u8; 4] = b"rply";

/// The protobuf wire tag for field 1, used to spot an unprefixed message.
///
/// See the module documentation; this is pyatv's heuristic, reproduced verbatim.
pub const UNPREFIXED_MESSAGE_MARKER: u8 = 0x08;

/// A parsed data-channel frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// Total frame size, header included.
    pub size: u32,
    /// Message type, space- or NUL-padded to twelve bytes.
    pub message_type: [u8; 12],
    /// Command, four bytes.
    pub command: [u8; 4],
    /// Sequence number, echoed back in a reply frame.
    pub seqno: u64,
}

impl DataHeader {
    /// Whether this frame requires a `rply` acknowledgement.
    #[must_use]
    pub fn needs_reply(&self) -> bool {
        self.message_type.starts_with(MESSAGE_TYPE_SYNC)
    }
}

/// MRP tunnelled over an AirPlay 2 data-stream channel.
#[derive(Debug)]
pub struct TunnelTransport {
    seqno: u64,
}

impl TunnelTransport {
    /// Wrap an already-established, already-pair-verified AirPlay data channel.
    ///
    /// Bringing that channel up is `pyatv-proto-airplay`'s job: it needs the RTSP control
    /// connection, its own pair-verify, and the seeded `DataStream-Salt` derivation.
    // TODO(step-1): take the established channel handle from pyatv-proto-airplay once its
    // `ap2_session` equivalent exists. See docs/research/mrp-companion.md §3.3.
    #[must_use]
    pub fn new() -> Self {
        Self { seqno: 0 }
    }

    /// The next sequence number this transport will use.
    #[must_use]
    pub fn seqno(&self) -> u64 {
        self.seqno
    }
}

impl Default for TunnelTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MrpTransport for TunnelTransport {
    async fn send(&self, message: Bytes) -> Result<()> {
        let _ = message;
        // TODO(step-1): varint-prefix the message, wrap it as {"params": {"data": ...}}, encode as
        // a binary plist, prepend the 32-byte header and hand it to the HAP session.
        todo!("TunnelTransport::send")
    }

    async fn receive(&self) -> Result<Option<Bytes>> {
        // TODO(step-1): parse the header, answer `sync` frames with `rply`, decode the plist body,
        // then split `data` into messages applying the UNPREFIXED_MESSAGE_MARKER heuristic.
        todo!("TunnelTransport::receive")
    }

    fn is_encrypted(&self) -> bool {
        // The data channel only exists after pair-verify, so it is always encrypted.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::{DATA_HEADER_LEN, DataHeader, MESSAGE_TYPE_SYNC};

    /// 4 + 12 + 4 + 8 + 4 bytes, packed big-endian.
    #[test]
    fn header_length_matches_the_field_layout() {
        assert_eq!(DATA_HEADER_LEN, 4 + 12 + 4 + 8 + 4);
    }

    /// The check is on the message type's prefix, because the field is padded out to twelve bytes.
    #[test]
    fn sync_frames_are_detected_by_prefix() {
        let mut message_type = [0u8; 12];
        message_type[..4].copy_from_slice(MESSAGE_TYPE_SYNC);

        let header = DataHeader {
            size: 32,
            message_type,
            command: [0; 4],
            seqno: 7,
        };
        assert!(header.needs_reply());

        let other = DataHeader {
            message_type: *b"rply\0\0\0\0\0\0\0\0",
            ..header
        };
        assert!(!other.needs_reply());
    }
}
