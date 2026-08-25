//! The 32-byte big-endian data-stream frame header.
//!
//! Port of `DataHeader` and the `encode_message`/`decode_message`/`encode_reply` trio
//! (`pyatv/protocols/airplay/channels.py:27-31,120-188`). `defpacket`
//! (`pyatv/support/packet.py:7-35`) prefixes every format string with `">"`, so **every field is
//! big-endian**, including `size` and the 64-bit `seqno`.
//!
//! ```text
//! | size u32 | message_type [u8; 12] | command [u8; 4] | seqno u64 | padding u32 | payload … |
//!   ^-- counts the 32-byte header too
//! ```
//!
//! This framing sits on the *plaintext* side of the HAP block encryption: one frame can span
//! several 1024-byte HAP blocks and one block can carry several frames plus a partial one, so the
//! two boundaries have nothing to do with each other (spec §5.5).

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use crate::{Error, Result};

/// Bytes in the header, `struct.calcsize(">I12s4sQI")`.
pub const HEADER_LEN: usize = 32;

/// `DATA_HEADER_PADDING` (`channels.py:27`), always zero.
pub const PADDING: u32 = 0x0000_0000;

/// `message_type` of an outbound MRP-carrying frame: `b"sync"` zero-padded to twelve bytes.
pub const MESSAGE_TYPE_SYNC: [u8; 12] = *b"sync\0\0\0\0\0\0\0\0";

/// `message_type` of an acknowledgement: `b"rply"` zero-padded to twelve bytes.
pub const MESSAGE_TYPE_REPLY: [u8; 12] = *b"rply\0\0\0\0\0\0\0\0";

/// `command` of an outbound MRP-carrying frame (`channels.py:272`).
pub const COMMAND_COMM: [u8; 4] = *b"comm";

/// `command` of an acknowledgement: four zero bytes (`channels.py:158`).
pub const COMMAND_NONE: [u8; 4] = [0; 4];

/// The prefix that marks a frame as one wanting an acknowledgement (`channels.py:254`).
pub const SYNC_PREFIX: &[u8] = b"sync";

/// One decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataHeader {
    /// Total frame size **including** these 32 bytes.
    pub size: u32,
    /// ASCII tag, zero-padded.
    pub message_type: [u8; 12],
    /// Four-byte command tag.
    pub command: [u8; 4],
    /// Echoed verbatim in the acknowledgement to this frame.
    pub seqno: u64,
    /// Always [`PADDING`].
    pub padding: u32,
}

impl DataHeader {
    /// Serialise the header.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&self.size.to_be_bytes());
        out[4..16].copy_from_slice(&self.message_type);
        out[16..20].copy_from_slice(&self.command);
        out[20..28].copy_from_slice(&self.seqno.to_be_bytes());
        out[28..32].copy_from_slice(&self.padding.to_be_bytes());
        out
    }

    /// Read a header off the front of `input`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if `input` is shorter than [`HEADER_LEN`], or if the declared
    /// `size` does not even cover the header — upstream's `DataHeader.decode` would happily return
    /// such a header and then slice a negative-length payload out of it.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut cursor = input.get(..HEADER_LEN).ok_or_else(|| {
            Error::Malformed(format!("data frame header is {} bytes", input.len()))
        })?;

        let header = Self {
            size: cursor.get_u32(),
            message_type: {
                let mut tag = [0u8; 12];
                cursor.copy_to_slice(&mut tag);
                tag
            },
            command: {
                let mut tag = [0u8; 4];
                cursor.copy_to_slice(&mut tag);
                tag
            },
            seqno: cursor.get_u64(),
            padding: cursor.get_u32(),
        };

        if (header.size as usize) < HEADER_LEN {
            return Err(Error::Malformed(format!(
                "data frame claims {} bytes, under the {HEADER_LEN}-byte header",
                header.size
            )));
        }

        Ok(header)
    }

    /// Whether this frame wants an acknowledgement (`channels.py:254`).
    #[must_use]
    pub fn wants_reply(&self) -> bool {
        self.message_type.starts_with(SYNC_PREFIX)
    }
}

/// A frame header and its payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataStreamMessage {
    /// The frame header as it arrived or will be sent.
    pub header: DataHeader,
    /// The binary property list body, empty for an acknowledgement.
    pub payload: Bytes,
}

/// Build an outbound MRP-carrying frame around an already-encoded payload.
///
/// `send_protobuf` (`channels.py:266-280`): `message_type = b"sync" + 8 zero bytes`, `command =
/// b"comm"`, `padding = 0`, and `size` computed as header plus payload.
#[must_use]
pub fn encode_sync(seqno: u64, payload: &[u8]) -> Vec<u8> {
    encode(
        &DataHeader {
            size: frame_size(payload.len()),
            message_type: MESSAGE_TYPE_SYNC,
            command: COMMAND_COMM,
            seqno,
            padding: PADDING,
        },
        payload,
    )
}

/// Build the acknowledgement to a `sync` frame.
///
/// `encode_reply` (`channels.py:153-163`): `b"rply"` zero-padded, a four-zero-byte command, **the
/// seqno the incoming frame carried** rather than this channel's own, and no payload — so `size` is
/// exactly [`HEADER_LEN`].
#[must_use]
pub fn encode_reply(seqno: u64) -> Vec<u8> {
    encode(
        &DataHeader {
            size: frame_size(0),
            message_type: MESSAGE_TYPE_REPLY,
            command: COMMAND_NONE,
            seqno,
            padding: PADDING,
        },
        &[],
    )
}

/// Header plus payload, contiguous.
fn encode(header: &DataHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.put_slice(&header.encode());
    out.put_slice(payload);
    out
}

/// `DataHeader.length + len(payload)`, saturating rather than wrapping on an implausible payload.
fn frame_size(payload_len: usize) -> u32 {
    u32::try_from(HEADER_LEN + payload_len).unwrap_or(u32::MAX)
}

/// Take one complete frame off the front of `buffer`, leaving a partial one in place.
///
/// `decode_message` (`channels.py:165-188`) plus the `while len(self.buffer) >= DataHeader.length`
/// guard around it (`channels.py:244`). Returns `Ok(None)` while the frame is still arriving.
///
/// # Errors
///
/// Returns [`Error::Malformed`] for a header whose declared size cannot be real.
pub fn decode(buffer: &mut BytesMut) -> Result<Option<DataStreamMessage>> {
    if buffer.len() < HEADER_LEN {
        return Ok(None);
    }

    let header = DataHeader::decode(buffer)?;
    let size = header.size as usize;
    if buffer.len() < size {
        tracing::trace!(have = buffer.len(), want = size, "partial data frame");
        return Ok(None);
    }

    let mut frame = buffer.split_to(size);
    let _ = frame.split_to(HEADER_LEN);

    Ok(Some(DataStreamMessage {
        header,
        payload: frame.freeze(),
    }))
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{
        COMMAND_COMM, COMMAND_NONE, DataHeader, HEADER_LEN, MESSAGE_TYPE_REPLY, MESSAGE_TYPE_SYNC,
        decode, encode_reply, encode_sync,
    };

    /// The header is 32 bytes, every field big-endian, in `struct.calcsize(">I12s4sQI")` order.
    #[test]
    fn the_header_is_thirty_two_big_endian_bytes() {
        let header = DataHeader {
            size: 0x0000_0028,
            message_type: MESSAGE_TYPE_SYNC,
            command: COMMAND_COMM,
            seqno: 0x0123_4567_89AB_CDEF,
            padding: 0,
        };

        assert_eq!(
            header.encode(),
            [
                0x00, 0x00, 0x00, 0x28, // size
                b's', b'y', b'n', b'c', 0, 0, 0, 0, 0, 0, 0, 0, // message_type
                b'c', b'o', b'm', b'm', // command
                0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // seqno
                0x00, 0x00, 0x00, 0x00, // padding
            ]
        );
        assert_eq!(HEADER_LEN, 32);
    }

    #[test]
    fn a_header_round_trips() {
        let header = DataHeader {
            size: 4_294_967_295,
            message_type: MESSAGE_TYPE_REPLY,
            command: COMMAND_NONE,
            seqno: u64::MAX,
            padding: 0,
        };

        assert_eq!(
            DataHeader::decode(&header.encode()).expect("decodes"),
            header
        );
    }

    /// An acknowledgement is header-only, with the incoming seqno and a zeroed command.
    #[test]
    fn a_reply_is_a_bare_header() {
        let wire = encode_reply(0x1_0000_0001);

        assert_eq!(wire.len(), HEADER_LEN);
        let header = DataHeader::decode(&wire).expect("decodes");
        assert_eq!(header.size, 32);
        assert_eq!(header.message_type, MESSAGE_TYPE_REPLY);
        assert_eq!(header.command, COMMAND_NONE);
        assert_eq!(header.seqno, 0x1_0000_0001);
        assert!(!header.wants_reply());
    }

    #[test]
    fn a_sync_frame_carries_its_payload_after_the_header() {
        let wire = encode_sync(7, b"payload");

        assert_eq!(wire.len(), HEADER_LEN + 7);
        assert_eq!(&wire[HEADER_LEN..], b"payload");
        assert_eq!(DataHeader::decode(&wire).expect("decodes").size, 39);
        assert!(DataHeader::decode(&wire).expect("decodes").wants_reply());
    }

    /// Frames are taken one at a time and a trailing partial one is retained.
    #[test]
    fn decoding_consumes_exactly_one_frame() {
        let mut buffer = BytesMut::new();
        buffer.extend_from_slice(&encode_sync(1, b"first"));
        buffer.extend_from_slice(&encode_sync(2, b"second"));
        buffer.extend_from_slice(&encode_sync(3, b"third")[..10]);

        let first = decode(&mut buffer).expect("decodes").expect("a frame");
        assert_eq!(first.payload, &b"first"[..]);
        assert_eq!(first.header.seqno, 1);

        let second = decode(&mut buffer).expect("decodes").expect("a frame");
        assert_eq!(second.payload, &b"second"[..]);

        assert!(decode(&mut buffer).expect("decodes").is_none());
        assert_eq!(buffer.len(), 10);
    }

    /// Fewer bytes than a header is "wait", not an error.
    #[test]
    fn a_short_buffer_is_not_an_error() {
        let mut buffer = BytesMut::from(&[0u8; 31][..]);
        assert!(decode(&mut buffer).expect("decodes").is_none());
        assert_eq!(buffer.len(), 31);
    }

    /// A size that does not cover the header is refused rather than producing a negative-length
    /// payload, which is what upstream's slice arithmetic would do.
    #[test]
    fn a_size_under_the_header_length_is_rejected() {
        let mut wire = encode_reply(1);
        wire[3] = 0x1F;

        assert!(DataHeader::decode(&wire).is_err());
        assert!(decode(&mut BytesMut::from(&wire[..])).is_err());
    }
}
