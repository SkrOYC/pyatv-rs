//! Companion frame framing: one type byte plus a three-byte big-endian length.
//!
//! Transcribed from `pyatv/protocols/companion/connection.py`; see
//! `docs/research/mrp-companion.md` §4.2.
//!
//! The length field counts the payload only, and when encryption is active the payload includes the
//! sixteen-byte Poly1305 tag. The four header bytes are used verbatim as the AEAD's associated
//! data, which binds the declared type and length to the ciphertext.

use bytes::{BufMut, BytesMut};

use crate::{Error, Result};

/// Length of the frame header in bytes.
pub const HEADER_LENGTH: usize = 4;

/// The largest payload a three-byte length field can describe.
pub const MAX_PAYLOAD: usize = 0x00FF_FFFF;

/// What a frame carries.
///
/// Value `2` is not defined upstream and is presumed reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Unspecified.
    Unknown = 0,
    /// Keepalive.
    NoOp = 1,
    /// Pair-setup, first message.
    PsStart = 3,
    /// Pair-setup, subsequent messages.
    PsNext = 4,
    /// Pair-verify, first message.
    PvStart = 5,
    /// Pair-verify, subsequent messages.
    PvNext = 6,
    /// Unencrypted OPACK.
    UOpack = 7,
    /// Encrypted OPACK. Carries every command and event once the session is up.
    EOpack = 8,
    /// OPACK variant whose purpose pyatv's source does not explain.
    POpack = 9,
    /// Pairing-adjacent request.
    PaReq = 10,
    /// Pairing-adjacent response.
    PaRsp = 11,
    /// Session start request.
    SessionStartRequest = 16,
    /// Session start response.
    SessionStartResponse = 17,
    /// Session payload.
    SessionData = 18,
    /// Family identity request.
    FamilyIdentityRequest = 32,
    /// Family identity response.
    FamilyIdentityResponse = 33,
    /// Family identity update.
    FamilyIdentityUpdate = 34,
}

impl FrameType {
    /// Map a raw type byte onto a known frame type.
    #[must_use]
    pub const fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Unknown,
            1 => Self::NoOp,
            3 => Self::PsStart,
            4 => Self::PsNext,
            5 => Self::PvStart,
            6 => Self::PvNext,
            7 => Self::UOpack,
            8 => Self::EOpack,
            9 => Self::POpack,
            10 => Self::PaReq,
            11 => Self::PaRsp,
            16 => Self::SessionStartRequest,
            17 => Self::SessionStartResponse,
            18 => Self::SessionData,
            32 => Self::FamilyIdentityRequest,
            33 => Self::FamilyIdentityResponse,
            34 => Self::FamilyIdentityUpdate,
            _ => return None,
        })
    }

    /// Whether frames of this type are ChaCha20-Poly1305 sealed once a session exists.
    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::EOpack)
    }
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// What the frame carries.
    pub frame_type: FrameType,
    /// Payload length in bytes, excluding these four header bytes but including the auth tag when
    /// the payload is encrypted.
    pub payload_length: usize,
}

impl FrameHeader {
    /// Build a header for a payload of the given length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] if the payload exceeds [`MAX_PAYLOAD`].
    pub fn new(frame_type: FrameType, payload_length: usize) -> Result<Self> {
        if payload_length > MAX_PAYLOAD {
            return Err(Error::Framing(format!(
                "payload of {payload_length} bytes exceeds the {MAX_PAYLOAD}-byte frame limit"
            )));
        }
        Ok(Self {
            frame_type,
            payload_length,
        })
    }

    /// Encode to the four wire bytes, which double as the AEAD associated data.
    #[must_use]
    pub fn encode(&self) -> [u8; HEADER_LENGTH] {
        let mut header = [0u8; HEADER_LENGTH];
        header[0] = self.frame_type as u8;
        // `FrameHeader::new` caps the length at MAX_PAYLOAD, so only the low three bytes are ever
        // significant here.
        let length = u32::try_from(self.payload_length)
            .unwrap_or(u32::MAX)
            .to_be_bytes();
        header[1..].copy_from_slice(&length[1..]);
        header
    }

    /// Decode the four wire bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] if fewer than [`HEADER_LENGTH`] bytes are supplied or the type
    /// byte is not a known [`FrameType`].
    pub fn decode(input: &[u8]) -> Result<Self> {
        let bytes: [u8; HEADER_LENGTH] = input
            .get(..HEADER_LENGTH)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| {
                Error::Framing(format!(
                    "need {HEADER_LENGTH} header bytes, got {}",
                    input.len()
                ))
            })?;

        let frame_type = FrameType::from_byte(bytes[0])
            .ok_or_else(|| Error::Framing(format!("unknown frame type {:#04x}", bytes[0])))?;

        let payload_length =
            usize::from(bytes[1]) << 16 | usize::from(bytes[2]) << 8 | usize::from(bytes[3]);

        Ok(Self {
            frame_type,
            payload_length,
        })
    }

    /// Total bytes this frame occupies on the wire.
    #[must_use]
    pub const fn total_length(&self) -> usize {
        HEADER_LENGTH + self.payload_length
    }
}

/// Write a complete frame: header followed by an already-sealed payload.
///
/// # Errors
///
/// Returns [`Error::Framing`] if the payload is too large for the length field.
pub fn encode_frame(frame_type: FrameType, payload: &[u8]) -> Result<BytesMut> {
    let header = FrameHeader::new(frame_type, payload.len())?;

    let mut out = BytesMut::with_capacity(header.total_length());
    out.put_slice(&header.encode());
    out.put_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{FrameHeader, FrameType, HEADER_LENGTH, MAX_PAYLOAD, encode_frame};

    /// The length is three bytes big-endian, so 0x010203 lands as those bytes in order.
    #[test]
    fn header_encodes_a_big_endian_three_byte_length() {
        let header = FrameHeader::new(FrameType::EOpack, 0x0001_0203).unwrap();
        assert_eq!(header.encode(), [0x08, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn header_round_trips() {
        for frame_type in [
            FrameType::NoOp,
            FrameType::PsStart,
            FrameType::EOpack,
            FrameType::FamilyIdentityUpdate,
        ] {
            let header = FrameHeader::new(frame_type, 42).unwrap();
            assert_eq!(FrameHeader::decode(&header.encode()).unwrap(), header);
        }
    }

    #[test]
    fn total_length_includes_the_header() {
        let header = FrameHeader::new(FrameType::EOpack, 100).unwrap();
        assert_eq!(header.total_length(), HEADER_LENGTH + 100);
    }

    #[test]
    fn oversized_payloads_are_rejected() {
        assert!(FrameHeader::new(FrameType::EOpack, MAX_PAYLOAD).is_ok());
        assert!(FrameHeader::new(FrameType::EOpack, MAX_PAYLOAD + 1).is_err());
    }

    /// Type 2 is undefined upstream and must not silently decode.
    #[test]
    fn undefined_type_bytes_are_rejected() {
        assert_eq!(FrameType::from_byte(2), None);
        assert!(FrameHeader::decode(&[0x02, 0, 0, 0]).is_err());
        assert!(FrameHeader::decode(&[0x08, 0, 0]).is_err());
    }

    #[test]
    fn a_whole_frame_is_the_header_followed_by_the_payload() {
        let frame = encode_frame(FrameType::UOpack, b"body").unwrap();
        assert_eq!(
            &frame[..],
            &[0x07, 0x00, 0x00, 0x04, b'b', b'o', b'd', b'y']
        );
    }

    /// Only `E_OPACK` is sealed; pairing frames travel in the clear by definition.
    #[test]
    fn only_encrypted_opack_is_sealed() {
        assert!(FrameType::EOpack.is_encrypted());
        assert!(!FrameType::UOpack.is_encrypted());
        assert!(!FrameType::PsStart.is_encrypted());
    }
}
