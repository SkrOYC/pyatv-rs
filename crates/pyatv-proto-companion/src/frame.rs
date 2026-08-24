//! Companion frame framing: one type byte plus a three-byte big-endian length.
//!
//! Transcribed from `pyatv/protocols/companion/connection.py:16-40,98-119,126-153`; see
//! `docs/research/companion-port-spec.md` §1.1-§1.2.
//!
//! The length field counts the payload only, and when encryption is active it counts the
//! sixteen-byte Poly1305 tag as well. The four header bytes are then used verbatim as the AEAD's
//! associated data, which binds the declared type and length to the ciphertext. [`crate::codec`]
//! owns that arithmetic; this module is only the header itself.

use bytes::{BufMut, BytesMut};

use crate::{Error, Result};

/// Length of the frame header in bytes (`connection.py:17`).
pub const HEADER_LENGTH: usize = 4;

/// The largest payload a three-byte length field can describe.
///
/// This is the *format's* ceiling, not the one this crate enforces; see
/// [`crate::codec::MAX_FRAME_PAYLOAD`].
pub const MAX_ENCODABLE_PAYLOAD: usize = 0x00FF_FFFF;

/// What a frame carries.
///
/// The numbering is sparse and is what appears on the wire, so it is mirrored exactly rather than
/// compacted (`connection.py:21-40`). Value `2` is absent upstream with no explanation, as are
/// `12..=15`, `19..=31` and `35..`.
///
/// pyatv's client only ever *acts* on the four auth types and the three OPACK types: every other
/// variant is logged and dropped by `frame_received` (`protocol.py:192-207`), and no code anywhere
/// in `pyatv/protocols/companion/` constructs one. This port mirrors that ignorance deliberately —
/// see `docs/research/companion-port-spec.md` §12 finding 1 — so the remaining variants exist to
/// name what arrives, not to be sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    /// Unspecified.
    Unknown = 0,
    /// Keepalive. pyatv never sends one and there is no Companion-level heartbeat.
    NoOp = 1,
    /// Pair-setup, first message.
    PsStart = 3,
    /// Pair-setup, subsequent messages — including the reply to [`FrameType::PsStart`].
    PsNext = 4,
    /// Pair-verify, first message.
    PvStart = 5,
    /// Pair-verify, subsequent messages — including the reply to [`FrameType::PvStart`].
    PvNext = 6,
    /// Unencrypted OPACK.
    UOpack = 7,
    /// Encrypted OPACK. Carries every command and event once the session is up.
    EOpack = 8,
    /// OPACK variant whose purpose pyatv's source does not explain.
    POpack = 9,
    /// Pairing-adjacent request. Never constructed or parsed by pyatv.
    PaReq = 10,
    /// Pairing-adjacent response. Never constructed or parsed by pyatv.
    PaRsp = 11,
    /// Session start request. Never constructed or parsed by pyatv.
    SessionStartRequest = 16,
    /// Session start response. Never constructed or parsed by pyatv.
    SessionStartResponse = 17,
    /// Session payload. Never constructed or parsed by pyatv.
    SessionData = 18,
    /// Family identity request. Never constructed or parsed by pyatv.
    FamilyIdentityRequest = 32,
    /// Family identity response. Never constructed or parsed by pyatv.
    FamilyIdentityResponse = 33,
    /// Family identity update. Never constructed or parsed by pyatv.
    FamilyIdentityUpdate = 34,
}

impl FrameType {
    /// Map a raw type byte onto a known frame type.
    ///
    /// `None` for anything unlisted. pyatv's `FrameType(header[0])` raises `ValueError` there,
    /// caught by `data_received`'s blanket `except` and logged (`connection.py:151-153`), so an
    /// unknown byte drops one frame rather than killing the connection.
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

    /// Whether this type carries an OPACK pairing envelope (`_pd`) rather than a message envelope.
    ///
    /// `_AUTH_FRAMES` (`protocol.py:25-30`).
    #[must_use]
    pub const fn is_auth(self) -> bool {
        matches!(
            self,
            Self::PsStart | Self::PsNext | Self::PvStart | Self::PvNext
        )
    }

    /// Whether this type carries an `_i`/`_t`/`_x`/`_c` message envelope.
    ///
    /// `_OPACK_FRAMES` (`protocol.py:32-36`).
    #[must_use]
    pub const fn is_opack(self) -> bool {
        matches!(self, Self::UOpack | Self::EOpack | Self::POpack)
    }

    /// The frame type the device answers a handshake message with.
    ///
    /// Port of the remap in `exchange_auth` (`protocol.py:132-140`): `*_Start` is only ever used
    /// for the *first* outbound message of a handshake, and the device's reply to it already comes
    /// back typed `*_Next`. From the second message on, request and response types coincide, so
    /// this is the identity for everything else.
    #[must_use]
    pub const fn response_type(self) -> Self {
        match self {
            Self::PsStart => Self::PsNext,
            Self::PvStart => Self::PvNext,
            other => other,
        }
    }
}

/// A decoded frame header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    /// What the frame carries.
    pub frame_type: FrameType,
    /// Payload length in bytes, excluding these four header bytes but **including** the
    /// sixteen-byte auth tag when the payload is encrypted.
    pub payload_length: usize,
}

impl FrameHeader {
    /// Build a header for a payload of the given on-wire length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] if the length does not fit the three-byte field.
    pub fn new(frame_type: FrameType, payload_length: usize) -> Result<Self> {
        if payload_length > MAX_ENCODABLE_PAYLOAD {
            return Err(Error::Framing(format!(
                "payload of {payload_length} bytes exceeds the {MAX_ENCODABLE_PAYLOAD}-byte frame \
                 length field"
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
        // `FrameHeader::new` caps the length at MAX_ENCODABLE_PAYLOAD, so only the low three bytes
        // are ever significant; the saturating conversion is for the compiler, not the wire.
        let length = u32::try_from(self.payload_length)
            .unwrap_or(u32::MAX)
            .to_be_bytes();
        header[1..].copy_from_slice(&length[1..]);
        header
    }

    /// Decode the four wire bytes.
    ///
    /// The length is read as a `u24` from bytes 1..4, never as a `u32` over all four
    /// (`connection.py:132-134` slices `[1:HEADER_LENGTH]`), so the type byte can never leak into
    /// the length.
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

    /// Total bytes this frame occupies on the wire, header included.
    ///
    /// This is what pyatv confusingly also calls `payload_length` (`connection.py:132-135`).
    #[must_use]
    pub const fn total_length(&self) -> usize {
        HEADER_LENGTH + self.payload_length
    }
}

/// Write a complete frame: header followed by an already-sealed payload.
///
/// The caller is responsible for having added the auth tag to `payload` before calling, because
/// the length field must count it; [`crate::codec::FrameCodec::encode`] is the entry point that
/// gets that right.
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
    use super::{FrameHeader, FrameType, HEADER_LENGTH, MAX_ENCODABLE_PAYLOAD, encode_frame};

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
        assert!(FrameHeader::new(FrameType::EOpack, MAX_ENCODABLE_PAYLOAD).is_ok());
        assert!(FrameHeader::new(FrameType::EOpack, MAX_ENCODABLE_PAYLOAD + 1).is_err());
    }

    /// Type 2 is undefined upstream and must not silently decode.
    #[test]
    fn undefined_type_bytes_are_rejected() {
        assert_eq!(FrameType::from_byte(2), None);
        assert!(FrameHeader::decode(&[0x02, 0, 0, 0]).is_err());
        assert!(FrameHeader::decode(&[0x08, 0, 0]).is_err());
    }

    /// The type byte must never be read as part of the length: a 0xFF type with a zero length is
    /// still a zero-length frame, not a 4-gigabyte one.
    #[test]
    fn the_length_is_a_u24_not_a_u32() {
        let header = FrameHeader::decode(&[0x08, 0xFF, 0xFF, 0xFF]).unwrap();
        assert_eq!(header.payload_length, MAX_ENCODABLE_PAYLOAD);
        assert_eq!(
            FrameHeader::decode(&[0x08, 0, 0, 0])
                .unwrap()
                .payload_length,
            0
        );
    }

    #[test]
    fn a_whole_frame_is_the_header_followed_by_the_payload() {
        let frame = encode_frame(FrameType::UOpack, b"body").unwrap();
        assert_eq!(
            &frame[..],
            &[0x07, 0x00, 0x00, 0x04, b'b', b'o', b'd', b'y']
        );
    }

    /// `*_Start` is outbound-only; the device answers with `*_Next` (`protocol.py:132-140`).
    #[test]
    fn only_the_two_start_types_remap_to_a_different_response() {
        assert_eq!(FrameType::PsStart.response_type(), FrameType::PsNext);
        assert_eq!(FrameType::PvStart.response_type(), FrameType::PvNext);
        assert_eq!(FrameType::PsNext.response_type(), FrameType::PsNext);
        assert_eq!(FrameType::PvNext.response_type(), FrameType::PvNext);
        assert_eq!(FrameType::EOpack.response_type(), FrameType::EOpack);
    }

    #[test]
    fn auth_and_opack_frames_are_disjoint_sets() {
        for frame_type in [
            FrameType::PsStart,
            FrameType::PsNext,
            FrameType::PvStart,
            FrameType::PvNext,
        ] {
            assert!(frame_type.is_auth());
            assert!(!frame_type.is_opack());
        }
        for frame_type in [FrameType::UOpack, FrameType::EOpack, FrameType::POpack] {
            assert!(frame_type.is_opack());
            assert!(!frame_type.is_auth());
        }
        assert!(!FrameType::NoOp.is_auth() && !FrameType::NoOp.is_opack());
    }
}
