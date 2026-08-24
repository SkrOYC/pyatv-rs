//! The sans-io Companion frame codec: buffering, the length arithmetic and the AEAD boundary.
//!
//! Port of `CompanionConnection.send`/`data_received` (`connection.py:98-153`) with the socket
//! taken out, so the framing can be tested against exact bytes with no runtime involved. The
//! tokio side lives in [`crate::connection`].
//!
//! Three rules from `docs/research/companion-port-spec.md` §1.1 that are easy to get subtly wrong:
//!
//! 1. **The length field is adjusted before it becomes AAD.** When a session key is installed and
//!    the payload is non-empty, sixteen is added to the transmitted length *first*, and the header
//!    carrying that already-adjusted length is what gets authenticated (`connection.py:103-116`).
//! 2. **Zero-length payloads are never sealed**, even mid-session. Both directions test
//!    `len(data) > 0` before touching the cipher (`connection.py:104,115,148`), so an empty frame
//!    travels in the clear with a zero length field and no tag. Forcing an AEAD call there would
//!    emit sixteen bytes the peer never expects.
//! 3. **The nonce is a bare twelve-byte little-endian counter**, not the zero-prefixed eight-byte
//!    one HAP framing uses — `Chacha20Cipher(..., nonce_length=12)` (`connection.py:92`) never
//!    reaches `_pad_nonce`. That is [`pyatv_pairing::chacha::Chacha20Cipher::with_bare_counter`].

use bytes::{Buf, BytesMut};
use pyatv_pairing::chacha::{AUTH_TAG_LENGTH, Chacha20Cipher};

use crate::frame::{FrameHeader, FrameType, HEADER_LENGTH};
use crate::{Error, Result};

/// The largest frame payload this codec will accept, in bytes.
///
/// **A deliberate divergence from pyatv, which enforces no bound at all** — a three-byte length
/// field lets a hostile or corrupt peer claim just under 16 MiB per frame and pyatv would buffer
/// for it (`docs/research/companion-port-spec.md` §12 finding 2). One mebibyte is roughly two
/// orders of magnitude above the largest payload Companion is known to carry (an app list of a few
/// hundred bundle identifiers and display names; artwork goes over other protocols), so it cannot
/// be hit by an honest device while capping what a single frame can make this process allocate.
///
/// Exceeding it is fatal to the connection rather than a dropped frame: a length that is not
/// trusted cannot be skipped over, because skipping requires trusting it.
pub const MAX_FRAME_PAYLOAD: usize = 1024 * 1024;

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// What the frame carried.
    pub frame_type: FrameType,
    /// The plaintext payload, already opened if the session was encrypted.
    pub payload: Vec<u8>,
}

/// Framing state for one Companion connection.
///
/// Holds the inbound byte accumulator and, once [`FrameCodec::enable_encryption`] has run, the
/// transport cipher. Both directions share one [`Chacha20Cipher`] because it keeps a counter per
/// direction internally, exactly as pyatv's single `self._chacha` does.
#[derive(Debug)]
pub struct FrameCodec {
    buffer: BytesMut,
    cipher: Option<Chacha20Cipher>,
}

impl Default for FrameCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameCodec {
    /// A codec for a connection that has not yet been encrypted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
            cipher: None,
        }
    }

    /// Install the transport keys pair-verify derived.
    ///
    /// `output_key` seals what this side sends and `input_key` opens what it receives, matching
    /// `enable_encryption(output_key, input_key)` (`connection.py:90-92`). For Companion the two
    /// come from the `ClientEncrypt-main` and `ServerEncrypt-main` info strings respectively — the
    /// names disambiguate the roles on their own, so unlike MRP there is no positional swap
    /// (`docs/research/hap-pairing-port-spec.md` §4.3).
    ///
    /// Calling this twice restarts both counters, which would reuse nonces under live keys; the
    /// connection layer only ever calls it once, after a successful pair-verify.
    pub fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]) {
        self.cipher = Some(Chacha20Cipher::with_bare_counter(&output_key, &input_key));
    }

    /// Whether a session key is installed.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.cipher.is_some()
    }

    /// How many bytes are buffered but not yet a whole frame.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.buffer.len()
    }

    /// Serialise one frame, sealing the payload when a session key is installed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] if the sealed payload would exceed [`MAX_FRAME_PAYLOAD`], or
    /// [`Error::Pairing`] if the AEAD seal fails.
    pub fn encode(&mut self, frame_type: FrameType, payload: &[u8]) -> Result<BytesMut> {
        // Rule 1 and rule 2: the tag budget joins the length before the header exists, and an
        // empty payload skips the cipher entirely.
        let sealed_length = if self.cipher.is_some() && !payload.is_empty() {
            payload.len() + AUTH_TAG_LENGTH
        } else {
            payload.len()
        };

        if sealed_length > MAX_FRAME_PAYLOAD {
            return Err(Error::Framing(format!(
                "outbound {frame_type:?} frame of {sealed_length} bytes exceeds the \
                 {MAX_FRAME_PAYLOAD}-byte limit"
            )));
        }

        let header = FrameHeader::new(frame_type, sealed_length)?;
        let header_bytes = header.encode();

        let body = match self.cipher.as_mut() {
            Some(cipher) if !payload.is_empty() => cipher.encrypt(payload, Some(&header_bytes))?,
            _ => payload.to_vec(),
        };

        let mut out = BytesMut::with_capacity(header.total_length());
        out.extend_from_slice(&header_bytes);
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Add freshly read bytes to the inbound buffer.
    pub fn push(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Take the next whole frame, or `None` while one is still arriving.
    ///
    /// Partial frames — a header that is not yet four bytes, or a payload still in flight — leave
    /// the buffer untouched and return `None`, so this can be called after every read
    /// (`connection.py:131-141`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] for an unknown frame type or a length above
    /// [`MAX_FRAME_PAYLOAD`], and [`Error::Pairing`] if the payload does not open. All three
    /// leave the connection unusable: pyatv logs and continues (`connection.py:152-153`), but it
    /// can only do so because it never validates the length in the first place. Here, a frame that
    /// fails to open has already advanced the inbound counter, and a length that is refused cannot
    /// be skipped without trusting it.
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.buffer.len() < HEADER_LENGTH {
            return Ok(None);
        }

        let header = FrameHeader::decode(&self.buffer[..HEADER_LENGTH])?;
        if header.payload_length > MAX_FRAME_PAYLOAD {
            return Err(Error::Framing(format!(
                "inbound {:?} frame declares {} bytes, above the {MAX_FRAME_PAYLOAD}-byte limit",
                header.frame_type, header.payload_length
            )));
        }

        let total = header.total_length();
        if self.buffer.len() < total {
            return Ok(None);
        }

        let header_bytes = header.encode();
        let frame = self.buffer.split_to(total);
        let body = &frame[HEADER_LENGTH..];

        let payload = match self.cipher.as_mut() {
            Some(cipher) if !body.is_empty() => cipher.decrypt(body, Some(&header_bytes))?,
            _ => body.to_vec(),
        };

        Ok(Some(Frame {
            frame_type: header.frame_type,
            payload,
        }))
    }

    /// Discard whatever is buffered, for a connection being torn down.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Reserve room for one more read, so `push` does not reallocate per chunk.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.buffer.reserve(additional);
    }

    /// The inbound buffer, for a reader that fills it in place.
    pub(crate) fn buffer_mut(&mut self) -> &mut BytesMut {
        &mut self.buffer
    }

    /// Whether the buffer holds anything at all, used to tell a clean close from a truncated one.
    pub(crate) fn has_remaining(&self) -> bool {
        self.buffer.has_remaining()
    }
}

#[cfg(test)]
mod tests {
    use super::{FrameCodec, MAX_FRAME_PAYLOAD};
    use crate::frame::FrameType;

    /// Two codecs wired back to back, as a client and a device would be after pair-verify.
    fn paired_codecs() -> (FrameCodec, FrameCodec) {
        let client_out = [0x11; 32];
        let client_in = [0x22; 32];

        let mut client = FrameCodec::new();
        let mut device = FrameCodec::new();
        client.enable_encryption(client_out, client_in);
        // The device's roles are the mirror image: it seals with what the client opens with.
        device.enable_encryption(client_in, client_out);
        (client, device)
    }

    #[test]
    fn a_plaintext_frame_is_the_header_then_the_body() {
        let mut codec = FrameCodec::new();
        let encoded = codec.encode(FrameType::PsStart, b"hello").unwrap();
        assert_eq!(&encoded[..], b"\x03\x00\x00\x05hello");
    }

    #[test]
    fn an_empty_plaintext_frame_is_four_bytes() {
        let mut codec = FrameCodec::new();
        let encoded = codec.encode(FrameType::NoOp, b"").unwrap();
        assert_eq!(&encoded[..], &[0x01, 0x00, 0x00, 0x00]);
    }

    /// The declared length is the plaintext length plus the sixteen-byte tag, and the frame is
    /// exactly that long on the wire (`connection.py:103-119`).
    #[test]
    fn encryption_adds_the_tag_to_the_declared_length() {
        let (mut client, _) = paired_codecs();
        let encoded = client.encode(FrameType::EOpack, b"body").unwrap();

        assert_eq!(encoded[0], FrameType::EOpack as u8);
        assert_eq!(&encoded[1..4], &[0x00, 0x00, 4 + 16]);
        assert_eq!(encoded.len(), 4 + 4 + 16);
        assert_ne!(&encoded[4..8], b"body", "the body must not be in the clear");
    }

    /// Rule 2: a zero-length payload skips the AEAD even with a live session key, so the frame
    /// stays four bytes rather than growing a tag.
    #[test]
    fn an_empty_payload_is_never_sealed_even_mid_session() {
        let (mut client, mut device) = paired_codecs();

        let encoded = client.encode(FrameType::NoOp, b"").unwrap();
        assert_eq!(&encoded[..], &[0x01, 0x00, 0x00, 0x00]);

        device.push(&encoded);
        let frame = device.next_frame().unwrap().unwrap();
        assert_eq!(frame.frame_type, FrameType::NoOp);
        assert!(frame.payload.is_empty());

        // And the counters did not move: the next sealed frame still decrypts.
        let sealed = client.encode(FrameType::EOpack, b"after").unwrap();
        device.push(&sealed);
        assert_eq!(device.next_frame().unwrap().unwrap().payload, b"after");
    }

    #[test]
    fn sealed_frames_round_trip_in_order() {
        let (mut client, mut device) = paired_codecs();

        for index in 0u8..5 {
            let payload = vec![index; 32];
            let encoded = client.encode(FrameType::EOpack, &payload).unwrap();
            device.push(&encoded);
            assert_eq!(device.next_frame().unwrap().unwrap().payload, payload);
        }
    }

    /// Rule 1: the header is the AEAD's associated data, so retyping a frame in flight must break
    /// the tag rather than silently deliver the body under a different type.
    #[test]
    fn tampering_with_the_header_breaks_the_tag() {
        let (mut client, mut device) = paired_codecs();

        let mut encoded = client.encode(FrameType::EOpack, b"body").unwrap();
        encoded[0] = FrameType::POpack as u8;

        device.push(&encoded);
        assert!(device.next_frame().is_err());
    }

    /// A frame arriving one byte at a time must decode exactly once, at the last byte.
    #[test]
    fn a_frame_split_across_reads_decodes_once_complete() {
        let mut writer = FrameCodec::new();
        let encoded = writer.encode(FrameType::UOpack, b"split payload").unwrap();

        let mut codec = FrameCodec::new();
        for (index, byte) in encoded.iter().enumerate() {
            codec.push(&[*byte]);
            let decoded = codec.next_frame().unwrap();
            if index + 1 == encoded.len() {
                assert_eq!(decoded.unwrap().payload, b"split payload");
            } else {
                assert!(decoded.is_none(), "frame decoded early at byte {index}");
            }
        }
        assert_eq!(codec.pending_bytes(), 0);
    }

    /// Several frames in one read must all come out, in order, and the trailing partial frame must
    /// stay buffered.
    #[test]
    fn a_read_holding_several_frames_yields_all_of_them() {
        let mut writer = FrameCodec::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(&writer.encode(FrameType::PsNext, b"one").unwrap());
        stream.extend_from_slice(&writer.encode(FrameType::PvNext, b"two").unwrap());
        stream.extend_from_slice(&writer.encode(FrameType::EOpack, b"three").unwrap());
        let truncated = stream.len() - 2;

        let mut codec = FrameCodec::new();
        codec.push(&stream[..truncated]);

        assert_eq!(codec.next_frame().unwrap().unwrap().payload, b"one");
        assert_eq!(codec.next_frame().unwrap().unwrap().payload, b"two");
        assert!(codec.next_frame().unwrap().is_none());
        assert_eq!(codec.pending_bytes(), truncated - 2 * (4 + 3));

        codec.push(&stream[truncated..]);
        assert_eq!(codec.next_frame().unwrap().unwrap().payload, b"three");
    }

    /// A header alone never yields a frame, however long the caller waits.
    #[test]
    fn a_bare_header_yields_nothing() {
        let mut codec = FrameCodec::new();
        codec.push(&[0x08, 0x00, 0x00, 0x10]);
        assert!(codec.next_frame().unwrap().is_none());
        assert_eq!(codec.pending_bytes(), 4);
    }

    #[test]
    fn an_unknown_frame_type_is_refused() {
        let mut codec = FrameCodec::new();
        codec.push(&[0x02, 0x00, 0x00, 0x00]);
        assert!(matches!(codec.next_frame(), Err(crate::Error::Framing(_))));
    }

    /// The bound this port adds over pyatv: a claimed length above the cap is refused before a
    /// byte of it is buffered.
    #[test]
    fn an_oversized_declared_length_is_refused_before_buffering() {
        let mut codec = FrameCodec::new();
        let length = u32::try_from(MAX_FRAME_PAYLOAD + 1).unwrap().to_be_bytes();
        codec.push(&[FrameType::EOpack as u8, length[1], length[2], length[3]]);

        assert!(matches!(codec.next_frame(), Err(crate::Error::Framing(_))));
    }

    #[test]
    fn a_payload_at_the_cap_is_still_accepted() {
        let mut codec = FrameCodec::new();
        let length = u32::try_from(MAX_FRAME_PAYLOAD).unwrap().to_be_bytes();
        codec.push(&[FrameType::EOpack as u8, length[1], length[2], length[3]]);

        // Refused only for want of bytes, not for the length itself.
        assert!(codec.next_frame().unwrap().is_none());
    }

    #[test]
    fn an_oversized_outbound_payload_is_refused() {
        let mut codec = FrameCodec::new();
        let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        assert!(codec.encode(FrameType::EOpack, &payload).is_err());
    }

    /// Encryption is one-way: what a codec sends before `enable_encryption` is plaintext, and what
    /// it sends after is not.
    #[test]
    fn enabling_encryption_changes_only_later_frames() {
        let mut codec = FrameCodec::new();
        assert!(!codec.is_encrypted());
        let clear = codec.encode(FrameType::PsStart, b"tlv").unwrap();
        assert_eq!(&clear[4..], b"tlv");

        codec.enable_encryption([0x33; 32], [0x44; 32]);
        assert!(codec.is_encrypted());
        let sealed = codec.encode(FrameType::EOpack, b"tlv").unwrap();
        assert_ne!(&sealed[4..7], b"tlv");
    }
}
