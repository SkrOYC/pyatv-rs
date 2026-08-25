//! The AirPlay HAP channel framing: 1024-byte chunks with a length-prefix AAD.
//!
//! Port of `pyatv/auth/hap_session.py:1-66`, driven by `pyatv/auth/hap_channel.py:52-72`.
//!
//! **This framing is AirPlay-only.** `docs/research/hap-pairing-port-spec.md` §4.0 corrects the
//! earlier research report on this point: the only importers of `hap_session`/`hap_channel` in
//! pyatv are the AirPlay RTSP control connection and the AirPlay 2 event and data-stream channels.
//! MRP encrypts a whole protobuf message per AEAD call with no AAD and no size cap, and Companion
//! uses a 4-byte frame header as AAD with a bare 12-byte counter — both talk to
//! [`crate::chacha::Chacha20Cipher`] directly and must not be routed through this type.
//!
//! Frame layout, per `hap_session.py:53-66`:
//!
//! ```text
//! | 2-byte LE plaintext length | ciphertext (length bytes) | 16-byte Poly1305 tag |
//!                       ^-- these two bytes are also the AEAD's associated data
//! ```

use crate::{
    Result,
    chacha::{Chacha20Cipher, NonceLayout},
};

pub use crate::chacha::{AUTH_TAG_LENGTH, NONCE_LENGTH, fixed_nonce};

/// Plaintext bytes per AEAD operation, "as specified by HAP, section 5.2.2 (Release R1)"
/// (`pyatv/auth/hap_session.py:17`).
pub const FRAME_LENGTH: usize = 1024;

/// Bytes of length prefix in front of each frame, also used verbatim as the AEAD's AAD.
pub const LENGTH_PREFIX_LEN: usize = 2;

// The length prefix is two bytes, so a frame can never be larger than `u16::MAX`. This makes the
// conversion in `encrypt` provably infallible.
const _: () = assert!(FRAME_LENGTH <= u16::MAX as usize);

/// Encrypted transport for an AirPlay HAP channel, after pair-verify has completed.
///
/// Read and write directions keep independent keys and counters. Inbound data is buffered
/// internally so a caller can feed arbitrary TCP segments in and get whole frames out, exactly as
/// `HAPSession._encrypted_data` does (`pyatv/auth/hap_session.py:24,36-51`).
#[derive(Debug)]
pub struct HapSession {
    cipher: Chacha20Cipher,
    buffer: Vec<u8>,
}

impl HapSession {
    /// Build a session from the two derived transport keys.
    ///
    /// Argument order matches `HAPSession.enable(output_key, input_key)`
    /// (`pyatv/auth/hap_session.py:27-29`): `output_key` encrypts what this side sends.
    #[must_use]
    pub fn new(output_key: &[u8; 32], input_key: &[u8; 32]) -> Self {
        Self {
            cipher: Chacha20Cipher::new(output_key, input_key, NonceLayout::PaddedCounter),
            buffer: Vec::new(),
        }
    }

    /// Bytes of a partial inbound frame currently held back.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Frame and encrypt `plaintext`, splitting it at [`FRAME_LENGTH`].
    ///
    /// An empty input produces an empty output and consumes no counter value: `while data:`
    /// (`pyatv/auth/hap_session.py:59`) never enters the loop.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Aead`] if the AEAD seal fails.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut output = Vec::with_capacity(framed_len(plaintext.len()));

        for chunk in plaintext.chunks(FRAME_LENGTH) {
            // `len(frame)` is at most FRAME_LENGTH, so this cast cannot truncate.
            let length = u16::try_from(chunk.len()).unwrap_or(u16::MAX).to_le_bytes();
            let frame = self.cipher.encrypt(chunk, Some(&length))?;

            output.extend_from_slice(&length);
            output.extend_from_slice(&frame);
        }

        Ok(output)
    }

    /// Buffer `ciphertext` and return the plaintext of every frame that is now complete.
    ///
    /// A trailing partial frame is retained for the next call, so this can be fed raw socket reads.
    ///
    /// The inbound length prefix is trusted up to its own `u16` ceiling, exactly as pyatv trusts it
    /// (`pyatv/auth/hap_session.py:36-51`).
    ///
    /// **[`FRAME_LENGTH`] bounds what this side *sends*, not what it accepts.** An earlier version
    /// of this port rejected any inbound prefix above 1024 on the reasoning that nothing conformant
    /// could produce one. A live run against an Apple TV 4K (gen 3) on tvOS 27.0 on 2026-08-25
    /// disproved that: the remote-control data channel delivered a single block claiming **8931**
    /// plaintext bytes, whose Poly1305 tag verified and whose contents decoded as a well-formed
    /// 8899-byte `sync`/`cmnd` data frame carrying a `SET_STATE_MESSAGE`. Real firmware does not
    /// chunk at the HAP "cap" on that channel, so enforcing it tore the tunnel down on the first
    /// now-playing update every time.
    ///
    /// Nothing is lost by trusting it. The prefix is two bytes, so a frame is bounded at 64 KiB by
    /// the format itself — a bound the buffer would hit anyway — and a desynchronised stream still
    /// fails the tag on the very next block.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Aead`] if a frame's tag does not verify. The session is not
    /// recoverable afterwards: pyatv advances the inbound counter before decrypting
    /// (`pyatv/support/chacha20.py:68-70`), so the stream is permanently out of step with the peer.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.buffer.extend_from_slice(ciphertext);

        let mut output = Vec::new();
        let mut consumed = 0usize;

        while let Some(rest) = self.buffer.get(consumed..) {
            let Some(length) = rest.get(..LENGTH_PREFIX_LEN) else {
                break;
            };
            let plaintext_length = usize::from(u16::from_le_bytes([length[0], length[1]]));
            let block_length = plaintext_length + AUTH_TAG_LENGTH;
            let Some(block) = rest.get(LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + block_length) else {
                break;
            };

            // The AAD is the two length bytes exactly as they arrived, not a re-encoding of the
            // decoded length (`pyatv/auth/hap_session.py:40-48`).
            let aad = [length[0], length[1]];
            output.extend_from_slice(&self.cipher.decrypt(block, Some(&aad))?);
            consumed += LENGTH_PREFIX_LEN + block_length;
        }

        self.buffer.drain(..consumed);
        Ok(output)
    }
}

/// Size of the framed form of a `plaintext_len`-byte payload.
fn framed_len(plaintext_len: usize) -> usize {
    let frames = plaintext_len.div_ceil(FRAME_LENGTH);
    plaintext_len + frames * (LENGTH_PREFIX_LEN + AUTH_TAG_LENGTH)
}

#[cfg(test)]
mod tests {
    use super::{AUTH_TAG_LENGTH, FRAME_LENGTH, HapSession, LENGTH_PREFIX_LEN};
    use crate::chacha::{Chacha20Cipher, NonceLayout};

    const OUT_KEY: [u8; 32] = [b'o'; 32];
    const IN_KEY: [u8; 32] = [b'i'; 32];

    /// One session's output must decrypt in a peer session whose keys are swapped, which is how a
    /// controller and an accessory actually face each other.
    fn peer() -> (HapSession, HapSession) {
        (
            HapSession::new(&OUT_KEY, &IN_KEY),
            HapSession::new(&IN_KEY, &OUT_KEY),
        )
    }

    #[test]
    fn short_payload_is_one_frame_and_round_trips() {
        let (mut local, mut remote) = peer();

        let framed = local.encrypt(b"hello").expect("encrypt");

        assert_eq!(framed.len(), LENGTH_PREFIX_LEN + 5 + AUTH_TAG_LENGTH);
        assert_eq!(&framed[..2], &[5, 0]);
        assert_eq!(remote.decrypt(&framed).expect("decrypt"), b"hello");
    }

    /// The frame bytes are checked against an independently driven cipher rather than against a
    /// hard-coded blob, so this tests the framing (chunking, prefix, AAD choice) and not just that
    /// the code agrees with itself.
    #[test]
    fn frame_bytes_match_the_primitive_driven_by_hand() {
        let mut session = HapSession::new(&OUT_KEY, &IN_KEY);
        let reference = Chacha20Cipher::new(&OUT_KEY, &IN_KEY, NonceLayout::PaddedCounter);

        let payload = b"exact frame bytes";
        let framed = session.encrypt(payload).expect("encrypt");

        let length = [0x11, 0x00];
        let expected = reference
            .encrypt_with_nonce(payload, &NonceLayout::PaddedCounter.nonce(0), Some(&length))
            .expect("reference encrypt");

        assert_eq!(&framed[..2], &length);
        assert_eq!(&framed[2..], expected.as_slice());
        // The reference call above used a fixed nonce and so left its counter at zero; the session
        // must have advanced its own.
        assert_eq!(reference.out_nonce(), NonceLayout::PaddedCounter.nonce(0));
    }

    /// Anything past 1024 bytes must be split, and each frame gets the next counter value.
    #[test]
    fn payloads_are_chunked_at_the_frame_length() {
        let (mut local, mut remote) = peer();
        let payload = vec![0x5Au8; FRAME_LENGTH * 2 + 1];

        let framed = local.encrypt(&payload).expect("encrypt");

        assert_eq!(
            framed.len(),
            payload.len() + 3 * (LENGTH_PREFIX_LEN + AUTH_TAG_LENGTH)
        );
        assert_eq!(&framed[..2], &[0x00, 0x04]);
        assert_eq!(remote.decrypt(&framed).expect("decrypt"), payload);
    }

    /// A payload that is an exact multiple of the frame length must not emit a trailing empty
    /// frame.
    #[test]
    fn an_exact_multiple_emits_no_empty_trailing_frame() {
        let (mut local, mut remote) = peer();
        let payload = vec![0x01u8; FRAME_LENGTH];

        let framed = local.encrypt(&payload).expect("encrypt");

        assert_eq!(
            framed.len(),
            FRAME_LENGTH + LENGTH_PREFIX_LEN + AUTH_TAG_LENGTH
        );
        assert_eq!(remote.decrypt(&framed).expect("decrypt"), payload);
    }

    /// `while data:` never runs for an empty payload, so nothing goes on the wire.
    #[test]
    fn an_empty_payload_produces_no_frame() {
        let mut session = HapSession::new(&OUT_KEY, &IN_KEY);

        assert!(session.encrypt(b"").expect("encrypt").is_empty());
    }

    /// Feeding the stream one byte at a time must reassemble both frames and hold back nothing at
    /// the end.
    #[test]
    fn partial_frames_are_buffered_until_complete() {
        let (mut local, mut remote) = peer();
        let first = local.encrypt(b"first message").expect("encrypt");
        let second = local
            .encrypt(&vec![0x7Fu8; FRAME_LENGTH + 5])
            .expect("encrypt");

        let mut stream = first;
        stream.extend_from_slice(&second);

        let mut received = Vec::new();
        for byte in &stream {
            received.extend_from_slice(&remote.decrypt(&[*byte]).expect("decrypt"));
        }

        let mut expected = b"first message".to_vec();
        expected.extend_from_slice(&vec![0x7Fu8; FRAME_LENGTH + 5]);
        assert_eq!(received, expected);
        assert_eq!(remote.buffered_len(), 0);
    }

    /// A frame delivered without its tag yields nothing and stays buffered.
    #[test]
    fn a_truncated_frame_yields_nothing_and_is_retained() {
        let (mut local, mut remote) = peer();
        let framed = local.encrypt(b"incomplete").expect("encrypt");
        let cut = framed.len() - 1;

        assert!(remote.decrypt(&framed[..cut]).expect("decrypt").is_empty());
        assert_eq!(remote.buffered_len(), cut);
        assert_eq!(
            remote.decrypt(&framed[cut..]).expect("decrypt"),
            b"incomplete"
        );
        assert_eq!(remote.buffered_len(), 0);
    }

    /// Flipping a ciphertext byte must fail the tag.
    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (mut local, mut remote) = peer();
        let mut framed = local.encrypt(b"authentic").expect("encrypt");
        framed[4] ^= 0x01;

        assert!(remote.decrypt(&framed).is_err());
    }

    /// The length prefix is the AAD, so rewriting it must fail the tag rather than silently
    /// producing a shorter plaintext.
    #[test]
    fn tampered_length_prefix_is_rejected() {
        let (mut local, mut remote) = peer();
        let mut framed = local.encrypt(&[0xAAu8; 32]).expect("encrypt");
        framed[0] = 31;

        assert!(remote.decrypt(&framed).is_err());
    }

    /// An inbound frame larger than [`FRAME_LENGTH`] must decrypt, because real firmware sends
    /// them.
    ///
    /// This is the regression test for the live failure recorded in [`HapSession::decrypt`]'s
    /// docs: an Apple TV 4K (gen 3) on tvOS 27.0 delivers `SET_STATE_MESSAGE`s on the
    /// remote-control data channel in a *single* HAP block of nearly nine kilobytes. Rejecting it
    /// tore the tunnel down on the first now-playing update.
    ///
    /// The peer is built by hand rather than through [`HapSession::encrypt`], which chunks at the
    /// cap and so cannot produce the frame under test.
    #[test]
    fn an_inbound_frame_over_the_send_cap_still_decrypts() {
        use crate::chacha::{Chacha20Cipher, NonceLayout};

        let plaintext = vec![0x5Au8; 8931];
        let length = u16::try_from(plaintext.len())
            .expect("under the u16 ceiling")
            .to_le_bytes();

        // The sender's roles are the mirror of the receiver's.
        let mut sender = Chacha20Cipher::new(&IN_KEY, &OUT_KEY, NonceLayout::PaddedCounter);
        let sealed = sender.encrypt(&plaintext, Some(&length)).expect("seal");

        let mut framed = length.to_vec();
        framed.extend_from_slice(&sealed);

        let mut session = HapSession::new(&OUT_KEY, &IN_KEY);
        assert_eq!(session.decrypt(&framed).expect("decrypt"), plaintext);
    }

    /// A frame of exactly [`FRAME_LENGTH`] is the largest the encoder emits, and still round-trips.
    #[test]
    fn a_maximum_size_outbound_frame_round_trips() {
        let (mut local, mut remote) = peer();
        let framed = local.encrypt(&vec![0x5Au8; FRAME_LENGTH]).expect("encrypt");

        assert_eq!(&framed[..2], &[0x00, 0x04]);
        assert_eq!(
            remote.decrypt(&framed).expect("decrypt").len(),
            FRAME_LENGTH
        );
    }
}
