//! ChaCha20-Poly1305 transport framing, and the three nonce layouts that are not interchangeable.
//!
//! Ported from `pyatv/auth/hap_session.py` and `pyatv/support/chacha20.py`. See
//! `docs/research/crypto-pairing.md` §5, which is emphatic that these layouts must stay separate:
//! the same counter value produces different nonce bytes under HAP framing and under Companion
//! framing, so a single shared nonce builder would decrypt to garbage on one of them.

use crate::Result;

/// Plaintext bytes per AEAD operation in HAP framing, from HAP spec section 5.2.2.
pub const FRAME_LENGTH: usize = 1024;

/// Poly1305 tag length.
pub const AUTH_TAG_LENGTH: usize = 16;

/// How a 12-byte ChaCha20-Poly1305 nonce is assembled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NonceLayout {
    /// Four zero bytes followed by an 8-byte little-endian counter.
    ///
    /// Used by [`HapSession`] framing and, with the counter replaced by a fixed ASCII string, by
    /// the pair-setup and pair-verify TLV encryption steps.
    PaddedCounter,
    /// A bare 12-byte little-endian counter with no zero prefix.
    ///
    /// Used by the Companion link only.
    BareCounter,
}

impl NonceLayout {
    /// Build the 12-byte nonce for `counter` under this layout.
    #[must_use]
    pub fn nonce(self, counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        match self {
            Self::PaddedCounter => nonce[4..].copy_from_slice(&counter.to_le_bytes()),
            Self::BareCounter => {
                nonce[..8].copy_from_slice(&counter.to_le_bytes());
            }
        }
        nonce
    }
}

/// The fixed ASCII nonces used during pair-setup and pair-verify.
///
/// These are literal strings, not counters. Each is left-padded with four zero bytes to reach 12
/// bytes, exactly as [`NonceLayout::PaddedCounter`] would for a counter.
pub mod fixed_nonce {
    /// Decrypt the device's M2 pair-verify payload.
    pub const PV_MSG02: &[u8; 8] = b"PV-Msg02";
    /// Encrypt the controller's M3 pair-verify payload.
    pub const PV_MSG03: &[u8; 8] = b"PV-Msg03";
    /// Encrypt the controller's M5 pair-setup payload.
    pub const PS_MSG05: &[u8; 8] = b"PS-Msg05";
    /// Decrypt the device's M6 pair-setup payload.
    pub const PS_MSG06: &[u8; 8] = b"PS-Msg06";

    /// Left-pad an 8-byte fixed nonce to the 12 bytes ChaCha20-Poly1305 requires.
    #[must_use]
    pub fn pad(nonce: &[u8; 8]) -> [u8; 12] {
        let mut padded = [0u8; 12];
        padded[4..].copy_from_slice(nonce);
        padded
    }
}

/// Encrypted transport for a HAP channel, after pair-verify has completed.
///
/// Wire format per frame is `2-byte little-endian plaintext length | ciphertext | 16-byte tag`,
/// with those same two length bytes used as the AEAD's associated data. Payloads longer than
/// [`FRAME_LENGTH`] are split across consecutive frames. Read and write directions keep independent
/// counters.
#[derive(Debug)]
pub struct HapSession {
    output_key: [u8; 32],
    input_key: [u8; 32],
    output_counter: u64,
    input_counter: u64,
}

impl HapSession {
    /// Build a session from the two derived transport keys.
    #[must_use]
    pub fn new(output_key: [u8; 32], input_key: [u8; 32]) -> Self {
        Self {
            output_key,
            input_key,
            output_counter: 0,
            input_counter: 0,
        }
    }

    /// Encrypt `plaintext`, splitting it into [`FRAME_LENGTH`]-byte frames.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Aead`] if the AEAD seal fails.
    // TODO(step-1): chunk at FRAME_LENGTH; per chunk emit the 2-byte LE length, then
    // `ChaCha20Poly1305::new(&output_key).encrypt(nonce, Payload { msg: chunk, aad: &length })`,
    // incrementing `output_counter` once per frame. See docs/research/crypto-pairing.md §5.2.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let _ = (plaintext, &self.output_key, self.output_counter);
        todo!("HapSession::encrypt")
    }

    /// Decrypt as many complete frames as `ciphertext` contains.
    ///
    /// Returns the recovered plaintext and how many bytes were consumed, so the caller can retain a
    /// partial trailing frame.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Aead`] if a frame's tag does not verify.
    // TODO(step-1): read the 2-byte LE length, wait for `length + AUTH_TAG_LENGTH` more bytes, then
    // decrypt with the length bytes as AAD and increment `input_counter`.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<(Vec<u8>, usize)> {
        let _ = (ciphertext, &self.input_key, self.input_counter);
        todo!("HapSession::decrypt")
    }
}

#[cfg(test)]
mod tests {
    use super::{NonceLayout, fixed_nonce};

    /// HAP framing prefixes four zero bytes; Companion does not. The same counter must therefore
    /// produce different bytes under the two layouts.
    #[test]
    fn the_two_nonce_layouts_disagree_for_the_same_counter() {
        assert_eq!(
            NonceLayout::PaddedCounter.nonce(1),
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            NonceLayout::BareCounter.nonce(1),
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_ne!(
            NonceLayout::PaddedCounter.nonce(1),
            NonceLayout::BareCounter.nonce(1)
        );
    }

    /// The counter is little-endian in both layouts.
    #[test]
    fn counters_are_little_endian() {
        assert_eq!(
            NonceLayout::PaddedCounter.nonce(0x0102),
            [0, 0, 0, 0, 0x02, 0x01, 0, 0, 0, 0, 0, 0]
        );
    }

    /// A fixed ASCII nonce lands in the same byte positions the padded counter uses.
    #[test]
    fn fixed_nonces_are_left_padded_to_twelve_bytes() {
        let padded = fixed_nonce::pad(fixed_nonce::PV_MSG02);

        assert_eq!(&padded[..4], &[0, 0, 0, 0]);
        assert_eq!(&padded[4..], b"PV-Msg02");
    }
}
