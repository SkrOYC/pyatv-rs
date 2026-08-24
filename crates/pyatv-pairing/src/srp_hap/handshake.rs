//! ChaCha20-Poly1305 with the four fixed handshake nonces.
//!
//! Pair-setup M5/M6 and pair-verify M2/M3 encrypt their inner TLV with a nonce that is a literal
//! eight-character ASCII string rather than a counter (`pyatv/auth/hap_srp.py:93,120,207-208`).
//! pyatv reaches those through `Chacha20Cipher8byteNonce`, whose `_pad_nonce`
//! (`pyatv/support/chacha20.py:49-51`) left-pads any short nonce to twelve bytes, so the wire nonce
//! is `00 00 00 00 || "PS-Msg05"` and so on.
//!
//! The counter-based transport nonces live in `chacha.rs`/[`crate::session`] and deliberately do
//! **not** share code with this module: `docs/research/crypto-pairing.md` §5 warns that a single
//! parameterised nonce builder is how the three layouts get mixed up.
//!
//! No associated data is used. pyatv calls `encrypt(data, nonce=...)` with `aad` defaulting to
//! `None` (`pyatv/support/chacha20.py:53-62`), which ChaCha20-Poly1305 treats as empty AAD.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};

use crate::{Error, Result};

/// Pair-setup M5: the controller's encrypted identity TLV.
pub const PAIR_SETUP_M5_NONCE: &[u8; 8] = b"PS-Msg05";
/// Pair-setup M6: the accessory's encrypted identity TLV.
pub const PAIR_SETUP_M6_NONCE: &[u8; 8] = b"PS-Msg06";
/// Pair-verify M2: the accessory's encrypted identity TLV.
pub const PAIR_VERIFY_M2_NONCE: &[u8; 8] = b"PV-Msg02";
/// Pair-verify M3: the controller's encrypted identity TLV.
pub const PAIR_VERIFY_M3_NONCE: &[u8; 8] = b"PV-Msg03";

/// Expand an eight-byte handshake label into the twelve-byte wire nonce.
///
/// The four leading zero bytes are what `_pad_nonce` produces; they are not part of the label.
#[must_use]
pub fn handshake_nonce(label: &[u8; 8]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(label);
    nonce
}

/// Encrypt `plaintext` under `key` with the fixed handshake nonce `label`.
///
/// # Errors
///
/// Returns [`Error::Aead`] if the AEAD refuses the input, which for ChaCha20-Poly1305 only happens
/// for implausibly large plaintexts.
pub fn seal(key: &[u8; 32], label: &[u8; 8], plaintext: &[u8]) -> Result<Vec<u8>> {
    cipher(key)
        .encrypt(&Nonce::from(handshake_nonce(label)), plaintext)
        .map_err(|_| Error::Aead {
            operation: "encrypt",
        })
}

/// Decrypt `ciphertext` under `key` with the fixed handshake nonce `label`.
///
/// # Errors
///
/// Returns [`Error::Aead`] if the Poly1305 tag does not verify, which is the only cryptographic
/// check pyatv performs on M6 and the outer check on every encrypted handshake TLV.
pub fn open(key: &[u8; 32], label: &[u8; 8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    cipher(key)
        .decrypt(&Nonce::from(handshake_nonce(label)), ciphertext)
        .map_err(|_| Error::Aead {
            operation: "decrypt",
        })
}

fn cipher(key: &[u8; 32]) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(&Key::from(*key))
}

#[cfg(test)]
mod tests {
    use super::{
        PAIR_SETUP_M5_NONCE, PAIR_SETUP_M6_NONCE, PAIR_VERIFY_M2_NONCE, handshake_nonce, open, seal,
    };

    #[test]
    fn nonces_are_four_zero_bytes_then_the_label() {
        assert_eq!(
            handshake_nonce(PAIR_SETUP_M5_NONCE),
            *b"\x00\x00\x00\x00PS-Msg05"
        );
        assert_eq!(
            handshake_nonce(PAIR_VERIFY_M2_NONCE),
            *b"\x00\x00\x00\x00PV-Msg02"
        );
    }

    #[test]
    fn round_trips_under_the_same_label() {
        let key = [7u8; 32];
        let sealed = seal(&key, PAIR_SETUP_M5_NONCE, b"inner tlv").unwrap();

        assert_eq!(
            open(&key, PAIR_SETUP_M5_NONCE, &sealed).unwrap(),
            b"inner tlv"
        );
    }

    /// The label is the nonce, so M5 ciphertext must not open as M6 — this is what makes mixing the
    /// four constants up a hard failure rather than silent corruption.
    #[test]
    fn a_different_label_fails_to_open() {
        let key = [7u8; 32];
        let sealed = seal(&key, PAIR_SETUP_M5_NONCE, b"inner tlv").unwrap();

        assert!(open(&key, PAIR_SETUP_M6_NONCE, &sealed).is_err());
        assert!(open(&[8u8; 32], PAIR_SETUP_M5_NONCE, &sealed).is_err());
    }
}
