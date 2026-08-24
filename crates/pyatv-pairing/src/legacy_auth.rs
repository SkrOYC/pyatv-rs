//! Legacy AirPlay device authentication: AES-128-CTR and AES-128-GCM, keyed by raw SHA-512.
//!
//! Ported from `pyatv/protocols/airplay/srp.py`. Documented in `docs/research/crypto-pairing.md`
//! §5.4. This path predates HAP entirely and shares nothing with it: no HKDF, no ChaCha20, no TLV8.
//! Key material comes from plain SHA-512 over a label concatenated with a shared secret, truncated
//! to 16 bytes.
//!
//! Two quirks are load-bearing:
//!
//! - **The pair-setup IV is incremented before use.** pyatv computes the IV, then adds 1 to its
//!   last byte, with a log line noting the change. It is almost certainly compensating for an
//!   off-by-one in Apple's original implementation. Omit it and pairing fails against real
//!   hardware with no useful diagnostic.
//! - **Pair-verify encrypts an opaque device-supplied blob alongside the signature.** The bytes of
//!   the M2 response past the first 32 are concatenated onto the signature before CTR encryption.
//!   pyatv's own source carries a `# TODO: what is this?` there. Copy the bytes through; do not try
//!   to interpret them.
//!
//! FairPlay is explicitly out of scope. pyatv parses the RAOP encryption-type bits that advertise
//! RSA, FairPlay and FairPlaySAPv25 but implements none of them, and no public implementation
//! exists because they depend on Apple's hardware-backed key material.

use sha2::{Digest, Sha512};

use crate::Result;

/// Label for the pair-verify AES key.
pub const VERIFY_AES_KEY_LABEL: &[u8] = b"Pair-Verify-AES-Key";
/// Label for the pair-verify AES IV.
pub const VERIFY_AES_IV_LABEL: &[u8] = b"Pair-Verify-AES-IV";
/// Label for the pair-setup AES key.
pub const SETUP_AES_KEY_LABEL: &[u8] = b"Pair-Setup-AES-Key";
/// Label for the pair-setup AES IV.
pub const SETUP_AES_IV_LABEL: &[u8] = b"Pair-Setup-AES-IV";

/// Fixed prefix of the legacy pair-verify M1 message, ahead of the two 32-byte public keys.
pub const VERIFY_M1_PREFIX: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Derive 16 bytes as `SHA512(label || secret)[..16]`.
///
/// Deliberately not HKDF: the legacy path never calls it, and substituting HKDF here would produce
/// keys no device accepts.
#[must_use]
pub fn derive_aes_material(label: &[u8], secret: &[u8]) -> [u8; 16] {
    let mut hasher = Sha512::new();
    hasher.update(label);
    hasher.update(secret);

    let mut output = [0u8; 16];
    output.copy_from_slice(&hasher.finalize()[..16]);
    output
}

/// Apply pyatv's pair-setup IV increment: add one to the last byte, wrapping.
///
/// See the module documentation. This exists purely to match Apple's behaviour.
#[must_use]
pub fn increment_setup_iv(mut iv: [u8; 16]) -> [u8; 16] {
    iv[15] = iv[15].wrapping_add(1);
    iv
}

/// AES-128-CTR-encrypt the pair-verify signature payload.
///
/// Raw CTR with no authentication tag, using the full 16-byte IV as the initial counter block.
///
/// # Errors
///
/// Currently infallible; the signature returns [`Result`] so a future keystream-length check can be
/// added without a breaking change.
// TODO(step-1): `ctr::Ctr128BE<aes::Aes128>`. The report flags the exact counter-block semantics as
// needing a known-answer test against a captured exchange before being trusted — see
// docs/research/crypto-pairing.md §5.4 and its open questions.
pub fn verify_encrypt(key: &[u8; 16], iv: &[u8; 16], payload: &[u8]) -> Result<Vec<u8>> {
    let _ = (key, iv, payload);
    todo!("legacy_auth::verify_encrypt")
}

/// AES-128-GCM-encrypt the controller's Ed25519 public key during pair-setup.
///
/// Returns the ciphertext and the 16-byte GCM tag. The IV passed here must already have been
/// through [`increment_setup_iv`].
///
/// # Errors
///
/// Returns [`crate::Error::Aead`] if the AEAD seal fails.
// TODO(step-1): `aes_gcm::Aes128Gcm`. pyatv passes the full 16-byte IV to `modes.GCM(aes_iv)`,
// which is not the standard 12-byte GCM nonce; confirm against a capture before shipping.
pub fn setup_encrypt(key: &[u8; 16], iv: &[u8; 16], payload: &[u8]) -> Result<(Vec<u8>, [u8; 16])> {
    let _ = (key, iv, payload);
    todo!("legacy_auth::setup_encrypt")
}

#[cfg(test)]
mod tests {
    use super::{
        SETUP_AES_IV_LABEL, SETUP_AES_KEY_LABEL, VERIFY_AES_KEY_LABEL, derive_aes_material,
        increment_setup_iv,
    };

    /// Key and IV come from the same secret but different labels, so they must differ.
    #[test]
    fn labels_separate_key_from_iv() {
        let secret = b"shared secret";

        assert_ne!(
            derive_aes_material(SETUP_AES_KEY_LABEL, secret),
            derive_aes_material(SETUP_AES_IV_LABEL, secret)
        );
        assert_ne!(
            derive_aes_material(SETUP_AES_KEY_LABEL, secret),
            derive_aes_material(VERIFY_AES_KEY_LABEL, secret)
        );
    }

    #[test]
    fn setup_iv_increment_touches_only_the_last_byte() {
        let iv = [0x11u8; 16];
        let bumped = increment_setup_iv(iv);

        assert_eq!(&bumped[..15], &iv[..15]);
        assert_eq!(bumped[15], 0x12);
    }

    #[test]
    fn setup_iv_increment_wraps_rather_than_panicking() {
        let mut iv = [0x00u8; 16];
        iv[15] = 0xFF;

        assert_eq!(increment_setup_iv(iv)[15], 0x00);
    }
}
