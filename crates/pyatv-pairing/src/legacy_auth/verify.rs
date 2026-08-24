//! Legacy AirPlay pair-verify: the two raw `/pair-verify` messages.
//!
//! Port of `AirPlayLegacyPairVerifyProcedure` (`pyatv/protocols/airplay/auth/legacy.py:84-114`)
//! and `LegacySRPAuthHandler.verify1`/`verify2` (`pyatv/protocols/airplay/srp.py:104-149`). No
//! property lists here: both bodies are raw octet streams.
//!
//! ```text
//! M1 (out) 0x01000000 ‖ X25519 public (32) ‖ Ed25519 public (32)
//! M2 (in)  device X25519 public (32) ‖ opaque blob (variable)
//! M3 (out) 0x00000000 ‖ AES-128-CTR(signature), keystream offset by the blob's length
//! M4 (in)  ignored entirely
//! ```
//!
//! Both key pairs come from the *same* 32-byte credential seed: the Ed25519 signing key and the
//! X25519 "ephemeral" are the same bytes reinterpreted (`pyatv/protocols/airplay/srp.py:87,106`).
//! It is therefore not ephemeral at all, which is why the captured session in
//! `tests/fake_device/airplay.py:38-44` is reproducible.
//!
//! This procedure produces **no transport keys**: `encryption_keys` raises `NotSupportedError`
//! upstream (`pyatv/protocols/airplay/auth/legacy.py:108-114`) and `verify_credentials` returns
//! `False` so callers skip the `HAPSession` wrap entirely
//! (`pyatv/protocols/airplay/auth/__init__.py:100-117`). Legacy AirPlay traffic stays in the clear
//! after verification.

use ed25519_dalek::{Signer, SigningKey};

use super::{
    VERIFY_AES_IV_LABEL, VERIFY_AES_KEY_LABEL, VERIFY_M1_PREFIX, VERIFY_M3_PREFIX,
    ctr_encrypt_at_offset, derive_aes_material, seed_from_ltsk,
};
use crate::{Error, HapCredentials, Result};

/// Length of an X25519 or Ed25519 public key.
const PUBLIC_KEY_LEN: usize = 32;

/// Drives the legacy AirPlay pair-verify exchange, bytes in and bytes out.
#[derive(Debug)]
pub struct LegacyPairVerify {
    signing_key: SigningKey,
    /// The X25519 secret, which is the same seed the Ed25519 key uses.
    verify_secret: [u8; PUBLIC_KEY_LEN],
    verify_public: [u8; PUBLIC_KEY_LEN],
}

impl LegacyPairVerify {
    /// Start a pair-verify against stored legacy credentials.
    ///
    /// # Errors
    ///
    /// Returns [`Error::KeyLength`] if `ltsk` is not 32 bytes.
    pub fn new(credentials: &HapCredentials) -> Result<Self> {
        let seed = seed_from_ltsk(&credentials.ltsk)?;

        Ok(Self {
            signing_key: SigningKey::from_bytes(&seed),
            verify_secret: seed,
            verify_public: x25519_dalek::x25519(seed, x25519_dalek::X25519_BASEPOINT_BYTES),
        })
    }

    /// Body of the first `/pair-verify` POST.
    ///
    /// `b"\x01\x00\x00\x00" + verify_public + auth_public`
    /// (`pyatv/protocols/airplay/srp.py:125`).
    #[must_use]
    pub fn step1_body(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(VERIFY_M1_PREFIX.len() + 2 * PUBLIC_KEY_LEN);
        body.extend_from_slice(&VERIFY_M1_PREFIX);
        body.extend_from_slice(&self.verify_public);
        body.extend_from_slice(self.signing_key.verifying_key().as_bytes());
        body
    }

    /// Body of the second `/pair-verify` POST, derived from the device's reply.
    ///
    /// The reply is split at 32 bytes into the device's X25519 public key and an opaque blob pyatv
    /// labels `# TODO: what is this?` (`pyatv/protocols/airplay/auth/legacy.py:98-99`). The blob is
    /// never transmitted; its only effect is to advance the CTR keystream by its own length before
    /// the signature is encrypted — see [`super::ctr_encrypt_at_offset`].
    ///
    /// The signature covers `own X25519 public ‖ device X25519 public`
    /// (`pyatv/protocols/airplay/srp.py:143-144`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::MalformedResponse`] if the reply is shorter than the 32-byte public key.
    pub fn step2_body(&self, response: &[u8]) -> Result<Vec<u8>> {
        let device_public: [u8; PUBLIC_KEY_LEN] = response
            .get(..PUBLIC_KEY_LEN)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| {
                Error::MalformedResponse(format!(
                    "pair-verify reply is {} bytes, need at least {PUBLIC_KEY_LEN}",
                    response.len()
                ))
            })?;
        let opaque = &response[PUBLIC_KEY_LEN..];

        let shared = x25519_dalek::x25519(self.verify_secret, device_public);
        let key = derive_aes_material(VERIFY_AES_KEY_LABEL, &shared);
        let iv = derive_aes_material(VERIFY_AES_IV_LABEL, &shared);

        let mut signed = Vec::with_capacity(2 * PUBLIC_KEY_LEN);
        signed.extend_from_slice(&self.verify_public);
        signed.extend_from_slice(&device_public);
        let signature = self.signing_key.sign(&signed).to_bytes();

        let encrypted = ctr_encrypt_at_offset(&key, &iv, opaque.len() as u64, signature.as_slice());

        let mut body = Vec::with_capacity(VERIFY_M3_PREFIX.len() + encrypted.len());
        body.extend_from_slice(&VERIFY_M3_PREFIX);
        body.extend_from_slice(&encrypted);
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::LegacyPairVerify;
    use crate::{HapCredentials, legacy_auth::tests_support as fixture};

    fn verifier() -> LegacyPairVerify {
        LegacyPairVerify::new(&HapCredentials {
            ltpk: Vec::new(),
            ltsk: fixture::unhex(fixture::DEVICE_AUTH_KEY),
            atv_id: Vec::new(),
            client_id: vec![0x11; 8],
        })
        .expect("credentials are well formed")
    }

    /// Known-answer test: the first body must be `_DEVICE_VERIFY_STEP1`
    /// (`tests/fake_device/airplay.py:38`) byte for byte, which pins both public keys being derived
    /// from the one seed.
    #[test]
    fn step1_body_matches_the_capture() {
        assert_eq!(hex::encode(verifier().step1_body()), fixture::VERIFY_STEP1);
    }

    /// Known-answer test: given `_DEVICE_VERIFY_STEP1_RESP`, the second body must be
    /// `_DEVICE_VERIFY_STEP2` (`tests/fake_device/airplay.py:39-40`) byte for byte. This is the
    /// only check that the CTR keystream really is offset by the opaque blob's length.
    #[test]
    fn step2_body_matches_the_capture() {
        let body = verifier()
            .step2_body(&fixture::unhex(fixture::VERIFY_STEP1_RESP))
            .expect("step 2");

        assert_eq!(hex::encode(body), fixture::VERIFY_STEP2);
    }

    /// Dropping the opaque blob would restart the keystream at zero and produce different bytes,
    /// so this proves the offset is not incidental.
    #[test]
    fn ignoring_the_opaque_blob_would_change_the_output() {
        let response = fixture::unhex(fixture::VERIFY_STEP1_RESP);

        let truncated = verifier().step2_body(&response[..32]).expect("step 2");

        assert_ne!(hex::encode(truncated), fixture::VERIFY_STEP2);
    }

    /// A different seed must produce a different exchange, so the capture is not being replayed.
    #[test]
    fn a_different_seed_produces_different_bodies() {
        let other = LegacyPairVerify::new(&HapCredentials {
            ltpk: Vec::new(),
            ltsk: vec![0u8; 32],
            atv_id: Vec::new(),
            client_id: vec![0x11; 8],
        })
        .expect("credentials are well formed");

        assert_ne!(hex::encode(other.step1_body()), fixture::VERIFY_STEP1);
    }

    /// A reply too short to contain the device's public key must be refused.
    #[test]
    fn a_short_reply_is_refused() {
        assert!(verifier().step2_body(&[0u8; 31]).is_err());
    }

    /// A credential seed of the wrong length is a configuration error, not a panic.
    #[test]
    fn a_short_seed_is_refused() {
        assert!(
            LegacyPairVerify::new(&HapCredentials {
                ltpk: Vec::new(),
                ltsk: vec![0u8; 16],
                atv_id: Vec::new(),
                client_id: Vec::new(),
            })
            .is_err()
        );
    }
}
