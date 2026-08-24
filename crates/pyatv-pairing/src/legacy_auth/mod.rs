//! Legacy AirPlay device authentication: AES-128-CTR and AES-128-GCM keyed by raw SHA-512.
//!
//! Port of `pyatv/protocols/airplay/srp.py:25-49,104-195` and
//! `pyatv/protocols/airplay/auth/legacy.py:1-114`. This path predates HAP entirely and shares
//! nothing with it: no HKDF, no ChaCha20, no TLV8. Key material is plain `SHA512(label ‖ secret)`
//! truncated to 16 bytes, and the SRP profile is [`crate::srp_legacy`].
//!
//! Everything here is sans-io. Each step takes the previous response body and returns the next
//! request body, so the AirPlay crate can drive it over HTTP without this crate knowing about HTTP.
//! The two request/response formats are not the same:
//!
//! | Route | Request body | Content type |
//! |---|---|---|
//! | `/pair-pin-start` | empty | none |
//! | `/pair-setup-pin` | Apple binary property list | `application/x-apple-binary-plist` |
//! | `/pair-verify` | raw bytes, no wrapper | `application/octet-stream` |
//!
//! (`pyatv/protocols/airplay/auth/legacy.py:40,71-81,103-106`.)
//!
//! ## The quirks that are load-bearing
//!
//! - **The pair-setup IV is incremented before use.** pyatv derives the IV then adds one to its
//!   last byte (`pyatv/protocols/airplay/srp.py:186-189`). [`increment_setup_iv`] uses a wrapping
//!   add; pyatv would raise `ValueError` for a derived IV ending in `0xFF`, which is its own bug,
//!   not a protocol rule (`docs/research/hap-pairing-port-spec.md` §5.5, §11.5).
//! - **The opaque trailing blob is keystream-advanced but never sent.** `aes_encrypt` is called
//!   with two payloads and reassigns rather than concatenates its result
//!   (`pyatv/protocols/airplay/srp.py:44-49,145`), so the blob's ciphertext is computed and thrown
//!   away while its length still offsets the CTR keystream for the signature that follows. See
//!   [`ctr_encrypt_at_offset`]; the earlier research report's "encrypted alongside the signature"
//!   wording would produce wire-incompatible output.
//! - **AES-GCM runs with a 16-byte IV**, not the usual 96-bit nonce
//!   (`pyatv/protocols/airplay/srp.py:192`), so `J0` comes from GHASH rather than from a
//!   concatenated counter.
//!
//! FairPlay is explicitly out of scope: pyatv parses the RAOP encryption-type bits that advertise
//! it but implements nothing, and no open implementation exists.

mod setup;
mod verify;

use aes::Aes128;
use aes_gcm::{
    AesGcm, KeyInit,
    aead::{Aead, Nonce, Payload, consts::U16},
};
use ctr::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use sha2::{Digest, Sha512};

use crate::{Error, Result};

pub use setup::LegacyPairSetup;
pub use verify::LegacyPairVerify;

/// Label for the pair-verify AES key (`pyatv/protocols/airplay/srp.py:138`).
pub const VERIFY_AES_KEY_LABEL: &[u8] = b"Pair-Verify-AES-Key";
/// Label for the pair-verify AES IV (`pyatv/protocols/airplay/srp.py:139`).
pub const VERIFY_AES_IV_LABEL: &[u8] = b"Pair-Verify-AES-IV";
/// Label for the pair-setup AES key (`pyatv/protocols/airplay/srp.py:185`).
pub const SETUP_AES_KEY_LABEL: &[u8] = b"Pair-Setup-AES-Key";
/// Label for the pair-setup AES IV (`pyatv/protocols/airplay/srp.py:186`).
pub const SETUP_AES_IV_LABEL: &[u8] = b"Pair-Setup-AES-IV";

/// Route that makes the device display its PIN (`pyatv/protocols/airplay/auth/legacy.py:40`).
pub const PIN_START_PATH: &str = "/pair-pin-start";
/// Route carrying the three binary-plist pair-setup messages.
pub const PAIR_SETUP_PIN_PATH: &str = "/pair-setup-pin";
/// Route carrying the two raw pair-verify messages.
pub const PAIR_VERIFY_PATH: &str = "/pair-verify";

/// Content type for the pair-setup bodies
/// (`pyatv/protocols/airplay/auth/legacy.py:75`).
pub const BINARY_PLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";
/// Content type for the pair-verify bodies
/// (`pyatv/protocols/airplay/auth/legacy.py:105`).
pub const OCTET_STREAM_CONTENT_TYPE: &str = "application/octet-stream";

/// Fixed prefix of the pair-verify M1 message (`pyatv/protocols/airplay/srp.py:125`).
pub const VERIFY_M1_PREFIX: [u8; 4] = [0x01, 0x00, 0x00, 0x00];
/// Fixed prefix of the pair-verify M3 message, "prepended with 0x00000000 (alignment?)"
/// (`pyatv/protocols/airplay/srp.py:148-149`).
pub const VERIFY_M3_PREFIX: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

/// AES-128 uses 16-byte keys, and both derived IVs are 16 bytes too.
pub const AES_BLOCK_LEN: usize = 16;

/// AES-128-GCM with the 16-byte IV pyatv passes to `modes.GCM`.
type Aes128Gcm16 = AesGcm<Aes128, U16>;

/// AES-128-CTR with the full 16-byte IV as the initial counter block.
type Aes128Ctr = ctr::Ctr128BE<Aes128>;

/// Derive 16 bytes as `SHA512(label ‖ secret)[..16]`.
///
/// Port of `hash_sha512` plus the `[0:16]` slice every caller applies
/// (`pyatv/protocols/airplay/srp.py:25-35,138-139,185-186`). Deliberately not HKDF: the legacy path
/// never calls it, and substituting HKDF here produces keys no device accepts.
#[must_use]
pub fn derive_aes_material(label: &[u8], secret: &[u8]) -> [u8; AES_BLOCK_LEN] {
    let mut hasher = Sha512::new();
    hasher.update(label);
    hasher.update(secret);

    let mut output = [0u8; AES_BLOCK_LEN];
    output.copy_from_slice(&hasher.finalize()[..AES_BLOCK_LEN]);
    output
}

/// Apply pyatv's pair-setup IV increment: add one to the last byte.
///
/// `tmp[-1] = tmp[-1] + 1` (`pyatv/protocols/airplay/srp.py:188`). Python raises `ValueError` when
/// the byte is already `0xFF`; wrapping instead is the safe divergence, since a crash there would
/// mean pyatv could never have paired with that device either.
#[must_use]
pub fn increment_setup_iv(mut iv: [u8; AES_BLOCK_LEN]) -> [u8; AES_BLOCK_LEN] {
    iv[AES_BLOCK_LEN - 1] = iv[AES_BLOCK_LEN - 1].wrapping_add(1);
    iv
}

/// AES-128-CTR-encrypt `payload` starting `skip` bytes into the keystream.
///
/// This models `aes_encrypt(modes.CTR, key, iv, discarded, payload)`
/// (`pyatv/protocols/airplay/srp.py:44-49,145`): the first argument's ciphertext is overwritten by
/// the second's, but the shared counter has already advanced past it. Restarting the counter at
/// zero, or returning both ciphertexts concatenated, both produce bytes a device rejects.
#[must_use]
pub fn ctr_encrypt_at_offset(
    key: &[u8; AES_BLOCK_LEN],
    iv: &[u8; AES_BLOCK_LEN],
    skip: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new(&(*key).into(), &(*iv).into());
    cipher.seek(skip);

    let mut output = payload.to_vec();
    cipher.apply_keystream(&mut output);
    output
}

/// AES-128-GCM-encrypt `payload`, returning the ciphertext and the 16-byte tag separately.
///
/// `epk, tag = aes_encrypt(modes.GCM, aes_key, aes_iv, self._auth_public)`
/// (`pyatv/protocols/airplay/srp.py:192`). The IV must already have been through
/// [`increment_setup_iv`].
///
/// # Errors
///
/// Returns [`Error::Aead`] if the AEAD seal fails, which for GCM means only an impossible input
/// length.
pub fn gcm_encrypt(
    key: &[u8; AES_BLOCK_LEN],
    iv: &[u8; AES_BLOCK_LEN],
    payload: &[u8],
) -> Result<(Vec<u8>, [u8; AES_BLOCK_LEN])> {
    let cipher = Aes128Gcm16::new(&(*key).into());
    let mut sealed = cipher
        .encrypt(
            &Nonce::<Aes128Gcm16>::from(*iv),
            Payload {
                msg: payload,
                aad: &[],
            },
        )
        .map_err(|_| Error::Aead {
            operation: "encrypt",
        })?;

    let split = sealed.len().checked_sub(AES_BLOCK_LEN).ok_or(Error::Aead {
        operation: "encrypt",
    })?;
    let mut tag = [0u8; AES_BLOCK_LEN];
    tag.copy_from_slice(&sealed[split..]);
    sealed.truncate(split);

    Ok((sealed, tag))
}

/// Read a 32-byte seed out of a credential's `ltsk` field.
///
/// # Errors
///
/// Returns [`Error::KeyLength`] if the field is not exactly 32 bytes.
pub(crate) fn seed_from_ltsk(ltsk: &[u8]) -> Result<[u8; 32]> {
    <[u8; 32]>::try_from(ltsk).map_err(|_| Error::KeyLength {
        expected: 32,
        actual: ltsk.len(),
    })
}

/// Captured legacy-AirPlay session, copied verbatim from `tests/fake_device/airplay.py:19-45`.
///
/// Every client-side value in that capture is a deterministic function of the identifier, the seed
/// and the PIN — pyatv reuses the Ed25519 seed as both the SRP ephemeral and the X25519 private key
/// — which is why pyatv's own fake device can get away with byte-equality replay and why these are
/// usable as known-answer tests here. Do not retype them; they are copied character for character.
#[cfg(test)]
pub(crate) mod tests_support {
    /// `DEVICE_IDENTIFIER`, the 8-byte client id as uppercase hex.
    pub const DEVICE_IDENTIFIER_HEX: &str = "75FBEEC773CFC563";
    /// `DEVICE_AUTH_KEY`, the 32-byte Ed25519/X25519 seed.
    pub const DEVICE_AUTH_KEY: &str =
        "8F06696F2542D70DF59286C761695C485F815BE3D152849E1361282D46AB1493";
    /// `DEVICE_PIN`, already in the zero-padded string form pyatv passes down.
    pub const DEVICE_PIN: &str = "2271";

    /// `_DEVICE_AUTH_STEP1`: `{method: "pin", user: <identifier>}`.
    pub const AUTH_STEP1: &str = "62706c6973743030d201020304566d6574686f6454757365725370696e5f101037354642454543373733434643353633080d14191d0000000000000101000000000000000500000000000000000000000000000030";
    /// `_DEVICE_AUTH_STEP1_RESP`: `{pk: B, salt: s}`.
    pub const AUTH_STEP1_RESP: &str = "62706c6973743030d20102030452706b5473616c744f1101008817e16146c7d12b45e810b0bf190a4ccb25d9a20a8d0504d874daa8db5574c51c8b33703a95c00bdbe99c8c3745d1ef1b38e538edfd98e09ec029effe6f28b3b54a1bd41c28d8f33da6f5ac9327bfce9a66869dae645b5cbd2c6b8fbe14a30ad4f8598154f2ef7f4f52cee3e3042a69780463c26bbb764870eb1995b26a2a4ade05564836d788baf07469a143c410ea9d07a068eb790b2b0aa5b86c990636814e3fa1a899ceba1af45b211ca4bd3b5b66ffaf16051a4f851e120476054258f257b8521a068907ad5e9c7220d5cef9aa072dec9edb7ebf633cad4d52d105cf58440f17e236332b0b26539851a879e9ac8d3c2da4c590785468e590296d39d7374f1010fca6dcb6b83a7c716a692f806e9159540008000d001000150119000000000000020100000000000000050000000000000000000000000000012c";
    /// `_DEVICE_AUTH_STEP2`: `{pk: A, proof: M1}`.
    pub const AUTH_STEP2: &str = "62706c6973743030d20102030452706b5570726f6f664f1101000819b6ba7feead4753809314e2b4c5db9109f737a0fc70b758342b6bbf536fae4e40cf94607588abb17c2076030cc00c2c1fa5fc3b3dfe8aa1ec2f23f74d917c0792fbf02f131377dfb8ae2a1656ceaa0a36bb3ab752586e1af17e1d5ef24ce083f3f9298d0be761f26c0d48af86510bf9aac7940cf90bff6bd214cf34b5536856c80f076cfbe06fd69af9d6a07a6d3ac580dfffc8a40b9730575a16c5046cd73321a944880dcf9fac952afc7ffd2d135e57ec208b11cef22b734f331ad4d8c9a737b588f7b30bd5210c65cae2ba0226f69ce7b505771faa63af89ed2f9e8325d7d5f3a2da7412f9d837860632d7f81b7fa5e09dd85e1539184070c0fa8433c24f1014fc6286910833d3e7ae0631d47ddbb0f492ef85b80008000d00100016011a0000000000000201000000000000000500000000000000000000000000000131";
    /// `_DEVICE_AUTH_STEP2_RESP`: `{proof: M2}`.
    pub const AUTH_STEP2_RESP: &str = "62706c6973743030d101025570726f6f664f101484a88548b12bce122ad1cea6caff312630edcf27080b110000000000000101000000000000000300000000000000000000000000000028";
    /// `_DEVICE_AUTH_STEP3`: `{authTag: t, epk: e}`.
    pub const AUTH_STEP3: &str = "62706c6973743030d20102030457617574685461675365706b4f101052a92f8712c6ea417f3adb3d03d8e5634f1020ff07fc8520d10728e6f2ab0a0245dfa20709b5d1ae5f9a19328b0663ba9414f2080d15192c000000000000010100000000000000050000000000000000000000000000004f";

    /// `_DEVICE_AUTH_STEP3_RESP`: `{epk: e, authTag: t}`, which pyatv never reads.
    pub const AUTH_STEP3_RESP: &str = "62706c6973743030d2010203045365706b57617574685461674f10206285b20afad4cefe1fce40cee685ab072c75240cb47fb71bc3b3d03dca52dc5d4f1010893eb8e5ae418b245e9b1bf7cba9116b080d11193c000000000000010100000000000000050000000000000000000000000000004f";

    /// `_DEVICE_VERIFY_STEP2_RESP`, empty: "Value not used by pyatv".
    pub const VERIFY_STEP2_RESP: &str = "";

    /// `_DEVICE_VERIFY_STEP1`: `0x01000000 ‖ X25519 public ‖ Ed25519 public`.
    pub const VERIFY_STEP1: &str = "01000000891bae9f581f68f9c9933c4f713fbb5b9de639ec7df5d0a4fd4f342f1c21aa6a5e9d1e843302d6265b8c48dd169e273460e567916b0b36280ac071001118f6b2";
    /// `_DEVICE_VERIFY_STEP1_RESP`: 32-byte device X25519 public key plus a 64-byte opaque blob.
    pub const VERIFY_STEP1_RESP: &str = "3221371da9f00d035955caa912455fd2acee68117b557f25e39168746af4b631cfab7b2c6d0b58e96cc10af884f5a4cdef8063858a9d9c04e866743cf4b77b4be50de1352ab4ff2691a1a7afd8c1341475b4170ac50455973b7fcf3c24324fa9";
    /// `_DEVICE_VERIFY_STEP2`: `0x00000000 ‖ CTR ciphertext of the signature`.
    pub const VERIFY_STEP2: &str = "00000000a1f91acf64aacb185684080b817103b423816ad63b7f5e001f62337b4cc4b3b92c1474959930b7c2a59d0004814300580459d06fc6cc6441bd82bac72a5c5cc7";

    /// Decode a fixture, panicking on a typo in this file rather than returning an error.
    pub fn unhex(value: &str) -> Vec<u8> {
        hex::decode(value).expect("test fixture is valid hex")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AES_BLOCK_LEN, SETUP_AES_IV_LABEL, SETUP_AES_KEY_LABEL, VERIFY_AES_KEY_LABEL,
        ctr_encrypt_at_offset, derive_aes_material, gcm_encrypt, increment_setup_iv,
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

    /// The derivation is a plain SHA-512 of the concatenation, truncated.
    #[test]
    fn derivation_is_a_truncated_sha512_of_label_and_secret() {
        use sha2::{Digest, Sha512};

        let expected = Sha512::digest([SETUP_AES_KEY_LABEL, b"secret"].concat());

        assert_eq!(
            derive_aes_material(SETUP_AES_KEY_LABEL, b"secret"),
            expected[..AES_BLOCK_LEN]
        );
    }

    #[test]
    fn setup_iv_increment_touches_only_the_last_byte() {
        let iv = [0x11u8; AES_BLOCK_LEN];
        let bumped = increment_setup_iv(iv);

        assert_eq!(&bumped[..15], &iv[..15]);
        assert_eq!(bumped[15], 0x12);
    }

    #[test]
    fn setup_iv_increment_wraps_rather_than_panicking() {
        let mut iv = [0x00u8; AES_BLOCK_LEN];
        iv[15] = 0xFF;

        assert_eq!(increment_setup_iv(iv)[15], 0x00);
    }

    /// Encrypting at offset `n` must equal the tail of the keystream from offset zero, which is
    /// what "the discarded chunk still advanced the counter" means concretely.
    #[test]
    fn offset_encryption_matches_the_tail_of_a_zero_offset_run() {
        let key = [0x11u8; AES_BLOCK_LEN];
        let iv = [0x22u8; AES_BLOCK_LEN];
        let whole = [0u8; 96];

        let from_zero = ctr_encrypt_at_offset(&key, &iv, 0, &whole);
        let from_offset = ctr_encrypt_at_offset(&key, &iv, 64, &[0u8; 32]);

        assert_eq!(&from_zero[64..], from_offset.as_slice());
        assert_ne!(&from_zero[..32], from_offset.as_slice());
    }

    /// The offset is a byte offset, not a block offset.
    #[test]
    fn offset_encryption_is_byte_granular() {
        let key = [0x33u8; AES_BLOCK_LEN];
        let iv = [0x44u8; AES_BLOCK_LEN];

        let from_zero = ctr_encrypt_at_offset(&key, &iv, 0, &[0u8; 32]);
        let from_three = ctr_encrypt_at_offset(&key, &iv, 3, &[0u8; 8]);

        assert_eq!(&from_zero[3..11], from_three.as_slice());
    }

    /// Replay of the whole captured session against a stand-in for `FakeAirPlayService`.
    ///
    /// `tests/fake_device/airplay.py:155-197` does not implement accessory-side crypto at all: it
    /// matches each incoming body against a fixed hex string and returns the matching canned reply,
    /// answering `403` to anything else. That is only sound because every client value is a
    /// deterministic function of the identifier, seed and PIN. The same trick works here, and it
    /// tests the client end to end rather than one step at a time — this is the strongest check in
    /// the crate, because the expected bytes came from real interoperating software rather than
    /// from a second reading of pyatv's source.
    #[test]
    fn the_captured_session_replays_end_to_end() {
        use super::tests_support as fixture;
        use crate::{HapCredentials, legacy_auth::LegacyPairSetup, legacy_auth::LegacyPairVerify};

        /// Stands in for `FakeAirPlayService.handle_pair_setup_pin`/`handle_legacy_pair_verify`.
        fn respond(request: &[u8]) -> Result<Vec<u8>, &'static str> {
            let exchanges = [
                (fixture::AUTH_STEP1, fixture::AUTH_STEP1_RESP),
                (fixture::AUTH_STEP2, fixture::AUTH_STEP2_RESP),
                (fixture::AUTH_STEP3, fixture::AUTH_STEP3_RESP),
                (fixture::VERIFY_STEP1, fixture::VERIFY_STEP1_RESP),
                (fixture::VERIFY_STEP2, fixture::VERIFY_STEP2_RESP),
            ];
            let hexlified = hex::encode(request);

            exchanges
                .iter()
                .find(|(expected, _)| *expected == hexlified)
                .map(|(_, reply)| fixture::unhex(reply))
                .ok_or("403 Not Authenticated")
        }

        let credentials = HapCredentials {
            ltpk: Vec::new(),
            ltsk: fixture::unhex(fixture::DEVICE_AUTH_KEY),
            atv_id: Vec::new(),
            client_id: fixture::unhex(fixture::DEVICE_IDENTIFIER_HEX),
        };

        let mut setup = LegacyPairSetup::new(credentials.clone()).expect("credentials");
        let mut reply = respond(&setup.step1_body(fixture::DEVICE_PIN).expect("step 1"))
            .expect("device accepts step 1");
        reply = respond(&setup.step2_body(&reply).expect("step 2")).expect("device accepts step 2");
        respond(&setup.step3_body(&reply).expect("step 3")).expect("device accepts step 3");
        assert_eq!(setup.finish(), credentials);

        let verify = LegacyPairVerify::new(&credentials).expect("credentials");
        let reply = respond(&verify.step1_body()).expect("device accepts verify 1");
        let final_reply = respond(&verify.step2_body(&reply).expect("verify 2"))
            .expect("device accepts verify 2");
        assert!(final_reply.is_empty());
    }

    /// The all-zero seed pyatv uses as `INVALID_AUTH_KEY`
    /// (`tests/protocols/airplay/auth/test_airplay_legacy_auth.py:18`) must produce bytes the
    /// replay server rejects, which is how pyatv's own failure-path tests work.
    #[test]
    fn a_wrong_seed_is_rejected_by_the_replay_server() {
        use super::tests_support as fixture;
        use crate::{HapCredentials, legacy_auth::LegacyPairVerify};

        let verify = LegacyPairVerify::new(&HapCredentials {
            ltpk: Vec::new(),
            ltsk: vec![0u8; 32],
            atv_id: Vec::new(),
            client_id: vec![0x11; 8],
        })
        .expect("credentials");

        assert_ne!(hex::encode(verify.step1_body()), fixture::VERIFY_STEP1);
    }

    /// GCM output is split into ciphertext and a detached 16-byte tag, as pyatv returns them.
    #[test]
    fn gcm_splits_ciphertext_from_tag() {
        let (ciphertext, tag) = gcm_encrypt(
            &[0x55u8; AES_BLOCK_LEN],
            &[0x66u8; AES_BLOCK_LEN],
            &[0x77u8; 32],
        )
        .expect("gcm encrypt");

        assert_eq!(ciphertext.len(), 32);
        assert_eq!(tag.len(), AES_BLOCK_LEN);
    }
}
