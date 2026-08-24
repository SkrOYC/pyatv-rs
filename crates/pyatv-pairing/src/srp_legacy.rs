//! SRP6a, legacy AirPlay profile: RFC 5054 2048-bit group, generator 2, SHA-1.
//!
//! Port of `AtvSRPContext`/`LegacySRPAuthHandler.step1..step3`
//! (`pyatv/protocols/airplay/srp.py:59-69,151-179`) together with the `srptools` code those drive
//! (`srptools/context.py:36-243`, `srptools/common.py:94-134`, `srptools/client.py:9-43`). Kept
//! deliberately apart from [`crate::srp_hap`]: different group, different hash, different session
//! key. Merging them guarantees one of the two breaks silently.
//!
//! ## Why this is hand-rolled instead of using the `srp` crate
//!
//! Three things `srp` cannot express:
//!
//! 1. **The doubled session key.** `K = SHA1(S ‖ 0x00000000) ‖ SHA1(S ‖ 0x00000001)`, 40 bytes,
//!    where every SRP crate computes `K = H(S)` (`pyatv/protocols/airplay/srp.py:62-69`).
//! 2. **`srptools`' minimal-length integer encoding.** Every integer fed to a hash goes through
//!    `int_to_bytes` (`srptools/utils.py:46-53`), which is `unhexlify('%x' % val)` — the *shortest*
//!    big-endian encoding, zero-padded only to an even number of hex digits. So `A` and `B` are
//!    hashed unpadded in `M1`, and `H(N) XOR H(g)` and `H(I)` are re-encoded as integers, losing any
//!    leading zero byte. Only `u = H(PAD(A) ‖ PAD(B))` and `k = H(N ‖ PAD(g))` pad, via
//!    `SRPContext.pad` (`srptools/context.py:64-71`).
//! 3. **Unpadded `H(g)` in `M1`.** `get_common_session_key_proof` hashes `self._gen` directly
//!    (`srptools/context.py:213-232`), i.e. the single byte `0x02`. This is the same quirk the HAP
//!    profile has, confirmed shared rather than assumed
//!    (`docs/research/hap-pairing-port-spec.md`, corrections §6).
//!
//! ## The other deviations, replicated
//!
//! - **The Ed25519 identity seed doubles as the SRP ephemeral secret `a`**
//!   (`pyatv/protocols/airplay/srp.py:159-161`), read as a big-endian integer. Poor hygiene, but
//!   changing it breaks interoperability and makes the captured known-answer test unreproducible.
//! - **The username is the AirPlay client identifier**, the 8-byte random client id rendered as
//!   uppercase hex (`pyatv/protocols/airplay/auth/legacy.py:51-54`), not a fixed literal.
//!
//! Everything here is verified byte-for-byte against the captured session in
//! `tests/fake_device/airplay.py:27-45`; see the tests at the bottom of this module.

use std::sync::LazyLock;

use num_bigint::BigUint;
use sha1::{Digest, Sha1};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// RFC 5054 2048-bit MODP group, `srptools/constants.py:26-35`.
pub const PRIME_2048_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CB",
    "B4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0",
    "CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740A",
    "DBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481",
    "F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDB",
    "F52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C382",
    "71AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F",
    "9E4AFF73",
);

/// Generator for the 2048-bit group, `srptools/constants.py:25`.
pub const GENERATOR: u8 = 2;

/// Suffix appended to `S` for the first half of the doubled session key.
pub const SESSION_KEY_COUNTER_0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
/// Suffix appended to `S` for the second half of the doubled session key.
pub const SESSION_KEY_COUNTER_1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Length of the doubled session key: two SHA-1 digests.
pub const SESSION_KEY_LEN: usize = 40;

// Parsing a compile-time-constant hex string cannot fail, and a bad parse here would be a build
// error in disguise, so the fallback is a deliberately impossible zero rather than a panic.
static PRIME: LazyLock<BigUint> =
    LazyLock::new(|| BigUint::parse_bytes(PRIME_2048_HEX.as_bytes(), 16).unwrap_or_default());

/// `int_to_bytes(N)`, 256 bytes, which is also the width `SRPContext.pad` pads to.
static PRIME_BYTES: LazyLock<Vec<u8>> = LazyLock::new(|| PRIME.to_bytes_be());

/// `srptools`' `int_to_bytes`: shortest big-endian encoding, `b"\x00"` for zero
/// (`srptools/utils.py:22-53`).
///
/// `BigUint::to_bytes_be` is already minimal for every value including zero, so the
/// [`crate::srp_encoding::minimal_be`] pass is a no-op here — it is applied anyway so both SRP
/// profiles demonstrably share one implementation of the rule rather than two that happen to agree.
fn int_to_bytes(value: &BigUint) -> Vec<u8> {
    crate::srp_encoding::minimal_be(&value.to_bytes_be()).to_vec()
}

/// `SRPContext.pad`: right-justify to the byte length of `N` (`srptools/context.py:64-71`).
fn pad(value: &BigUint) -> Vec<u8> {
    let bytes = int_to_bytes(value);
    let width = PRIME_BYTES.len();
    let mut padded = vec![0u8; width.saturating_sub(bytes.len())];
    padded.extend_from_slice(&bytes);
    padded
}

fn sha1_of(parts: &[&[u8]]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// `SRPContext.hash(...)` in its default integer-returning mode (`srptools/context.py:73-102`).
fn sha1_as_int(parts: &[&[u8]]) -> BigUint {
    BigUint::from_bytes_be(&sha1_of(parts))
}

/// Build the legacy profile's 40-byte session key from the premaster secret.
///
/// `K = SHA1(S ‖ 0x00000000) ‖ SHA1(S ‖ 0x00000001)`, where `S` is in its shortest big-endian form
/// because `SRPContext.hash` converts the integer with `int_to_bytes`
/// (`pyatv/protocols/airplay/srp.py:62-69`).
#[must_use]
pub fn compute_doubled_session_key(premaster_secret: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(SESSION_KEY_LEN);
    for counter in [SESSION_KEY_COUNTER_0, SESSION_KEY_COUNTER_1] {
        key.extend_from_slice(&sha1_of(&[premaster_secret, &counter]));
    }
    key
}

/// Client side of the legacy AirPlay SRP exchange.
///
/// One instance per pair-setup attempt. Construct it, send [`LegacySrpClient::public_key`] only
/// after [`LegacySrpClient::process_challenge`] has run (pyatv reads `session.public` from the same
/// object, and `A` does not depend on the challenge, but keeping the order matches the wire flow).
#[derive(Debug)]
pub struct LegacySrpClient {
    /// SRP username `I`: the AirPlay client identifier as uppercase hex.
    username: String,
    /// SRP ephemeral secret `a`, which is the Ed25519 seed read as a big-endian integer.
    ephemeral_secret: BigUint,
    /// `A = g^a mod N`.
    public: BigUint,
    /// The 40-byte doubled session key `K`, once the challenge has been processed.
    session_key: Option<Vec<u8>>,
    /// `M2 = H(A ‖ M1 ‖ K)`, the value the device is expected to return.
    expected_device_proof: Option<[u8; 20]>,
}

impl LegacySrpClient {
    /// Start an exchange for an existing AirPlay identity.
    ///
    /// `ephemeral_secret` is the credential's 32-byte seed, reused verbatim as `a`; see the module
    /// documentation for why.
    #[must_use]
    pub fn new(username: impl Into<String>, ephemeral_secret: &[u8]) -> Self {
        let secret = BigUint::from_bytes_be(ephemeral_secret);
        let public = BigUint::from(GENERATOR).modpow(&secret, &PRIME);
        Self {
            username: username.into(),
            ephemeral_secret: secret,
            public,
            session_key: None,
            expected_device_proof: None,
        }
    }

    /// The client's public value `A`, in `srptools`' shortest big-endian form.
    ///
    /// pyatv transmits `binascii.unhexlify(session.public)`
    /// (`pyatv/protocols/airplay/auth/legacy.py:62-64`), and `session.public` is `hex_from(A)`, so
    /// a leading zero byte would be dropped rather than padded to 256 bytes.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        int_to_bytes(&self.public)
    }

    /// Consume the device's salt and `B`, producing the client proof `M1`.
    ///
    /// Follows `SRPClientSession.process` (`srptools/common.py:94-134`,
    /// `srptools/client.py:27-38`) step for step:
    /// `x = H(s ‖ H(I ‖ ":" ‖ P))`, `u = H(PAD(A) ‖ PAD(B))`, `v = g^x mod N`,
    /// `S = (B - k·v)^(a + u·x) mod N`, then the doubled `K` and
    /// `M1 = H(H(N) XOR H(g) ‖ H(I) ‖ s ‖ A ‖ B ‖ K)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SrpPublicKey`] if `B mod N == 0`, the one check `srptools` performs
    /// (`srptools/common.py:122-123`).
    pub fn process_challenge(
        &mut self,
        password: &str,
        salt: &[u8],
        device_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let prime = &*PRIME;
        let generator = BigUint::from(GENERATOR);

        let device_public = BigUint::from_bytes_be(device_public_key) % prime;
        if device_public == BigUint::ZERO {
            return Err(Error::SrpPublicKey { peer: "accessory" });
        }

        // k = H(N | PAD(g)) -- both operands padded, unlike M1's H(g).
        let multiplier = sha1_as_int(&[&PRIME_BYTES, &pad(&generator)]);
        // x = H(s | H(I | ":" | P))
        let identity = sha1_of(&[self.username.as_bytes(), b":", password.as_bytes()]);
        let password_hash = sha1_as_int(&[salt, &identity]);
        // u = H(PAD(A) | PAD(B))
        let common_secret = sha1_as_int(&[&pad(&self.public), &pad(&device_public)]);

        let verifier = generator.modpow(&password_hash, prime);
        // Python's three-argument pow accepts the negative `B - k*v` directly; reducing first is
        // equivalent because the exponent is positive.
        let base = (device_public.clone() + prime - (multiplier * verifier) % prime) % prime;
        let exponent = &self.ephemeral_secret + common_secret * &password_hash;
        let premaster_secret = base.modpow(&exponent, prime);

        let session_key = compute_doubled_session_key(&int_to_bytes(&premaster_secret));

        // M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K), with every integer in shortest form.
        let hash_n = sha1_as_int(&[&PRIME_BYTES]);
        let hash_g = sha1_as_int(&[&int_to_bytes(&generator)]);
        let hash_xor = int_to_bytes(&(hash_n ^ hash_g));
        let hash_identity = int_to_bytes(&sha1_as_int(&[self.username.as_bytes()]));
        let public_bytes = int_to_bytes(&self.public);
        let device_public_bytes = int_to_bytes(&device_public);
        let proof = sha1_of(&[
            &hash_xor,
            &hash_identity,
            salt,
            &public_bytes,
            &device_public_bytes,
            &session_key,
        ]);

        // M2 = H(A | M1 | K), which the device echoes back.
        self.expected_device_proof = Some(sha1_of(&[&public_bytes, &proof, &session_key]));
        self.session_key = Some(session_key);

        Ok(proof.to_vec())
    }

    /// The 40-byte doubled session key `K`, available after
    /// [`LegacySrpClient::process_challenge`].
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }

    /// The proof `M2 = H(A ‖ M1 ‖ K)` this client expects the device to return.
    #[must_use]
    pub fn expected_device_proof(&self) -> Option<&[u8; 20]> {
        self.expected_device_proof.as_ref()
    }

    /// Check the device's proof in constant time.
    ///
    /// **Deliberate deviation from pyatv.** `LegacySRPAuthHandler.step2` calls
    /// `session.verify_proof(session.key_proof_hash)`
    /// (`pyatv/protocols/airplay/srp.py:177-178`), which compares `srptools`' locally computed
    /// value against itself (`srptools/client.py:40-42`) and therefore can never fail; the device's
    /// actual proof is never passed in. Verifying it for real is what SRP is for, costs nothing
    /// against an honest device, and closes a man-in-the-middle gap
    /// (`docs/research/hap-pairing-port-spec.md` §11.1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::ProofMismatch`] if the proof differs or the challenge has not been
    /// processed yet.
    pub fn verify_device_proof(&self, proof: &[u8]) -> Result<()> {
        let expected = self
            .expected_device_proof
            .as_ref()
            .ok_or(Error::ProofMismatch)?;

        if bool::from(expected.ct_eq(proof)) {
            Ok(())
        } else {
            Err(Error::ProofMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GENERATOR, LegacySrpClient, PRIME_2048_HEX, SESSION_KEY_LEN, compute_doubled_session_key,
        int_to_bytes, pad,
    };
    use num_bigint::BigUint;

    /// Captured session constants, `tests/fake_device/airplay.py:20-22`.
    const DEVICE_IDENTIFIER: &str = "75FBEEC773CFC563";
    const DEVICE_AUTH_KEY: &str =
        "8F06696F2542D70DF59286C761695C485F815BE3D152849E1361282D46AB1493";
    const DEVICE_PIN: &str = "2271";

    /// `B` from `_DEVICE_AUTH_STEP1_RESP` (`tests/fake_device/airplay.py:29`).
    const DEVICE_B_HEX: &str = concat!(
        "8817e16146c7d12b45e810b0bf190a4ccb25d9a20a8d0504d874daa8db5574c51c8b3370",
        "3a95c00bdbe99c8c3745d1ef1b38e538edfd98e09ec029effe6f28b3b54a1bd41c28d8f3",
        "3da6f5ac9327bfce9a66869dae645b5cbd2c6b8fbe14a30ad4f8598154f2ef7f4f52cee3",
        "e3042a69780463c26bbb764870eb1995b26a2a4ade05564836d788baf07469a143c410ea",
        "9d07a068eb790b2b0aa5b86c990636814e3fa1a899ceba1af45b211ca4bd3b5b66ffaf16",
        "051a4f851e120476054258f257b8521a068907ad5e9c7220d5cef9aa072dec9edb7ebf63",
        "3cad4d52d105cf58440f17e236332b0b26539851a879e9ac8d3c2da4c590785468e59029",
        "6d39d737",
    );
    /// `salt` from the same response.
    const DEVICE_SALT_HEX: &str = "fca6dcb6b83a7c716a692f806e915954";
    /// `pk` from `_DEVICE_AUTH_STEP2` — the client's `A` as pyatv actually put it on the wire.
    const EXPECTED_A_HEX: &str = concat!(
        "0819b6ba7feead4753809314e2b4c5db9109f737a0fc70b758342b6bbf536fae4e40cf94",
        "607588abb17c2076030cc00c2c1fa5fc3b3dfe8aa1ec2f23f74d917c0792fbf02f131377",
        "dfb8ae2a1656ceaa0a36bb3ab752586e1af17e1d5ef24ce083f3f9298d0be761f26c0d48",
        "af86510bf9aac7940cf90bff6bd214cf34b5536856c80f076cfbe06fd69af9d6a07a6d3a",
        "c580dfffc8a40b9730575a16c5046cd73321a944880dcf9fac952afc7ffd2d135e57ec20",
        "8b11cef22b734f331ad4d8c9a737b588f7b30bd5210c65cae2ba0226f69ce7b505771faa",
        "63af89ed2f9e8325d7d5f3a2da7412f9d837860632d7f81b7fa5e09dd85e1539184070c0",
        "fa8433c2",
    );
    /// `proof` from `_DEVICE_AUTH_STEP2` — the client's `M1`.
    const EXPECTED_M1_HEX: &str = "fc6286910833d3e7ae0631d47ddbb0f492ef85b8";
    /// `proof` from `_DEVICE_AUTH_STEP2_RESP` — the device's `M2`.
    const DEVICE_M2_HEX: &str = "84a88548b12bce122ad1cea6caff312630edcf27";

    fn unhex(value: &str) -> Vec<u8> {
        hex::decode(value).expect("test fixture is valid hex")
    }

    fn captured_client() -> LegacySrpClient {
        LegacySrpClient::new(DEVICE_IDENTIFIER, &unhex(DEVICE_AUTH_KEY))
    }

    /// The 2048-bit group must be the RFC 5054 one, 256 bytes wide, and must agree with
    /// `srp::groups::G2048` — the transcription from `srptools/constants.py` is checked against a
    /// completely independent copy of the same RFC table rather than trusted.
    #[test]
    fn prime_is_the_rfc_5054_2048_bit_group() {
        use srp::bigint::modular::ConstMontyParams;

        let prime = BigUint::parse_bytes(PRIME_2048_HEX.as_bytes(), 16).expect("prime parses");

        assert_eq!(prime.to_bytes_be().len(), 256);
        assert_eq!(prime.bits(), 2048);
        assert_eq!(GENERATOR, 2);
        assert_eq!(
            prime,
            BigUint::from_bytes_be(&srp::groups::G2048::PARAMS.modulus().to_be_bytes())
        );
    }

    /// `pad` widens to `len(N)`, `int_to_bytes` does not pad at all — the distinction that decides
    /// whether `M1` matches a real device.
    #[test]
    fn padding_applies_only_where_srptools_asks_for_it() {
        let generator = BigUint::from(GENERATOR);

        assert_eq!(int_to_bytes(&generator), vec![0x02]);
        assert_eq!(pad(&generator).len(), 256);
        assert_eq!(pad(&generator)[255], 0x02);
        assert_eq!(int_to_bytes(&BigUint::ZERO), vec![0x00]);
    }

    /// Two SHA-1 digests concatenated, so exactly 40 bytes, and the halves must differ because the
    /// counter suffix differs.
    #[test]
    fn doubled_session_key_is_forty_bytes_of_two_distinct_halves() {
        let key = compute_doubled_session_key(b"premaster secret");

        assert_eq!(key.len(), SESSION_KEY_LEN);
        assert_ne!(&key[..20], &key[20..]);
    }

    /// The counter suffix is appended to `S`, so the first half must not be a plain `SHA1(S)`.
    #[test]
    fn first_half_is_not_a_plain_hash_of_the_secret() {
        use sha1::{Digest, Sha1};

        let key = compute_doubled_session_key(b"premaster secret");

        assert_ne!(&key[..20], Sha1::digest(b"premaster secret").as_slice());
    }

    /// Known-answer test against the captured session in `tests/fake_device/airplay.py:27-33`:
    /// given the fixed identifier, seed, PIN, salt and `B`, the client must produce exactly the
    /// `A` and `M1` pyatv put on the wire.
    #[test]
    fn captured_session_reproduces_a_and_m1_byte_for_byte() {
        let mut client = captured_client();

        let proof = client
            .process_challenge(DEVICE_PIN, &unhex(DEVICE_SALT_HEX), &unhex(DEVICE_B_HEX))
            .expect("challenge processes");

        assert_eq!(client.public_key(), unhex(EXPECTED_A_HEX));
        assert_eq!(proof, unhex(EXPECTED_M1_HEX));
    }

    /// The device's returned proof in the same capture must match the `M2` this client derives,
    /// which independently confirms `K` and `M1`.
    #[test]
    fn captured_session_device_proof_verifies() {
        let mut client = captured_client();
        client
            .process_challenge(DEVICE_PIN, &unhex(DEVICE_SALT_HEX), &unhex(DEVICE_B_HEX))
            .expect("challenge processes");

        assert_eq!(
            client.expected_device_proof().map(<[u8; 20]>::as_slice),
            Some(unhex(DEVICE_M2_HEX).as_slice())
        );
        assert!(client.verify_device_proof(&unhex(DEVICE_M2_HEX)).is_ok());
        assert!(client.verify_device_proof(&[0u8; 20]).is_err());
        assert_eq!(client.session_key().map(<[u8]>::len), Some(SESSION_KEY_LEN));
    }

    /// A wrong PIN must change `M1`; this is the check the device performs and the client cannot.
    #[test]
    fn a_different_pin_produces_a_different_proof() {
        let mut client = captured_client();

        let proof = client
            .process_challenge("0000", &unhex(DEVICE_SALT_HEX), &unhex(DEVICE_B_HEX))
            .expect("challenge processes");

        assert_ne!(proof, unhex(EXPECTED_M1_HEX));
    }

    /// `B mod N == 0` is the one input `srptools` rejects outright.
    #[test]
    fn a_zero_device_public_value_is_rejected() {
        let mut client = captured_client();

        assert!(
            client
                .process_challenge(DEVICE_PIN, &unhex(DEVICE_SALT_HEX), &[0u8; 256])
                .is_err()
        );
    }

    /// Verifying before a challenge has been processed must not succeed by accident.
    #[test]
    fn verification_before_the_challenge_fails() {
        assert!(captured_client().verify_device_proof(&[0u8; 20]).is_err());
    }
}
