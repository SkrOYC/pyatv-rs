//! The controller side of the HAP SRP6a exchange (pair-setup M1 through M4).

use sha2::{Digest, Sha512};
use srp::{
    Client, Group,
    groups::G3072,
    utils::{compute_m1_rfc5054, compute_m2},
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, Result, srp_encoding::minimal_be};

/// The literal SRP username the HAP profile uses. Not a per-device identity.
///
/// `pyatv/auth/hap_srp.py:140` passes this as `SRPContext`'s username for every pairing.
pub const PAIR_SETUP_USERNAME: &[u8] = b"Pair-Setup";

/// Byte width of the HAP profile's modulus `N` — the 3072-bit RFC 5054 group, so 384 bytes.
///
/// Any SRP public value wider than this is out of range by definition, and forwarding one into
/// `srp` is not merely wrong but fatal: `Client::process_reply` calls `BoxedUint::resize` (through
/// `validate_b_pub` and `utils::monty_form`) to bring the value down to `N`'s precision, and
/// `crypto_bigint`'s `Resize` **panics** rather than erroring when the value does not fit;
/// `utils::compute_u_padded` would underflow `n.len() - b_pub.len()` first in a release build.
/// TLV8 fragments values across same-tag entries with no length ceiling
/// ([`crate::tlv8`]), so a hostile or broken accessory can produce a 385-byte `PublicKey` with no
/// effort at all. Both directions therefore range-check before any bignum touches the value.
pub const MODULUS_LEN: usize = 384;

/// 3072-bit group, SHA-512, username folded into `x` — matching `srptools`' defaults.
type HapClient = Client<G3072, Sha512>;

/// Client side of the HAP SRP exchange.
///
/// Drives the SRP half of pair-setup: `A` for M3, the client proof `M1` for M3, verification of the
/// accessory's `M2` from M4, and the session key `K` that every later HKDF derivation uses as its
/// IKM. One instance per pairing attempt; the ephemeral secret `a` must never be reused across
/// attempts.
///
/// pyatv's equivalent is `SRPAuthHandler.step1`/`step2` (`pyatv/auth/hap_srp.py:138-163`).
pub struct HapSrpClient {
    /// The PIN shown on the device, stringified as pyatv does.
    pin: String,
    /// The client's ephemeral secret exponent `a` — the controller's Ed25519 seed, reused.
    ephemeral_secret: [u8; 32],
    /// `A = g^a mod N`, minimal big-endian, exactly as it goes on the wire.
    public_key: Vec<u8>,
    /// Populated by [`HapSrpClient::process_challenge`].
    exchange: Option<Exchange>,
}

// Hand-written: the derived `Debug` would print the PIN, the ephemeral exponent `a` and — through
// `Exchange` — the SRP session key `K`, which is the IKM for every transport key in the session.
// Only `A` is public, and even that is abbreviated because it is 384 bytes of noise in a log line.
impl std::fmt::Debug for HapSrpClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HapSrpClient")
            .field("pin", &"<redacted>")
            .field("ephemeral_secret", &"<redacted>")
            .field("public_key_len", &self.public_key.len())
            .field("challenge_processed", &self.exchange.is_some())
            .finish_non_exhaustive()
    }
}

// `Zeroize` itself is deliberately not implemented for the state machines: a public `zeroize()`
// would let a caller wipe a live exchange and then keep driving it. Only the drop is exposed, as
// the `ZeroizeOnDrop` marker.
impl Drop for HapSrpClient {
    fn drop(&mut self) {
        self.pin.zeroize();
        self.ephemeral_secret.zeroize();
        // `exchange` wipes itself; dropping it here is only for symmetry with the fields above.
        self.exchange = None;
    }
}

impl ZeroizeOnDrop for HapSrpClient {}

struct Exchange {
    /// SRP session key `K = SHA512(S)`.
    session_key: Vec<u8>,
    /// The controller's proof `M1`, sent in pair-setup M3.
    client_proof: Vec<u8>,
    /// The accessory proof `M2 = H(A | M1 | K)` we expect back in M4.
    expected_device_proof: Vec<u8>,
}

// Hand-written for the same reason as [`HapSrpClient`]'s: `session_key` is `K`. The two proofs are
// public values but are redacted together for uniformity — a proof leaked before it is sent is a
// PIN-guessing oracle for whoever reads the log.
impl std::fmt::Debug for Exchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Exchange")
            .field("session_key", &"<redacted>")
            .field("client_proof", &"<redacted>")
            .field("expected_device_proof", &"<redacted>")
            .finish()
    }
}

impl Zeroize for Exchange {
    fn zeroize(&mut self) {
        self.session_key.zeroize();
        self.client_proof.zeroize();
        self.expected_device_proof.zeroize();
    }
}

impl Drop for Exchange {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Exchange {}

impl HapSrpClient {
    /// Start an exchange for a numeric `pin` with a given ephemeral secret.
    ///
    /// `pin` is rendered zero-padded to four digits, which is what every pyatv pairing handler does
    /// before the value reaches the SRP layer (`pyatv/protocols/mrp/pairing.py:83-85` and the
    /// Companion/AirPlay equivalents all call `str(pin).zfill(4)`). PINs of more than four digits
    /// are passed through unchanged.
    ///
    /// `ephemeral_secret` is the controller's Ed25519 seed; see the [`super`] module documentation for why the same
    /// bytes serve as both.
    #[must_use]
    pub fn new(pin: u32, ephemeral_secret: [u8; 32]) -> Self {
        Self::with_pin(&format!("{pin:04}"), ephemeral_secret)
    }

    /// Start an exchange for a PIN that is already in its exact on-the-wire string form.
    #[must_use]
    pub fn with_pin(pin: &str, ephemeral_secret: [u8; 32]) -> Self {
        // `compute_public_ephemeral` already trims leading zero bytes, but `A` goes on the wire and
        // into `M1`/`M2` so the minimal form is a wire-format requirement, not an implementation
        // detail of that crate — route it through the shared helper and let the tests pin it.
        let public_key =
            minimal_be(&HapClient::new().compute_public_ephemeral(&ephemeral_secret)).to_vec();

        Self {
            pin: pin.to_owned(),
            ephemeral_secret,
            public_key,
            exchange: None,
        }
    }

    /// The client's public value `A = g^a mod N`, sent in pair-setup M3.
    ///
    /// Minimal big-endian with leading zero bytes stripped, matching `srptools`' `hex_from`
    /// rendering (`srptools:srptools/utils.py:22-34`) that pyatv unhexlifies onto the wire.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Consume the accessory's M2 (`salt` and `B`) and produce the client proof `M1` for M3.
    ///
    /// `B` is normalised to `srptools`' minimal big-endian form before anything else touches it,
    /// because that is the encoding pyatv hashes into `M1` — see [`crate::srp_encoding`]. Values
    /// wider than [`MODULUS_LEN`] are rejected outright rather than handed to `srp`, which would
    /// panic on them.
    ///
    /// The proof is computed with an **unpadded** `H(g)`; see the module documentation for why the
    /// crate's own `process_reply` proof cannot be used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SrpPublicKey`] if `B` is wider than the modulus or if `B mod N == 0`, the
    /// safeguard RFC 5054 requires.
    pub fn process_challenge(&mut self, salt: &[u8], device_public_key: &[u8]) -> Result<Vec<u8>> {
        let device_public_key = minimal_be(device_public_key);
        if device_public_key.len() > MODULUS_LEN {
            return Err(Error::SrpPublicKey { peer: "accessory" });
        }

        let client = HapClient::new();
        let verifier = client
            .process_reply(
                &self.ephemeral_secret,
                PAIR_SETUP_USERNAME,
                self.pin.as_bytes(),
                salt,
                device_public_key,
            )
            .map_err(|_| Error::SrpPublicKey { peer: "accessory" })?;

        // `ClientVerifier::key()` is the raw premaster secret `S`; the HAP session key is `H(S)`,
        // which `srptools` calls `session.key` (`srptools:srptools/context.py:143-149`).
        let session_key = Sha512::digest(verifier.key()).to_vec();

        let client_proof = compute_m1_rfc5054::<Sha512>(
            &G3072::generator(),
            true,
            PAIR_SETUP_USERNAME,
            salt,
            &self.public_key,
            device_public_key,
            &session_key,
        );
        let expected_device_proof =
            compute_m2::<Sha512>(&self.public_key, &client_proof, &session_key);

        self.exchange = Some(Exchange {
            session_key,
            client_proof: client_proof.to_vec(),
            expected_device_proof: expected_device_proof.to_vec(),
        });

        Ok(client_proof.to_vec())
    }

    /// The proof to send in pair-setup M3, once [`HapSrpClient::process_challenge`] has run.
    #[must_use]
    pub fn client_proof(&self) -> Option<&[u8]> {
        self.exchange.as_ref().map(|state| &*state.client_proof)
    }

    /// Verify the accessory's M4 proof `M2 = H(A | M1 | K)`.
    ///
    /// **This is a deliberate divergence from pyatv.** `SRPAuthHandler.step2`
    /// (`pyatv/auth/hap_srp.py:151-163`) calls `session.verify_proof(session.key_proof_hash)`,
    /// which compares a value against itself (`srptools:srptools/client.py:40-42`) and can never
    /// fail; `step2` has no parameter for the accessory's proof at all, and all four call sites
    /// read the M4 `Proof` TLV only to log it. Checking it here is what actually gives SRP's
    /// mutual-authentication property — without it a MITM that relays M1–M3 is undetectable by the
    /// controller. See `docs/research/hap-pairing-port-spec.md` §11 finding 1.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfOrder`] if the challenge has not been processed yet, and
    /// [`Error::ProofMismatch`] if the accessory's proof does not match.
    pub fn verify_device_proof(&self, proof: &[u8]) -> Result<()> {
        let exchange = self
            .exchange
            .as_ref()
            .ok_or(Error::OutOfOrder("SRP challenge has not been processed"))?;

        if bool::from(exchange.expected_device_proof.ct_eq(proof)) {
            Ok(())
        } else {
            Err(Error::ProofMismatch)
        }
    }

    /// The SRP session key `K`, which every subsequent HKDF derivation takes as its IKM.
    ///
    /// Note this is `K = SHA512(S)`, not the raw premaster secret `S`.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.exchange.as_ref().map(|state| &*state.session_key)
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha512};
    use srp::{Group, groups::G3072, utils::compute_hash_n_xor_hash_g};

    use super::{HapClient, HapSrpClient, MODULUS_LEN, PAIR_SETUP_USERNAME};

    /// `srptools` renders `H(N) XOR H(g)` and `H(I)` through an integer, so a leading zero byte in
    /// either would make its hashed input shorter than RustCrypto's fixed-width one. Both constants
    /// were computed for this profile and neither has one; pin the first bytes so that stays true.
    /// See the module documentation.
    #[test]
    fn the_srp_proof_constants_have_no_leading_zero_byte() {
        let n_xor_g = compute_hash_n_xor_hash_g::<Sha512>(&G3072::generator());
        assert_eq!(n_xor_g.len(), 64);
        assert_eq!(&hex::encode(&n_xor_g[..4]), "b3d63ef6");

        let username_hash = Sha512::digest(PAIR_SETUP_USERNAME);
        assert_eq!(hex::encode(&username_hash[..1]), "cd");
    }

    /// [`MODULUS_LEN`] has to be the real width of `N`, not a guess; read it back off the group.
    #[test]
    fn the_modulus_length_matches_the_group() {
        use srp::bigint::modular::ConstMontyParams;

        assert_eq!(
            G3072::PARAMS.modulus().to_be_bytes().len(),
            MODULUS_LEN,
            "the 3072-bit group is 384 bytes wide"
        );
    }

    #[test]
    fn a_is_deterministic_in_the_ephemeral_secret() {
        let first = HapSrpClient::new(1111, [0x11; 32]);
        let second = HapSrpClient::new(1111, [0x11; 32]);
        let other = HapSrpClient::new(1111, [0x12; 32]);

        assert_eq!(first.public_key(), second.public_key());
        assert_ne!(first.public_key(), other.public_key());
        assert!(!first.public_key().is_empty());
        // Minimal encoding: `A` is at most the modulus width and never carries a leading zero.
        assert!(first.public_key().len() <= MODULUS_LEN);
        assert_ne!(first.public_key()[0], 0);
    }

    #[test]
    fn pins_are_zero_padded_to_four_digits() {
        assert_eq!(HapSrpClient::new(42, [1; 32]).pin, "0042");
        assert_eq!(HapSrpClient::new(1111, [1; 32]).pin, "1111");
        assert_eq!(HapSrpClient::new(123_456, [1; 32]).pin, "123456");
    }

    /// The one boolean this whole module exists for: the proof we send must be the **unpadded**-`g`
    /// form, which is not what `Client::process_reply` computes. If these two ever agree, either the
    /// crate changed its default or the port silently reverted to the RFC 5054 padded form, and
    /// every real accessory would reject M3 with an authentication error.
    #[test]
    fn the_proof_is_the_unpadded_g_form_and_not_the_crates_default() {
        let salt = [0x5A; 16];
        let mut client = HapSrpClient::new(1111, [0x11; 32]);
        // Any `B` with `B mod N != 0` will do; `N` starts `ff…`, so this is in range.
        let device_public_key = vec![0x33u8; MODULUS_LEN];

        let proof = client.process_challenge(&salt, &device_public_key).unwrap();
        let padded = HapClient::new()
            .process_reply(
                &[0x11; 32],
                PAIR_SETUP_USERNAME,
                b"1111",
                &salt,
                &device_public_key,
            )
            .unwrap();

        assert_eq!(proof.len(), 64);
        assert_ne!(proof, padded.proof());
        assert_eq!(client.client_proof(), Some(&proof[..]));
        assert_eq!(client.session_key().map(<[u8]>::len), Some(64));
    }

    /// A `B` with a leading zero byte must hash as its minimal form, i.e. identically to the same
    /// value sent without the padding. `srptools` parses `B` as an integer and re-serialises it
    /// minimally, so the two encodings are the same number and must produce the same `M1`.
    #[test]
    fn a_leading_zero_in_b_does_not_change_the_proof() {
        let salt = [0x5A; 16];
        let mut padded_b = vec![0x00u8; 1];
        padded_b.extend(std::iter::repeat_n(0x33u8, MODULUS_LEN - 1));
        let trimmed_b = &padded_b[1..];

        let mut from_padded = HapSrpClient::new(1111, [0x11; 32]);
        let mut from_trimmed = HapSrpClient::new(1111, [0x11; 32]);

        assert_eq!(
            from_padded.process_challenge(&salt, &padded_b).unwrap(),
            from_trimmed.process_challenge(&salt, trimmed_b).unwrap()
        );
        assert_eq!(from_padded.session_key(), from_trimmed.session_key());
    }

    #[test]
    fn a_zero_device_public_key_is_rejected() {
        let mut client = HapSrpClient::new(1111, [0x11; 32]);
        assert!(
            client
                .process_challenge(&[0u8; 16], &[0u8; MODULUS_LEN])
                .is_err()
        );
    }

    /// A `B` wider than `N` must be refused, not forwarded: `srp` panics on it. The boundary is
    /// exercised from both sides so a future off-by-one shows up as a test failure rather than as
    /// an abort in the field.
    #[test]
    fn an_oversized_device_public_key_is_rejected_rather_than_panicking() {
        use crate::Error;

        for length in [MODULUS_LEN - 1, MODULUS_LEN] {
            let mut client = HapSrpClient::new(1111, [0x11; 32]);
            assert!(
                client
                    .process_challenge(&[0u8; 16], &vec![0x33u8; length])
                    .is_ok(),
                "{length} bytes is in range and must be accepted"
            );
        }

        for length in [MODULUS_LEN + 1, 512] {
            let mut client = HapSrpClient::new(1111, [0x11; 32]);
            assert!(
                matches!(
                    client.process_challenge(&[0u8; 16], &vec![0x33u8; length]),
                    Err(Error::SrpPublicKey { peer: "accessory" })
                ),
                "{length} bytes is out of range and must be refused"
            );
        }
    }

    /// Leading zeros do not count towards the width: a 385-byte `B` whose first byte is zero is a
    /// perfectly ordinary 384-byte value and must be accepted, normalised.
    #[test]
    fn an_oversized_but_leading_zero_padded_key_is_accepted() {
        let mut padded = vec![0x00u8];
        padded.extend(std::iter::repeat_n(0x33u8, MODULUS_LEN));

        let mut client = HapSrpClient::new(1111, [0x11; 32]);
        assert!(client.process_challenge(&[0u8; 16], &padded).is_ok());
    }

    #[test]
    fn proof_verification_requires_a_processed_challenge() {
        let client = HapSrpClient::new(1111, [0x11; 32]);
        assert!(client.session_key().is_none());
        assert!(client.verify_device_proof(&[0u8; 64]).is_err());
    }

    /// A `Debug` print must not expose the PIN, the ephemeral exponent or the session key.
    #[test]
    fn debug_redacts_every_secret() {
        let mut client = HapSrpClient::new(1234, [0x11; 32]);
        client
            .process_challenge(&[0x5A; 16], &vec![0x33u8; MODULUS_LEN])
            .unwrap();

        let rendered = format!("{client:?}");
        assert!(!rendered.contains("1234"), "the PIN leaked: {rendered}");
        assert!(!rendered.contains(&hex::encode([0x11u8; 32])));
        assert!(!rendered.contains(&hex::encode(client.session_key().unwrap())));
        assert!(!rendered.contains(&hex::encode(client.client_proof().unwrap())));
        assert!(rendered.contains("<redacted>"));

        // The inner state has its own `Debug`; check it directly too, since it is what a future
        // `#[derive(Debug)]` on the outer type would print.
        let inner = format!("{:?}", client.exchange.as_ref().unwrap());
        assert!(!inner.contains(&hex::encode(client.session_key().unwrap())));
        assert!(inner.contains("<redacted>"));
    }
}
