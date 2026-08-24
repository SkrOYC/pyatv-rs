//! The controller side of the HAP SRP6a exchange (pair-setup M1 through M4).

use sha2::{Digest, Sha512};
use srp::{
    Client, Group,
    groups::G3072,
    utils::{compute_m1_rfc5054, compute_m2},
};
use subtle::ConstantTimeEq;

use crate::{Error, Result};

/// The literal SRP username the HAP profile uses. Not a per-device identity.
///
/// `pyatv/auth/hap_srp.py:140` passes this as `SRPContext`'s username for every pairing.
pub const PAIR_SETUP_USERNAME: &[u8] = b"Pair-Setup";

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
#[derive(Debug)]
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

#[derive(Debug)]
struct Exchange {
    /// SRP session key `K = SHA512(S)`.
    session_key: Vec<u8>,
    /// The controller's proof `M1`, sent in pair-setup M3.
    client_proof: Vec<u8>,
    /// The accessory proof `M2 = H(A | M1 | K)` we expect back in M4.
    expected_device_proof: Vec<u8>,
}

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
        Self {
            pin: pin.to_owned(),
            ephemeral_secret,
            public_key: HapClient::new().compute_public_ephemeral(&ephemeral_secret),
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
    /// The proof is computed with an **unpadded** `H(g)`; see the module documentation for why the
    /// crate's own `process_reply` proof cannot be used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::SrpPublicKey`] if `B mod N == 0`, the safeguard RFC 5054 requires.
    pub fn process_challenge(&mut self, salt: &[u8], device_public_key: &[u8]) -> Result<Vec<u8>> {
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

    use super::{HapClient, HapSrpClient, PAIR_SETUP_USERNAME};

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

    #[test]
    fn a_is_deterministic_in_the_ephemeral_secret() {
        let first = HapSrpClient::new(1111, [0x11; 32]);
        let second = HapSrpClient::new(1111, [0x11; 32]);
        let other = HapSrpClient::new(1111, [0x12; 32]);

        assert_eq!(first.public_key(), second.public_key());
        assert_ne!(first.public_key(), other.public_key());
        assert!(!first.public_key().is_empty());
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
        let device_public_key = vec![0x33u8; 384];

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

    #[test]
    fn a_zero_device_public_key_is_rejected() {
        let mut client = HapSrpClient::new(1111, [0x11; 32]);
        assert!(client.process_challenge(&[0u8; 16], &[0u8; 384]).is_err());
    }

    #[test]
    fn proof_verification_requires_a_processed_challenge() {
        let client = HapSrpClient::new(1111, [0x11; 32]);
        assert!(client.session_key().is_none());
        assert!(client.verify_device_proof(&[0u8; 64]).is_err());
    }
}
