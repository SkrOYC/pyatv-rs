//! Ed25519 identity keys and X25519 pair-verify ephemerals.
//!
//! Ported from `pyatv/auth/hap_srp.py:66-82` (`initialize`). Two things there are worth restating
//! because they look like accidents and are not:
//!
//! - The controller's Ed25519 **seed** is reused verbatim as the SRP client ephemeral exponent `a`
//!   (`hap_srp.py:147-149`). `docs/research/hap-pairing-port-spec.md` §2.6 corrects the earlier
//!   research report on this: the reuse is not legacy-AirPlay-only, the modern HAP profile does it
//!   too, for every MRP/Companion/AirPlay pairing. [`crate::pairing::PairSetup`] therefore hands
//!   the same 32 bytes to both [`sign`] and [`crate::srp_hap::HapSrpClient`].
//! - pyatv regenerates *both* keypairs on every `initialize()`, including during pair-verify where
//!   the fresh Ed25519 pair is immediately discarded in favour of the stored `ltsk`
//!   (`hap_srp.py:84-124`). This port only generates what each flow actually needs.
//!
//! `zeroize` is available as a non-default feature on both dalek crates but is deliberately not
//! enabled: `docs/research/crate-verification-2026-08-24.md` did not verify that feature's
//! resolution against the rest of the pinned tree, and turning it on is a dependency change rather
//! than a code change. Secrets in this crate live in plain `[u8; 32]`/`Vec<u8>` and are not wiped.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::SysRng;
use rand_core::{Rng, UnwrapErr};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{Error, Result};

/// Length of an Ed25519 seed, an X25519 scalar and every HKDF output in this stack.
pub const SEED_LEN: usize = 32;
/// Length of an X25519 public key and of the ECDH shared secret.
pub const X25519_LEN: usize = 32;

/// Fill 32 bytes from the operating system CSPRNG.
///
/// Uses `rand_core::UnwrapErr(rand::rngs::SysRng)`, the adapter the `rand` 0.10 fallible-RNG
/// redesign requires in order to satisfy the infallible `CryptoRng` bound the dalek crates expect;
/// it panics only if the OS entropy source itself fails.
#[must_use]
pub fn random_seed() -> [u8; SEED_LEN] {
    let mut seed = [0u8; SEED_LEN];
    UnwrapErr(SysRng).fill_bytes(&mut seed);
    seed
}

/// The Ed25519 public key for a raw 32-byte seed.
#[must_use]
pub fn ed25519_public_key(seed: &[u8; SEED_LEN]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign `message` with the Ed25519 key derived from `seed`.
#[must_use]
pub fn sign(seed: &[u8; SEED_LEN], message: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Whether `signature` is a valid Ed25519 signature over `message` for `public_key`.
///
/// Returns `false` — never an error — when the public key or the signature is the wrong length or
/// is not a canonical point, so callers can map one boolean onto whichever protocol-specific error
/// variant describes the step they are in.
///
/// `verify_strict` is used rather than the permissive `verify`: it additionally rejects small-order
/// public keys and small-order `R` values. pyatv verifies via `cryptography`, which does not make
/// that distinction; no honest accessory produces such a signature.
#[must_use]
pub fn verify_signature(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(public_key) = <[u8; 32]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&public_key) else {
        return false;
    };

    verifying_key
        .verify_strict(message, &Signature::from_bytes(&signature))
        .is_ok()
}

/// Raw X25519 for a caller that holds a long-lived scalar.
///
/// Only the reference accessory needs this: it derives its "ephemeral" X25519 key from the same
/// fixed seed as its Ed25519 identity and reuses it for every session
/// (`pyatv/protocols/mrp/server_auth.py:29-45`). Controllers use [`EphemeralExchange`], whose
/// single-use guarantee is enforced by the type system.
#[must_use]
pub fn x25519_shared_secret(
    scalar: &[u8; SEED_LEN],
    peer_public_key: &[u8; X25519_LEN],
) -> [u8; X25519_LEN] {
    x25519_dalek::x25519(*scalar, *peer_public_key)
}

/// The X25519 public key for a long-lived scalar, i.e. `x25519(scalar, basepoint)`.
///
/// Same caveat as [`x25519_shared_secret`]: controllers should use [`EphemeralExchange`].
#[must_use]
pub fn x25519_public_key(scalar: &[u8; SEED_LEN]) -> [u8; X25519_LEN] {
    x25519_dalek::x25519(*scalar, x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// A single-use X25519 keypair for one pair-verify exchange.
pub struct EphemeralExchange {
    secret: Secret,
    public_key: [u8; X25519_LEN],
}

/// The scalar behind an [`EphemeralExchange`].
///
/// The production path is always [`Secret::Generated`], whose `EphemeralSecret` cannot be built
/// from caller-supplied bytes and zeroizes on drop. [`Secret::Pinned`] exists only so known-answer
/// tests can replay a captured exchange; both arms compute the same function, because
/// `EphemeralSecret::diffie_hellman` is `their_public.mul_clamped(scalar)` and so is
/// [`x25519_shared_secret`].
enum Secret {
    Generated(EphemeralSecret),
    #[cfg(feature = "test-server")]
    Pinned([u8; SEED_LEN]),
}

// `EphemeralSecret` has no `Debug` impl, and printing one would be a leak anyway.
impl std::fmt::Debug for EphemeralExchange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EphemeralExchange")
            .field("public_key", &hex::encode(self.public_key))
            .finish_non_exhaustive()
    }
}

impl EphemeralExchange {
    /// Generate a fresh keypair from the operating system CSPRNG.
    #[must_use]
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random_from_rng(&mut UnwrapErr(SysRng));
        let public_key = PublicKey::from(&secret).to_bytes();
        Self {
            secret: Secret::Generated(secret),
            public_key,
        }
    }

    /// Build a keypair from a caller-supplied scalar, for known-answer tests only.
    ///
    /// The whole point of [`EphemeralExchange::generate`] is that a controller's pair-verify
    /// keypair is fresh per session and never reused, so this must never be reachable from a
    /// shipping build: it is gated behind the test-only `test-server` feature and hidden from the
    /// documentation. `tests/hap_srp_kat.rs` needs it to replay the fixed exchange whose ciphertexts
    /// pyatv produced.
    #[cfg(feature = "test-server")]
    #[doc(hidden)]
    #[must_use]
    pub fn from_scalar(scalar: [u8; SEED_LEN]) -> Self {
        Self {
            public_key: x25519_public_key(&scalar),
            secret: Secret::Pinned(scalar),
        }
    }

    /// The public key to put in the pair-verify M1 `PublicKey` TLV.
    #[must_use]
    pub fn public_key(&self) -> &[u8; X25519_LEN] {
        &self.public_key
    }

    /// Consume the keypair and produce the ECDH shared secret with `peer_public_key`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the peer's key is not 32 bytes.
    pub fn exchange(self, peer_public_key: &[u8]) -> Result<[u8; X25519_LEN]> {
        let peer =
            <[u8; X25519_LEN]>::try_from(peer_public_key).map_err(|_| Error::InvalidKey {
                kind: "peer X25519 public",
            })?;

        Ok(match self.secret {
            Secret::Generated(secret) => secret.diffie_hellman(&PublicKey::from(peer)).to_bytes(),
            #[cfg(feature = "test-server")]
            Secret::Pinned(scalar) => x25519_shared_secret(&scalar, &peer),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EphemeralExchange, ed25519_public_key, random_seed, sign, verify_signature,
        x25519_shared_secret,
    };

    /// `docs/research/hap-pairing-port-spec.md` §8: the reference accessory's seed is 32 bytes of
    /// `0xAA`, and the `ltpk` field of pyatv's `CLIENT_CREDENTIALS` constant is exactly its Ed25519
    /// public key. This is the cheapest end-to-end check that the seed handling is right.
    #[test]
    fn accessory_seed_matches_the_pyatv_credentials_anchor() {
        assert_eq!(
            hex::encode(ed25519_public_key(&[0xAA; 32])),
            "e734ea6c2b6257de72355e472aa05a4c487e6b463c029ed306df2f01b5636b58"
        );
    }

    #[test]
    fn signatures_verify_and_tampering_does_not() {
        let seed = random_seed();
        let public_key = ed25519_public_key(&seed);
        let signature = sign(&seed, b"device info");

        assert!(verify_signature(&public_key, b"device info", &signature));
        assert!(!verify_signature(&public_key, b"other info", &signature));
        assert!(!verify_signature(&[0u8; 32], b"device info", &signature));
        assert!(!verify_signature(
            &public_key,
            b"device info",
            &signature[..63]
        ));
    }

    #[test]
    fn ephemeral_and_static_x25519_agree() {
        let controller = EphemeralExchange::generate();
        let controller_public = *controller.public_key();

        let accessory_scalar = [0xAA; 32];
        let accessory_public =
            x25519_shared_secret(&accessory_scalar, &x25519_dalek::X25519_BASEPOINT_BYTES);

        let controller_shared = controller.exchange(&accessory_public).unwrap();
        let accessory_shared = x25519_shared_secret(&accessory_scalar, &controller_public);

        assert_eq!(controller_shared, accessory_shared);
    }

    #[test]
    fn a_short_peer_key_is_rejected() {
        assert!(EphemeralExchange::generate().exchange(&[0u8; 31]).is_err());
    }
}
