//! SRP6a, legacy AirPlay profile: RFC 5054 2048-bit group, generator 2, SHA-1.
//!
//! Used only by pre-HAP AirPlay device authentication
//! (`pyatv/protocols/airplay/srp.py::LegacySRPAuthHandler`). Kept deliberately separate from
//! [`crate::srp_hap`]: the group, the hash, the username semantics and the session-key derivation
//! all differ, and merging them would guarantee one of the two breaks silently. See
//! `docs/research/crypto-pairing.md` §2.2.
//!
//! Three deviations no SRP crate implements, all of which must be reproduced exactly:
//!
//! 1. **Doubled session key.** `K = SHA1(S || 0x00000000) || SHA1(S || 0x00000001)`, a 40-byte
//!    value, rather than the standard `K = H(S)`. Reminiscent of RFC 2945's interleaved-SHA1 trick
//!    but simpler: two whole-value hashes with a 4-byte big-endian counter suffix, no bit
//!    interleaving.
//! 2. **The Ed25519 identity seed doubles as the SRP ephemeral secret.** pyatv feeds the raw
//!    Ed25519 seed straight into the SRP client as `a`, conflating two normally independent
//!    secrets. Generating a separate ephemeral would be better cryptographic hygiene and would
//!    break interoperability with real devices.
//! 3. **The username is the AirPlay client identifier**, an uppercased hex string derived from an
//!    8-byte random ID, not a fixed literal.
//!
//! pyatv shares `srptools`' M1 code path across both profiles, so by inspection this profile also
//! uses the unpadded `H(g)`. The research report flags that as unconfirmed against a real capture;
//! treat it as an open question, not a settled fact.

use crate::Result;

/// Suffix appended to `S` for the first half of the doubled session key.
pub const SESSION_KEY_COUNTER_0: [u8; 4] = [0x00, 0x00, 0x00, 0x00];
/// Suffix appended to `S` for the second half of the doubled session key.
pub const SESSION_KEY_COUNTER_1: [u8; 4] = [0x00, 0x00, 0x00, 0x01];

/// Client side of the legacy AirPlay SRP exchange.
#[derive(Debug)]
pub struct LegacySrpClient {
    /// The AirPlay client identifier, used as the SRP username.
    username: String,
    /// The Ed25519 seed, reused as the SRP ephemeral secret `a`.
    identity_seed: [u8; 32],
    /// The 40-byte doubled session key, once computed.
    session_key: Option<Vec<u8>>,
}

impl LegacySrpClient {
    /// Start an exchange for an existing AirPlay identity.
    #[must_use]
    pub fn new(username: impl Into<String>, identity_seed: [u8; 32]) -> Self {
        Self {
            username: username.into(),
            identity_seed,
            session_key: None,
        }
    }

    /// The client's public value `A`.
    // TODO(step-1): `srp::groups::G2048` with SHA-1, ephemeral secret = `identity_seed`.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        todo!("LegacySrpClient::public_key")
    }

    /// Consume the device's salt and `B`, producing the client proof.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ProofMismatch`] if `B` is invalid.
    // TODO(step-1): compute S with `Client::compute_premaster_secret`, then build K with
    // `compute_doubled_session_key` rather than any of the crate's session-key helpers, which all
    // do single-hash K = H(S).
    pub fn process_challenge(
        &mut self,
        password: &str,
        salt: &[u8],
        device_public_key: &[u8],
    ) -> Result<Vec<u8>> {
        let _ = (
            password,
            salt,
            device_public_key,
            &self.username,
            &self.identity_seed,
        );
        todo!("LegacySrpClient::process_challenge")
    }

    /// The 40-byte doubled session key.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}

/// Build the legacy profile's 40-byte session key from the premaster secret.
///
/// `K = SHA1(S || 0x00000000) || SHA1(S || 0x00000001)`.
#[must_use]
pub fn compute_doubled_session_key(premaster_secret: &[u8]) -> Vec<u8> {
    use sha1::{Digest, Sha1};

    let mut key = Vec::with_capacity(40);
    for counter in [SESSION_KEY_COUNTER_0, SESSION_KEY_COUNTER_1] {
        let mut hasher = Sha1::new();
        hasher.update(premaster_secret);
        hasher.update(counter);
        key.extend_from_slice(&hasher.finalize());
    }
    key
}

#[cfg(test)]
mod tests {
    use super::compute_doubled_session_key;

    /// Two SHA-1 digests concatenated, so exactly 40 bytes, and the halves must differ because the
    /// counter suffix differs.
    #[test]
    fn doubled_session_key_is_forty_bytes_of_two_distinct_halves() {
        let key = compute_doubled_session_key(b"premaster secret");

        assert_eq!(key.len(), 40);
        assert_ne!(&key[..20], &key[20..]);
    }

    /// The suffix is appended to `S`, so it must not be equivalent to hashing `S` alone.
    #[test]
    fn first_half_is_not_a_plain_hash_of_the_secret() {
        use sha1::{Digest, Sha1};

        let key = compute_doubled_session_key(b"premaster secret");
        let plain = Sha1::digest(b"premaster secret");

        assert_ne!(&key[..20], plain.as_slice());
    }
}
