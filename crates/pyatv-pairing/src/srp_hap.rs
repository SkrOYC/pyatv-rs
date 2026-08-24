//! SRP6a, HAP profile: RFC 5054 3072-bit group, generator 5, SHA-512 throughout.
//!
//! Used by MRP, Companion, modern AirPlay and transient AirPlay pairing. See
//! `docs/research/crypto-pairing.md` §2.1 and §9 for the full derivation and the integration
//! strategy summarised below.
//!
//! ## Why this cannot call `srp::Client::process_reply`
//!
//! pyatv computes M1 through `srptools`, which hashes the generator **unpadded**:
//! `M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)` with `H(g)` over the single byte `0x05` rather
//! than over `g` zero-extended to `len(N)`. RustCrypto's `srp` hardcodes `g_no_pad = false` inside
//! `process_reply`, producing the padded form, so the ergonomic API is off by exactly one boolean.
//!
//! The escape hatch is that `srp::utils` is `#[doc(hidden)] pub` rather than private, and
//! `compute_m1_rfc5054` takes `g_no_pad` as a caller-supplied argument. The plan is therefore to
//! reimplement the fifteen lines of `process_reply` here against the crate's own public
//! primitives, with the flag set to `true`. Everything else — the group constants, `u = H(PAD(A) |
//! PAD(B))`, `k = H(N | PAD(g))`, `K = H(S)` — matches RustCrypto's defaults exactly.
//!
//! Relying on a `#[doc(hidden)]` module is a real risk, and `srp` 0.7 has been in release-candidate
//! since December 2025. Known-answer tests against captured device traffic are a prerequisite for
//! trusting any of this.

use crate::Result;

/// The literal SRP username the HAP profile uses. Not a per-device identity.
pub const PAIR_SETUP_USERNAME: &str = "Pair-Setup";

/// Client side of the HAP SRP exchange.
///
/// Drives M1 through M6 of pair-setup. One instance per pairing attempt; the ephemeral secret `a`
/// must never be reused across attempts.
#[derive(Debug)]
pub struct HapSrpClient {
    /// The PIN shown on the device, stringified as pyatv does.
    pin: String,
    /// The client's ephemeral secret exponent `a`, 32 random bytes.
    ephemeral_secret: [u8; 32],
    /// SRP session key `K = SHA512(S)`, available after [`HapSrpClient::process_challenge`].
    session_key: Option<Vec<u8>>,
}

impl HapSrpClient {
    /// Start an exchange for `pin` with a freshly generated ephemeral secret.
    #[must_use]
    pub fn new(pin: u32, ephemeral_secret: [u8; 32]) -> Self {
        Self {
            pin: pin.to_string(),
            ephemeral_secret,
            session_key: None,
        }
    }

    /// The client's public value `A = g^a mod N`, sent in M1.
    // TODO(step-1): call `srp::Client::new_with_options` against `srp::groups::G3072` with SHA-512
    // and return `compute_public_ephemeral`. See docs/research/crypto-pairing.md §9.1.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        todo!("HapSrpClient::public_key")
    }

    /// Consume the device's M2 (`salt` and `B`) and produce the M3 proof `M1`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ProofMismatch`] if `B` is invalid, i.e. `B mod N == 0`.
    // TODO(step-1): x = H(salt | H("Pair-Setup" | ":" | pin)); S via
    // `Client::compute_premaster_secret`; K = SHA512(S); then
    // `srp::utils::compute_m1_rfc5054::<Sha512>(g, /* g_no_pad */ true, ...)`. The `true` is the
    // whole point — see the module docs and docs/research/crypto-pairing.md §9.3.
    pub fn process_challenge(&mut self, salt: &[u8], device_public_key: &[u8]) -> Result<Vec<u8>> {
        let _ = (salt, device_public_key, &self.pin, &self.ephemeral_secret);
        todo!("HapSrpClient::process_challenge")
    }

    /// Verify the device's M4 proof `M2 = H(A | M1 | K)`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ProofMismatch`] if the device's proof does not match.
    // TODO(step-1): recompute M2 with `srp::utils::compute_m2` and compare in constant time via
    // `subtle::ConstantTimeEq`.
    pub fn verify_device_proof(&self, proof: &[u8]) -> Result<()> {
        let _ = proof;
        todo!("HapSrpClient::verify_device_proof")
    }

    /// The SRP session key `K`, which every subsequent HKDF derivation takes as its IKM.
    ///
    /// Note this is `K`, not the raw premaster secret `S`.
    #[must_use]
    pub fn session_key(&self) -> Option<&[u8]> {
        self.session_key.as_deref()
    }
}
