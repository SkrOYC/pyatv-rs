//! The HAP crypto and pairing stack shared by MRP, Companion and AirPlay.
//!
//! Everything here is a port of pyatv's `pyatv/auth/` package plus `pyatv/protocols/airplay/srp.py`, and `docs/research/crypto-pairing.md` is the authoritative description of what it must do. That report was written from a direct read of pyatv's source and calls out several deviations from textbook HAP that will silently fail against real hardware if they are "corrected" — the most important being:
//!
//! - **Two unrelated SRP profiles.** HAP pairing (MRP, Companion, modern AirPlay) uses the RFC 5054 3072-bit group with SHA-512 and the literal username `"Pair-Setup"` ([`srp_hap`]); legacy AirPlay device auth uses the 2048-bit group with SHA-1 and a non-standard doubled-hash session key ([`srp_legacy`]). They must not share a code path. See report §2.
//! - **Unpadded `H(g)` in M1.** pyatv inherits this from `srptools`, and RustCrypto's `srp` hardcodes the padded form in `Client::process_reply`, so the high-level API cannot be used as-is. The fix is to call `srp::utils::compute_m1_rfc5054` directly with `g_no_pad = true`; see report §9.4.
//! - **Three different ChaCha20-Poly1305 nonce layouts.** Fixed ASCII nonces during pair-verify, a 4-zero-byte-prefixed 8-byte counter for [`session`] framing, and a bare 12-byte counter for Companion. See report §5.
//!
//! Nothing in this crate performs I/O: it is a set of sans-io state machines and codecs that the protocol crates drive. That keeps the pairing logic testable against captured byte vectors with no runtime involved, which is the only practical way to validate a reverse-engineered protocol.

#![warn(missing_docs)]
pub mod chacha;
pub mod credentials;
pub mod error;
pub mod hkdf_derive;
pub mod legacy_auth;
pub mod pairing;
#[cfg(feature = "test-server")]
pub mod server;
pub mod session;
mod srp_encoding;
pub mod srp_hap;
pub mod srp_legacy;
pub mod tlv8;

pub use credentials::{AuthenticationType, HapCredentials};
pub use error::Error;
pub use pairing::{PairSetup, PairVerify, SessionKeys, TransientPairSetup};
pub use tlv8::{Tlv8, TlvValue};

/// Convenience alias for fallible pairing operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

#[cfg(test)]
mod zeroize_policy {
    //! A compile-time inventory of the types that hold a secret for longer than one call.
    //!
    //! Wiping cannot be observed from safe Rust — reading the memory after the drop is exactly the
    //! undefined behaviour `zeroize` exists to make pointless — so what is checkable is that each
    //! type still claims the guarantee. Removing a `Drop` impl silently would otherwise be
    //! invisible; here it is a compile error naming the type.

    fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

    #[test]
    fn every_long_lived_secret_holder_wipes_itself() {
        assert_zeroize_on_drop::<crate::PairSetup>();
        assert_zeroize_on_drop::<crate::PairVerify>();
        assert_zeroize_on_drop::<crate::SessionKeys>();
        assert_zeroize_on_drop::<crate::srp_hap::HapSrpClient>();
        assert_zeroize_on_drop::<crate::legacy_auth::LegacyPairVerify>();
    }
}
