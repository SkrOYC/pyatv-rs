//! SRP6a, HAP profile: RFC 5054 3072-bit group, generator 5, SHA-512 throughout.
//!
//! Used by MRP, Companion, modern AirPlay and transient AirPlay pairing. Ported from
//! `pyatv/auth/hap_srp.py:1-233`; `docs/research/hap-pairing-port-spec.md` §2 is the byte-level
//! description this implementation was written against.
//!
//! ## Why this cannot call `srp::Client::process_reply` for the proof
//!
//! pyatv computes M1 through `srptools`, which hashes the generator **unpadded**:
//! `M1 = H(H(N) XOR H(g) | H(I) | s | A | B | K)` with `H(g)` taken over the single byte `0x05`
//! rather than over `g` zero-extended to `len(N)` (`srptools:srptools/context.py:213-232`, whose
//! `hash()` helper converts integer arguments with the minimal-length `int_to_bytes`). RustCrypto's
//! `srp` hardcodes `g_no_pad = false` inside `Client::process_reply`
//! (`srp-0.7.0-rc.3/src/client.rs:229-237`), producing the padded form, so the ergonomic API is off
//! by exactly one boolean.
//!
//! `srp::utils` is `#[doc(hidden)] pub` rather than private and `compute_m1_rfc5054` takes
//! `g_no_pad` as an argument, so [`HapSrpClient`] uses `process_reply` only for the premaster secret `S`
//! (and for its `B mod N != 0` safeguard) and computes `M1`/`M2` itself with the flag set to
//! `true`. Everything else — the group constants, `u = H(PAD(A) | PAD(B))`, `k = H(N | PAD(g))`,
//! `x = H(s | H(I | ":" | P))`, `K = H(S)` — matches RustCrypto's defaults exactly.
//!
//! ### The one place minimal-length encoding could have diverged
//!
//! `srptools` renders `H(N) XOR H(g)` and `H(I)` as integers and back to their *minimal* big-endian
//! byte strings, so a leading zero byte in either would shorten the hashed input relative to
//! `srp`'s fixed 64-byte rendering. Both are constants for this profile and both were computed
//! during the port: `H(N) XOR H(g)` starts `b3 d6 3e f6 …` and `SHA-512("Pair-Setup")` starts
//! `cd …`. Neither has a leading zero, so the two encodings agree; [`HapSrpClient`]'s tests pin those
//! first bytes so a future group or hash change cannot silently break the equivalence.
//!
//! Relying on a `#[doc(hidden)]` module is a real risk, and `srp` 0.7 is still a release candidate.
//! The hermetic round trips in `tests/hap_pairing.rs` are what actually guard this.

mod client;
mod handshake;
mod keys;

pub use client::{HapSrpClient, PAIR_SETUP_USERNAME};
pub use handshake::{
    PAIR_SETUP_M5_NONCE, PAIR_SETUP_M6_NONCE, PAIR_VERIFY_M2_NONCE, PAIR_VERIFY_M3_NONCE,
    handshake_nonce, open, seal,
};
pub use keys::{
    EphemeralExchange, SEED_LEN, X25519_LEN, ed25519_public_key, random_seed, sign,
    verify_signature, x25519_public_key, x25519_shared_secret,
};
