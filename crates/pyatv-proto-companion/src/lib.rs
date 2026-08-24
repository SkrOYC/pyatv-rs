//! The Companion link protocol.
//!
//! Companion is the newest of the five protocols and the one that carries most of what users think of as "the remote": app launching, the on-screen keyboard, trackpad gestures, user account switching and power control. It is also the simplest to frame — a four-byte header over an OPACK body — which makes it a good first protocol to bring up end to end.
//!
//! Its transport encryption is deliberately *not* HAP session framing, despite sharing the same pair-setup and pair-verify exchange. See `docs/research/crypto-pairing.md` §5.3 and `docs/research/mrp-companion.md` §4:
//!
//! - The AAD is the full four-byte header, not just the length, so the frame type is bound into the ciphertext.
//! - The nonce is a bare twelve-byte little-endian counter with no zero prefix, unlike the padded counter HAP framing uses. The same counter value produces different nonce bytes under the two schemes, so the nonce builder must be selected per protocol rather than shared.
//! - There is no 1024-byte chunking cap; a frame is however large its OPACK body serialises to.

pub mod connection;
pub mod error;
pub mod frame;
pub mod pairing;

pub use error::Error;
pub use frame::{FrameHeader, FrameType};

/// Convenience alias for fallible Companion operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
