//! The Companion link protocol.
//!
//! Companion is the newest of the five protocols and the one that carries most of what users think
//! of as "the remote": app launching, the on-screen keyboard, trackpad gestures, user account
//! switching and power control. It is also the simplest to frame — a four-byte header over an OPACK
//! body — which makes it a good first protocol to bring up end to end.
//!
//! `docs/research/companion-port-spec.md` is the byte-level reference and every module here cites
//! the pyatv line it was ported from. The layering matches upstream's, module for module:
//!
//! | Here | pyatv | Role |
//! |---|---|---|
//! | [`frame`] + [`codec`] | `companion/connection.py` | header, buffering, the AEAD boundary |
//! | [`connection`] | `companion/connection.py` | the socket |
//! | [`message`] + [`protocol`] | `companion/protocol.py` | envelope, XIDs, correlation, events |
//! | [`auth`] | `companion/auth.py` | pair-setup and pair-verify framing |
//! | [`session`] | `companion/api.py` | the post-verify bring-up chain |
//! | [`pairing`] | `companion/pairing.py` | the [`pyatv_core::interface::PairingHandler`] |
//!
//! Its transport encryption is deliberately *not* HAP session framing, despite sharing the same
//! pair-setup and pair-verify exchange. See `docs/research/crypto-pairing.md` §5.3 and
//! `docs/research/companion-port-spec.md` §1.3:
//!
//! - The AAD is the full four-byte header, not just the length, so the frame type is bound into the
//!   ciphertext.
//! - The nonce is a bare twelve-byte little-endian counter with no zero prefix, unlike the padded
//!   counter HAP framing uses. The same counter value produces different nonce bytes under the two
//!   schemes, so the nonce builder must be selected per protocol rather than shared.
//! - There is no 1024-byte chunking cap; a frame is however large its OPACK body serialises to,
//!   subject to the bound in [`codec::MAX_FRAME_PAYLOAD`] that this port adds and pyatv does not
//!   have.
//! - A zero-length payload is never sealed, even mid-session.

#![warn(missing_docs)]
pub mod api;
pub mod auth;
pub mod codec;
pub mod connection;
pub mod error;
pub mod facade;
pub mod frame;
pub mod keyed_archiver;
pub mod message;
pub mod pairing;
pub mod plist_payloads;
pub mod protocol;
pub mod session;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use codec::{Frame, FrameCodec};
pub use connection::CompanionConnection;
pub use error::Error;
pub use frame::{FrameHeader, FrameType};
pub use message::{Envelope, MessageType};
pub use pairing::{CompanionPairingHandler, CompanionPairingOptions};
pub use protocol::{CompanionEvent, CompanionProtocol, EventStream};

/// Convenience alias for fallible Companion operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
