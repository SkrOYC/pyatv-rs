//! The transport abstraction that makes the MRP tunnel invisible to everything above it.
//!
//! pyatv defines `AbstractMrpConnection` and implements it twice; the research report
//! (`docs/research/mrp-companion.md` §3.4) singles this out as the design to copy, because the
//! entire MRP protocol state machine, player state tracking and command handling then work
//! unchanged over either transport.

pub mod direct;
pub mod tunnel;

use bytes::Bytes;

use crate::Result;

pub use tunnel::TunnelTransport;

/// A bidirectional channel carrying serialised MRP protobuf messages.
///
/// Implementations own their framing and encryption; callers see whole messages only. Deliberately
/// byte-oriented rather than typed on the generated protobuf types, so the transports can be
/// written and tested before the `.proto` corpus is vendored.
pub trait MrpTransport: Send + Sync + std::fmt::Debug {
    /// Send one serialised message, framing and encrypting as this transport requires.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket write fails, or [`crate::Error::Framing`] if the
    /// message is too large for the transport's framing.
    fn send(&self, message: Bytes) -> impl Future<Output = Result<()>> + Send;

    /// Await the next complete message.
    ///
    /// Returns `Ok(None)` when the peer closed the connection cleanly.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Framing`] on a malformed frame, or [`crate::Error::Pairing`] if a
    /// frame fails to decrypt.
    fn receive(&self) -> impl Future<Output = Result<Option<Bytes>>> + Send;

    /// Whether transport encryption has been enabled by a completed pair-verify.
    fn is_encrypted(&self) -> bool;
}
