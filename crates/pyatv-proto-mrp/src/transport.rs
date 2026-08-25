//! The transport abstraction that makes the AirPlay tunnel invisible to everything above it.
//!
//! pyatv defines `AbstractMrpConnection` and implements it twice — `MrpConnection` over a raw TCP
//! socket and `AirPlayMrpConnection` over an already-open AirPlay 2 data-stream channel — and then
//! shares *everything* above it: `MrpProtocol.start()`, the request/response correlation,
//! `PlayerStateManager` and the whole facade are called identically by both paths, differing only
//! in which connection object and which `requires_heatbeat` value they were handed
//! (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §7, §7.1). This trait is the direct
//! port of that seam.
//!
//! # The one behavioural difference the trait has to carry
//!
//! Direct MRP performs its own pair-verify and seals every message with ChaCha20-Poly1305
//! (§8.1-§8.2). The tunnel does neither: `AirPlayMrpConnection.enable_encryption` is a documented
//! no-op because the data channel is already HAP-encrypted, and the dummy `MutableService` the
//! tunnel path registers carries no credentials, so `MrpProtocol._enable_encryption` returns
//! immediately at its `if self.service.credentials is None: return` guard
//! (`pyatv/protocols/mrp/protocol.py:207-210`, `pyatv/protocols/airplay/__init__.py:241-244`) and
//! the `CryptoPairingMessage` exchange never happens over a tunnel at all.
//!
//! That is a protocol-visible fork, not an implementation detail, so it is a value on the trait —
//! [`MrpTransport::encryption`] — rather than something callers infer from which concrete type they
//! happen to hold.

pub mod direct;
pub mod tunnel;

use pyatv_core::interface::BoxFuture;

use crate::Result;
use crate::message::MrpMessage;

pub use direct::DirectTransport;
pub use tunnel::{ByteChannel, TunnelTransport};

/// Whether MRP runs its own pair-verify and encryption on this transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportEncryption {
    /// Direct TCP: run `CryptoPairingMessage` pair-verify when credentials exist, then install the
    /// derived keys through [`MrpTransport::enable_encryption`].
    MrpLevel,
    /// AirPlay tunnel: the channel is already sealed one layer down. No pair-verify, no keys.
    ///
    /// Naming this rather than modelling it as "keys that are installed and then never used" is
    /// deliberate: at every call site the alternative reads like a bug.
    DelegatedToTunnel,
}

impl TransportEncryption {
    /// Whether the protocol layer should run an MRP-level pair-verify on this transport.
    #[must_use]
    pub const fn needs_pair_verify(self) -> bool {
        matches!(self, Self::MrpLevel)
    }
}

/// A bidirectional channel carrying whole MRP messages.
///
/// Implementations own their framing and encryption; callers see complete [`MrpMessage`]s only.
/// Every method takes `&self` so one transport can be shared between the actor's writer and its
/// reader without a lock at this level — implementations serialise internally.
///
/// Object-safe on purpose: the protocol layer stores `Arc<dyn MrpTransport>` and must not be
/// generic over the transport, or the tunnel and direct paths would monomorphise the whole stack
/// twice for no benefit.
pub trait MrpTransport: Send + Sync + std::fmt::Debug {
    /// Send one message, framing and encrypting as this transport requires.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Closed`] if the connection has gone away, or
    /// [`crate::Error::Io`] if the write fails.
    fn send(&self, message: &MrpMessage) -> BoxFuture<'_, Result<()>>;

    /// Await the next complete message.
    ///
    /// Returns `Ok(None)` when the peer closed the connection cleanly — the transport's EOF, which
    /// the protocol actor turns into a `connection_closed` notification.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Framing`] on a malformed frame, [`crate::Error::Decode`] if the
    /// bytes are not a `ProtocolMessage`, or [`crate::Error::Pairing`] if a frame fails to
    /// decrypt.
    fn recv(&self) -> BoxFuture<'_, Result<Option<MrpMessage>>>;

    /// Install the transport keys a completed pair-verify derived.
    ///
    /// `MrpConnection.enable_encryption(output_key, input_key)` (`connection.py:93-95`), whose
    /// argument order is what decides which derived key encrypts and which decrypts: pyatv passes
    /// `verify2("MediaRemote-Salt", "MediaRemote-Write-Encryption-Key",
    /// "MediaRemote-Read-Encryption-Key")` positionally (`protocol.py:26-28,218-219`), so the
    /// client **encrypts with the `Write`-derived key and decrypts with the `Read`-derived key**.
    /// The reference accessory reaches the mirror image by swapping at its own call site
    /// (`docs/research/hap-pairing-port-spec.md` §4.3).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotSupported`] on a transport whose
    /// [`MrpTransport::encryption`] is [`TransportEncryption::DelegatedToTunnel`]. Calling it
    /// there is a caller bug, not a no-op to be swallowed: the protocol layer already knows not
    /// to pair-verify on such a transport.
    fn enable_encryption(&self, output_key: [u8; 32], input_key: [u8; 32]) -> Result<()>;

    /// Whether this transport expects MRP to pair-verify and encrypt for itself.
    fn encryption(&self) -> TransportEncryption;

    /// Whether messages are currently being sealed at the MRP layer.
    ///
    /// Always `false` for a tunnel, whose traffic is sealed one layer down instead.
    fn is_encrypted(&self) -> bool;

    /// Whether the connection is usable.
    ///
    /// `AirPlayMrpConnection.connected` is hardcoded `True`
    /// (`pyatv/protocols/airplay/mrp_connection.py:47-50`): a tunnel has no notion of being
    /// half-open, and failure surfaces asynchronously through the channel instead.
    fn connected(&self) -> bool;

    /// Release the connection. Must be safe to call more than once.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket could not be shut down cleanly.
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}
