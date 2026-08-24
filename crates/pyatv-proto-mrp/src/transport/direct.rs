//! Direct TCP transport: varint-prefixed protobuf on a plain socket.
//!
//! Used by tvOS before 15 and by HomePod. See `docs/research/mrp-companion.md` §1.2.
//!
//! Framing is `write_variant(len(payload)) || payload`. Before pair-verify the payload is the raw
//! serialised protobuf; afterwards it is the ChaCha20-Poly1305 ciphertext, and the length prefix
//! covers the ciphertext *including* its 16-byte tag. Note this is one seal per message, not the
//! 1024-byte `HAPSession` chunking used on AirPlay channels — direct MRP does not chunk.

use std::net::SocketAddr;

use bytes::Bytes;

use crate::Result;
use crate::transport::MrpTransport;

/// A direct MRP connection over TCP.
#[derive(Debug)]
pub struct DirectTransport {
    peer: SocketAddr,
    encrypted: bool,
}

impl DirectTransport {
    /// Open a connection to `peer`. The connection starts unencrypted; pair-verify enables
    /// encryption afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the device is unreachable.
    // TODO(step-1): `tokio::net::TcpStream::connect(peer)`, then split into a read half driving a
    // receive loop and a write half behind a mutex.
    pub async fn connect(peer: SocketAddr) -> Result<Self> {
        let _ = peer;
        todo!("DirectTransport::connect")
    }

    /// Install the transport keys derived by pair-verify and start encrypting.
    ///
    /// Salt and info strings come from `pyatv_pairing::hkdf_derive::transport::MRP`.
    // TODO(step-1): store a `pyatv_pairing`-owned cipher pair with independent send/receive
    // counters, using the padded-counter nonce layout.
    pub fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]) {
        let _ = (output_key, input_key);
        todo!("DirectTransport::enable_encryption")
    }

    /// The address this transport is connected to.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }
}

impl MrpTransport for DirectTransport {
    async fn send(&self, message: Bytes) -> Result<()> {
        let _ = message;
        // TODO(step-1): seal if encrypted, then write `variant::write(payload.len())` followed by
        // the payload.
        todo!("DirectTransport::send")
    }

    async fn receive(&self) -> Result<Option<Bytes>> {
        // TODO(step-1): read a varint length, then exactly that many bytes, then open the seal if
        // encryption is active. Partial frames must be buffered, not dropped.
        todo!("DirectTransport::receive")
    }

    fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}
