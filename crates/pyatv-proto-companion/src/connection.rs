//! The Companion TCP connection: framing, encryption and request/response correlation.
//!
//! See `docs/research/mrp-companion.md` §4 for the message shapes carried inside `E_OPACK` frames.

use std::net::SocketAddr;

use pyatv_opack::Value;

use crate::Result;
use crate::frame::FrameType;

/// A connected Companion session.
#[derive(Debug)]
pub struct CompanionConnection {
    peer: SocketAddr,
    /// Frames sent so far, driving the outbound nonce counter.
    output_counter: u64,
    /// Frames received so far, driving the inbound nonce counter.
    input_counter: u64,
    encrypted: bool,
}

impl CompanionConnection {
    /// Open a connection to `peer`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the device is unreachable.
    // TODO(step-1): `tokio::net::TcpStream::connect`, then a read loop that accumulates into a
    // BytesMut and emits whole frames per FrameHeader::total_length.
    pub async fn connect(peer: SocketAddr) -> Result<Self> {
        let _ = peer;
        todo!("CompanionConnection::connect")
    }

    /// Install the transport keys derived by pair-verify.
    ///
    /// Salt and info strings come from `pyatv_pairing::hkdf_derive::transport::COMPANION` — note
    /// the salt there is the empty string, which is not a placeholder.
    // TODO(step-1): build ciphers using the BARE twelve-byte counter nonce layout, not the padded
    // one HAP framing uses. See docs/research/crypto-pairing.md §5.3.
    pub fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]) {
        let _ = (output_key, input_key);
        todo!("CompanionConnection::enable_encryption")
    }

    /// Send an OPACK payload and await the matching response.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Rejected`] if the device answers with an error, or
    /// [`crate::Error::Io`] if the connection drops.
    // TODO(step-1): serialise with pyatv_opack::pack, seal with the header as AAD when the frame
    // type is encrypted, then correlate the response by its `_x` transaction identifier.
    pub async fn send(&self, frame_type: FrameType, payload: Value) -> Result<Value> {
        let _ = (
            frame_type,
            payload,
            self.peer,
            self.output_counter,
            self.input_counter,
        );
        todo!("CompanionConnection::send")
    }

    /// Whether transport encryption is active.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }
}
