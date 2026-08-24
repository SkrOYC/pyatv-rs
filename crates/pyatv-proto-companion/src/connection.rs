//! The Companion TCP connection: a socket wrapped around [`crate::codec::FrameCodec`].
//!
//! Port of `CompanionConnection` (`pyatv/protocols/companion/connection.py:53-168`). pyatv builds
//! it on `asyncio.Protocol`, so its receive path is a `data_received` callback that pushes whole
//! frames at a listener; here the same state machine is driven by an owning caller that awaits
//! [`CompanionConnection::recv_frame`], which is what lets the pairing handshake read as a
//! sequence of exchanges rather than a callback graph.
//!
//! There is **no keepalive and no idle timeout** at this layer, matching pyatv exactly: nothing in
//! `connection.py`, `protocol.py` or `api.py` sends periodic traffic
//! (`docs/research/companion-port-spec.md` §1.5). Whether real devices drop idle Companion
//! connections is unanswered by pyatv's source and would need a live capture, so nothing is
//! invented here.

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::codec::{Frame, FrameCodec};
use crate::frame::FrameType;
use crate::{Error, Result};

/// How much room to leave for one socket read. Companion frames are small — the largest pyatv
/// sends is the `_systemInfo` request — so this is sized to hold a typical frame whole rather than
/// to minimise syscalls.
const READ_CHUNK: usize = 4096;

/// A connected Companion session.
///
/// Owns the socket exclusively. Cloning or sharing it is deliberately impossible: the transport
/// cipher keeps one counter per direction, and two writers would produce two frames claiming the
/// same nonce.
#[derive(Debug)]
pub struct CompanionConnection {
    peer: SocketAddr,
    stream: TcpStream,
    codec: FrameCodec,
}

impl CompanionConnection {
    /// Open a connection to `peer`.
    ///
    /// The port must come from the device's mDNS SRV record; there is no default Companion port.
    /// No TLS and no application handshake happen here — the first frame on the wire is whatever
    /// the caller sends (`connection.py:79-81`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Connect`] if the device is unreachable or refuses the connection.
    pub async fn connect(peer: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(peer)
            .await
            .map_err(|source| Error::Connect { peer, source })?;

        // Companion is a request/response protocol with small frames; batching a header behind
        // Nagle's algorithm adds a round trip's worth of latency to every exchange.
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%peer, %error, "could not disable Nagle on the Companion socket");
        }

        tracing::debug!(%peer, "connected to Companion device");
        Ok(Self {
            peer,
            stream,
            codec: FrameCodec::new(),
        })
    }

    /// Wrap an already-connected stream, for tests and for callers that dial themselves.
    #[must_use]
    pub fn from_stream(peer: SocketAddr, stream: TcpStream) -> Self {
        Self {
            peer,
            stream,
            codec: FrameCodec::new(),
        }
    }

    /// The address this connection was opened to.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Install the transport keys derived by pair-verify.
    ///
    /// Every frame after this call is sealed, apart from zero-length ones — see
    /// [`crate::codec`]. The argument order is `enable_encryption(output_key, input_key)`, matching
    /// `connection.py:90-92`, and for Companion those come from `ClientEncrypt-main` and
    /// `ServerEncrypt-main` respectively with an empty HKDF salt.
    pub fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]) {
        tracing::debug!(peer = %self.peer, "enabling Companion transport encryption");
        self.codec.enable_encryption(output_key, input_key);
    }

    /// Whether transport encryption is active.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.codec.is_encrypted()
    }

    /// Send one frame, sealing the payload if a session key is installed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Framing`] if the payload is too large, [`Error::Pairing`] if the AEAD
    /// seal fails, or [`Error::Io`] if the socket write fails.
    pub async fn send_frame(&mut self, frame_type: FrameType, payload: &[u8]) -> Result<()> {
        let encoded = self.codec.encode(frame_type, payload)?;

        tracing::trace!(
            peer = %self.peer,
            ?frame_type,
            payload_bytes = payload.len(),
            frame_bytes = encoded.len(),
            "sending Companion frame"
        );

        self.stream.write_all(&encoded).await?;
        Ok(())
    }

    /// Await the next whole frame.
    ///
    /// # Cancellation
    ///
    /// Safe to drop mid-await. The inbound buffer lives in the codec rather than on the stack, and
    /// [`tokio::io::AsyncReadExt::read_buf`] either appends bytes to it or does not, so a cancelled
    /// call loses nothing and a later call resumes where this one stopped.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the peer hangs up, [`Error::Framing`] for a malformed or
    /// oversized frame, [`Error::Pairing`] if the payload does not open, and [`Error::Io`] for a
    /// socket failure.
    pub async fn recv_frame(&mut self) -> Result<Frame> {
        loop {
            if let Some(frame) = self.codec.next_frame()? {
                tracing::trace!(
                    peer = %self.peer,
                    frame_type = ?frame.frame_type,
                    payload_bytes = frame.payload.len(),
                    "received Companion frame"
                );
                return Ok(frame);
            }

            self.codec.reserve(READ_CHUNK);
            let read = self.stream.read_buf(self.codec.buffer_mut()).await?;
            if read == 0 {
                return Err(Error::Closed {
                    partial: self.codec.has_remaining(),
                });
            }
        }
    }

    /// Shut the socket down cleanly and discard any partial frame.
    ///
    /// Idempotent, like `close()` upstream (`connection.py:83-88`): shutting down an already-closed
    /// socket is reported by the OS as "not connected", which is the state the caller asked for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the shutdown fails for any reason other than the socket already
    /// being closed.
    pub async fn close(&mut self) -> Result<()> {
        self.codec.clear();
        match self.stream.shutdown().await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Drop the connection without a shutdown handshake.
    ///
    /// For teardown paths that cannot await, and for abandoning a connection whose peer has
    /// already misbehaved.
    pub fn abort(self) {
        drop(self);
    }
}
