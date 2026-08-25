//! One HAP-encrypted TCP socket, split so a read loop and a writer can run in the same task
//! without borrowing each other.
//!
//! Port of `AbstractHAPChannel` and `setup_channel` (`pyatv/auth/hap_channel.py:17-97`), which is
//! the single primitive both AirPlay 2 side channels are built from: derive `(output, input)` keys
//! from the completed pair-verify, dial a fresh TCP connection, and wrap it in the 1024-byte
//! [`HapSession`] framing. Only the salt, the two info strings and the port differ between the
//! event channel and the data-stream channel (`ap2_session.py:140-148,176-184`).
//!
//! **The controller dials both channels.** `setup_channel` calls `loop.create_connection`
//! (`hap_channel.py:92-96`) for the event channel too, despite the "connection originates from
//! receiver" comment at its call site (`ap2_session.py:139`) — that comment explains why the two
//! *info strings* are swapped, not who opens the socket.

use std::net::SocketAddr;

use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use crate::Result;
use crate::http::CONNECT_TIMEOUT;

/// Bytes read from the socket per `read` call, before decryption.
const READ_CHUNK: usize = 8 * 1024;

/// Dial `address` and wrap it in HAP framing keyed by `keys`.
///
/// # Errors
///
/// Returns [`crate::Error::Io`] if the socket cannot be opened within [`CONNECT_TIMEOUT`].
pub(crate) async fn connect(
    address: SocketAddr,
    keys: &SessionKeys,
) -> Result<(HapReader, HapWriter)> {
    tracing::debug!(%address, "opening AirPlay HAP channel");

    let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("timed out connecting to {address}"),
            )
        })??;
    stream.set_nodelay(true)?;

    let (read_half, write_half) = stream.into_split();

    // Two `HapSession`s rather than one shared behind a lock. The type carries an independent
    // counter per direction (`pyatv/support/chacha20.py`'s `_out_counter`/`_in_counter`), and each
    // half here only ever touches one of them: the reader only decrypts, the writer only encrypts.
    // Giving each half its own instance is therefore byte-identical to sharing one, and it lets the
    // read future and a write live in the same `select!` without aliasing.
    Ok((
        HapReader {
            half: read_half,
            session: HapSession::new(&keys.output_key, &keys.input_key),
            address,
        },
        HapWriter {
            half: write_half,
            session: HapSession::new(&keys.output_key, &keys.input_key),
            address,
        },
    ))
}

/// The receiving half of a HAP channel.
#[derive(Debug)]
pub(crate) struct HapReader {
    half: OwnedReadHalf,
    session: HapSession,
    address: SocketAddr,
}

impl HapReader {
    /// Read one TCP segment and return whatever whole HAP frames it completed.
    ///
    /// `Ok(None)` means the peer closed the connection. `Ok(Some(bytes))` may be empty when the
    /// segment only advanced a partial frame, which [`HapSession`] holds back internally.
    ///
    /// Cancel-safe: the only await point is [`tokio::io::AsyncReadExt::read`], which guarantees no
    /// bytes were consumed if the future is dropped. That is what lets it sit in a `select!` arm
    /// alongside an outbound queue.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] on a socket failure and [`crate::Error::Pairing`] if a frame's
    /// Poly1305 tag does not verify — after which the stream is permanently out of step and the
    /// channel must be torn down.
    pub(crate) async fn read(&mut self) -> Result<Option<Vec<u8>>> {
        let mut chunk = [0u8; READ_CHUNK];

        let read = self.half.read(&mut chunk).await?;
        if read == 0 {
            tracing::debug!(address = %self.address, "HAP channel closed by peer");
            return Ok(None);
        }

        Ok(Some(self.session.decrypt(&chunk[..read])?))
    }
}

/// The sending half of a HAP channel.
#[derive(Debug)]
pub(crate) struct HapWriter {
    half: OwnedWriteHalf,
    session: HapSession,
    address: SocketAddr,
}

impl HapWriter {
    /// Frame, encrypt and write `plaintext`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket rejects the write and
    /// [`crate::Error::Pairing`] if the AEAD seal fails.
    pub(crate) async fn send(&mut self, plaintext: &[u8]) -> Result<()> {
        let framed = self.session.encrypt(plaintext)?;
        self.half.write_all(&framed).await?;
        self.half.flush().await?;
        Ok(())
    }

    /// Shut the write side down, which is how a channel is closed.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket could not be shut down cleanly.
    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        tracing::debug!(address = %self.address, "closing AirPlay HAP channel");
        self.half.shutdown().await?;
        Ok(())
    }
}
