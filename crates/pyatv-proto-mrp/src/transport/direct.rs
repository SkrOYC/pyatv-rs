//! Direct TCP transport: varint-prefixed protobuf on a plain socket.
//!
//! Used by tvOS before 15 and by `HomePod`. Port of `MrpConnection`
//! (`pyatv/protocols/mrp/connection.py:42-177`), whose framing is
//! `write_variant(len(payload)) ‖ payload`: before pair-verify the payload is the raw serialised
//! protobuf, afterwards it is the ChaCha20-Poly1305 ciphertext *including* its 16-byte tag, and the
//! length prefix is computed over whichever of the two is on the wire.
//!
//! Three things about the AEAD here differ from every AirPlay channel and are easy to get wrong
//! (`docs/research/hap-pairing-port-spec.md` §5.3):
//!
//! * **No AAD.** `self._chacha.encrypt(serialized)` passes no `aad`, so the varint length prefix is
//!   not authenticated at all. It is framing, not part of the sealed message.
//! * **No 1024-byte chunking.** A whole `ProtocolMessage`, however large, is one AEAD call. That is
//!   `HAPSession`'s contract, and `HAPSession` is an AirPlay-only concept.
//! * **The nonce is the padded counter** — four zero bytes then an 8-byte little-endian counter,
//!   independent per direction ([`Chacha20Cipher::with_padded_counter`]).

use std::net::SocketAddr;
use std::sync::Mutex;

use bytes::{Bytes, BytesMut};
use pyatv_core::interface::BoxFuture;
use pyatv_pairing::chacha::Chacha20Cipher;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex as AsyncMutex;

use crate::message::MrpMessage;
use crate::transport::{MrpTransport, TransportEncryption};
use crate::{Error, Result, variant};

/// Refuse a frame whose length prefix is implausible.
///
/// Not an upstream concept: pyatv will happily buffer whatever a varint claims. A length prefix is
/// unauthenticated (see the module docs), so a corrupted or hostile one would otherwise reserve an
/// arbitrary allocation. The cap is far above any real MRP message — artwork travels in a
/// `PLAYBACK_QUEUE_REQUEST_MESSAGE` response and is the largest thing seen in practice.
pub const MAX_FRAME_LEN: usize = 8 * 1024 * 1024;

/// How many bytes are read from the socket in one go.
const READ_CHUNK: usize = 8 * 1024;

/// The receive half: the socket plus the reassembly buffer partial frames accumulate in.
#[derive(Debug)]
struct Reader {
    socket: OwnedReadHalf,
    buffer: BytesMut,
    /// Set once the peer has sent EOF, so later `recv` calls keep reporting a clean close.
    finished: bool,
}

/// A direct MRP connection over TCP.
#[derive(Debug)]
pub struct DirectTransport {
    peer: SocketAddr,
    reader: AsyncMutex<Reader>,
    writer: AsyncMutex<Option<OwnedWriteHalf>>,
    /// `None` until pair-verify completes; `MrpConnection._chacha` (`connection.py:56`).
    ///
    /// A `std::sync::Mutex` rather than a `tokio` one because the critical section is a single
    /// AEAD call with no `.await` inside it. Both directions share one cipher, as upstream does,
    /// so the two counters cannot drift apart.
    cipher: Mutex<Option<Chacha20Cipher>>,
}

impl DirectTransport {
    /// Dial `peer`. The connection starts in the clear; pair-verify enables encryption afterwards.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Connect`] if the device is unreachable.
    pub async fn connect(peer: SocketAddr) -> Result<Self> {
        let stream = TcpStream::connect(peer)
            .await
            .map_err(|source| Error::Connect { peer, source })?;

        // `tcp_keepalive(sock)` (`connection.py:63-67`) is best-effort upstream too: it logs and
        // carries on where the platform refuses. `set_nodelay` is this port's addition — MRP is a
        // request/response chat protocol and Nagle only adds latency to it.
        if let Err(error) = stream.set_nodelay(true) {
            tracing::debug!(%error, "could not disable Nagle on the MRP socket");
        }

        Ok(Self::from_stream(peer, stream))
    }

    /// Wrap an already-connected socket. Used by tests that dial a loopback fake device.
    #[must_use]
    pub fn from_stream(peer: SocketAddr, stream: TcpStream) -> Self {
        let (read, write) = stream.into_split();
        Self {
            peer,
            reader: AsyncMutex::new(Reader {
                socket: read,
                buffer: BytesMut::new(),
                finished: false,
            }),
            writer: AsyncMutex::new(Some(write)),
            cipher: Mutex::new(None),
        }
    }

    /// The address this transport is connected to.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Frame and encrypt one payload, then write it.
    async fn write_frame(&self, payload: &[u8]) -> Result<()> {
        let mut guard = self.writer.lock().await;
        let socket = guard.as_mut().ok_or(Error::Closed)?;

        // Sealing happens under the write lock so the counter order matches the wire order.
        let sealed = self.seal(payload)?;
        let length = u64::try_from(sealed.len())
            .map_err(|_| Error::Framing("outbound frame does not fit in a varint".to_owned()))?;
        let mut frame = variant::write(length);
        frame.extend_from_slice(&sealed);

        socket.write_all(&frame).await?;
        socket.flush().await?;
        Ok(())
    }

    /// Encrypt if a cipher has been installed, otherwise pass through.
    fn seal(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut cipher = self
            .cipher
            .lock()
            .map_err(|_| Error::InvalidState("the MRP cipher lock was poisoned"))?;

        match cipher.as_mut() {
            Some(cipher) => Ok(cipher.encrypt(payload, None)?),
            None => Ok(payload.to_vec()),
        }
    }

    /// Decrypt if a cipher has been installed, otherwise pass through.
    fn open(&self, payload: Bytes) -> Result<Bytes> {
        let mut cipher = self
            .cipher
            .lock()
            .map_err(|_| Error::InvalidState("the MRP cipher lock was poisoned"))?;

        match cipher.as_mut() {
            Some(cipher) => Ok(Bytes::from(cipher.decrypt(&payload, None)?)),
            None => Ok(payload),
        }
    }

    /// Pull one complete frame out of the buffer, reading more bytes until there is one.
    ///
    /// `data_received` (`connection.py:137-163`): read a varint length, wait for that many bytes,
    /// slice the frame off and leave the remainder buffered.
    async fn read_frame(&self) -> Result<Option<Bytes>> {
        let mut reader = self.reader.lock().await;

        loop {
            if let Some(frame) = take_frame(&mut reader.buffer)? {
                return Ok(Some(frame));
            }
            if reader.finished {
                return if reader.buffer.is_empty() {
                    Ok(None)
                } else {
                    Err(Error::Framing(format!(
                        "connection closed with {} bytes of a partial frame buffered",
                        reader.buffer.len()
                    )))
                };
            }

            let mut chunk = [0u8; READ_CHUNK];
            let read = reader.socket.read(&mut chunk).await?;
            if read == 0 {
                reader.finished = true;
            } else {
                reader.buffer.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

/// Split one complete frame off the front of `buffer`, if there is one.
fn take_frame(buffer: &mut BytesMut) -> Result<Option<Bytes>> {
    if buffer.is_empty() {
        return Ok(None);
    }

    let (length, consumed) = match variant::read(buffer) {
        Ok(parsed) => parsed,
        // A truncated varint just means the prefix has not fully arrived yet; an over-long one is
        // a real framing failure and must not be waited out.
        Err(Error::Framing(_)) if buffer.len() < variant::MAX_LEN => return Ok(None),
        Err(error) => return Err(error),
    };

    let length = usize::try_from(length)
        .ok()
        .filter(|it| *it <= MAX_FRAME_LEN)
        .ok_or_else(|| Error::Framing(format!("frame length {length} exceeds {MAX_FRAME_LEN}")))?;

    if buffer.len() < consumed + length {
        return Ok(None);
    }

    let _prefix = buffer.split_to(consumed);
    Ok(Some(buffer.split_to(length).freeze()))
}

impl MrpTransport for DirectTransport {
    fn send(&self, message: &MrpMessage) -> BoxFuture<'_, Result<()>> {
        let payload = message.bytes().clone();
        Box::pin(async move { self.write_frame(&payload).await })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<MrpMessage>>> {
        Box::pin(async move {
            let Some(frame) = self.read_frame().await? else {
                return Ok(None);
            };
            MrpMessage::decode(self.open(frame)?).map(Some)
        })
    }

    fn enable_encryption(&self, output_key: [u8; 32], input_key: [u8; 32]) -> Result<()> {
        let mut cipher = self
            .cipher
            .lock()
            .map_err(|_| Error::InvalidState("the MRP cipher lock was poisoned"))?;
        *cipher = Some(Chacha20Cipher::with_padded_counter(&output_key, &input_key));
        Ok(())
    }

    fn encryption(&self) -> TransportEncryption {
        TransportEncryption::MrpLevel
    }

    fn is_encrypted(&self) -> bool {
        self.cipher.lock().is_ok_and(|cipher| cipher.is_some())
    }

    fn connected(&self) -> bool {
        self.writer.try_lock().is_ok_and(|writer| writer.is_some())
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if let Some(mut socket) = self.writer.lock().await.take() {
                socket.shutdown().await?;
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_FRAME_LEN, take_frame};
    use bytes::BytesMut;

    #[test]
    fn a_partial_length_prefix_is_not_an_error() {
        // 0x80 is a continuation byte, so this varint is incomplete.
        let mut buffer = BytesMut::from(&[0x80u8][..]);
        assert!(take_frame(&mut buffer).unwrap().is_none());
        assert_eq!(buffer.len(), 1, "the prefix must stay buffered");
    }

    #[test]
    fn a_partial_body_is_not_an_error() {
        let mut buffer = BytesMut::from(&[0x04u8, 0xAA, 0xBB][..]);
        assert!(take_frame(&mut buffer).unwrap().is_none());
        assert_eq!(buffer.len(), 3);
    }

    #[test]
    fn frames_are_taken_one_at_a_time_and_the_rest_stays() {
        let mut buffer = BytesMut::from(&[0x02u8, 0xAA, 0xBB, 0x01, 0xCC][..]);

        assert_eq!(
            take_frame(&mut buffer).unwrap().unwrap().as_ref(),
            [0xAA, 0xBB]
        );
        assert_eq!(take_frame(&mut buffer).unwrap().unwrap().as_ref(), [0xCC]);
        assert!(take_frame(&mut buffer).unwrap().is_none());
    }

    /// A length prefix is not covered by the AEAD, so an absurd one must be rejected rather than
    /// used to size an allocation.
    #[test]
    fn an_implausible_length_is_rejected() {
        let mut buffer = BytesMut::new();
        let too_long = u64::try_from(MAX_FRAME_LEN).unwrap() + 1;
        buffer.extend_from_slice(&crate::variant::write(too_long));
        assert!(take_frame(&mut buffer).is_err());
    }
}
