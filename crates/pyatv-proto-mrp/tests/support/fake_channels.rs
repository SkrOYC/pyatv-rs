//! An in-memory [`ByteChannel`], standing in for an AirPlay 2 data-stream channel.
//!
//! [`pyatv_proto_mrp::TunnelTransport`] is generic over [`ByteChannel`] precisely so the tunnel can
//! be exercised without an AirPlay stack: this crate must not depend on `pyatv-proto-airplay`, and
//! the umbrella is what will adapt the real `DataStreamChannel` to this trait.
//!
//! Each [`LoopbackChannel`] is one end of a pair. `send` puts a `data` blob on the peer's queue and
//! `recv` takes one off its own, which is exactly the contract
//! `AirPlayMrpConnection` has with `DataStreamChannel` (`pyatv/protocols/airplay/mrp_connection.py`)
//! minus the plist framing and the HAP block cipher, neither of which belongs to MRP.

use std::sync::Arc;

use bytes::Bytes;
use pyatv_core::interface::BoxFuture;
use pyatv_proto_mrp::{ByteChannel, Error, Result};
use tokio::sync::{Mutex, mpsc, watch};

/// One end of an in-memory duplex byte channel.
///
/// `close` deliberately does **not** take the receive lock: a transport's reader task parks inside
/// `recv` for as long as the peer stays quiet, so a `close` that waited for that lock would
/// deadlock against its own reader. Any real implementor of [`ByteChannel`] has the same
/// obligation, which is why the fixture models it rather than papering over it.
#[derive(Debug)]
pub struct LoopbackChannel {
    outgoing: mpsc::UnboundedSender<Bytes>,
    incoming: Mutex<mpsc::UnboundedReceiver<Bytes>>,
    closed: watch::Sender<bool>,
    /// Every blob this end has sent, so a test can assert on the length prefixing.
    sent: Arc<std::sync::Mutex<Vec<Bytes>>>,
}

impl LoopbackChannel {
    /// Build a connected pair.
    #[must_use]
    pub fn pair() -> (Self, Self) {
        let (left_out, right_in) = mpsc::unbounded_channel();
        let (right_out, left_in) = mpsc::unbounded_channel();
        (
            Self {
                outgoing: left_out,
                incoming: Mutex::new(left_in),
                closed: watch::Sender::new(false),
                sent: Arc::default(),
            },
            Self {
                outgoing: right_out,
                incoming: Mutex::new(right_in),
                closed: watch::Sender::new(false),
                sent: Arc::default(),
            },
        )
    }

    /// Everything this end has written, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<Bytes> {
        self.sent
            .lock()
            .map(|sent| sent.clone())
            .unwrap_or_default()
    }
}

impl ByteChannel for LoopbackChannel {
    fn send(&self, data: Bytes) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            if let Ok(mut sent) = self.sent.lock() {
                sent.push(data.clone());
            }
            self.outgoing.send(data).map_err(|_| Error::Closed)
        })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<Bytes>>> {
        Box::pin(async move {
            if *self.closed.borrow() {
                return Ok(None);
            }

            let mut closed = self.closed.subscribe();
            let mut incoming = self.incoming.lock().await;
            tokio::select! {
                data = incoming.recv() => Ok(data),
                _ = closed.changed() => Ok(None),
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let _ = self.closed.send(true);
            Ok(())
        })
    }
}
