//! The adapter that lets MRP ride an AirPlay 2 data-stream channel.
//!
//! This module is the whole reason the umbrella crate exists as a place where protocols meet.
//! `pyatv-proto-mrp` may not depend on `pyatv-proto-airplay` and the reverse is equally forbidden,
//! so neither of them can name the other's type — the two halves of the tunnel are joined here, in
//! the one crate that is allowed to know about both.
//!
//! Upstream's equivalent is `AirPlayMrpConnection`
//! (`pyatv/protocols/airplay/mrp_connection.py:17-76`), which lives inside the AirPlay package
//! because Python has no such layering rule.
//!
//! # Which seam this is cut at
//!
//! `pyatv_proto_mrp::ByteChannel` deals in whole `params.data` blobs: MRP owns the varint length
//! prefix inside them, and `TunnelTransport` has already applied it by the time `send` is called.
//! So this forwards to
//! [`DataStreamChannel::send_payload`](pyatv_proto_airplay::DataStreamChannel::send_payload) rather
//! than to `send`, which would length-prefix a second time and produce a frame no receiver can
//! parse. The same holds in reverse for `recv_payload`.

use std::sync::Arc;

use bytes::Bytes;
use pyatv_core::interface::BoxFuture;
use pyatv_proto_airplay::DataStreamChannel;
use pyatv_proto_mrp::transport::ByteChannel;

/// An open AirPlay data-stream channel, presented as something MRP can talk over.
#[derive(Debug)]
pub struct AirPlayByteChannel {
    channel: Arc<DataStreamChannel>,
}

impl AirPlayByteChannel {
    /// Wrap a channel that is already up.
    ///
    /// The `Arc` is shared with the [`pyatv_proto_airplay::Ap2Session`] that opened it: closing
    /// the session closes this channel too, and both orders are safe.
    #[must_use]
    pub const fn new(channel: Arc<DataStreamChannel>) -> Self {
        Self { channel }
    }
}

impl ByteChannel for AirPlayByteChannel {
    fn send(&self, data: Bytes) -> BoxFuture<'_, pyatv_proto_mrp::Result<()>> {
        Box::pin(async move { self.channel.send_payload(&data).await.map_err(as_mrp_error) })
    }

    /// A closed channel is an end-of-stream, not a failure.
    ///
    /// `AirPlayMrpConnection` has no read method at all — the data channel pushes into
    /// `handle_protobuf` and reports its own death through `handle_connection_lost`
    /// (`mrp_connection.py:63-76`). Pulling instead of pushing means the same distinction has to be
    /// made in the return value, and `Ok(None)` is what the MRP protocol actor turns into the
    /// `connection_closed` notification that callback produced.
    fn recv(&self) -> BoxFuture<'_, pyatv_proto_mrp::Result<Option<Bytes>>> {
        Box::pin(async move { Ok(self.channel.recv_payload().await) })
    }

    /// `AirPlayMrpConnection.close` (`mrp_connection.py:52-56`): close the data channel and forget
    /// it. Safe to call more than once, and — importantly — safe to call while another task is
    /// parked in [`ByteChannel::recv`]; see [`DataStreamChannel`]'s own documentation for why that
    /// is not merely true today but a property the channel is obliged to keep.
    fn close(&self) -> BoxFuture<'_, pyatv_proto_mrp::Result<()>> {
        Box::pin(async move {
            self.channel.close();
            Ok(())
        })
    }
}

/// Restate an AirPlay transport failure in MRP's vocabulary.
///
/// Only the two shapes the data channel can actually produce are distinguished. A broken pipe out
/// of a closed channel is [`pyatv_proto_mrp::Error::Closed`], because that is the variant the
/// protocol layer already treats as "stop, do not retry"; everything else keeps its own text.
fn as_mrp_error(error: pyatv_proto_airplay::Error) -> pyatv_proto_mrp::Error {
    match error {
        pyatv_proto_airplay::Error::Io(inner)
            if inner.kind() == std::io::ErrorKind::BrokenPipe
                || inner.kind() == std::io::ErrorKind::UnexpectedEof =>
        {
            pyatv_proto_mrp::Error::Closed
        }
        pyatv_proto_airplay::Error::Io(inner) => pyatv_proto_mrp::Error::Io(inner),
        other => pyatv_proto_mrp::Error::Framing(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::as_mrp_error;

    /// A write to a channel whose frame loop has stopped must read as `Closed`, not as a generic
    /// I/O error: the protocol actor gives up on the former and retries the latter.
    #[test]
    fn a_broken_pipe_becomes_a_closed_connection() {
        let error = as_mrp_error(pyatv_proto_airplay::Error::Io(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "data channel is closed",
        )));

        assert!(matches!(error, pyatv_proto_mrp::Error::Closed));
    }

    #[test]
    fn other_io_failures_keep_their_kind() {
        let error = as_mrp_error(pyatv_proto_airplay::Error::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionReset,
            "reset",
        )));

        assert!(matches!(error, pyatv_proto_mrp::Error::Io(_)));
    }

    /// A malformed envelope is a framing problem, and saying so keeps the original text.
    #[test]
    fn a_plist_failure_becomes_a_framing_error() {
        let error = as_mrp_error(pyatv_proto_airplay::Error::Plist("not a plist".to_owned()));

        match error {
            pyatv_proto_mrp::Error::Framing(text) => assert!(text.contains("not a plist")),
            other => panic!("expected a framing error, got {other:?}"),
        }
    }
}
