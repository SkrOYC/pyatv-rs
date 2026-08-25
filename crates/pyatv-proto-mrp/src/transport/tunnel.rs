//! AirPlay-tunnel transport: MRP messages carried by an AirPlay 2 data-stream channel.
//!
//! Mandatory on tvOS 15 and later, where `_mediaremotetv._tcp` is no longer advertised at all.
//! Port of `AirPlayMrpConnection` (`pyatv/protocols/airplay/mrp_connection.py:17-76`), which is
//! almost entirely pass-throughs into an already-running `DataStreamChannel`.
//!
//! # Where the seam is, and why it is here
//!
//! The data channel's own framing — the 32-byte big-endian `DataHeader`, the `bplist00` body shaped
//! `{"params": {"data": …}}`, the `sync`/`rply` acknowledgement, the HAP block encryption — belongs
//! to `pyatv-proto-airplay` (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §5). What
//! belongs to *MRP* is the content of that `data` field: concatenated, individually
//! variant-length-prefixed serialised `ProtocolMessage`s (`channels.py:143-151,198-226`).
//!
//! [`ByteChannel`] is therefore defined at exactly that boundary. An implementor hands over the
//! decoded `data` blob and takes one back; this module owns the length prefixing and the
//! unprefixed-message heuristic. That keeps this crate free of any dependency on the AirPlay crate,
//! which the workspace's dependency rule requires, and it keeps the plist/`DataHeader` layer out of
//! a module that has no business parsing plists.
//!
//! # No MRP-level encryption, and no MRP pair-verify
//!
//! `AirPlayMrpConnection.enable_encryption` is a documented no-op, and the tunnel path registers a
//! dummy `MutableService(None, Protocol.MRP, …)` with **no credentials**
//! (`pyatv/protocols/airplay/__init__.py:241-244`), so `MrpProtocol._enable_encryption` returns at
//! its `if self.service.credentials is None: return` guard (`protocol.py:207-210`) and the
//! `CryptoPairingMessage` exchange never runs over a tunnel. Everything above the transport is
//! unchanged; see [`TransportEncryption`].

use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};
use pyatv_core::interface::BoxFuture;
use tokio::sync::Mutex;

use crate::message::MrpMessage;
use crate::transport::{MrpTransport, TransportEncryption};
use crate::{Error, Result, variant};

/// The protobuf wire tag for `ProtocolMessage.type` (field 1, varint), which is the marker for an
/// unprefixed message.
///
/// Every `ProtocolMessage` sets `type`, and the smallest real message is around forty bytes, so a
/// leading `0x08` cannot be a plausible length varint in this position. pyatv applies the check to
/// every incoming buffer unconditionally rather than gating it on a message type, and notes that
/// `ConfigureConnectionMessage` is the case it was observed on (`channels.py:198-226`).
pub const UNPREFIXED_MESSAGE_MARKER: u8 = 0x08;

/// Refuse a `data` blob whose length prefix is implausible; see
/// [`crate::transport::direct::MAX_FRAME_LEN`].
pub const MAX_MESSAGE_LEN: usize = 8 * 1024 * 1024;

/// An opaque, already-encrypted byte channel carrying MRP payloads.
///
/// Implemented by the umbrella crate over `pyatv-proto-airplay`'s data-stream channel: `send` is
/// `DataStreamChannel.send_protobuf`'s payload, `recv` is what `_process_payload` pulls out of
/// `params.data` (`channels.py:241-280`). Nothing about AirPlay appears in the signature, so a test
/// can implement it over an in-memory pipe and run the entire MRP stack unchanged.
pub trait ByteChannel: Send + Sync + std::fmt::Debug {
    /// Hand one `data` blob to the channel for delivery.
    ///
    /// # Errors
    ///
    /// Returns whatever the channel reports; [`Error::Closed`] if it has gone away.
    fn send(&self, data: Bytes) -> BoxFuture<'_, Result<()>>;

    /// Await the next `data` blob. `Ok(None)` means the channel closed cleanly.
    ///
    /// # Errors
    ///
    /// As [`ByteChannel::send`].
    fn recv(&self) -> BoxFuture<'_, Result<Option<Bytes>>>;

    /// Tear the channel down. Must be safe to call more than once.
    ///
    /// # Errors
    ///
    /// As [`ByteChannel::send`].
    fn close(&self) -> BoxFuture<'_, Result<()>>;
}

/// MRP tunnelled over an AirPlay 2 data-stream channel.
///
/// Constructed from an **already-established** channel. pyatv enforces that ordering at runtime —
/// `AirPlayMrpConnection.connect()` raises `InvalidStateError` if the data channel is not up yet
/// (`mrp_connection.py:26-31`) — where taking the channel by value makes the invalid state
/// unrepresentable instead.
#[derive(Debug)]
pub struct TunnelTransport<C: ByteChannel> {
    channel: C,
    /// One `data` blob can carry several messages; the surplus waits here for the next `recv`.
    pending: Mutex<VecDeque<MrpMessage>>,
}

impl<C: ByteChannel> TunnelTransport<C> {
    /// Wrap an established, already-pair-verified data channel.
    pub const fn new(channel: C) -> Self {
        Self {
            channel,
            pending: Mutex::const_new(VecDeque::new()),
        }
    }

    /// The channel this transport writes to.
    pub const fn channel(&self) -> &C {
        &self.channel
    }
}

/// Length-prefix one serialised message for the `data` field.
///
/// `encode_protobufs` (`channels.py:143-151`). pyatv's encoder can batch, but `send_protobuf`
/// only ever passes a single-element list, so this does too.
#[must_use]
pub fn encode_payload(message: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(message.len() + variant::MAX_LEN);
    out.extend_from_slice(&variant::write(
        u64::try_from(message.len()).unwrap_or(u64::MAX),
    ));
    out.extend_from_slice(message);
    out.freeze()
}

/// Split a `data` blob into messages, applying the unprefixed-message heuristic.
///
/// `decode_protobufs` (`channels.py:198-226`). Upstream asserts `message[0] == 0x8` after the fact
/// and lets the enclosing `except Exception` swallow the failure with a log line; this returns a
/// typed error instead, which is a deliberate improvement on a debuggability liability rather than
/// a wire-format divergence.
///
/// # Errors
///
/// Returns [`Error::Framing`] if a length prefix runs past the end of the buffer, or if a message
/// does not begin with [`UNPREFIXED_MESSAGE_MARKER`].
pub fn decode_payload(mut data: &[u8]) -> Result<Vec<Bytes>> {
    let mut messages = Vec::new();

    while !data.is_empty() {
        let message = if data[0] == UNPREFIXED_MESSAGE_MARKER {
            // The whole remainder is one message with no length prefix.
            let whole = data;
            data = &[];
            whole
        } else {
            let (length, consumed) = variant::read(data)?;
            let length = usize::try_from(length)
                .ok()
                .filter(|it| *it <= MAX_MESSAGE_LEN)
                .ok_or_else(|| {
                    Error::Framing(format!(
                        "tunnelled message length {length} exceeds {MAX_MESSAGE_LEN}"
                    ))
                })?;

            let rest = &data[consumed..];
            if rest.len() < length {
                return Err(Error::Framing(format!(
                    "tunnelled message claims {length} bytes but only {} are present",
                    rest.len()
                )));
            }
            data = &rest[length..];
            &rest[..length]
        };

        if message.first() != Some(&UNPREFIXED_MESSAGE_MARKER) {
            return Err(Error::Framing(
                "tunnelled message does not start with the ProtocolMessage.type tag".to_owned(),
            ));
        }
        messages.push(Bytes::copy_from_slice(message));
    }

    Ok(messages)
}

impl<C: ByteChannel> MrpTransport for TunnelTransport<C> {
    fn send(&self, message: &MrpMessage) -> BoxFuture<'_, Result<()>> {
        let payload = encode_payload(message.bytes());
        Box::pin(async move { self.channel.send(payload).await })
    }

    fn recv(&self) -> BoxFuture<'_, Result<Option<MrpMessage>>> {
        Box::pin(async move {
            loop {
                if let Some(message) = self.pending.lock().await.pop_front() {
                    return Ok(Some(message));
                }

                let Some(data) = self.channel.recv().await? else {
                    return Ok(None);
                };

                let mut pending = self.pending.lock().await;
                for bytes in decode_payload(&data)? {
                    pending.push_back(MrpMessage::decode(bytes)?);
                }
                // An empty `data` blob is legal — upstream just decodes zero messages from it —
                // so loop rather than returning, and wait for the next one.
            }
        })
    }

    fn enable_encryption(&self, _output_key: [u8; 32], _input_key: [u8; 32]) -> Result<()> {
        Err(Error::NotSupported(
            "the AirPlay tunnel is already encrypted at the HAP layer; MRP must not install keys \
             on top of it",
        ))
    }

    fn encryption(&self) -> TransportEncryption {
        TransportEncryption::DelegatedToTunnel
    }

    fn is_encrypted(&self) -> bool {
        // Not at the MRP layer. The data channel below is, which is why MRP must not be.
        false
    }

    fn connected(&self) -> bool {
        // `AirPlayMrpConnection.connected` is hardcoded `True` (`mrp_connection.py:47-50`):
        // failure reaches the protocol asynchronously, through the channel closing.
        true
    }

    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move { self.channel.close().await })
    }
}

#[cfg(test)]
mod tests {
    use super::{UNPREFIXED_MESSAGE_MARKER, decode_payload, encode_payload};
    use bytes::{Bytes, BytesMut};

    fn message(len: usize) -> Vec<u8> {
        let mut body = vec![UNPREFIXED_MESSAGE_MARKER];
        body.resize(len, 0x00);
        body
    }

    #[test]
    fn a_prefixed_message_round_trips() {
        let body = message(50);
        let encoded = encode_payload(&body);

        assert_eq!(encoded[0], 50);
        assert_eq!(decode_payload(&encoded).unwrap(), vec![Bytes::from(body)]);
    }

    /// Several messages can share one `data` blob; upstream's encoder supports it even though its
    /// only caller sends one at a time.
    #[test]
    fn several_prefixed_messages_are_split() {
        let first = message(40);
        let second = message(60);

        let mut blob = BytesMut::new();
        blob.extend_from_slice(&encode_payload(&first));
        blob.extend_from_slice(&encode_payload(&second));

        assert_eq!(
            decode_payload(&blob).unwrap(),
            vec![Bytes::from(first), Bytes::from(second)]
        );
    }

    /// The heuristic: a leading `0x08` means "no length prefix, take the rest".
    #[test]
    fn an_unprefixed_message_consumes_the_whole_buffer() {
        let body = message(64);
        assert_eq!(
            decode_payload(&body).unwrap(),
            vec![Bytes::from(body.clone())]
        );
    }

    #[test]
    fn a_truncated_message_is_a_typed_error_not_a_silent_drop() {
        // Claims 40 bytes, supplies 3.
        let blob = [40u8, 0x08, 0x01, 0x02];
        assert!(decode_payload(&blob).is_err());
    }

    /// A prefixed payload whose body does not start with the `type` tag is malformed; upstream
    /// asserts the same thing and swallows the assertion.
    #[test]
    fn a_message_without_the_type_tag_is_rejected() {
        let blob = [2u8, 0x10, 0x01];
        assert!(decode_payload(&blob).is_err());
    }

    #[test]
    fn an_empty_blob_decodes_to_nothing() {
        assert!(decode_payload(&[]).unwrap().is_empty());
    }
}
