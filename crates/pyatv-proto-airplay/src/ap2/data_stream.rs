//! The AirPlay 2 data-stream channel, which is what an MRP session is tunnelled through.
//!
//! Port of `DataStreamChannel` (`pyatv/protocols/airplay/channels.py:229-280`) and the half of
//! `AP2Session._setup_data_channel` that follows the `SETUP` reply (`ap2_session.py:176-187`).
//!
//! This crate carries MRP bytes without understanding them: [`DataStreamChannel::send`] takes an
//! already-serialised `ProtocolMessage` and [`DataStreamChannel::recv`] hands one back. The
//! dependency direction forbids depending on `pyatv-proto-mrp`, and nothing in the framing needs
//! to — the payload is opaque to every layer described here.
//!
//! # What rides on top of what
//!
//! ```text
//! MRP ProtocolMessage bytes            <- opaque to this crate
//!   varint length prefix               <- payload::encode_messages
//!     bplist {"params": {"data": …}}   <- payload::encode_envelope
//!       32-byte DataHeader             <- frame::encode_sync
//!         HAP 1024-byte block framing  <- pyatv_pairing::session::HapSession
//!           TCP
//! ```
//!
//! # Encryption
//!
//! Exactly one layer: the HAP block framing on this socket, keyed by
//! `DataStream-Salt{seed}` / `DataStream-Output-Encryption-Key` /
//! `DataStream-Input-Encryption-Key` — **unswapped**, unlike the event channel, because the
//! controller both opens this socket and drives it (`ap2_session.py:176-184`). MRP's own
//! pair-verify still runs over the tunnel for state-machine parity with the device, but its derived
//! keys are discarded rather than installed (spec §7 point 2); nothing in this module ever encrypts
//! a payload a second time.

pub mod frame;
pub mod payload;
mod setup;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};
use pyatv_pairing::hkdf_derive::{data_stream_salt, transport::AIRPLAY_DATA_STREAM};
use pyatv_pairing::pairing::SessionKeys;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

pub use frame::{
    COMMAND_COMM, COMMAND_NONE, DataHeader, DataStreamMessage, HEADER_LEN, MESSAGE_TYPE_REPLY,
    MESSAGE_TYPE_SYNC, PADDING,
};
pub use setup::{CLIENT_TYPE_UUID, CONTROL_TYPE, DataStreamRequest, DataStreamSetup, STREAM_TYPE};

use crate::auth::PairVerifyProcedure;
use crate::{Error, Result};

use super::channel::{self, HapReader, HapWriter};

/// How many undelivered inbound messages are buffered before the read loop applies backpressure.
const INBOUND_QUEUE_DEPTH: usize = 64;

/// How many unsent outbound frames are queued before [`DataStreamChannel::send`] waits.
const OUTBOUND_QUEUE_DEPTH: usize = 64;

/// What to do with the frame header's `seqno` on each outbound message.
///
/// Upstream draws `send_seqno` once at channel construction from `randrange(0x100000000,
/// 0x1FFFFFFFF)` and **never touches it again** (`channels.py:232-235`), so every MRP-carrying
/// frame of a session repeats the same value. `docs/research/airplay-control-mrp-tunnel-port-spec.md`
/// correction 5 confirms that as pyatv's real behaviour rather than a documentation slip, and its
/// open questions record that no capture proves whether real firmware tolerates it.
///
/// [`SeqnoPolicy::Fixed`] is therefore the default, because behavioural parity with the reference
/// implementation is the thing this port is judged against. [`SeqnoPolicy::Increment`] exists so
/// that hypothesis can be tested against hardware without patching the channel — it is a knob, not
/// a fix, and switching it is a deliberate divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SeqnoPolicy {
    /// One value for the lifetime of the channel. pyatv's behaviour.
    #[default]
    Fixed,
    /// Advance by one per outbound frame.
    Increment,
}

/// Derive the data-stream channel's transport keys for a session `seed`.
///
/// The salt is `DataStream-Salt` with the seed's **decimal** representation appended
/// (`ap2_session.py:181`); the two info strings carry no seed. The call order is the ordinary one,
/// unlike the event channel's.
///
/// # Errors
///
/// Returns [`Error::NoEncryptionKeys`] if `verifier` ran an exchange that derives none, and
/// [`Error::Pairing`] if it has not completed.
pub fn data_stream_keys(verifier: &PairVerifyProcedure, seed: u64) -> Result<SessionKeys> {
    let (salt, output_info, input_info) = data_stream_key_spec(seed);
    verifier.encryption_keys(&salt, output_info, input_info)
}

/// The `(salt, output_info, input_info)` triple the data channel derives with.
///
/// Split out from [`data_stream_keys`] so the seeded salt and the *unswapped* argument order can be
/// asserted against the `airplay_data_stream` row of
/// `crates/pyatv-pairing/tests/kat/hap_srp_kat.json`, a vector generated from pyatv.
#[must_use]
pub fn data_stream_key_spec(seed: u64) -> (String, &'static str, &'static str) {
    (
        data_stream_salt(seed),
        AIRPLAY_DATA_STREAM.write_info,
        AIRPLAY_DATA_STREAM.read_info,
    )
}

/// A running data-stream channel.
///
/// `Send + Sync`, so the umbrella crate can hand one to an `MrpTransport` adapter and drive it from
/// wherever it likes. Dropping it stops the read loop and closes the socket.
#[derive(Debug)]
pub struct DataStreamChannel {
    address: SocketAddr,
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: Mutex<mpsc::Receiver<Bytes>>,
    seqno: AtomicU64,
    policy: SeqnoPolicy,
    task: JoinHandle<()>,
}

impl Drop for DataStreamChannel {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl DataStreamChannel {
    /// Dial the receiver's `dataPort` and start the frame loop.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the port cannot be reached.
    pub async fn connect(
        address: SocketAddr,
        keys: &SessionKeys,
        policy: SeqnoPolicy,
    ) -> Result<Self> {
        let (reader, writer) = channel::connect(address, keys).await?;

        let (outbound, outbound_rx) = mpsc::channel(OUTBOUND_QUEUE_DEPTH);
        let (inbound_tx, inbound) = mpsc::channel(INBOUND_QUEUE_DEPTH);

        let task = tokio::spawn(async move {
            run(reader, writer, outbound_rx, inbound_tx, address).await;
        });

        Ok(Self {
            address,
            outbound,
            inbound: Mutex::new(inbound),
            // `randrange(0x100000000, 0x1FFFFFFFF)` (`channels.py:235`): a 33-bit value above
            // 2^32, so it can never be mistaken for a small counter.
            seqno: AtomicU64::new(rand::random_range(0x1_0000_0000..0x1_FFFF_FFFF)),
            policy,
            task,
        })
    }

    /// The receiver-side address this channel was opened to.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The `seqno` the next outbound frame will carry.
    #[must_use]
    pub fn seqno(&self) -> u64 {
        self.seqno.load(Ordering::Relaxed)
    }

    /// Send one serialised MRP message.
    ///
    /// `send_protobuf` (`channels.py:266-280`) with the protobuf serialisation already done by the
    /// caller: the bytes are varint-prefixed, wrapped in `{"params": {"data": …}}`, framed with a
    /// `sync`/`comm` header and written to the encrypted socket.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if the envelope cannot be serialised, and [`Error::Io`] if the
    /// channel has been closed.
    pub async fn send(&self, message: &[u8]) -> Result<()> {
        let envelope = payload::encode_envelope(payload::encode_messages(&[message]))?;
        let frame = frame::encode_sync(self.next_seqno(), &envelope);

        self.outbound.send(frame).await.map_err(|_| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("data channel to {} is closed", self.address),
            ))
        })
    }

    /// Await the next MRP message the receiver sent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] once the channel has closed and no further message can arrive.
    pub async fn recv(&self) -> Result<Bytes> {
        self.inbound.lock().await.recv().await.ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                format!("data channel to {} is closed", self.address),
            ))
        })
    }

    /// Stop the frame loop and close the socket.
    pub fn close(&self) {
        tracing::debug!(address = %self.address, "closing AirPlay data-stream channel");
        self.task.abort();
    }

    /// The `seqno` for the frame about to be built, honouring [`SeqnoPolicy`].
    fn next_seqno(&self) -> u64 {
        match self.policy {
            SeqnoPolicy::Fixed => self.seqno.load(Ordering::Relaxed),
            SeqnoPolicy::Increment => self.seqno.fetch_add(1, Ordering::Relaxed),
        }
    }
}

/// Pump frames in both directions until either side goes away.
async fn run(
    mut reader: HapReader,
    mut writer: HapWriter,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    inbound: mpsc::Sender<Bytes>,
    address: SocketAddr,
) {
    let mut buffer = BytesMut::new();

    loop {
        tokio::select! {
            queued = outbound.recv() => {
                let Some(frame) = queued else { break };
                if let Err(error) = writer.send(&frame).await {
                    tracing::debug!(%address, %error, "data channel write failed");
                    break;
                }
            }
            // `HapReader::read` is cancel-safe, so losing this race consumes nothing.
            read = reader.read() => {
                match read {
                    Ok(Some(plaintext)) => buffer.extend_from_slice(&plaintext),
                    Ok(None) => break,
                    Err(error) => {
                        tracing::debug!(%address, %error, "data channel read failed");
                        break;
                    }
                }

                if let Err(error) = drain(&mut buffer, &mut writer, &inbound, address).await {
                    tracing::debug!(%address, %error, "data channel torn down");
                    break;
                }
            }
        }
    }

    let _ = writer.shutdown().await;
}

/// Decode every complete frame in `buffer`, acknowledging and dispatching as it goes.
async fn drain(
    buffer: &mut BytesMut,
    writer: &mut HapWriter,
    inbound: &mpsc::Sender<Bytes>,
    address: SocketAddr,
) -> Result<()> {
    while let Some(message) = frame::decode(buffer)? {
        tracing::debug!(
            %address,
            message_type = %ascii_tag(&message.header.message_type),
            command = %ascii_tag(&message.header.command),
            seqno = message.header.seqno,
            padding = message.header.padding,
            payload = message.payload.len(),
            "inbound data frame"
        );

        if !message.payload.is_empty() {
            dispatch(&message, inbound, address).await;
        }

        // Upstream acknowledges *any* `sync`-prefixed frame regardless of whether its payload was
        // understood (`channels.py:253-255`); a receiver that gets no reply treats the channel as
        // unresponsive.
        if message.header.wants_reply() {
            writer
                .send(&frame::encode_reply(message.header.seqno))
                .await?;
        }
    }

    Ok(())
}

/// Render a zero-padded ASCII frame tag for a log line.
///
/// The tags are fixed-width fields (`12s`, `4s`) holding a short ASCII word, so the padding is
/// noise; anything non-ASCII is rendered as hex rather than as replacement characters, because a
/// tag this port does not recognise is exactly what a log reader needs to see accurately.
fn ascii_tag(tag: &[u8]) -> String {
    let trimmed: Vec<u8> = tag.iter().copied().take_while(|byte| *byte != 0).collect();

    if trimmed.iter().all(u8::is_ascii_graphic) {
        String::from_utf8_lossy(&trimmed).into_owned()
    } else {
        use std::fmt::Write as _;

        trimmed.iter().fold(String::new(), |mut out, byte| {
            // Writing into a `String` is infallible; the `Result` exists only for the trait.
            let _ = write!(out, "{byte:02x}");
            out
        })
    }
}

/// Unwrap one frame's payload and hand each message inside it to the consumer.
///
/// A payload that is not the expected envelope is logged and dropped, matching upstream's
/// early return (`channels.py:257-261`) — a receiver sending something else on this channel is not
/// a reason to tear the tunnel down.
async fn dispatch(message: &DataStreamMessage, inbound: &mpsc::Sender<Bytes>, address: SocketAddr) {
    let Some(data) = payload::decode_envelope(&message.payload) else {
        tracing::debug!(
            %address,
            bytes = message.payload.len(),
            "data frame carried no params.data"
        );
        return;
    };

    let messages = match payload::decode_messages(&data) {
        Ok(messages) => messages,
        Err(error) => {
            tracing::warn!(%address, %error, "could not split a data frame's messages");
            return;
        }
    };

    for message in messages {
        if inbound.send(message).await.is_err() {
            tracing::debug!(%address, "nothing is reading the data channel");
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SeqnoPolicy, frame, payload};

    /// The full outbound stack, asserted against its parts rather than against a captured blob:
    /// header, envelope and varint prefix all have to line up for the bytes to decode again.
    #[test]
    fn an_outbound_frame_unwraps_back_to_the_message() {
        let message = [0x08u8, 0x2A, 0x52, 0x01];

        let envelope =
            payload::encode_envelope(payload::encode_messages(&[&message])).expect("encodes");
        let wire = frame::encode_sync(0x1_2345_6789, &envelope);

        let mut buffer = bytes::BytesMut::from(&wire[..]);
        let decoded = frame::decode(&mut buffer)
            .expect("decodes")
            .expect("a frame");

        assert_eq!(decoded.header.seqno, 0x1_2345_6789);
        assert_eq!(decoded.header.message_type, frame::MESSAGE_TYPE_SYNC);
        assert_eq!(decoded.header.command, frame::COMMAND_COMM);
        assert!(decoded.header.wants_reply());

        let data = payload::decode_envelope(&decoded.payload).expect("an envelope");
        let messages = payload::decode_messages(&data).expect("splits");
        assert_eq!(messages.len(), 1);
        assert_eq!(&messages[0][..], &message[..]);
    }

    /// The default policy is upstream's: one seqno for the life of the channel.
    #[test]
    fn the_default_seqno_policy_is_fixed() {
        assert_eq!(SeqnoPolicy::default(), SeqnoPolicy::Fixed);
    }
}
