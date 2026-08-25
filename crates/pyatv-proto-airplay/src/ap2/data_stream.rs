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
//! Two seams are exposed, one per layer of that stack.
//! [`DataStreamChannel::send_payload`]/[`DataStreamChannel::recv_payload`] work on the whole
//! `params.data` blob and do no length prefixing at all; that is the seam
//! `pyatv_proto_mrp::transport::ByteChannel` is cut at, because the varint framing inside the blob
//! is MRP's own and the tunnel transport already owns it.
//! [`DataStreamChannel::send`]/[`DataStreamChannel::recv`] sit one layer up and deal in individual
//! messages, which is what pyatv's `send_protobuf`/`handle_protobuf` pair does
//! (`channels.py:266-280`). Using both at once on one channel would prefix twice; pick a layer.
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

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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

/// How long [`DataStreamChannel::send_payload`] waits for room in the outbound queue.
///
/// Not an upstream concept — pyatv writes straight into an `asyncio` transport, whose buffer is
/// unbounded, so a stalled write shows up as memory growth rather than as a parked caller. A
/// bounded queue is the better trade, but only if a caller can never park on it forever: the MRP
/// protocol actor performs *every* write from its single `select!` loop, so one `send_payload` that
/// never returns stops the actor from serving anything at all, including the shutdown request that
/// would free it. The deadline is deliberately a shade above `pyatv-proto-mrp`'s own five-second
/// `REQUEST_TIMEOUT`, so an exchange times out on its own terms first and this only fires when the
/// write side is genuinely wedged.
const SEND_TIMEOUT: Duration = Duration::from_secs(6);

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
///
/// # Closing while a reader is parked
///
/// [`DataStreamChannel::close`] takes **no lock that [`DataStreamChannel::recv_payload`] can be
/// parked on**, and is not `async`. That is a load-bearing property rather than an accident: the
/// MRP protocol actor keeps a task sitting in `recv` for the whole life of a session and calls
/// `close` from a *different* task, so a `close` that had to acquire the inbound lock would
/// deadlock against its own reader. Aborting the frame loop drops the inbound sender, which is what
/// wakes the parked reader with an end-of-stream.
#[derive(Debug)]
pub struct DataStreamChannel {
    address: SocketAddr,
    outbound: mpsc::Sender<Vec<u8>>,
    inbound: Mutex<mpsc::Receiver<Bytes>>,
    /// Messages split out of a payload that carried more than one, waiting for the next
    /// message-level [`DataStreamChannel::recv`].
    pending: Mutex<VecDeque<Bytes>>,
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
            pending: Mutex::new(VecDeque::new()),
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

    /// Send one already-framed `params.data` blob.
    ///
    /// The lower of this channel's two seams: whatever the caller hands over becomes the `data`
    /// field verbatim, with no length prefixing. A caller that owns MRP's varint framing — the
    /// umbrella crate's `ByteChannel` adapter does — wants this one, because
    /// [`DataStreamChannel::send`] would prefix a second time.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if the envelope cannot be serialised, [`Error::Io`] with
    /// [`std::io::ErrorKind::BrokenPipe`] if the channel has been closed, and [`Error::Io`] with
    /// [`std::io::ErrorKind::TimedOut`] if the outbound queue stayed full for [`SEND_TIMEOUT`].
    pub async fn send_payload(&self, data: &[u8]) -> Result<()> {
        let envelope = payload::encode_envelope(data.to_vec())?;
        let frame = frame::encode_sync(self.next_seqno(), &envelope);

        let closed = || {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                format!("data channel to {} is closed", self.address),
            ))
        };

        match tokio::time::timeout(SEND_TIMEOUT, self.outbound.send(frame)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(closed()),
            Err(_) => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "data channel to {} did not drain within {SEND_TIMEOUT:?}",
                    self.address
                ),
            ))),
        }
    }

    /// Await the next `params.data` blob the receiver sent.
    ///
    /// `None` means the channel has closed and nothing further can arrive — an end-of-stream, not
    /// a failure. See the type's own docs for why this is safe to park on across a
    /// [`DataStreamChannel::close`] from another task.
    pub async fn recv_payload(&self) -> Option<Bytes> {
        self.inbound.lock().await.recv().await
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
        self.send_payload(&payload::encode_messages(&[message]))
            .await
    }

    /// Await the next MRP message the receiver sent.
    ///
    /// One payload can carry several messages (`channels.py:198-226`); the surplus is buffered and
    /// handed out by subsequent calls.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Malformed`] if a payload cannot be split into messages, and [`Error::Io`]
    /// once the channel has closed and no further message can arrive.
    pub async fn recv(&self) -> Result<Bytes> {
        loop {
            if let Some(message) = self.pending.lock().await.pop_front() {
                return Ok(message);
            }

            let Some(data) = self.recv_payload().await else {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("data channel to {} is closed", self.address),
                )));
            };

            let mut pending = self.pending.lock().await;
            pending.extend(payload::decode_messages(&data)?);
        }
    }

    /// Stop the frame loop and close the socket.
    ///
    /// Synchronous and lock-free by design; see the type's own docs.
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
///
/// # Acknowledge first, then dispatch
///
/// Upstream's ordering is the other way round — `_process_payload` runs and *then* the `rply` goes
/// out (`channels.py:241-255`) — but every step of it is synchronous, so "before" and "after" are
/// the same instant as far as the socket is concerned. Here they are not, and getting the order
/// wrong is a three-way deadlock rather than a latency wobble:
///
/// 1. this loop parks awaiting room in the bounded inbound queue,
/// 2. so it never writes the `rply`, and never services the outbound queue either,
/// 3. so the MRP actor's next write parks on the full outbound queue,
/// 4. so the MRP actor never runs its own `recv`, which is the only thing that drains the inbound
///    queue that step 1 is waiting on.
///
/// The acknowledgement is what the receiver actually needs — an unacknowledged `sync` makes it
/// treat the channel as unresponsive and drop the tunnel — so it goes out unconditionally and
/// first, straight down the writer this loop owns rather than through the outbound queue. The
/// payload is then offered without waiting, and dropped with a log if nothing is draining, exactly
/// as the event channel does (`ap2/event_channel.rs`). A dropped payload costs one push update; a
/// deadlock costs the session.
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

        // Upstream acknowledges *any* `sync`-prefixed frame regardless of whether its payload was
        // understood (`channels.py:253-255`).
        if message.header.wants_reply() {
            writer
                .send(&frame::encode_reply(message.header.seqno))
                .await?;
        }
        if !message.payload.is_empty() {
            dispatch(&message, inbound, address);
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

/// Unwrap one frame's `params.data` blob and hand it to the consumer.
///
/// A payload that is not the expected envelope is logged and dropped, matching upstream's
/// early return (`channels.py:257-261`) — a receiver sending something else on this channel is not
/// a reason to tear the tunnel down.
///
/// Splitting the blob into individual messages happens at the layer above, in
/// [`DataStreamChannel::recv`] or in the tunnel transport, so that a caller working at the payload
/// seam sees exactly the bytes the receiver put in the field.
///
/// **Never waits.** See [`drain`] for why offering the payload rather than handing it over is what
/// keeps the acknowledgements flowing; a consumer that has stopped draining loses payloads, and
/// says so in the log, instead of stalling the frame loop.
fn dispatch(message: &DataStreamMessage, inbound: &mpsc::Sender<Bytes>, address: SocketAddr) {
    let Some(data) = payload::decode_envelope(&message.payload) else {
        tracing::debug!(
            %address,
            bytes = message.payload.len(),
            "data frame carried no params.data"
        );
        return;
    };

    match inbound.try_send(Bytes::from(data)) {
        Ok(()) => {}
        Err(mpsc::error::TrySendError::Full(dropped)) => tracing::warn!(
            %address,
            bytes = dropped.len(),
            depth = INBOUND_QUEUE_DEPTH,
            "dropping a data-channel payload because nothing is draining the queue"
        ),
        Err(mpsc::error::TrySendError::Closed(_)) => {
            tracing::debug!(%address, "nothing is reading the data channel");
        }
    }
}

#[cfg(test)]
mod tests;
