//! The Companion protocol driver: XID allocation, correlation, events and connection bring-up.
//!
//! Port of `CompanionProtocol` (`pyatv/protocols/companion/protocol.py:72-234`). The framing below
//! it is [`crate::connection`]; the session bring-up above it is [`crate::session`].
//!
//! # Where this differs from pyatv's shape
//!
//! Upstream is callback-driven: `CompanionConnection` pushes frames into `frame_received`, which
//! resolves whichever `SharedData` future is parked under the frame's key, and a caller awaits that
//! future. This port instead has the caller own the connection and drive the read loop from inside
//! [`CompanionProtocol::exchange_opack`]. Two consequences, both deliberate:
//!
//! * **One exchange is in flight at a time.** pyatv can have many, keyed by XID
//!   (`protocol.py:143-153`). Serialising them is what removes the background task, the shared
//!   mutable queue map and pyatv's own unbounded `_queues` leak when a caller cancels a wait
//!   (`docs/research/companion-port-spec.md` §12 finding 12). A response whose XID is not the one
//!   being awaited is still kept — see `stash` — so nothing is lost if that changes later.
//! * **Events are delivered on a channel** rather than to a listener object, so a caller that is
//!   not currently in an exchange still receives them the next time it drives the loop.
//!
//! Everything on the wire is unchanged by either.

use std::collections::HashMap;
use std::time::Duration;

use pyatv_opack::Value;
use pyatv_pairing::HapCredentials;
use tokio::sync::mpsc;

use crate::auth::PairVerifyProcedure;
use crate::connection::CompanionConnection;
use crate::frame::FrameType;
use crate::message::{Envelope, KEY_XID, MessageType};
use crate::{Error, Result};

/// How long one exchange waits for its answer (`DEFAULT_TIMEOUT`, `protocol.py:38`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// An event the device pushed.
#[derive(Debug, Clone, PartialEq)]
pub struct CompanionEvent {
    /// The event name, from `_i`.
    pub name: String,
    /// The event payload, from `_c`.
    pub content: Value,
}

/// The receiving half of the event stream.
pub type EventStream = mpsc::UnboundedReceiver<CompanionEvent>;

/// What [`CompanionProtocol::pump`] is waiting for.
#[derive(Debug, Clone, Copy)]
enum Awaiting {
    /// A pairing frame of exactly this type.
    Auth(FrameType),
    /// A response carrying this `_x`.
    Xid(u32),
}

/// Drives one Companion connection.
#[derive(Debug)]
pub struct CompanionProtocol {
    connection: CompanionConnection,
    /// Next `_x` to hand out.
    xid: u32,
    /// Responses that arrived for an XID nobody was waiting for yet, kept as raw OPACK so no key
    /// is lost on the way back out.
    stash: HashMap<u32, Value>,
    events: mpsc::UnboundedSender<CompanionEvent>,
    timeout: Duration,
    started: bool,
}

impl CompanionProtocol {
    /// Wrap a connection, returning the protocol and the stream its events arrive on.
    ///
    /// The XID counter starts at a random value, as upstream's `randint(0, 2**16)` does with the
    /// comment "Don't know range here, just use something" (`protocol.py:89`). Upstream then
    /// increments a Python bignum forever; this port uses a wrapping `u32`, which OPACK encodes at
    /// whatever width the current value needs, so the wire form is identical for the values a real
    /// session reaches (`docs/research/companion-port-spec.md` §12 finding 3).
    #[must_use]
    pub fn new(connection: CompanionConnection) -> (Self, EventStream) {
        Self::with_xid(connection, rand::random::<u16>().into())
    }

    /// Wrap a connection with a chosen starting XID, so a test can assert on exact wire bytes.
    #[must_use]
    pub fn with_xid(connection: CompanionConnection, xid: u32) -> (Self, EventStream) {
        let (events, stream) = mpsc::unbounded_channel();
        let protocol = Self {
            connection,
            xid,
            stash: HashMap::new(),
            events,
            timeout: DEFAULT_TIMEOUT,
            started: false,
        };
        (protocol, stream)
    }

    /// Override the per-exchange deadline.
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    /// The connection underneath, for callers that need its address or encryption state.
    #[must_use]
    pub const fn connection(&self) -> &CompanionConnection {
        &self.connection
    }

    /// Whether transport encryption is active.
    #[must_use]
    pub const fn is_encrypted(&self) -> bool {
        self.connection.is_encrypted()
    }

    /// Install transport keys derived elsewhere, for callers that drive pair-verify themselves.
    ///
    /// [`CompanionProtocol::start`] does this for the ordinary path; this exists for the pairing
    /// handler's proof step, which needs the keys and the connection separately.
    pub fn enable_encryption(&mut self, output_key: [u8; 32], input_key: [u8; 32]) {
        self.connection.enable_encryption(output_key, input_key);
    }

    /// Take the next `_x` and advance the counter.
    fn next_xid(&mut self) -> u32 {
        let xid = self.xid;
        self.xid = self.xid.wrapping_add(1);
        xid
    }

    /// Bring the connection up: pair-verify against stored credentials, then encrypt.
    ///
    /// Faithful to `CompanionProtocol.start()` (`protocol.py:94-123`), including its two quirks:
    /// calling it twice **raises** rather than silently no-opping, and with no credentials it is a
    /// no-op that leaves the connection in the clear. That second case is not an oversight — it is
    /// the path pair-setup runs on, since pair-setup establishes trust from nothing and therefore
    /// cannot be encrypted.
    ///
    /// The `_systemInfo`/`_sessionStart` bring-up chain is **not** here. Upstream splits it out
    /// into `CompanionAPI.connect()` (`api.py:135-159`), one layer above the transport, and
    /// `docs/research/companion-port-spec.md` §2.4 is explicit that a port should keep that
    /// boundary. It lives in [`crate::session::begin_session`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotReady`] if called twice, or a [`Error::Pairing`] variant if the device
    /// rejects the credentials.
    pub async fn start(&mut self, credentials: Option<&HapCredentials>) -> Result<()> {
        if self.started {
            return Err(Error::NotReady("the protocol has already been started"));
        }
        self.started = true;

        let Some(credentials) = credentials else {
            tracing::debug!("no Companion credentials; leaving the connection unencrypted");
            return Ok(());
        };

        let keys = PairVerifyProcedure::new(credentials.clone())
            .verify_credentials(self)
            .await?;
        self.connection
            .enable_encryption(keys.output_key, keys.input_key);
        Ok(())
    }

    /// Send a frame carrying an OPACK dict, stamping an `_x` on if it has none.
    ///
    /// Port of `send_opack` (`protocol.py:178-186`). The auto-stamping is easy to miss and is
    /// wire-visible: pairing frames and outbound events never set `_x` themselves, so **every
    /// outbound OPACK frame carries one**, even though the device's answer to an auth frame is
    /// correlated by frame type and events are never correlated at all
    /// (`docs/research/companion-port-spec.md` §2.2).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Envelope`] if `payload` is not a dict, [`Error::Opack`] if it cannot be
    /// packed, or an [`Error::Io`]/[`Error::Framing`] from the connection.
    pub async fn send_opack(&mut self, frame_type: FrameType, payload: Value) -> Result<()> {
        let Value::Dict(mut entries) = payload else {
            return Err(Error::Envelope(format!(
                "a {frame_type:?} payload must be a dict, got {payload:?}"
            )));
        };

        if !entries.iter().any(|(key, _)| key.as_str() == Some(KEY_XID)) {
            let xid = self.next_xid();
            entries.push((Value::from(KEY_XID), Value::from(xid)));
        }

        let packed = pyatv_opack::pack(&Value::Dict(entries))?;
        self.connection.send_frame(frame_type, &packed).await
    }

    /// Send a pairing frame and await the device's answer.
    ///
    /// Port of `exchange_auth` (`protocol.py:125-141`). The response to a `*_Start` frame arrives
    /// typed `*_Next`, never echoing the `*_Start` type back, so the awaited type is
    /// [`FrameType::response_type`] rather than the type just sent — the one asymmetry in the whole
    /// handshake.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the device does not answer inside the deadline, plus anything
    /// [`CompanionProtocol::send_opack`] can return.
    pub async fn exchange_auth(&mut self, frame_type: FrameType, payload: Value) -> Result<Value> {
        self.send_opack(frame_type, payload).await?;
        self.pump(Awaiting::Auth(frame_type.response_type())).await
    }

    /// Send an OPACK message and await the response with the matching `_x`.
    ///
    /// Port of `exchange_opack` (`protocol.py:143-153`): the XID is written into the outgoing dict
    /// and used as the dispatch key in the same breath.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rejected`] if the device answered with an `_em`, [`Error::Timeout`] on the
    /// deadline, and [`Error::Envelope`] if `payload` is not a dict.
    pub async fn exchange_opack(&mut self, frame_type: FrameType, payload: Value) -> Result<Value> {
        let Value::Dict(mut entries) = payload else {
            return Err(Error::Envelope(format!(
                "a {frame_type:?} payload must be a dict, got {payload:?}"
            )));
        };

        let xid = self.next_xid();
        entries.retain(|(key, _)| key.as_str() != Some(KEY_XID));
        entries.push((Value::from(KEY_XID), Value::from(xid)));

        self.send_opack(frame_type, Value::Dict(entries)).await?;
        self.pump(Awaiting::Xid(xid)).await
    }

    /// Send a request and return its response envelope, failing on `_em`.
    ///
    /// The `_send_command` layer (`api.py:161-186`), which every Companion command goes through.
    ///
    /// # Errors
    ///
    /// As [`CompanionProtocol::exchange_opack`], plus [`Error::Envelope`] if the response is not a
    /// dict.
    pub async fn send_command(&mut self, identifier: &str, content: Value) -> Result<Envelope> {
        let request = Envelope::request(identifier, content).to_value();
        let response = self.exchange_opack(FrameType::EOpack, request).await?;
        Envelope::from_value(&response)
    }

    /// Send an event, which the device never answers.
    ///
    /// `_send_event` (`api.py:247-265`).
    ///
    /// # Errors
    ///
    /// As [`CompanionProtocol::send_opack`].
    pub async fn send_event(&mut self, identifier: &str, content: Value) -> Result<()> {
        let event = Envelope::event(identifier, content).to_value();
        self.send_opack(FrameType::EOpack, event).await
    }

    /// Read frames until the awaited one arrives, dispatching everything else on the way.
    ///
    /// The `_em`-presence check lives here rather than in the callers because upstream puts it in
    /// `_exchange_generic_opack` (`protocol.py:168-176`), the body **both** `exchange_auth` and
    /// `exchange_opack` funnel through — so a pairing frame carrying an error message fails the
    /// same way a command does.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] on the deadline, [`Error::Closed`] if the device hangs up, and
    /// [`Error::Rejected`] if the awaited response carried an `_em`.
    async fn pump(&mut self, awaiting: Awaiting) -> Result<Value> {
        let what = match awaiting {
            Awaiting::Auth(frame_type) => format!("a {frame_type:?} frame"),
            Awaiting::Xid(xid) => format!("a response to XID {xid}"),
        };

        let value = tokio::time::timeout(self.timeout, self.pump_inner(awaiting))
            .await
            .map_err(|_| Error::Timeout {
                what,
                millis: u64::try_from(self.timeout.as_millis()).unwrap_or(u64::MAX),
            })??;

        Envelope::from_value(&value)?.into_result()?;
        Ok(value)
    }

    async fn pump_inner(&mut self, awaiting: Awaiting) -> Result<Value> {
        // A response may already have arrived while an earlier exchange was being served.
        if let Awaiting::Xid(xid) = awaiting
            && let Some(value) = self.stash.remove(&xid)
        {
            return Ok(value);
        }

        loop {
            if let Some(value) = self.read_and_dispatch(Some(awaiting)).await? {
                return Ok(value);
            }
        }
    }

    /// Read exactly one frame and dispatch it, without waiting for anything in particular.
    ///
    /// This is what lets a caller keep the socket drained while no exchange is in flight, so
    /// device-pushed events (`_iMC`, `SystemStatus`, `_tiStarted`) arrive as they happen rather
    /// than only when the next command is sent. pyatv gets this for free from `asyncio.Protocol`'s
    /// always-running `data_received` callback (`connection.py:141-168`); this port has an owning
    /// caller instead, so it needs an explicit idle read.
    ///
    /// # Cancellation
    ///
    /// Safe to drop mid-await, and therefore safe as a `tokio::select!` branch. The only await
    /// point is [`CompanionConnection::recv_frame`], which is itself cancel-safe; everything after
    /// it runs synchronously inside the same poll, so a frame can never be read and then lost.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] when the device hangs up, plus any framing or decryption failure.
    pub async fn poll_once(&mut self) -> Result<()> {
        self.read_and_dispatch(None).await.map(|_| ())
    }

    /// Read one frame, hand it to whoever it belongs to, and report whether it was the awaited one.
    async fn read_and_dispatch(&mut self, awaiting: Option<Awaiting>) -> Result<Option<Value>> {
        let frame = self.connection.recv_frame().await?;

        // pyatv decodes every auth and OPACK frame and logs-and-drops anything that fails
        // (`protocol.py:188-207`); a malformed frame must not kill a live connection.
        let value = if frame.frame_type.is_auth() || frame.frame_type.is_opack() {
            match pyatv_opack::unpack(&frame.payload) {
                Ok((value, _)) => value,
                Err(error) => {
                    tracing::warn!(
                        frame_type = ?frame.frame_type,
                        %error,
                        "dropping a Companion frame whose OPACK body did not decode"
                    );
                    return Ok(None);
                }
            }
        } else {
            tracing::debug!(frame_type = ?frame.frame_type, "ignoring an unhandled frame type");
            return Ok(None);
        };

        if frame.frame_type.is_auth() {
            match awaiting {
                Some(Awaiting::Auth(wanted)) if wanted == frame.frame_type => {
                    return Ok(Some(value));
                }
                _ => tracing::warn!(
                    frame_type = ?frame.frame_type,
                    "no receiver for this auth frame"
                ),
            }
            return Ok(None);
        }

        let envelope = match Envelope::from_value(&value) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::debug!(%error, "dropping an OPACK frame that is not a message");
                return Ok(None);
            }
        };

        match envelope.message_type {
            Some(MessageType::Event) => self.dispatch_event(envelope),
            Some(MessageType::Response) => {
                if let Some(awaiting) = awaiting {
                    return Ok(self.dispatch_response(awaiting, &envelope, value));
                }
                self.stash_response(&envelope, value);
            }
            Some(MessageType::Request) | None => {
                tracing::warn!(
                    message_type = ?envelope.message_type,
                    "ignoring an OPACK frame with an unsupported message type"
                );
            }
        }

        Ok(None)
    }

    /// Hand an event to the caller's stream.
    ///
    /// An event with no `_i` is dropped: upstream indexes `opack_data["_i"]` unguarded and the
    /// resulting `KeyError` is swallowed by `frame_received`'s blanket handler
    /// (`protocol.py:223-224,204-205`), which is the same net behaviour without the traceback.
    fn dispatch_event(&self, envelope: Envelope) {
        let Some(name) = envelope.identifier else {
            tracing::debug!("dropping an event with no identifier");
            return;
        };

        tracing::debug!(%name, "received a Companion event");
        // A closed receiver means the caller stopped listening; the connection is still fine.
        if self
            .events
            .send(CompanionEvent {
                name,
                content: envelope.content,
            })
            .is_err()
        {
            tracing::trace!("no listener for Companion events");
        }
    }

    /// Return the response if it is the awaited one, otherwise keep it for later.
    ///
    /// The raw `value` is what is returned and stashed, never a re-serialised envelope: the error
    /// keys and any field this port does not model would be lost in the round trip.
    fn dispatch_response(
        &mut self,
        awaiting: Awaiting,
        envelope: &Envelope,
        value: Value,
    ) -> Option<Value> {
        let Some(xid) = envelope.xid else {
            tracing::warn!("dropping a response with no XID");
            return None;
        };

        if matches!(awaiting, Awaiting::Xid(wanted) if wanted == xid) {
            return Some(value);
        }

        tracing::debug!(
            xid,
            "stashing a response for an XID that is not being awaited"
        );
        self.stash.insert(xid, value);
        None
    }

    /// Keep a response nobody is waiting for, for the idle-read path.
    fn stash_response(&mut self, envelope: &Envelope, value: Value) {
        let Some(xid) = envelope.xid else {
            tracing::warn!("dropping a response with no XID");
            return;
        };
        tracing::debug!(xid, "stashing a response that arrived while idle");
        self.stash.insert(xid, value);
    }

    /// Close the connection and drop anything still queued (`stop`, `protocol.py:109-112`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket shutdown fails.
    pub async fn close(&mut self) -> Result<()> {
        self.stash.clear();
        self.connection.close().await
    }
}

#[cfg(test)]
mod tests;
