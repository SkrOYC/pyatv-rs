//! The MRP protocol state machine: bring-up, correlation, heartbeats and dispatch.
//!
//! Port of `MrpProtocol` (`pyatv/protocols/mrp/protocol.py:100-295`). Everything here is
//! transport-agnostic — the direct socket and the AirPlay tunnel run this same code, differing only
//! in what [`crate::transport::MrpTransport::encryption`] reports and whether a heartbeat was asked
//! for (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §7.1).
//!
//! # Shape difference from upstream
//!
//! pyatv's protocol is an `asyncio.Protocol` callback target: `data_received` runs forever, so
//! device pushes land whether or not a request is in flight. Here the transport is an owned object
//! with `&self` methods, so the always-reading half is explicit: [`MrpProtocol::connect`] spawns a
//! reader task that drains the transport into a channel, and an [`actor`] task that owns the
//! outstanding-request table and serialises writes. The consequences are the same as they were for
//! Companion — pushes are processed continuously, and requests go out in submission order, which
//! is what an HID down/up pair needs.

pub mod actor;
pub mod heartbeat;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use pyatv_core::interface::DeviceListener;
use pyatv_core::storage::InfoSettings;
use pyatv_pairing::HapCredentials;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::message::MrpMessage;
use crate::protocol::actor::{Actor, Request};
use crate::state::MrpState;
use crate::transport::MrpTransport;
use crate::{Error, Result, messages};

/// How long a request waits for its response (`send_and_receive`'s `timeout=5.0`,
/// `protocol.py:237`).
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Default interval between heartbeats (`HEARTBEAT_INTERVAL`, `pyatv/core/protocol.py:20`).
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Retries after a failed heartbeat before the connection is torn down
/// (`HEARTBEAT_RETRIES`, `pyatv/core/protocol.py:21`) — one regular attempt plus this many.
pub const HEARTBEAT_RETRIES: usize = 1;

/// How many requests may be queued before a caller has to wait for the actor to catch up.
const REQUEST_QUEUE: usize = 32;

/// How many inbound messages may be buffered between the reader task and the actor.
const INBOUND_QUEUE: usize = 64;

/// Everything [`MrpProtocol::connect`] needs beyond the transport.
#[derive(Debug, Clone)]
pub struct MrpProtocolOptions {
    /// The identity this controller presents in `DEVICE_INFO_MESSAGE`.
    pub info: InfoSettings,
    /// The controller's pairing identifier, sent as `DeviceInfoMessage.uniqueIdentifier`.
    ///
    /// Overridden by the credentials' `client_id` when credentials are supplied, which is what
    /// `start()` does before sending the first message (`protocol.py:133-137`).
    pub pairing_id: String,
    /// Credentials to pair-verify with, if any.
    ///
    /// Ignored on a transport whose encryption is
    /// [`crate::transport::TransportEncryption::DelegatedToTunnel`]: the tunnel path registers a
    /// service with no credentials at all upstream, so no `CryptoPairingMessage` exchange ever
    /// happens there.
    pub credentials: Option<HapCredentials>,
    /// Heartbeat interval, or `None` to disable.
    ///
    /// `create_with_connection(..., requires_heatbeat=...)` (`__init__.py:1127-1131`): true for
    /// direct connections, explicitly false for the tunnel, which already has the AirPlay control
    /// channel's own `FEEDBACK` keepalive. Configurable rather than fixed at 30 seconds because
    /// heartbeat desync against recent tvOS builds is a live, unresolved upstream issue.
    pub heartbeat_interval: Option<Duration>,
    /// How long a request waits for its response.
    pub request_timeout: Duration,
    /// Notified when the connection drops without the caller asking.
    pub listener: Option<Arc<dyn DeviceListener>>,
}

impl Default for MrpProtocolOptions {
    fn default() -> Self {
        Self {
            info: InfoSettings::default(),
            pairing_id: Uuid::new_v4().to_string().to_uppercase(),
            credentials: None,
            heartbeat_interval: Some(HEARTBEAT_INTERVAL),
            request_timeout: REQUEST_TIMEOUT,
            listener: None,
        }
    }
}

/// A connected MRP protocol instance.
#[derive(Debug)]
pub struct MrpProtocol {
    requests: mpsc::Sender<Request>,
    transport: Arc<dyn MrpTransport>,
    state: Arc<MrpState>,
    options: MrpProtocolOptions,
    tasks: Vec<JoinHandle<()>>,
    heartbeat: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for MrpProtocol {
    /// Stop the background tasks if the caller dropped the protocol without closing it.
    ///
    /// Not a graceful teardown — that is [`MrpProtocol::close`] — but it does stop the tasks from
    /// holding a socket open for the rest of the process's life.
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        if let Ok(mut heartbeat) = self.heartbeat.lock()
            && let Some(task) = heartbeat.take()
        {
            task.abort();
        }
    }
}

impl MrpProtocol {
    /// Attach to a transport and start serving, without running the bring-up sequence.
    ///
    /// Separate from [`MrpProtocol::start`] because pair-setup needs a live protocol that has sent
    /// `DEVICE_INFO_MESSAGE` and nothing more — upstream's `skip_initial_messages=True`
    /// (`protocol.py:151-153`, `auth.py:36-40`).
    #[must_use]
    pub fn connect(transport: Arc<dyn MrpTransport>, options: MrpProtocolOptions) -> Self {
        let state = Arc::new(MrpState::new());
        let (requests, receiver) = mpsc::channel(REQUEST_QUEUE);
        let (inbound, inbound_receiver) = mpsc::channel(INBOUND_QUEUE);

        let reader = tokio::spawn(actor::read_loop(Arc::clone(&transport), inbound));
        let actor = Actor::new(
            Arc::clone(&transport),
            Arc::clone(&state),
            receiver,
            inbound_receiver,
            options.listener.clone(),
        );
        let actor = tokio::spawn(actor.run());

        Self {
            requests,
            transport,
            state,
            options,
            tasks: vec![reader, actor],
            heartbeat: Mutex::new(None),
        }
    }

    /// The shared device observation the facades read.
    #[must_use]
    pub fn state(&self) -> &Arc<MrpState> {
        &self.state
    }

    /// The transport this protocol runs over.
    #[must_use]
    pub fn transport(&self) -> &Arc<dyn MrpTransport> {
        &self.transport
    }

    /// The pairing identifier this protocol presents, credentials taking precedence.
    ///
    /// `if self.service.credentials: self.srp.pairing_id = parse_credentials(...).client_id`
    /// (`protocol.py:133-137`).
    #[must_use]
    pub fn pairing_id(&self) -> String {
        self.options
            .credentials
            .as_ref()
            .and_then(|it| String::from_utf8(it.client_id.clone()).ok())
            .unwrap_or_else(|| self.options.pairing_id.clone())
    }

    /// Send `DEVICE_INFO_MESSAGE` and dispatch the reply, which every connection must do first.
    ///
    /// "The first message must always be `DEVICE_INFORMATION`, otherwise the device will not respond
    /// with anything" (`protocol.py:141-149`). The reply is dispatched to the state explicitly
    /// because `send_and_receive` consumed it and would otherwise stop it propagating.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the device does not answer, or [`Error::Closed`] if the
    /// connection went away.
    pub async fn exchange_device_info(&self) -> Result<MrpMessage> {
        let message = messages::device_information(&self.options.info, &self.pairing_id(), false)?;
        let response = self.send_and_receive(message).await?;
        self.state.handle(&response)?;
        Ok(response)
    }

    /// Run the full bring-up sequence.
    ///
    /// `MrpProtocol.start()` (`protocol.py:123-172`), in its confirmed order:
    /// `DEVICE_INFO_MESSAGE` → pair-verify (only with credentials, only on a transport that does
    /// its own encryption) → `SET_CONNECTION_STATE_MESSAGE` fire-and-forget →
    /// `CLIENT_UPDATES_CONFIG_MESSAGE` → `GET_KEYBOARD_SESSION_MESSAGE`.
    ///
    /// There is no `REGISTER_HID_DEVICE_MESSAGE` and no `WAKE_DEVICE_MESSAGE` here: neither has any
    /// caller in the bring-up path upstream
    /// (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §8.3 and its Corrections 2 and 3).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if any request goes unanswered, [`Error::Pairing`] if
    /// pair-verify fails, or [`Error::Closed`] if the connection drops mid-sequence.
    pub async fn start(&self) -> Result<()> {
        self.exchange_device_info().await?;
        self.enable_encryption().await?;

        // "This should be the first message sent after encryption has been enabled"
        // (`protocol.py:159-160`) — and it is a plain `send`, not a round trip.
        self.send(messages::set_connection_state()?).await?;
        self.send_and_receive(messages::client_updates_config()?)
            .await?;
        self.send_and_receive(messages::get_keyboard_session())
            .await?;

        if let Some(interval) = self.options.heartbeat_interval {
            self.enable_heartbeat(interval);
        }
        Ok(())
    }

    /// Pair-verify and install the transport keys, if this connection does that at all.
    ///
    /// `_enable_encryption` (`protocol.py:207-221`) returns immediately when the service has no
    /// credentials, which is exactly the tunnel's situation. The transport reports which case it
    /// is in, so the decision is not inferred from a `None` that could equally mean "not paired".
    async fn enable_encryption(&self) -> Result<()> {
        if !self.transport.encryption().needs_pair_verify() {
            tracing::debug!("skipping MRP pair-verify: the transport is already encrypted");
            return Ok(());
        }
        let Some(credentials) = self.options.credentials.clone() else {
            tracing::debug!("skipping MRP pair-verify: no credentials");
            return Ok(());
        };

        let keys = crate::auth::verify_credentials(self, credentials).await?;
        self.transport
            .enable_encryption(keys.output_key, keys.input_key)
    }

    /// Send a message and expect no response (`protocol.py:223-231`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the connection has gone away, or an I/O failure from the write.
    pub async fn send(&self, message: MrpMessage) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Request::Send { message, reply })
            .await
            .map_err(|_| Error::Closed)?;
        response.await.map_err(|_| Error::Closed)?
    }

    /// Send a message and wait for the device's response (`protocol.py:233-260`).
    ///
    /// A fresh uppercase UUID is stamped on `identifier` and used as the correlation key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Timeout`] if the device does not answer within the configured deadline,
    /// or [`Error::Closed`] if the connection dropped.
    pub async fn send_and_receive(&self, message: MrpMessage) -> Result<MrpMessage> {
        self.exchange(message, true).await
    }

    /// Send a message that correlates by *type* rather than by identifier.
    ///
    /// `generate_identifier=False` (`protocol.py:246-252`), used only by the
    /// `CryptoPairingMessage` exchanges: the device never echoes an identifier back on those, and
    /// only one can be outstanding at a time, so the key is the synthetic `"type_<n>"` string.
    ///
    /// # Errors
    ///
    /// As [`MrpProtocol::send_and_receive`].
    pub async fn exchange_untagged(&self, message: MrpMessage) -> Result<MrpMessage> {
        self.exchange(message, false).await
    }

    async fn exchange(&self, message: MrpMessage, tag: bool) -> Result<MrpMessage> {
        actor::exchange(&self.requests, message, tag, self.options.request_timeout).await
    }

    /// Start sending periodic `GENERIC_MESSAGE` round trips.
    ///
    /// `enable_heartbeat` (`protocol.py:188-205`). Direct connections only upstream; the tunnel
    /// relies on the AirPlay control channel's `FEEDBACK` instead. Calling it twice replaces the
    /// running heartbeat rather than adding a second one.
    pub fn enable_heartbeat(&self, interval: Duration) {
        let task = tokio::spawn(heartbeat::run(
            self.requests.clone(),
            interval,
            self.options.request_timeout,
        ));

        if let Ok(mut heartbeat) = self.heartbeat.lock()
            && let Some(previous) = heartbeat.replace(task)
        {
            previous.abort();
        }
    }

    /// Tear the connection down (`protocol.py:174-186`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket could not be shut down cleanly. Closing twice is safe.
    pub async fn close(&self) -> Result<()> {
        let (reply, response) = oneshot::channel();
        if self
            .requests
            .send(Request::Shutdown { reply })
            .await
            .is_err()
        {
            // The actor is already gone, which is the state the caller asked for.
            return Ok(());
        }
        if let Ok(mut heartbeat) = self.heartbeat.lock()
            && let Some(task) = heartbeat.take()
        {
            task.abort();
        }

        response.await.unwrap_or(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::{HEARTBEAT_INTERVAL, HEARTBEAT_RETRIES, MrpProtocolOptions, REQUEST_TIMEOUT};

    #[test]
    fn the_defaults_match_upstreams_constants() {
        assert_eq!(HEARTBEAT_INTERVAL.as_secs(), 30);
        assert_eq!(HEARTBEAT_RETRIES, 1);
        assert_eq!(REQUEST_TIMEOUT.as_secs(), 5);

        let options = MrpProtocolOptions::default();
        assert_eq!(options.heartbeat_interval, Some(HEARTBEAT_INTERVAL));
        assert_eq!(options.request_timeout, REQUEST_TIMEOUT);
    }

    /// The pairing identifier is a fresh uppercase UUID unless credentials supply one.
    #[test]
    fn a_default_pairing_id_is_generated() {
        let options = MrpProtocolOptions::default();
        assert_eq!(options.pairing_id.len(), 36);
        assert_eq!(options.pairing_id, options.pairing_id.to_uppercase());
    }
}
