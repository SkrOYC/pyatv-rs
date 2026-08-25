//! The AirPlay 2 remote-control session: control connection, pair-verify, both side channels and
//! the two-second keepalive.
//!
//! Port of `AP2Session` (`pyatv/protocols/airplay/ap2_session.py:40-201`). One TCP connection to
//! the AirPlay service's own port carries pairing, both `SETUP`s, `RECORD` and every `/feedback`;
//! only its encryption state changes mid-stream, when [`crate::auth::verify_connection`] splices a
//! [`pyatv_pairing::session::HapSession`] in behind the HTTP parser.
//!
//! # Order of operations
//!
//! 1. `POST /pair-verify` M1–M4, then `Control-Salt` keys and encryption on
//!    (`ap2_session.py:62-73`).
//! 2. Event-channel `SETUP`, then dial `eventPort` (`ap2_session.py:115-149`).
//! 3. `RECORD` — **unless the receiver answered `skipRecord: true`**, see below
//!    (`ap2_session.py:81`).
//! 4. Data-stream `SETUP`, then dial `dataPort` (`ap2_session.py:151-187`).
//! 5. `POST /feedback` every two seconds for as long as the tunnel is wanted
//!    (`ap2_session.py:84-108`).
//!
//! # Divergence: `skipRecord`
//!
//! Upstream sends `RECORD` unconditionally. The tvOS 27 test device answers the event-channel
//! `SETUP` with `skipRecord: true`, a key that appears nowhere in pyatv, and the only thing there
//! is to skip at that point in the sequence is that `RECORD`
//! (`docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` experiment 4). This port honours
//! it and sends `RECORD` whenever the key is absent, which is what upstream always does — so on a
//! receiver that does not send the key the two behave identically.
//!
//! That experiment left open whether omitting `RECORD` breaks anything downstream. A live run of
//! `examples/airplay_tunnel_probe` against the same device on 2026-08-24 answers it: with `RECORD`
//! withheld, the data-stream `SETUP` was still answered `200` with a `dataPort`, and that socket
//! accepted the HAP handshake and stayed open under a two-second `/feedback` keepalive. Skipping is
//! safe on this device class; whether *sending* it anyway would have been is still untested.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pyatv_core::interface::DeviceListener;
use pyatv_pairing::HapCredentials;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::Result;
use crate::ap2::data_stream::{
    self, DataStreamChannel, DataStreamRequest, DataStreamSetup, SeqnoPolicy,
};
use crate::ap2::event_channel::{self, EventChannel};
use crate::ap2::{EventChannelSetup, InfoSettings, random_uuid, remote_control_setup_body};
use crate::auth::{PairVerifyProcedure, verify_connection};
use crate::http::HttpConnection;
use crate::rtsp::RtspSession;

/// How often the control connection is kept alive.
///
/// `FEEDBACK_INTERVAL = 2.0` with the source comment "This is what iOS uses"
/// (`ap2_session.py:28-29`). Receivers drop a tunnel after roughly thirty seconds without one, so
/// this is not a cadence to relax independently.
pub const FEEDBACK_INTERVAL: Duration = Duration::from_secs(2);

/// Extra attempts per keepalive period before the connection is declared lost.
///
/// `HEARTBEAT_RETRIES = 1` (`pyatv/core/protocol.py:21`): one ordinary attempt plus one immediate
/// retry with no sleep in between, then `failure_func`.
pub const FEEDBACK_RETRIES: u32 = 1;

/// The ports a receiver handed out during remote-control setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteControlPorts {
    /// The event channel's port, and whether the receiver asked for `RECORD` to be skipped.
    pub event: EventChannelSetupPorts,
    /// `streams[0].dataPort`.
    pub data_port: u16,
    /// The seed that salted the data channel's keys.
    pub seed: u64,
}

/// The scalar part of an event-channel `SETUP` reply, kept `Copy` for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EventChannelSetupPorts {
    /// `eventPort`.
    pub port: u16,
    /// `timingPort`, absent on tvOS 27.
    pub timing_port: Option<u16>,
    /// `skipRecord`, absent from pyatv entirely.
    pub skip_record: Option<bool>,
}

impl From<&EventChannelSetup> for EventChannelSetupPorts {
    fn from(setup: &EventChannelSetup) -> Self {
        Self {
            port: setup.event_port,
            timing_port: setup.timing_port,
            skip_record: setup.skip_record,
        }
    }
}

/// The control connection and the RTSP state that rides on it.
///
/// Kept behind one lock so the keepalive task and a caller driving setup cannot interleave two
/// requests on a connection that answers strictly one at a time.
#[derive(Debug)]
struct Control {
    http: HttpConnection,
    rtsp: RtspSession,
}

/// A live AirPlay 2 remote-control session.
#[derive(Debug)]
pub struct Ap2Session {
    control: Arc<Mutex<Control>>,
    address: SocketAddr,
    info: InfoSettings,
    verifier: PairVerifyProcedure,
    ports: Option<RemoteControlPorts>,
    /// The event-channel `SETUP` reply exactly as the receiver sent it, kept for diagnostics: the
    /// typed [`EventChannelSetup`] only names the three keys this port knows about, and a receiver
    /// that starts sending a fourth would otherwise be invisible.
    event_reply: Option<plist::Value>,
    /// The data-stream `SETUP` reply, kept for the same reason.
    data_reply: Option<plist::Value>,
    event: Option<EventChannel>,
    data: Option<Arc<DataStreamChannel>>,
    keepalive: Option<JoinHandle<()>>,
}

impl Drop for Ap2Session {
    fn drop(&mut self) {
        if let Some(keepalive) = self.keepalive.take() {
            keepalive.abort();
        }
    }
}

impl Ap2Session {
    /// Open the control connection and complete pair-verify.
    ///
    /// `AP2Session.connect` (`ap2_session.py:62-73`). `port` is the **AirPlay service's own port**
    /// from its SRV record — 7000 on current hardware — not a separately advertised one.
    ///
    /// Any HAP pairing registered on the device is accepted here, whichever protocol created it;
    /// see [`crate::setup::tunnel_credentials`] for why that matters.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the device is unreachable, [`crate::Error::NotAuthenticated`] if it
    /// rejects the credentials, and [`crate::Error::Pairing`] if a proof or signature does not verify.
    pub async fn connect(
        address: IpAddr,
        port: u16,
        credentials: &HapCredentials,
        info: InfoSettings,
    ) -> Result<Self> {
        let address = SocketAddr::new(address, port);
        tracing::debug!(%address, "setting up AirPlay remote connection");

        let mut http = HttpConnection::connect(address).await?;
        let verifier = verify_connection(credentials, &mut http).await?;

        Ok(Self {
            control: Arc::new(Mutex::new(Control {
                http,
                rtsp: RtspSession::new(),
            })),
            address,
            info,
            verifier,
            ports: None,
            event_reply: None,
            data_reply: None,
            event: None,
            data: None,
            keepalive: None,
        })
    }

    /// The control connection's address.
    #[must_use]
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The ports negotiated by [`Ap2Session::setup_remote_control`], once it has run.
    #[must_use]
    pub fn ports(&self) -> Option<RemoteControlPorts> {
        self.ports
    }

    /// The event-channel `SETUP` reply verbatim, once it has arrived.
    #[must_use]
    pub fn event_setup_reply(&self) -> Option<&plist::Value> {
        self.event_reply.as_ref()
    }

    /// The data-stream `SETUP` reply verbatim, once it has arrived.
    #[must_use]
    pub fn data_setup_reply(&self) -> Option<&plist::Value> {
        self.data_reply.as_ref()
    }

    /// The event channel, once it is up.
    #[must_use]
    pub fn event_channel(&self) -> Option<&EventChannel> {
        self.event.as_ref()
    }

    /// The data channel, once it is up.
    #[must_use]
    pub fn data_channel(&self) -> Option<Arc<DataStreamChannel>> {
        self.data.clone()
    }

    /// Bring up both side channels and return the one that carries MRP.
    ///
    /// `AP2Session.setup_remote_control` (`ap2_session.py:75-82`), with the `RECORD` made
    /// conditional on `skipRecord` as described in this module's header.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] if the receiver refuses a `SETUP` or the `RECORD`,
    /// [`crate::Error::Plist`] if a reply does not carry the port it must, and [`crate::Error::Io`] if either
    /// channel's socket cannot be opened.
    pub async fn setup_remote_control(
        &mut self,
        policy: SeqnoPolicy,
    ) -> Result<Arc<DataStreamChannel>> {
        let event = self.setup_event_channel().await?;

        if event.should_record() {
            tracing::debug!(address = %self.address, "sending RECORD");
            let mut control = self.control.lock().await;
            let Control { http, rtsp } = &mut *control;
            rtsp.record(http).await?;
        } else {
            tracing::debug!(
                address = %self.address,
                "receiver asked for RECORD to be skipped"
            );
        }

        let (data, request) = self.setup_data_channel(policy).await?;

        self.ports = Some(RemoteControlPorts {
            event: EventChannelSetupPorts::from(&event),
            data_port: data.address().port(),
            seed: request.seed,
        });
        self.data = Some(Arc::clone(&data));

        Ok(data)
    }

    /// `SETUP` the event channel and dial it.
    async fn setup_event_channel(&mut self) -> Result<EventChannelSetup> {
        let body = remote_control_setup_body(&self.info, &random_uuid());

        let reply = {
            let mut control = self.control.lock().await;
            let Control { http, rtsp } = &mut *control;
            rtsp.setup(http, &body).await?
        };
        let setup = EventChannelSetup::from_plist(&reply)?;
        self.event_reply = Some(reply);
        tracing::debug!(
            address = %self.address,
            port = setup.event_port,
            timing_port = ?setup.timing_port,
            skip_record = ?setup.skip_record,
            "event channel negotiated"
        );

        let keys = event_channel::event_channel_keys(&self.verifier)?;
        self.event = Some(
            EventChannel::connect(SocketAddr::new(self.address.ip(), setup.event_port), &keys)
                .await?,
        );

        Ok(setup)
    }

    /// `SETUP` the data channel and dial it.
    async fn setup_data_channel(
        &mut self,
        policy: SeqnoPolicy,
    ) -> Result<(Arc<DataStreamChannel>, DataStreamRequest)> {
        let request = DataStreamRequest::new();

        let reply = {
            let mut control = self.control.lock().await;
            let Control { http, rtsp } = &mut *control;
            rtsp.setup(http, &request.body()).await?
        };
        let setup = DataStreamSetup::from_plist(&reply)?;
        self.data_reply = Some(reply);
        tracing::debug!(
            address = %self.address,
            port = setup.data_port,
            "data channel negotiated"
        );

        let keys = data_stream::data_stream_keys(&self.verifier, request.seed)?;
        let channel = DataStreamChannel::connect(
            SocketAddr::new(self.address.ip(), setup.data_port),
            &keys,
            policy,
        )
        .await?;

        Ok((Arc::new(channel), request))
    }

    /// Start posting `/feedback` every [`FEEDBACK_INTERVAL`].
    ///
    /// `AP2Session.start_keep_alive` (`ap2_session.py:84-108`) driven by the shared `heartbeater`
    /// loop (`pyatv/core/protocol.py:35-76`): sleep, send, and on failure retry immediately without
    /// sleeping up to [`FEEDBACK_RETRIES`] extra times before reporting the connection lost and
    /// stopping. Losing this is fatal to the tunnel, so `listener` — when given — is told.
    ///
    /// Calling it twice replaces the running task.
    pub fn start_keep_alive(&mut self, listener: Option<Arc<dyn DeviceListener>>) {
        if let Some(previous) = self.keepalive.take() {
            previous.abort();
        }

        let control = Arc::clone(&self.control);
        let address = self.address;

        self.keepalive = Some(tokio::spawn(async move {
            keep_alive(control, address, listener).await;
        }));
    }

    /// Stop the keepalive without closing anything else.
    pub fn stop_keep_alive(&mut self) {
        if let Some(keepalive) = self.keepalive.take() {
            keepalive.abort();
        }
    }

    /// Close the keepalive, both side channels and the control connection.
    ///
    /// `AP2Session.stop` (`ap2_session.py:189-201`). No RTSP `TEARDOWN` is sent: upstream has the
    /// verb but never calls it from this session, and the tunnel is torn down purely by closing
    /// sockets.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the control socket could not be shut down cleanly. Both channels
    /// are stopped regardless.
    pub async fn close(&mut self) -> Result<()> {
        self.stop_keep_alive();

        if let Some(data) = self.data.take() {
            data.close();
        }
        if let Some(event) = self.event.take() {
            event.close();
        }

        self.control.lock().await.http.close().await
    }
}

/// The keepalive loop.
async fn keep_alive(
    control: Arc<Mutex<Control>>,
    address: SocketAddr,
    listener: Option<Arc<dyn DeviceListener>>,
) {
    tracing::debug!(%address, "starting AirPlay feedback loop");
    let mut attempts = 0u32;

    loop {
        // Re-attempts carry no delay, so a recoverable blip recovers within the same period.
        if attempts == 0 {
            tokio::time::sleep(FEEDBACK_INTERVAL).await;
        }

        let outcome = {
            let mut control = control.lock().await;
            let Control { http, rtsp } = &mut *control;
            rtsp.feedback(http, false).await
        };

        match outcome {
            Ok(_) => attempts = 0,
            Err(error) => {
                attempts += 1;
                if attempts > FEEDBACK_RETRIES {
                    tracing::debug!(%address, %error, "AirPlay feedback failed, connection lost");
                    if let Some(listener) = listener.as_ref() {
                        listener.connection_lost(&error.to_string());
                    }
                    return;
                }
                tracing::debug!(%address, %error, "AirPlay feedback failed, retrying");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EventChannelSetupPorts, FEEDBACK_INTERVAL, FEEDBACK_RETRIES};
    use crate::ap2::EventChannelSetup;

    /// `FEEDBACK_INTERVAL = 2.0` and `HEARTBEAT_RETRIES = 1`, verbatim.
    #[test]
    fn the_keepalive_constants_match_upstream() {
        assert_eq!(FEEDBACK_INTERVAL.as_secs(), 2);
        assert_eq!(FEEDBACK_RETRIES, 1);
    }

    #[test]
    fn the_reported_ports_carry_every_key_the_reply_had() {
        let setup = EventChannelSetup {
            event_port: 49_191,
            timing_port: None,
            skip_record: Some(true),
        };

        assert_eq!(
            EventChannelSetupPorts::from(&setup),
            EventChannelSetupPorts {
                port: 49_191,
                timing_port: None,
                skip_record: Some(true),
            }
        );
    }
}
