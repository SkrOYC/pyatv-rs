//! The background task that owns the connection.
//!
//! pyatv's Companion client is callback-driven: `asyncio.Protocol.data_received` runs forever, so
//! device-pushed events land whether or not a command is in flight (`connection.py:141-168`). This
//! port's [`CompanionProtocol`] instead has one owner and `&mut self` methods, which is what makes
//! the pairing handshake readable as a sequence of exchanges — so the always-reading half has to be
//! put back explicitly. That is this task.
//!
//! It owns the protocol outright, serves command and event requests from an `mpsc` channel, and
//! reads the socket whenever no request is pending. The `select!` is **biased** towards the request
//! channel on purpose: `tokio::select!` polls branches in order and stops at the first ready one,
//! so a pending request can never cause an already-buffered frame to be read and then dropped —
//! [`CompanionProtocol::poll_once`] is simply not polled that round, and the bytes stay in the
//! codec's buffer for the next.

use std::sync::Arc;

use pyatv_opack::{Value, opack};
use tokio::sync::{mpsc, oneshot};

use crate::api::commands::{MediaControlCommand, SystemStatus};
use crate::api::state::{ApiState, focus_from_payload, media_control_flags};
use crate::message::Envelope;
use crate::protocol::{CompanionEvent, CompanionProtocol, EventStream};
use crate::session::{MEDIA_CONTROL_EVENT, SERVICE_TYPE};
use crate::{Error, Result};

/// Event names the power facade subscribes to.
///
/// pyatv subscribes to **both** and wires them to one handler (`__init__.py:239-246`), because it
/// does not know which name a given tvOS version pushes.
pub const SYSTEM_STATUS_EVENTS: [&str; 2] = ["SystemStatus", "TVSystemStatus"];

/// What a facade asks the task to do.
#[derive(Debug)]
pub enum Request {
    /// Send a request and wait for its response.
    Command {
        /// The `_i` identifier.
        identifier: String,
        /// The `_c` content.
        content: Value,
        /// Where the response goes.
        reply: oneshot::Sender<Result<Envelope>>,
    },
    /// Send a fire-and-forget event.
    Event {
        /// The `_i` identifier.
        identifier: String,
        /// The `_c` content.
        content: Value,
        /// Where the send result goes.
        reply: oneshot::Sender<Result<()>>,
    },
    /// Run the teardown chain and stop.
    Shutdown {
        /// Where the teardown result goes.
        reply: oneshot::Sender<Result<()>>,
    },
}

/// Owns one Companion connection for the lifetime of a session.
#[derive(Debug)]
pub struct Actor {
    protocol: CompanionProtocol,
    events: EventStream,
    state: Arc<ApiState>,
    requests: mpsc::Receiver<Request>,
    /// The composite session id `_sessionStop` has to quote back.
    sid: u64,
    /// Event names `_interest` has registered, deregistered on shutdown in the order pyatv walks
    /// its own `_subscribed_events` list (`api.py:114-116`).
    subscribed: Vec<String>,
}

/// Why the task stopped, so the caller can tell a clean close from a dropped connection.
#[derive(Debug)]
pub enum Stopped {
    /// [`Request::Shutdown`] was served.
    OnRequest,
    /// Every handle to the request channel was dropped.
    Abandoned,
    /// The connection failed.
    ConnectionLost(Error),
}

impl Actor {
    /// Wrap a connected, session-started protocol.
    #[must_use]
    pub fn new(
        protocol: CompanionProtocol,
        events: EventStream,
        state: Arc<ApiState>,
        requests: mpsc::Receiver<Request>,
        sid: u64,
    ) -> Self {
        Self {
            protocol,
            events,
            state,
            requests,
            sid,
            subscribed: vec![MEDIA_CONTROL_EVENT.to_owned()],
        }
    }

    /// Serve requests and drain the socket until one of them ends the session.
    pub async fn run(mut self) -> Stopped {
        loop {
            let outcome = tokio::select! {
                biased;

                request = self.requests.recv() => match request {
                    Some(Request::Shutdown { reply }) => {
                        let _ = reply.send(self.shutdown().await);
                        return Stopped::OnRequest;
                    }
                    Some(request) => {
                        self.serve(request).await;
                        Ok(())
                    }
                    None => return Stopped::Abandoned,
                },

                result = self.protocol.poll_once() => result,
            };

            if let Err(error) = outcome {
                tracing::debug!(%error, "the Companion connection went away");
                return Stopped::ConnectionLost(error);
            }

            self.drain_events().await;
        }
    }

    /// Serve one request, reporting the outcome to whoever asked.
    ///
    /// A dropped `reply` receiver means the caller gave up waiting; the command still went out, so
    /// there is nothing to undo and the send result is discarded.
    async fn serve(&mut self, request: Request) {
        match request {
            Request::Command {
                identifier,
                content,
                reply,
            } => {
                let result = self.protocol.send_command(&identifier, content).await;
                let _ = reply.send(result);
            }
            Request::Event {
                identifier,
                content,
                reply,
            } => {
                self.remember_interest(&identifier, &content);
                let result = self.protocol.send_event(&identifier, content).await;
                let _ = reply.send(result);
            }
            Request::Shutdown { .. } => unreachable!("handled by the caller"),
        }
    }

    /// Keep the subscription list in step with the `_interest` events going out.
    ///
    /// pyatv maintains the same list on the API object rather than the transport
    /// (`_subscribed_events`, `api.py:267-277`); reading it off the wire here keeps the one
    /// authority in the one place that sees every send, so a caller cannot subscribe behind the
    /// task's back and leave a registration dangling at shutdown.
    fn remember_interest(&mut self, identifier: &str, content: &Value) {
        if identifier != "_interest" {
            return;
        }

        if let Some(events) = content.get("_regEvents").and_then(Value::as_array) {
            for event in events.iter().filter_map(Value::as_str) {
                if !self.subscribed.iter().any(|known| known == event) {
                    self.subscribed.push(event.to_owned());
                }
            }
        }
        if let Some(events) = content.get("_deregEvents").and_then(Value::as_array) {
            self.subscribed
                .retain(|known| !events.iter().any(|event| event.as_str() == Some(known)));
        }
    }

    /// Handle every event that has arrived, including ones that arrive while handling one.
    ///
    /// Two subtleties, both of which cost a stranded event if missed:
    ///
    /// * Events are **collected before being handled**, so the borrow on `self.events` is released
    ///   before a handler needs `&mut self.protocol` — `_iMC` answers by issuing a `GetVolume`
    ///   command of its own.
    /// * That nested command pumps the socket itself, so any event the device sent alongside the
    ///   response lands in the channel *during* the handler. The outer loop is what picks it up:
    ///   without it, a `SystemStatus` pushed next to an `_iMC` would sit unread until the device
    ///   happened to send another frame.
    async fn drain_events(&mut self) {
        loop {
            let mut pending = Vec::new();
            while let Ok(event) = self.events.try_recv() {
                pending.push(event);
            }
            if pending.is_empty() {
                return;
            }

            for event in pending {
                self.handle_event(event).await;
            }
        }
    }

    /// Route one device-pushed event.
    async fn handle_event(&mut self, event: CompanionEvent) {
        match event.name.as_str() {
            MEDIA_CONTROL_EVENT => self.handle_control_flags(&event.content).await,
            name if SYSTEM_STATUS_EVENTS.contains(&name) => {
                self.handle_system_status(&event.content);
            }
            "_tiStarted" | "_tiStopped" => {
                self.state.set_focus(focus_from_payload(&event.content));
            }
            other => tracing::debug!(event = other, "no handler for this Companion event"),
        }
    }

    /// `_handle_control_flag_update` (`__init__.py:439-451`), which both `CompanionAudio` and
    /// `CompanionFeatures` register for.
    ///
    /// The volume level is **not** read off the push: the flag only says volume is controllable,
    /// and the level itself comes from a follow-up `GetVolume`.
    async fn handle_control_flags(&mut self, content: &Value) {
        let Some(flags) = content.get("_mcF").and_then(Value::as_u64) else {
            tracing::debug!("an _iMC event carried no _mcF");
            return;
        };
        self.state.set_control_flags(flags);

        if flags & media_control_flags::VOLUME == 0 {
            self.state.clear_volume();
            return;
        }

        match self.get_volume().await {
            Ok(volume) => self.state.set_volume(volume),
            Err(error) => tracing::debug!(%error, "could not read the volume back"),
        }
    }

    /// `_mcc` `GetVolume`, whose response carries a `0.0..=1.0` fraction under `_vol`.
    async fn get_volume(&mut self) -> Result<f32> {
        let response = self
            .protocol
            .send_command(
                "_mcc",
                opack! { "_mcc" => MediaControlCommand::GetVolume.code() },
            )
            .await?;

        let volume = response
            .content
            .get("_vol")
            .and_then(Value::as_f64)
            .ok_or_else(|| Error::Envelope("GetVolume returned no _vol".to_owned()))?;

        // Percent, as `resp["_c"]["_vol"] * 100.0` (`__init__.py:444`).
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the public Audio API is f32; a volume percentage loses nothing at f32"
        )]
        Ok((volume * 100.0) as f32)
    }

    /// `_handle_system_status_update` (`__init__.py:253-261`).
    ///
    /// A `state` outside `0x01..=0x04` is logged and dropped. Upstream's `SystemStatus(int(...))`
    /// raises `ValueError`, caught by its own `except Exception` — the same net effect.
    fn handle_system_status(&self, content: &Value) {
        let status = content
            .get("state")
            .and_then(Value::as_u64)
            .and_then(SystemStatus::from_code);

        if let Some(status) = status {
            self.state.set_power(status.to_power_state());
        } else {
            tracing::debug!(?content, "a SystemStatus event carried no usable state");
        }
    }

    /// The teardown chain, `disconnect()` (`api.py:109-128`).
    ///
    /// Every step is best-effort: upstream wraps the lot in one `try/except Exception` whose
    /// comment reads "Sometimes unsubscribe fails for an unknown reason, but we are not going to
    /// bother with that and just swallow the error". Only the socket shutdown is reported.
    async fn shutdown(&mut self) -> Result<()> {
        for event in std::mem::take(&mut self.subscribed) {
            self.best_effort_event(
                "_interest",
                opack! { "_deregEvents" => Value::array([event.as_str()]) },
            )
            .await;
        }

        self.best_effort_command(
            "_sessionStop",
            opack! { "_srvT" => SERVICE_TYPE, "_sid" => self.sid },
        )
        .await;
        self.best_effort_command("_touchStop", opack! { "_i" => 1u64 })
            .await;
        self.best_effort_command("_tiStop", opack! {}).await;

        self.protocol.close().await
    }

    async fn best_effort_command(&mut self, identifier: &str, content: Value) {
        if let Err(error) = self.protocol.send_command(identifier, content).await {
            tracing::debug!(identifier, %error, "ignoring an error during disconnect");
        }
    }

    async fn best_effort_event(&mut self, identifier: &str, content: Value) {
        if let Err(error) = self.protocol.send_event(identifier, content).await {
            tracing::debug!(identifier, %error, "ignoring an error during disconnect");
        }
    }
}
