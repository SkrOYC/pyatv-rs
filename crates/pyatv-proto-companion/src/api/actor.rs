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

use std::collections::VecDeque;
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

/// How many events one [`Actor::drain_events`] call handles before yielding.
///
/// The drain terminates on its own — no event handler touches the socket any more, so nothing can
/// refill the channel while it runs — but resting that guarantee on a property of every future
/// handler is how the previous version got into trouble. Anything left over is picked up by the
/// next pass, which follows immediately.
const MAX_EVENTS_PER_DRAIN: usize = 256;

/// How many drain/deferred rounds [`Actor::run`] performs before going back to the `select!`.
///
/// Deferred work talks to the device, so the device can answer it with another event, which queues
/// more deferred work, and so on for as long as it likes. Capping the rounds is what guarantees the
/// request channel is polled again promptly however the device behaves; anything still outstanding
/// is carried into the next iteration of the loop.
const MAX_DRAIN_PASSES: usize = 8;

/// Follow-up work an event handler asked for, run outside the drain.
///
/// `_handle_control_flag_update` answers an `_iMC` push by *sending a command of its own*
/// (`__init__.py:439-451`), and that command pumps the socket, which can surface another `_iMC`,
/// which sends another command. Doing that inline meant the drain loop could be kept spinning by
/// the device indefinitely, with the request channel never polled again — a device that attaches an
/// `_iMC` to every response starved every caller. Queuing the follow-up instead keeps each pass
/// through [`Actor::run`] bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Deferred {
    /// Read the volume back after an `_iMC` said it is controllable.
    ReadVolume,
}

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
    /// Follow-up commands the event handlers asked for, deduplicated.
    deferred: VecDeque<Deferred>,
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
            deferred: VecDeque::new(),
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

            // Handle what arrived, then whatever those handlers asked for, then anything that
            // arrived while *that* was happening — for a bounded number of rounds, after which the
            // loop returns to the `select!` so a queued request is served.
            for _ in 0..MAX_DRAIN_PASSES {
                self.drain_events();
                if !self.run_deferred().await {
                    break;
                }
            }
        }
    }

    /// Serve one request, reporting the outcome to whoever asked.
    ///
    /// A dropped `reply` receiver means the caller gave up waiting; the command still went out, so
    /// there is nothing to undo and the send result is discarded.
    ///
    /// [`Request::Shutdown`] is handled by [`Actor::run`] before it gets here, because it is the
    /// one request that ends the loop. Reaching it here would be a routing bug, and a live device
    /// session is not worth aborting the process over — the reply channel carries the complaint
    /// instead.
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
                let Some(content) = self.filter_interest(&identifier, content) else {
                    // Every registration in it was redundant, so there is nothing to send and
                    // nothing went wrong.
                    let _ = reply.send(Ok(()));
                    return;
                };
                let result = self.protocol.send_event(&identifier, content).await;
                let _ = reply.send(result);
            }
            Request::Shutdown { reply } => {
                tracing::error!("a shutdown request reached the request handler; ignoring it");
                let _ = reply.send(Err(Error::NotReady(
                    "shutdown is handled by the task loop, not by the request handler",
                )));
            }
        }
    }

    /// Drop the redundant half of an outgoing `_interest`, and keep the subscription list in step.
    ///
    /// pyatv guards both directions — `if event not in self._subscribed_events` before registering
    /// and `if event in self._subscribed_events` before deregistering (`api.py:267-277`) — so a
    /// second `subscribe_event` for the same name sends nothing at all. That guard was missing
    /// here, which meant `initialize_power` re-registering `SystemStatus` put a redundant frame on
    /// the wire every time.
    ///
    /// The list lives on the task rather than on the API object because the task is the one place
    /// that sees every send: a caller cannot subscribe behind its back and leave a registration
    /// dangling at shutdown.
    ///
    /// Returns `None` when nothing is left to send.
    fn filter_interest(&mut self, identifier: &str, content: Value) -> Option<Value> {
        if identifier != "_interest" {
            return Some(content);
        }

        let register: Vec<String> = names(&content, "_regEvents")
            .filter(|event| !self.subscribed.iter().any(|known| known == event))
            .collect();
        let deregister: Vec<String> = names(&content, "_deregEvents")
            .filter(|event| self.subscribed.iter().any(|known| known == event))
            .collect();

        // Anything the caller sent that is not one of the two event lists is passed through
        // untouched, so this cannot swallow a key the port does not model.
        let mut entries: Vec<(Value, Value)> = content
            .as_dict()
            .unwrap_or_default()
            .iter()
            .filter(|(key, _)| !matches!(key.as_str(), Some("_regEvents" | "_deregEvents")))
            .cloned()
            .collect();
        let passthrough = !entries.is_empty();

        if !register.is_empty() {
            entries.push((
                Value::from("_regEvents"),
                Value::array(register.iter().map(String::as_str)),
            ));
        }
        if !deregister.is_empty() {
            entries.push((
                Value::from("_deregEvents"),
                Value::array(deregister.iter().map(String::as_str)),
            ));
        }

        if register.is_empty() && deregister.is_empty() && !passthrough {
            tracing::debug!("every event in this _interest was already in that state; not sending");
            return None;
        }

        self.subscribed.extend(register);
        self.subscribed
            .retain(|known| !deregister.iter().any(|event| event == known));
        Some(Value::Dict(entries))
    }

    /// Handle every event that has arrived, up to [`MAX_EVENTS_PER_DRAIN`].
    ///
    /// Every handler is synchronous and touches nothing but [`ApiState`] and the deferred queue, so
    /// nothing can put an event into the channel while this is draining it and the loop is
    /// guaranteed to finish. That was not true when the `_iMC` handler issued its own `GetVolume`
    /// inline: the nested command pumped the socket, the device could answer with another `_iMC`,
    /// and the drain never returned.
    fn drain_events(&mut self) {
        for _ in 0..MAX_EVENTS_PER_DRAIN {
            let Ok(event) = self.events.try_recv() else {
                return;
            };
            self.handle_event(&event);
        }
        tracing::debug!("event backlog exceeded one drain; carrying the rest to the next pass");
    }

    /// Run one queued follow-up, reporting whether there was anything to run.
    ///
    /// One per call rather than the whole queue, so a device that keeps adding to it cannot keep
    /// [`Actor::run`] away from the request channel.
    async fn run_deferred(&mut self) -> bool {
        let Some(work) = self.deferred.pop_front() else {
            return false;
        };

        match work {
            Deferred::ReadVolume => match self.get_volume().await {
                Ok(volume) => self.state.set_volume(volume),
                Err(error) => tracing::debug!(%error, "could not read the volume back"),
            },
        }
        true
    }

    /// Queue a follow-up unless the same one is already waiting.
    ///
    /// Deduplicating matters: a burst of `_iMC` pushes must produce one `GetVolume`, not one per
    /// push.
    fn defer(&mut self, work: Deferred) {
        if !self.deferred.contains(&work) {
            self.deferred.push_back(work);
        }
    }

    /// Route one device-pushed event.
    fn handle_event(&mut self, event: &CompanionEvent) {
        match event.name.as_str() {
            MEDIA_CONTROL_EVENT => self.handle_control_flags(&event.content),
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
    /// and the level itself comes from a follow-up `GetVolume` — queued rather than sent from here,
    /// see [`Deferred`].
    fn handle_control_flags(&mut self, content: &Value) {
        let Some(flags) = content.get("_mcF").and_then(Value::as_u64) else {
            tracing::debug!("an _iMC event carried no _mcF");
            return;
        };
        self.state.set_control_flags(flags);

        if flags & media_control_flags::VOLUME == 0 {
            self.state.clear_volume();
            return;
        }

        self.defer(Deferred::ReadVolume);
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
    /// bother with that and just swallow the error".
    ///
    /// # Two deliberate divergences from `disconnect()`
    ///
    /// * **Every subscription is deregistered here; upstream deregisters roughly half.** Upstream
    ///   writes `for event in self._subscribed_events: await self.unsubscribe_event(event)`, and
    ///   `unsubscribe_event` calls `self._subscribed_events.remove(event)` — it mutates the list it
    ///   is iterating, so Python's index-based iteration skips the element that shifts into each
    ///   vacated slot. With the three names a normal session registers (`_iMC`, `SystemStatus`,
    ///   `TVSystemStatus`) upstream deregisters the first and the third and silently leaves the
    ///   second registered. `std::mem::take` takes the list first, so all three go out.
    /// * **The socket shutdown is reported; upstream's is not.** Upstream's `finally` calls the
    ///   infallible `self._protocol.stop()` and discards everything, so `disconnect()` cannot fail.
    ///   Here the four commands are still swallowed but a failure to close the socket reaches the
    ///   caller, because "the connection is gone" and "the connection is still open and I could not
    ///   close it" are worth telling apart.
    async fn shutdown(&mut self) -> Result<()> {
        // Nothing queued survives teardown: the session is going away, so a pending `GetVolume`
        // would only add a doomed round trip to it.
        self.deferred.clear();

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

/// The string entries of a named array inside an OPACK dict.
fn names<'a>(content: &'a Value, key: &str) -> impl Iterator<Item = String> + 'a {
    content
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
}
