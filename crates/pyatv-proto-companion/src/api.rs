//! The Companion command surface: `CompanionAPI`, one layer above the transport.
//!
//! Port of `pyatv/protocols/companion/api.py` (`docs/research/companion-port-spec.md` §3). Every
//! command pyatv can send has a method here, and each one cites the upstream line it came from.
//!
//! # Shape difference from upstream, and why
//!
//! pyatv's `CompanionAPI` is a plain object that calls `await self.connect()` at the top of every
//! send, so the connection is established lazily and re-established implicitly (`api.py:161-186`).
//! That works because its transport is a callback-driven `asyncio.Protocol` which is always
//! reading.
//!
//! Here the transport is an owned [`crate::protocol::CompanionProtocol`] with `&mut self` methods —
//! the shape that makes the pairing handshake a readable sequence of exchanges — so it is handed to
//! a background task ([`actor::Actor`]) and every method below becomes a message to that task. The
//! consequences are all improvements rather than compromises:
//!
//! * The socket is drained continuously, so `_iMC`, `SystemStatus` and `_tiStarted` pushes update
//!   [`state::ApiState`] as they arrive rather than only when a command happens to be in flight.
//! * Connecting is explicit ([`CompanionApi::connect`]) instead of implicit-on-first-use, so a
//!   caller learns about a refused pair-verify at connect time.
//! * Commands are serialised in submission order, which is what a `_hidC` down/up pair needs.

pub mod actor;
pub mod commands;
pub mod hid;
pub mod state;
pub mod text_input;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pyatv_core::facade::StateDispatcher;
use pyatv_core::interface::{DeviceListener, PowerListener};
use pyatv_opack::{Value, opack};
use pyatv_pairing::HapCredentials;
use tokio::sync::{mpsc, oneshot};

use crate::api::actor::{Actor, Request, SYSTEM_STATUS_EVENTS, Stopped};
use crate::api::commands::{MediaControlCommand, SystemStatus, is_url_or_scheme};
use crate::api::state::{ApiState, Observed, focus_from_payload};
use crate::message::Envelope;
use crate::pairing::verify;
use crate::session::{MEDIA_CONTROL_EVENT, SystemInfo, begin_session};
use crate::{Error, Result};

/// Delay between the two `_hidC` frames of a `click()` tap (`asyncio.sleep(0.02)`,
/// `api.py:382`).
pub(crate) const CLICK_TAP_DELAY: Duration = Duration::from_millis(20);

/// How long `click(Hold)` and `_press_button(Hold)` keep the button down (`api.py:389`,
/// `__init__.py:406`).
pub(crate) const HOLD_DELAY: Duration = Duration::from_secs(1);

/// Interval between interpolated `_hidT` frames during a swipe (`TOUCHPAD_DELAY_MS`,
/// `api.py:90`).
pub(crate) const TOUCHPAD_DELAY: Duration = Duration::from_millis(16);

/// The skip interval used when a caller does not name one (`_DEFAULT_SKIP_TIME`,
/// `__init__.py:82`).
pub const DEFAULT_SKIP_TIME: f32 = 10.0;

/// How long the audio facade waits for the device to confirm a volume change
/// (`asyncio.wait_for(..., timeout=5.0)`, `__init__.py:473`).
pub const VOLUME_TIMEOUT: Duration = Duration::from_secs(5);

/// How many requests may be queued before a caller has to wait for the task to catch up.
///
/// Not an upstream concept — pyatv has an unbounded queue per XID and leaks entries when a caller
/// cancels a wait (`docs/research/companion-port-spec.md` §12 finding 12). A bounded channel makes
/// backpressure explicit instead.
const REQUEST_QUEUE: usize = 32;

/// A connected Companion session.
#[derive(Debug)]
pub struct CompanionApi {
    peer: SocketAddr,
    requests: mpsc::Sender<Request>,
    state: Arc<ApiState>,
    /// `_touchStart`'s baseline; every `_hidT` reports `_ns` relative to it.
    touch_base: Instant,
    task: tokio::task::JoinHandle<Stopped>,
}

impl Drop for CompanionApi {
    /// Stop the background task if the caller dropped the API without closing it.
    ///
    /// Not a graceful teardown — that is [`CompanionApi::close`] — but it does stop the task from
    /// holding a socket open for the rest of the process's life.
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl CompanionApi {
    /// Connect, pair-verify, run the bring-up chain and start serving.
    ///
    /// `CompanionAPI.connect()` (`api.py:135-159`) plus the pair-verify its
    /// `CompanionProtocol.start()` performs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Connect`] if the device is unreachable, [`Error::Pairing`] if it refuses
    /// the credentials, and anything [`begin_session`] can return if a bring-up command fails.
    pub async fn connect(
        peer: SocketAddr,
        credentials: &HapCredentials,
        info: &SystemInfo,
        listener: Option<Arc<dyn DeviceListener>>,
        power_listener: Option<Arc<dyn PowerListener>>,
        state_dispatcher: Option<Arc<dyn StateDispatcher>>,
    ) -> Result<Self> {
        let (mut protocol, events) = verify(peer, credentials).await?;
        let session = begin_session(&mut protocol, info).await?;

        let state = Arc::new(ApiState::with_listeners(power_listener, state_dispatcher));
        // `_tiStart`'s response is upstream's initial focus signal; see `session::Session`.
        state.set_focus(focus_from_payload(&session.text_input));

        let (requests, receiver) = mpsc::channel(REQUEST_QUEUE);
        let actor = Actor::new(protocol, events, Arc::clone(&state), receiver, session.sid);

        let task = tokio::spawn(async move {
            let stopped = actor.run().await;
            if let (Stopped::ConnectionLost(error), Some(listener)) = (&stopped, listener) {
                listener.connection_lost(&error.to_string());
            }
            stopped
        });

        Ok(Self {
            peer,
            requests,
            state,
            touch_base: session.touch_base,
            task,
        })
    }

    /// The address this session is connected to.
    #[must_use]
    pub const fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Everything the device has reported asynchronously so far.
    #[must_use]
    pub fn observed(&self) -> Observed {
        self.state.observed()
    }

    /// The shared state, for facades that need to await a change rather than read one.
    #[must_use]
    pub fn state(&self) -> &Arc<ApiState> {
        &self.state
    }

    /// Send a request and wait for the device's response.
    ///
    /// `_send_command` (`api.py:161-186`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the session has already stopped, [`Error::Timeout`] if the
    /// device does not answer, and [`Error::Rejected`] if it answers with an `_em`.
    pub async fn send_command(&self, identifier: &str, content: Value) -> Result<Envelope> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Request::Command {
                identifier: identifier.to_owned(),
                content,
                reply,
            })
            .await
            .map_err(|_| Error::Closed { partial: false })?;

        response
            .await
            .map_err(|_| Error::Closed { partial: false })?
    }

    /// Send a fire-and-forget event, which the device never answers.
    ///
    /// `_send_event` (`api.py:247-265`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the session has already stopped, or an I/O failure from the
    /// socket write.
    pub async fn send_event(&self, identifier: &str, content: Value) -> Result<()> {
        let (reply, response) = oneshot::channel();
        self.requests
            .send(Request::Event {
                identifier: identifier.to_owned(),
                content,
                reply,
            })
            .await
            .map_err(|_| Error::Closed { partial: false })?;

        response
            .await
            .map_err(|_| Error::Closed { partial: false })?
    }

    /// Ask the device to start pushing an event.
    ///
    /// `subscribe_event` (`api.py:267-271`). The registration is tracked by the background task,
    /// which deregisters everything on [`CompanionApi::close`].
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_event`].
    pub async fn subscribe_event(&self, event: &str) -> Result<()> {
        self.send_event(
            "_interest",
            opack! { "_regEvents" => Value::array([event]) },
        )
        .await
    }

    /// Tear the session down: deregister events, stop the session, touch and text-input.
    ///
    /// `disconnect()` (`api.py:109-128`). Every step but the socket shutdown is best-effort.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket could not be shut down. A session that has already
    /// stopped reports success, so closing twice is safe.
    pub async fn close(&self) -> Result<()> {
        let (reply, response) = oneshot::channel();
        if self
            .requests
            .send(Request::Shutdown { reply })
            .await
            .is_err()
        {
            // The task is already gone, which is the state the caller asked for.
            return Ok(());
        }

        response.await.unwrap_or(Ok(()))
    }

    // ---- Apps and accounts (`api.py:279-303`) ----

    /// `FetchLaunchableApplicationsEvent`, whose response content is a flat
    /// `{bundle_id: display_name}` dict.
    ///
    /// Despite the `Event` suffix in the identifier it is an ordinary request; the name is Apple's
    /// convention leaking into the wire string.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn app_list(&self) -> Result<Envelope> {
        self.send_command("FetchLaunchableApplicationsEvent", opack! {})
            .await
    }

    /// `_launchApp`, keyed `_urlS` for anything with a URL scheme and `_bundleID` otherwise.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn launch_app(&self, bundle_id_or_url: &str) -> Result<()> {
        let key = if is_url_or_scheme(bundle_id_or_url) {
            "_urlS"
        } else {
            "_bundleID"
        };

        self.send_command("_launchApp", Value::dict([(key, bundle_id_or_url)]))
            .await
            .map(|_| ())
    }

    /// `FetchUserAccountsEvent`, a flat `{account_id: display_name}` dict.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn account_list(&self) -> Result<Envelope> {
        self.send_command("FetchUserAccountsEvent", opack! {}).await
    }

    /// `SwitchUserAccountEvent`.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn switch_account(&self, account_id: &str) -> Result<()> {
        self.send_command(
            "SwitchUserAccountEvent",
            opack! { "SwitchAccountID" => account_id },
        )
        .await
        .map(|_| ())
    }

    // ---- HID, in [`hid`] ----

    // ---- Media control (`api.py:395-399`) ----

    /// `_mcc` with no arguments.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn mediacontrol_command(&self, command: MediaControlCommand) -> Result<Envelope> {
        self.mediacontrol_command_with(command, Vec::new()).await
    }

    /// `_mcc` with extra content keys.
    ///
    /// The command's own number is nested inside the content dict under the same `_mcc` key as the
    /// outer identifier — a same-name-different-scope collision worth not "tidying up".
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn mediacontrol_command_with(
        &self,
        command: MediaControlCommand,
        extra: Vec<(Value, Value)>,
    ) -> Result<Envelope> {
        let mut entries = vec![(Value::from("_mcc"), Value::from(command.code()))];
        entries.extend(extra);
        self.send_command("_mcc", Value::Dict(entries)).await
    }

    /// `_mcc` `SkipBy`, seconds under `_skpS`.
    ///
    /// Always a float, never an integer. pyatv's comment reads "float cast: opack fails with
    /// negative integers" (`__init__.py:372`), and this port's OPACK encoder genuinely has no
    /// signed integer encoding either — [`pyatv_opack::Value`] has no signed variant at all —
    /// so the workaround is a requirement here rather than an inherited quirk.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn skip_by(&self, seconds: f32) -> Result<()> {
        self.mediacontrol_command_with(
            MediaControlCommand::SkipBy,
            vec![(Value::from("_skpS"), Value::from(f64::from(seconds)))],
        )
        .await
        .map(|_| ())
    }

    /// `_mcc` `SetVolume`, as a `0.0..=1.0` fraction under `_vol`.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn set_volume(&self, percent: f32) -> Result<()> {
        self.mediacontrol_command_with(
            MediaControlCommand::SetVolume,
            vec![(
                Value::from("_vol"),
                Value::from(f64::from(percent) / 100.0_f64),
            )],
        )
        .await
        .map(|_| ())
    }

    // ---- Power (`api.py:454-462`, `__init__.py:219-292`) ----

    /// `FetchAttentionState`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rejected`] on newer tvOS, which answers "No request handler" — the caller
    /// must treat that as non-fatal, exactly as `CompanionPower.initialize` does.
    pub async fn fetch_attention_state(&self) -> Result<SystemStatus> {
        let response = self.send_command("FetchAttentionState", opack! {}).await?;
        response
            .content
            .get("state")
            .and_then(Value::as_u64)
            .and_then(SystemStatus::from_code)
            .ok_or_else(|| Error::Envelope("FetchAttentionState returned no state".to_owned()))
    }

    /// Seed the power state and subscribe to live updates.
    ///
    /// `CompanionPower.initialize` (`__init__.py:219-246`). The initial fetch failing must not stop
    /// the subscriptions: newer tvOS refuses `FetchAttentionState` outright, and the pushed
    /// `SystemStatus`/`TVSystemStatus` events are the only way power state ever becomes known on
    /// those devices. Both event names are subscribed because pyatv does not know which one a given
    /// tvOS version pushes.
    ///
    /// # Errors
    ///
    /// Never fails: both halves are best-effort by design. The signature stays fallible-free so
    /// callers cannot accidentally treat a refused `FetchAttentionState` as a connect failure.
    pub async fn initialize_power(&self) {
        match self.fetch_attention_state().await {
            Ok(status) => self.state.set_power(status.to_power_state()),
            Err(error) => tracing::debug!(%error, "could not fetch the initial SystemStatus"),
        }

        for event in SYSTEM_STATUS_EVENTS {
            if let Err(error) = self.subscribe_event(event).await {
                tracing::debug!(event, %error, "could not subscribe to SystemStatus updates");
            }
        }
    }

    /// The media-control event bring-up already subscribed to, for callers that want to re-arm it.
    #[must_use]
    pub const fn media_control_event() -> &'static str {
        MEDIA_CONTROL_EVENT
    }

    // ---- Text input, in [`text_input`] ----

    /// `_tiStart`, returning the response content.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn text_input_start(&self) -> Result<Value> {
        let response = self.send_command("_tiStart", opack! {}).await?;
        self.state.set_focus(focus_from_payload(&response.content));
        Ok(response.content)
    }

    /// `_tiStop`.
    ///
    /// # Errors
    ///
    /// As [`CompanionApi::send_command`].
    pub async fn text_input_stop(&self) -> Result<()> {
        self.send_command("_tiStop", opack! {}).await.map(|_| ())
    }
}
