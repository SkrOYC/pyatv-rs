//! The `AirPlay` 2 half of `play_url`.
//!
//! Port of `AirPlayV2.play_url` and the `_setup_base`/`start_feedback` it opens with
//! (`pyatv/protocols/raop/protocols/airplayv2.py:51-105,167-181,210-273`), specified in
//! `docs/research/airplay-playurl-raop-port-spec.md` §2.3.
//!
//! The sequence is: pair-verify, base `SETUP`, dial the event channel, start the two-second
//! `/feedback` loop, `RECORD`, `POST /play`, then five fire-and-forget property calls.

use std::net::SocketAddr;

use pyatv_pairing::HapCredentials;
use tokio::task::JoinHandle;

use crate::ap2::event_channel::{EventChannel, event_channel_keys};
use crate::ap2::{EventChannelSetup, random_uuid};
use crate::auth::PairVerifyProcedure;
use crate::codec::Response;
use crate::http::RequestSpec;
use crate::rtsp::{encode_plist, method};
use crate::stream::bodies;
use crate::stream::control::PlayControl;
use crate::{Error, Result, stream::PlayTiming};

/// How many times the event channel is dialled before giving up (`airplayv2.py:84`).
///
/// Upstream's comment blames `airplay2-receiver`, which answers the `SETUP` with a port it has not
/// finished binding. A real receiver answers on the first attempt.
const EVENT_CHANNEL_RETRIES: u32 = 5;

/// One `AirPlay` 2 play session's protocol state.
#[derive(Debug)]
pub struct AirPlayV2 {
    control: PlayControl,
    timing: PlayTiming,
    /// `self.uuid = str(uuid4())` — per instance, lowercase (`airplayv2.py:49`).
    uuid: String,
    /// The completed pair-verify, kept for the same reason `self._verifier` is upstream
    /// (`airplayv2.py:45`): it is the only handle on the session's shared secret, and every further
    /// channel is keyed from it. `play_url` needs no further channel, so nothing here reads it
    /// after the event channel is up — see [`AirPlayV2::verifier`].
    verifier: Option<PairVerifyProcedure>,
    event: Option<EventChannel>,
    feedback: Option<JoinHandle<()>>,
    /// `skipRecord: true` in the base `SETUP` reply, which upstream has no concept of.
    skip_record: bool,
}

impl Drop for AirPlayV2 {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl AirPlayV2 {
    /// A protocol bound to one control connection.
    #[must_use]
    pub fn new(control: PlayControl, timing: PlayTiming) -> Self {
        Self {
            control,
            timing,
            uuid: random_uuid().to_lowercase(),
            verifier: None,
            event: None,
            feedback: None,
            skip_record: false,
        }
    }

    /// The `uuid` the `/play` body will carry, for a caller that wants to correlate.
    #[must_use]
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// The completed pair-verify, once [`AirPlayV2::play_url`] has run one.
    ///
    /// `None` before that. Every channel this session could open is keyed from it, so anything
    /// added on top of a live play session — an audio stream, say — derives from here rather than
    /// verifying again.
    #[must_use]
    pub fn verifier(&self) -> Option<&PairVerifyProcedure> {
        self.verifier.as_ref()
    }

    /// Run the whole sequence and return the `/play` response, whatever its status.
    ///
    /// `allow_error` is set on the `/play` itself, because the outer driver branches on the status
    /// code rather than on an exception (`airplayv2.py:257-262`, and [`super::player`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] if pair-verify is refused, [`Error::Status`] if the
    /// receiver refuses the `SETUP` or the `RECORD`, [`Error::Plist`] if the `SETUP` reply carries
    /// no `eventPort`, and [`Error::Io`] on any transport failure.
    pub async fn play_url(
        &mut self,
        credentials: &HapCredentials,
        timing_port: u16,
        url: &str,
        position: f64,
    ) -> Result<Response> {
        self.setup_base(credentials, timing_port).await?;
        self.start_feedback();
        self.record().await?;

        let session_id = random_uuid().to_lowercase();
        let body = encode_plist(&bodies::v2_play_body(url, position, &self.uuid))?;
        let headers = bodies::v2_play_headers(&session_id);

        tracing::debug!(address = %self.control.address(), url, position, "starting to play");
        let response = self
            .control
            .send(&RequestSpec {
                method: method::POST,
                uri: bodies::PLAY_PATH,
                headers: &headers,
                body: &body,
                allow_error: true,
                ..RequestSpec::default()
            })
            .await?;

        self.send_properties().await;

        Ok(response)
    }

    /// Pair-verify, base `SETUP`, event channel (`airplayv2.py:51-105`).
    async fn setup_base(&mut self, credentials: &HapCredentials, timing_port: u16) -> Result<()> {
        let verifier = self.control.verify(credentials).await?;

        let body = bodies::v2_base_setup_body(timing_port, &random_uuid());
        let reply = self.control.setup(&body).await?;
        let setup = EventChannelSetup::from_plist(&reply)?;
        tracing::debug!(
            address = %self.control.address(),
            port = setup.event_port,
            skip_record = ?setup.skip_record,
            "play session negotiated"
        );

        let keys = event_channel_keys(&verifier)?;
        let address = SocketAddr::new(self.control.address().ip(), setup.event_port);
        self.event = Some(self.dial_event_channel(address, &keys).await?);
        self.verifier = Some(verifier);
        self.skip_record = !setup.should_record();

        Ok(())
    }

    /// Dial the event channel, retrying a refused connection (`airplayv2.py:84-104`).
    async fn dial_event_channel(
        &self,
        address: SocketAddr,
        keys: &pyatv_pairing::pairing::SessionKeys,
    ) -> Result<EventChannel> {
        let mut remaining = EVENT_CHANNEL_RETRIES;

        loop {
            match EventChannel::connect(address, keys).await {
                Ok(channel) => return Ok(channel),
                Err(Error::Io(error))
                    if error.kind() == std::io::ErrorKind::ConnectionRefused && remaining > 1 =>
                {
                    remaining -= 1;
                    tracing::debug!(%address, "event channel refused the connection, retrying");
                    tokio::time::sleep(self.timing.retry_delay).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// `RECORD`, unless the receiver asked for it to be skipped.
    ///
    /// Upstream sends it unconditionally (`airplayv2.py:212`). The tvOS 27 test device answers the
    /// base `SETUP` with `skipRecord: true`, a key that appears nowhere in pyatv, and this port
    /// honours it here for the same reason [`crate::ap2::Ap2Session`] does — see that module's
    /// header for the live evidence. A receiver that omits the key is treated exactly as upstream
    /// treats every receiver.
    async fn record(&self) -> Result<()> {
        if self.skip_record {
            tracing::debug!(
                address = %self.control.address(),
                "receiver asked for RECORD to be skipped"
            );
            return Ok(());
        }

        self.control.record().await.map(|_| ())
    }

    /// Start the keepalive if it is not already running (`airplayv2.py:167-181`).
    ///
    /// Best effort in both directions: a failed `/feedback` is logged and the loop carries on,
    /// exactly as upstream's bare `except Exception` does. The task is stopped by
    /// [`AirPlayV2::teardown`], which — unlike upstream, whose player never calls `teardown()` —
    /// this port runs when the play session ends (`docs/research/airplay-playurl-raop-port-spec.md`
    /// §16.2).
    fn start_feedback(&mut self) {
        if self.feedback.is_some() {
            return;
        }

        let control = self.control.clone();
        let interval = self.timing.feedback_interval;
        self.feedback = Some(tokio::spawn(async move {
            tracing::debug!(address = %control.address(), "starting feedback task");
            loop {
                if let Err(error) = control.feedback().await {
                    tracing::debug!(%error, "feedback failed");
                }
                tokio::time::sleep(interval).await;
            }
        }));
    }

    /// The five calls after `/play` (`airplayv2.py:246-272`).
    ///
    /// **Divergence.** Upstream sends these through `RtspSession.exchange` with its default
    /// `allow_error=False`, so a non-`2xx` on any of them raises and aborts `play_url` — even
    /// though the comment above them (`# TODO: Maybe check some return values?`) shows that was not
    /// the intent, and even though the media is already playing by then. This port sends them with
    /// errors allowed and only logs: aborting a stream that has already started because a receiver
    /// declined a decorative property would be worse than telling the user about it. `/rate` logs
    /// at warning level because without it the stream starts paused; the rest at debug.
    async fn send_properties(&self) {
        for (index, (path, body)) in bodies::SET_PROPERTY_PATHS
            .iter()
            .zip(bodies::set_property_bodies())
            .enumerate()
        {
            // `/rate` goes between the second and third `setProperty` (`airplayv2.py:252`).
            if index == 2 {
                self.report(
                    bodies::RATE_PATH,
                    self.control
                        .exchange(method::POST, bodies::RATE_PATH, None, true)
                        .await,
                    true,
                );
            }

            self.report(
                path,
                self.control.exchange(PUT, path, Some(&body), true).await,
                false,
            );
        }
    }

    /// Log whatever one fire-and-forget call did.
    fn report(&self, path: &str, outcome: Result<Response>, important: bool) {
        match outcome {
            Ok(response) if response.is_success() => {}
            Ok(response) if important => tracing::warn!(
                address = %self.control.address(),
                path,
                status = response.status,
                "the receiver refused the playback rate, so the stream may stay paused"
            ),
            Ok(response) => tracing::debug!(
                address = %self.control.address(),
                path,
                status = response.status,
                "the receiver refused a playback property"
            ),
            Err(error) => tracing::debug!(
                address = %self.control.address(),
                path,
                %error,
                "a playback property call failed"
            ),
        }
    }

    /// Stop the keepalive and close the event channel (`airplayv2.py:157-165`).
    pub fn teardown(&mut self) {
        if let Some(feedback) = self.feedback.take() {
            feedback.abort();
        }
        if let Some(event) = self.event.take() {
            event.close();
        }
    }
}

/// The verb the four property calls use (`airplayv2.py:246`). Not in [`crate::rtsp::method`],
/// which lists the verbs the tunnel needs.
const PUT: &str = "PUT";

#[cfg(test)]
mod tests {
    use super::{EVENT_CHANNEL_RETRIES, PUT};

    /// `retries = 5` (`airplayv2.py:84`) and the verb the property calls travel under.
    #[test]
    fn the_constants_match_upstream() {
        assert_eq!(EVENT_CHANNEL_RETRIES, 5);
        assert_eq!(PUT, "PUT");
    }
}
