//! The AirPlay 2 RAOP protocol: a base `SETUP`, an event channel, an audio-stream `SETUP`, and
//! ChaCha20-Poly1305 on every audio payload.
//!
//! Port of `AirPlayV2` (`pyatv/protocols/raop/protocols/airplayv2.py`).
//!
//! # This is *not* the MRP tunnel's `_setup_base`
//!
//! [`crate::ap2::remote_control_setup_body`] and [`base_setup_body`] look alike and are separate
//! implementations upstream, with values that genuinely differ — `timingProtocol: "NTP"` here
//! versus `"None"` there, a `timingPort`, `isMultiSelectAirPlay`, `senderSupportsRelay`,
//! `statsCollectionEnabled`, and a hardcoded `deviceID`/`macAddress` rather than one taken from
//! settings. RAOP needs real audio timing; the remote-control tunnel needs none. They must not be
//! merged into one function with a switch (`airplay-playurl-raop-port-spec.md` §2.3.1).
//!
//! # The `shk` is borrowed from the event channel
//!
//! `out_key, _ = verifier.encryption_keys(EVENTS_SALT, EVENTS_WRITE_INFO, EVENTS_READ_INFO)` —
//! the *unswapped* order, so not the same derivation the event channel's own transport uses — and
//! the first 32 bytes become the audio stream's `shk` (`airplayv2.py:117-125`). pyatv's own comment
//! calls this "not really correct" and justifies it as "it doesn't really matter what the key is
//! … it's merely a security feature". Replicated exactly, because the audio cipher is keyed from
//! it and any vector captured from pyatv's runtime uses this value.

pub mod bodies;

use std::net::SocketAddr;
use std::time::Duration;

use pyatv_pairing::chacha::Chacha20Cipher;
use pyatv_pairing::hkdf_derive::transport::AIRPLAY_EVENTS;
use pyatv_pairing::{HapCredentials, session::HapSession};
use tokio::task::JoinHandle;

use crate::ap2::event_channel::{EventChannel, event_channel_keys};
use crate::ap2::random_uuid;
use crate::auth::{PairVerifyProcedure, verify_connection};
use crate::raop::connection::{SharedConnection, with_connection};
use crate::raop::context::StreamContext;
use crate::{Error, Result};

pub use bodies::{
    AUDIO_FORMAT_PCM, COMPRESSION_TYPE_PCM, LATENCY_MAX, LATENCY_MIN, STREAM_SAMPLE_RATE,
    STREAM_TYPE_AUDIO, audio_stream_ports, audio_stream_setup_body, base_setup_body,
};

/// How often `/feedback` is posted.
///
/// `FEEDBACK_INTERVAL = 2.0` (`airplayv2.py:25`).
pub const FEEDBACK_INTERVAL: Duration = Duration::from_secs(2);

/// How many times the event channel is dialled before giving up.
///
/// `retries = 5` with a one-second sleep between attempts (`airplayv2.py:86-104`). The upstream
/// comment explains it: `airplay2-receiver` answers with an `eventPort` slightly before it is
/// listening on it.
pub const EVENT_CHANNEL_RETRIES: u32 = 5;

/// How long to wait between event-channel dial attempts.
pub const EVENT_CHANNEL_RETRY_DELAY: Duration = Duration::from_secs(1);

/// The AirPlay 2 streaming protocol.
#[derive(Debug)]
pub struct AirPlayV2 {
    uuid: String,
    cipher: Option<Chacha20Cipher>,
    event_channel: Option<EventChannel>,
    feedback: Option<JoinHandle<()>>,
}

impl Drop for AirPlayV2 {
    fn drop(&mut self) {
        self.teardown();
    }
}

impl Default for AirPlayV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl AirPlayV2 {
    /// A protocol with a fresh per-instance session UUID.
    ///
    /// `self.uuid = str(uuid4())` (`airplayv2.py:49`) — lowercase, per instance, unlike the
    /// `X-Apple-Session-ID` header constant `play_url` uses.
    #[must_use]
    pub fn new() -> Self {
        Self {
            uuid: random_uuid().to_lowercase(),
            cipher: None,
            event_channel: None,
            feedback: None,
        }
    }

    /// The session UUID this instance presents.
    #[must_use]
    pub fn uuid(&self) -> &str {
        &self.uuid
    }

    /// Key the audio cipher directly, skipping the pair-verify exchange.
    ///
    /// Only for fixtures and known-answer tests: production keys it from [`shared_key`] inside
    /// [`AirPlayV2::setup`]. The key is used in both directions, as upstream's
    /// `Chacha20Cipher8byteNonce(out_key, out_key)` does (`airplayv2.py:124-125`).
    #[doc(hidden)]
    #[must_use]
    pub fn with_audio_key(key: &[u8; 32]) -> Self {
        let mut protocol = Self::new();
        protocol.cipher = Some(Chacha20Cipher::with_padded_counter(key, key));
        protocol
    }

    /// Pair-verify, the base `SETUP`, the event channel and the audio-stream `SETUP`.
    ///
    /// `AirPlayV2.setup` (`airplayv2.py:107-156`).
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::NotAuthenticated`] if the receiver rejects the credentials,
    /// [`Error::Plist`] if either `SETUP` reply is missing a port, and [`crate::Error::Io`] if the
    /// event channel cannot be reached within [`EVENT_CHANNEL_RETRIES`] attempts.
    pub async fn setup(
        &mut self,
        connection: &SharedConnection,
        context: &mut StreamContext,
        credentials: &HapCredentials,
        timing_port: u16,
        control_port: u16,
    ) -> Result<()> {
        let verifier = self
            .setup_base(connection, credentials, timing_port)
            .await?;
        self.setup_audio_stream(connection, context, &verifier, control_port)
            .await
    }

    /// Pair-verify, the base `SETUP` and the event channel.
    ///
    /// `_setup_base` (`airplayv2.py:51-105`).
    async fn setup_base(
        &mut self,
        connection: &SharedConnection,
        credentials: &HapCredentials,
        timing_port: u16,
    ) -> Result<PairVerifyProcedure> {
        let body = base_setup_body(&random_uuid(), timing_port);

        let (verifier, reply, remote) = {
            let mut guard = connection.lock().await;
            let verifier = verify_connection(credentials, &mut guard.http).await?;
            let remote = guard.http.remote_address();
            let reply = {
                let crate::raop::connection::RaopConnection { http, rtsp } = &mut *guard;
                rtsp.setup(http, &body).await?
            };
            (verifier, reply, remote)
        };

        let event_port = reply
            .as_dictionary()
            .and_then(|reply| reply.get("eventPort"))
            .and_then(plist::Value::as_unsigned_integer)
            .and_then(|port| u16::try_from(port).ok())
            .unwrap_or(0);
        tracing::debug!(event_port, "RAOP base stream negotiated");

        let keys = event_channel_keys(&verifier)?;
        let address = SocketAddr::new(remote.ip(), event_port);
        self.event_channel = Some(dial_event_channel(address, &keys).await?);

        Ok(verifier)
    }

    /// The audio-specific second `SETUP`.
    ///
    /// `setup_audio_stream` (`airplayv2.py:112-156`).
    async fn setup_audio_stream(
        &mut self,
        connection: &SharedConnection,
        context: &mut StreamContext,
        verifier: &PairVerifyProcedure,
        control_port: u16,
    ) -> Result<()> {
        let shared_key = shared_key(verifier)?;
        let stream_connection_id =
            with_connection(connection, async |rtsp, _| Ok(rtsp.session_id())).await?;
        let body = audio_stream_setup_body(control_port, &shared_key, stream_connection_id);

        let reply =
            with_connection(connection, async |rtsp, http| rtsp.setup(http, &body).await).await?;
        let (control, data) = audio_stream_ports(&reply)?;

        context.control_port = control;
        context.server_port = data;
        // `Chacha20Cipher8byteNonce(shared_secret, shared_secret)`: the same key in both
        // directions, since audio only flows one way and the API still wants an input key.
        self.cipher = Some(Chacha20Cipher::with_padded_counter(
            &shared_key,
            &shared_key,
        ));

        tracing::debug!(control, data, "RAOP audio stream negotiated");
        Ok(())
    }

    /// Start posting `/feedback` every [`FEEDBACK_INTERVAL`].
    ///
    /// `start_feedback`/`_feedback_task_loop` (`airplayv2.py:167-181`). Failures are swallowed
    /// entirely — upstream wraps the call in a bare `except Exception` — and the loop has no end
    /// condition other than being cancelled. Calling it twice is a no-op, matching the
    /// `if self._feedback_task is None` guard.
    pub fn start_feedback(&mut self, connection: &SharedConnection) {
        if self.feedback.is_some() {
            return;
        }

        let connection = connection.clone();
        self.feedback = Some(tokio::spawn(async move {
            tracing::debug!("starting RAOP feedback task");
            loop {
                let outcome = with_connection(&connection, async |rtsp, http| {
                    rtsp.feedback(http, false).await
                })
                .await;
                if let Err(error) = outcome {
                    tracing::debug!(%error, "feedback failed");
                }

                tokio::time::sleep(FEEDBACK_INTERVAL).await;
            }
        }));
    }

    /// Stop the feedback task and close the event channel.
    ///
    /// `AirPlayV2.teardown` (`airplayv2.py:158-165`).
    pub fn teardown(&mut self) {
        if let Some(feedback) = self.feedback.take() {
            feedback.abort();
        }
        if let Some(channel) = self.event_channel.take() {
            channel.close();
        }
    }

    /// Build one encrypted audio packet.
    ///
    /// `AirPlayV2.send_audio_packet` (`airplayv2.py:183-208`). The nonce is read **before**
    /// encrypting and the encryption is then left to advance the counter itself; passing the peeked
    /// nonce back in would leave the counter at zero forever, which upstream's comment records as a
    /// bug it once shipped. Only the low eight bytes of the twelve-byte nonce go on the wire — the
    /// top four are always zero.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Pairing`] if the AEAD seal fails, and [`Error::NotStarted`] if
    /// called before [`AirPlayV2::setup`] produced a cipher.
    pub fn audio_packet(&mut self, header: &[u8], audio: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let cipher = self
            .cipher
            .as_mut()
            .ok_or(Error::NotStarted("the AirPlay 2 audio stream"))?;

        let nonce = cipher.out_nonce();
        let encrypted = cipher.encrypt(audio, Some(aad))?;

        let mut packet = Vec::with_capacity(header.len() + encrypted.len() + 8);
        packet.extend_from_slice(header);
        packet.extend_from_slice(&encrypted);
        packet.extend_from_slice(&nonce[nonce.len() - 8..]);
        Ok(packet)
    }
}

/// Derive the audio stream's `shk`.
///
/// See this module's header for why it comes from the event channel's info strings, unswapped.
///
/// # Errors
///
/// Returns [`crate::Error::NoEncryptionKeys`] if the exchange derives none.
pub fn shared_key(verifier: &PairVerifyProcedure) -> Result<[u8; 32]> {
    Ok(verifier
        .encryption_keys(
            AIRPLAY_EVENTS.salt,
            AIRPLAY_EVENTS.write_info,
            AIRPLAY_EVENTS.read_info,
        )?
        .output_key)
}

/// Dial the event channel, retrying a receiver that answered with a port it is not yet listening
/// on.
///
/// **Only** a refused connection is retried. Upstream catches bare `OSError`
/// (`airplayv2.py:86-104`) and so retries anything, but the failure the retry loop exists for is
/// specifically `airplay2-receiver` answering the `SETUP` a moment before it binds `eventPort` —
/// which is `ECONNREFUSED` and nothing else. Retrying a rejected pair-verify or a malformed reply
/// five times over five seconds just delays a failure that was never going to resolve itself.
/// [`crate::stream::ap2::AirPlayV2`] makes the same choice for the same reason; the two loops are
/// kept deliberately identical.
async fn dial_event_channel(
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
                tokio::time::sleep(EVENT_CHANNEL_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Splice a session into a connection, so a caller outside this module can too.
///
/// Only used by the test fixtures; production code reaches it through [`verify_connection`].
#[doc(hidden)]
#[must_use]
pub fn hap_session(keys: &pyatv_pairing::pairing::SessionKeys) -> HapSession {
    HapSession::new(&keys.output_key, &keys.input_key)
}

#[cfg(test)]
mod tests {
    use super::{AirPlayV2, EVENT_CHANNEL_RETRIES, FEEDBACK_INTERVAL};
    use pyatv_pairing::chacha::Chacha20Cipher;
    use pyatv_pairing::chacha::NonceLayout;

    /// The packet is header, ciphertext, then the low eight bytes of the nonce — and the counter
    /// advances once per packet, so the trailer differs between them.
    #[test]
    fn an_audio_packet_carries_the_counter_in_its_trailer() {
        let mut protocol = AirPlayV2::new();
        protocol.cipher = Some(Chacha20Cipher::with_padded_counter(
            &[0x11; 32],
            &[0x11; 32],
        ));

        let header = [0x80, 0x60, 0x00, 0x01, 0, 0, 0, 2, 0, 0, 0, 3];
        let first = protocol
            .audio_packet(&header, &[0xAA; 16], &header[4..12])
            .expect("encrypts");
        let second = protocol
            .audio_packet(&header, &[0xAA; 16], &header[4..12])
            .expect("encrypts");

        assert_eq!(&first[..12], &header);
        // 16 bytes of payload, a 16-byte Poly1305 tag, then the 8-byte nonce trailer.
        assert_eq!(first.len(), 12 + 16 + 16 + 8);
        assert_eq!(&first[first.len() - 8..], &[0u8; 8]);
        assert_eq!(&second[second.len() - 8..], &1u64.to_le_bytes());
        assert_ne!(first[12..28], second[12..28], "the ciphertext must differ");
    }

    /// The trailer is the *counter* half of the nonce, which is why the padded layout's four
    /// leading zero bytes are dropped.
    #[test]
    fn the_trailer_is_the_low_eight_bytes_of_a_twelve_byte_nonce() {
        assert_eq!(NonceLayout::PaddedCounter.zero_prefix_len(), 4);
        assert_eq!(NonceLayout::PaddedCounter.counter_len(), 8);
    }

    /// Encrypting before `setup` is an error rather than a silent plaintext packet.
    #[test]
    fn an_audio_packet_without_a_cipher_is_an_error() {
        let mut protocol = AirPlayV2::new();

        assert!(
            protocol
                .audio_packet(&[0u8; 12], &[0u8; 4], &[0u8; 8])
                .is_err()
        );
    }

    #[test]
    fn the_constants_match_upstream() {
        assert_eq!(FEEDBACK_INTERVAL.as_secs(), 2);
        assert_eq!(EVENT_CHANNEL_RETRIES, 5);
    }

    /// The UUID is lowercase here, unlike the base `SETUP` body's `sessionUUID`.
    #[test]
    fn the_instance_uuid_is_lowercase() {
        let protocol = AirPlayV2::new();

        assert_eq!(protocol.uuid(), protocol.uuid().to_lowercase());
        assert_eq!(protocol.uuid().len(), 36);
    }
}
