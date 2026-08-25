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
use crate::rtsp::FRAMES_PER_PACKET;
use crate::{Error, Result};

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

/// `audioFormat` in the audio-stream `SETUP`. Raw PCM; there is no branch that ever sends anything
/// else (`airplayv2.py:130`).
pub const AUDIO_FORMAT_PCM: u64 = 0x800;

/// `ct` — compression type `1`, "Raw PCM" (`airplayv2.py:134`).
pub const COMPRESSION_TYPE_PCM: u64 = 1;

/// `type` — the RTP payload type, `0x60` (`airplayv2.py:141`).
pub const STREAM_TYPE_AUDIO: u64 = 0x60;

/// `latencyMax` (`airplayv2.py:136`).
pub const LATENCY_MAX: u64 = 88_200;

/// `latencyMin` (`airplayv2.py:137`).
pub const LATENCY_MIN: u64 = 11_025;

/// `sr` in the audio-stream `SETUP`. Hardcoded upstream, not taken from the receiver's `sr` TXT
/// key (`airplayv2.py:140`).
pub const STREAM_SAMPLE_RATE: u64 = 44_100;

/// Build the base `SETUP` body.
///
/// `AirPlayV2._setup_base` (`airplayv2.py:56-72`), fifteen keys, all but `sessionUUID` and
/// `timingPort` hardcoded literals — including the `deviceID` and `macAddress`, which upstream does
/// **not** take from `InfoSettings` on this path even though it does on the tunnel path.
#[must_use]
pub fn base_setup_body(session_uuid: &str, timing_port: u16) -> plist::Value {
    let mut body = plist::Dictionary::new();
    body.insert("deviceID".to_owned(), "AA:BB:CC:DD:EE:FF".into());
    body.insert("sessionUUID".to_owned(), session_uuid.into());
    body.insert("timingPort".to_owned(), u64::from(timing_port).into());
    body.insert("timingProtocol".to_owned(), "NTP".into());
    body.insert("isMultiSelectAirPlay".to_owned(), true.into());
    body.insert("groupContainsGroupLeader".to_owned(), false.into());
    body.insert("macAddress".to_owned(), "AA:BB:CC:DD:EE:FF".into());
    body.insert("model".to_owned(), "iPhone14,3".into());
    body.insert("name".to_owned(), "pyatv".into());
    body.insert("osBuildVersion".to_owned(), "20F66".into());
    body.insert("osName".to_owned(), "iPhone OS".into());
    body.insert("osVersion".to_owned(), "16.5".into());
    body.insert("senderSupportsRelay".to_owned(), false.into());
    body.insert("sourceVersion".to_owned(), "690.7.1".into());
    body.insert("statsCollectionEnabled".to_owned(), false.into());
    plist::Value::Dictionary(body)
}

/// Build the audio-stream `SETUP` body.
///
/// `AirPlayV2.setup_audio_stream` (`airplayv2.py:127-149`): a one-element `streams` array whose
/// dictionary is a fixed literal apart from `controlPort`, `shk` and `streamConnectionID`. Nothing
/// in it is conditional on what the receiver advertised — not the codec, not the sample rate.
#[must_use]
pub fn audio_stream_setup_body(
    control_port: u16,
    shared_key: &[u8; 32],
    stream_connection_id: u32,
) -> plist::Value {
    let mut stream = plist::Dictionary::new();
    stream.insert("audioFormat".to_owned(), AUDIO_FORMAT_PCM.into());
    stream.insert("audioMode".to_owned(), "default".into());
    stream.insert("controlPort".to_owned(), u64::from(control_port).into());
    stream.insert("ct".to_owned(), COMPRESSION_TYPE_PCM.into());
    stream.insert("isMedia".to_owned(), true.into());
    stream.insert("latencyMax".to_owned(), LATENCY_MAX.into());
    stream.insert("latencyMin".to_owned(), LATENCY_MIN.into());
    stream.insert("shk".to_owned(), plist::Value::Data(shared_key.to_vec()));
    stream.insert("spf".to_owned(), u64::from(FRAMES_PER_PACKET).into());
    stream.insert("sr".to_owned(), STREAM_SAMPLE_RATE.into());
    stream.insert("type".to_owned(), STREAM_TYPE_AUDIO.into());
    stream.insert("supportsDynamicStreamID".to_owned(), false.into());
    stream.insert(
        "streamConnectionID".to_owned(),
        u64::from(stream_connection_id).into(),
    );

    let mut body = plist::Dictionary::new();
    body.insert(
        "streams".to_owned(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
    );
    plist::Value::Dictionary(body)
}

/// Read `controlPort` and `dataPort` out of the audio-stream `SETUP` reply.
///
/// `stream = resp["streams"][0]` (`airplayv2.py:151-155`).
///
/// # Errors
///
/// Returns [`Error::Plist`] if the reply has no first stream, or that stream omits either port.
pub fn audio_stream_ports(reply: &plist::Value) -> Result<(u16, u16)> {
    let stream = reply
        .as_dictionary()
        .and_then(|body| body.get("streams"))
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary)
        .ok_or_else(|| Error::Plist("audio SETUP reply has no streams[0]".to_owned()))?;

    let port = |key: &str| -> Result<u16> {
        stream
            .get(key)
            .and_then(plist::Value::as_unsigned_integer)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| Error::Plist(format!("audio SETUP reply has no usable {key}")))
    };

    Ok((port("controlPort")?, port("dataPort")?))
}

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
async fn dial_event_channel(
    address: SocketAddr,
    keys: &pyatv_pairing::pairing::SessionKeys,
) -> Result<EventChannel> {
    let mut remaining = EVENT_CHANNEL_RETRIES;

    loop {
        match EventChannel::connect(address, keys).await {
            Ok(channel) => return Ok(channel),
            Err(error) => {
                remaining -= 1;
                if remaining == 0 {
                    return Err(error);
                }
                tracing::debug!(%address, %error, "event channel connect failed, retrying");
                tokio::time::sleep(EVENT_CHANNEL_RETRY_DELAY).await;
            }
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
    use super::{
        AUDIO_FORMAT_PCM, AirPlayV2, COMPRESSION_TYPE_PCM, EVENT_CHANNEL_RETRIES,
        FEEDBACK_INTERVAL, STREAM_TYPE_AUDIO, audio_stream_ports, audio_stream_setup_body,
        base_setup_body,
    };
    use pyatv_pairing::chacha::Chacha20Cipher;
    use pyatv_pairing::chacha::NonceLayout;

    fn setup_keys(body: &plist::Value) -> Vec<String> {
        let mut keys: Vec<String> = body
            .as_dictionary()
            .expect("a dictionary")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    /// Fifteen keys, and `timingProtocol` is `NTP` — the one field that most obviously separates
    /// this from the remote-control tunnel's `SETUP`.
    #[test]
    fn the_base_setup_body_carries_pyatvs_fifteen_keys() {
        let body = base_setup_body("A-B-C", 6002);
        let dictionary = body.as_dictionary().expect("a dictionary");

        assert_eq!(
            setup_keys(&body),
            [
                "deviceID",
                "groupContainsGroupLeader",
                "isMultiSelectAirPlay",
                "macAddress",
                "model",
                "name",
                "osBuildVersion",
                "osName",
                "osVersion",
                "senderSupportsRelay",
                "sessionUUID",
                "sourceVersion",
                "statsCollectionEnabled",
                "timingPort",
                "timingProtocol",
            ]
        );
        assert_eq!(dictionary["timingProtocol"].as_string(), Some("NTP"));
        assert_eq!(dictionary["timingPort"].as_unsigned_integer(), Some(6002));
        assert_eq!(dictionary["sourceVersion"].as_string(), Some("690.7.1"));
        assert_eq!(
            dictionary["deviceID"].as_string(),
            Some("AA:BB:CC:DD:EE:FF")
        );
    }

    /// The audio stream is raw PCM at 44100, unconditionally.
    #[test]
    fn the_audio_stream_body_is_raw_pcm() {
        let body = audio_stream_setup_body(6001, &[0xAB; 32], 0xDEAD_BEEF);
        let stream = body.as_dictionary().expect("a dictionary")["streams"]
            .as_array()
            .expect("an array")[0]
            .as_dictionary()
            .expect("a dictionary");

        assert_eq!(
            stream["audioFormat"].as_unsigned_integer(),
            Some(AUDIO_FORMAT_PCM)
        );
        assert_eq!(
            stream["ct"].as_unsigned_integer(),
            Some(COMPRESSION_TYPE_PCM)
        );
        assert_eq!(
            stream["type"].as_unsigned_integer(),
            Some(STREAM_TYPE_AUDIO)
        );
        assert_eq!(stream["spf"].as_unsigned_integer(), Some(352));
        assert_eq!(stream["sr"].as_unsigned_integer(), Some(44_100));
        assert_eq!(stream["latencyMin"].as_unsigned_integer(), Some(11_025));
        assert_eq!(stream["latencyMax"].as_unsigned_integer(), Some(88_200));
        assert_eq!(stream["audioMode"].as_string(), Some("default"));
        assert_eq!(stream["isMedia"].as_boolean(), Some(true));
        assert_eq!(stream["supportsDynamicStreamID"].as_boolean(), Some(false));
        assert_eq!(
            stream["streamConnectionID"].as_unsigned_integer(),
            Some(0xDEAD_BEEF)
        );
        assert_eq!(stream["shk"].as_data(), Some(&[0xAB; 32][..]));
    }

    #[test]
    fn the_reply_ports_come_out_of_the_first_stream() {
        let mut stream = plist::Dictionary::new();
        stream.insert("controlPort".to_owned(), 7001u64.into());
        stream.insert("dataPort".to_owned(), 7002u64.into());
        let mut reply = plist::Dictionary::new();
        reply.insert(
            "streams".to_owned(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );

        assert_eq!(
            audio_stream_ports(&plist::Value::Dictionary(reply)).expect("parses"),
            (7001, 7002)
        );
    }

    #[test]
    fn a_reply_without_streams_is_an_error() {
        let reply = plist::Value::Dictionary(plist::Dictionary::new());

        assert!(audio_stream_ports(&reply).is_err());
    }

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
