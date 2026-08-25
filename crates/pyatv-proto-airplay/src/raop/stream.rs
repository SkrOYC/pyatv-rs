//! The generic streaming client both protocol versions sit under.
//!
//! Port of `StreamClient` (`pyatv/protocols/raop/stream_client.py:204-619`): it owns the two UDP
//! sockets, the packet backlog, the negotiated capabilities, and the pacing loop, and delegates
//! everything version-specific to a [`StreamProtocol`].

mod data;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pyatv_core::airplay::{EncryptionType, MetadataType, get_encryption_types, get_metadata_types};
use pyatv_pairing::HapCredentials;

use crate::Result;
use crate::audio::AudioSource;
use crate::raop::connection::{SharedConnection, with_connection};
use crate::raop::context::{SharedContext, StreamContext};
use crate::raop::metadata::TrackMetadata;
use crate::raop::net::{AudioSender, ControlClient, TimingServer};
use crate::raop::protocol::StreamProtocol;
use crate::raop::rtsp::{self as raop_rtsp, RtpInfo};
use crate::raop::volume::{format_dbfs, pct_to_dbfs};

use super::AudioProperties;

/// The encryption schemes this port can actually stream under.
///
/// `SUPPORTED_ENCRYPTIONS = EncryptionType.Unencrypted | EncryptionType.MFiSAP`
/// (`stream_client.py:54`). Note that upstream only *logs* when the receiver advertises none of
/// them and streams anyway; that is reproduced, because a receiver advertising only FairPlay still
/// accepts an unencrypted stream in practice.
pub const SUPPORTED_ENCRYPTIONS: EncryptionType = EncryptionType::from_bits_truncate(
    EncryptionType::UNENCRYPTED.bits() | EncryptionType::MFI_SAP.bits(),
);

/// What a listener is told when playback starts.
#[derive(Debug, Clone, PartialEq)]
pub struct PlaybackInfo {
    /// The metadata being displayed, with the placeholder identity already substituted.
    pub metadata: TrackMetadata,
    /// Position in seconds at the moment the callback fired.
    pub position: f64,
}

/// Told when a RAOP stream starts and stops.
///
/// `RaopListener` (`stream_client.py:203-212`). Upstream holds this weakly and silently stops
/// calling a listener nothing else references; here the caller keeps the `Arc` alive, which is
/// both explicit and impossible to get wrong by accident.
pub trait RaopListener: Send + Sync + std::fmt::Debug {
    /// Playback is starting. Fires **before** `RECORD`, i.e. optimistically, at the moment the
    /// client commits to streaming rather than when the receiver confirms
    /// (`stream_client.py:433-435`).
    fn playing(&self, info: &PlaybackInfo);

    /// Playback has ended, successfully or not. Fires exactly once per `send_audio`
    /// (`stream_client.py:472-474`).
    fn stopped(&self);
}

/// One RAOP streaming session.
#[derive(Debug)]
pub struct StreamClient {
    connection: SharedConnection,
    context: SharedContext,
    protocol: StreamProtocol,
    local: IpAddr,
    control: Option<ControlClient>,
    timing: Option<TimingServer>,
    encryption_types: EncryptionType,
    metadata_types: MetadataType,
    properties: HashMap<String, String>,
    info: plist::Dictionary,
    metadata: TrackMetadata,
    playing: Arc<AtomicBool>,
    listener: Option<Arc<dyn RaopListener>>,
}

impl StreamClient {
    /// A client that has not yet opened any socket.
    #[must_use]
    pub fn new(connection: SharedConnection, protocol: StreamProtocol, local: IpAddr) -> Self {
        Self {
            connection,
            context: SharedContext::default(),
            protocol,
            local,
            control: None,
            timing: None,
            encryption_types: EncryptionType::UNKNOWN,
            metadata_types: MetadataType::NOT_SUPPORTED,
            properties: HashMap::new(),
            info: plist::Dictionary::new(),
            metadata: TrackMetadata::default(),
            playing: Arc::new(AtomicBool::new(false)),
            listener: None,
        }
    }

    /// Register the listener told about playback starting and stopping.
    pub fn set_listener(&mut self, listener: Arc<dyn RaopListener>) {
        self.listener = Some(listener);
    }

    /// The shared session state, for a facade that wants to read the position or the volume.
    #[must_use]
    pub fn context(&self) -> SharedContext {
        self.context.clone()
    }

    /// A handle that stops the pacing loop from elsewhere.
    ///
    /// `StreamClient.stop` (`stream_client.py:365-368`) is a plain flag flip; `RaopRemoteControl`
    /// calls it for both `stop()` and `pause()`.
    #[must_use]
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle(Arc::clone(&self.playing))
    }

    /// The receiver's `/info` reply, once [`StreamClient::initialize`] has read it.
    #[must_use]
    pub fn info(&self) -> &plist::Dictionary {
        &self.info
    }

    /// What is currently playing.
    ///
    /// `StreamClient.playback_info` (`stream_client.py:266-272`), placeholder substitution and all.
    #[must_use]
    pub fn playback_info(&self) -> PlaybackInfo {
        PlaybackInfo {
            metadata: self.metadata.or_placeholder(),
            position: self.context.snapshot().position(),
        }
    }

    /// Read the receiver's capabilities, open the UDP sockets, and set the stream up.
    ///
    /// `StreamClient.initialize` (`stream_client.py:287-338`), in upstream's order: parse `et` and
    /// `md`, apply `sr`/`ch`/`ss`, bind the control and timing sockets, `GET /info`, `/auth-setup`
    /// if the receiver is an `MFiSAP` AirPort, then the protocol's own `setup`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if a socket cannot be bound or the receiver is unreachable, and
    /// whatever the chosen protocol's `setup` returns.
    pub async fn initialize(
        &mut self,
        properties: &HashMap<String, String>,
        credentials: &HapCredentials,
        password: Option<&str>,
    ) -> Result<()> {
        self.properties.clone_from(properties);
        self.encryption_types = get_encryption_types(properties);
        self.metadata_types = get_metadata_types(properties);
        tracing::debug!(
            encryption = ?self.encryption_types,
            metadata = ?self.metadata_types,
            "initialising RAOP session"
        );

        // Upstream's "misplaced check": it only logs, it never refuses to continue
        // (`stream_client.py:299-302`).
        if (self.encryption_types & SUPPORTED_ENCRYPTIONS).is_empty() {
            tracing::debug!("no supported encryption type, continuing anyway");
        }

        let audio = AudioProperties::from_properties(properties);
        // The RTP `ssrc` is the RTSP session identifier, drawn once per connection and constant
        // from here on — so it is read once rather than on every packet. See `StreamContext::ssrc`.
        let ssrc = with_connection(&self.connection, async |rtsp, _| Ok(rtsp.session_id())).await?;
        self.context.with(|context| {
            context.audio = audio;
            context.latency = super::context::latency_for(audio.sample_rate);
            context.ssrc = ssrc;
        });

        // Both receive loops only answer this address; see `raop::net`'s module header.
        let receiver = self.connection.lock().await.http.remote_address().ip();
        let control = ControlClient::start(self.local, 0, receiver).await?;
        let timing = TimingServer::start(self.local, 0, receiver).await?;
        tracing::debug!(
            control = control.port(),
            timing = timing.port(),
            "local RAOP ports bound"
        );

        self.info = with_connection(&self.connection, async |rtsp, http| rtsp.info(http).await)
            .await?
            .into_dictionary()
            .unwrap_or_default();

        if self.requires_auth_setup() {
            with_connection(&self.connection, async |rtsp, http| {
                raop_rtsp::auth_setup(rtsp, http).await
            })
            .await?;
        }

        let (timing_port, control_port) = (timing.port(), control.port());
        let mut context = self.context.snapshot();
        self.protocol
            .setup(
                &self.connection,
                &mut context,
                credentials,
                password,
                timing_port,
                control_port,
            )
            .await?;
        self.context.with(|shared| *shared = context);

        self.control = Some(control);
        self.timing = Some(timing);
        Ok(())
    }

    /// Whether `/auth-setup` should be sent.
    ///
    /// `_requires_auth_setup` (`stream_client.py:353-363`): **both** the `MFiSAP` bit in `et` and
    /// a model name starting with `AirPort`, not either. A third-party receiver advertising `MFiSAP`
    /// does not get the call, by design — the fix it exists for was scoped to one issue (#1134).
    #[must_use]
    pub fn requires_auth_setup(&self) -> bool {
        let model = self.properties.get("am").map_or("", String::as_str);

        self.encryption_types.contains(EncryptionType::MFI_SAP) && model.starts_with("AirPort")
    }

    /// Change the volume on the receiver.
    ///
    /// `StreamClient.set_volume` (`stream_client.py:370-373`): the wire call first, then the local
    /// record — so a receiver that refuses leaves the context unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] if the receiver refuses, which some do before streaming has
    /// started.
    pub async fn set_volume(&self, dbfs: f32) -> Result<()> {
        with_connection(&self.connection, async |rtsp, http| {
            raop_rtsp::set_parameter(rtsp, http, "volume", &format_dbfs(dbfs)).await
        })
        .await?;
        self.context.with(|context| context.volume = Some(dbfs));
        Ok(())
    }

    /// Stream a whole source to the receiver.
    ///
    /// `StreamClient.send_audio` (`stream_client.py:375-474`), in upstream's order: reset the
    /// clock, open the audio socket, start sync packets, send progress/metadata/artwork, start the
    /// keepalive, tell the listener, `RECORD`, `FLUSH`, an optional deferred volume, then the
    /// pacing loop. Teardown runs whatever happened.
    ///
    /// `volume` is the deferred one: `RaopStream.stream_file` passes it only when setting the
    /// volume *before* streaming failed, because some receivers answer `500` until `FLUSH`
    /// (`raop/__init__.py:392-399`, `stream_client.py:450-451`).
    ///
    /// **Divergence.** Upstream guards the retry with `if volume:`, so a deferred `0.0` — a mute —
    /// is dropped, because zero is falsy in Python. `Some(0.0)` is applied here; see
    /// [`crate::raop::manager::RaopPlaybackManager`]'s `negotiate_volume`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the audio socket cannot be opened, [`crate::Error::Status`] if the
    /// receiver refuses `RECORD` or `FLUSH`, and [`crate::Error::Pairing`] if an AirPlay 2 payload cannot
    /// be sealed.
    pub async fn send_audio(
        &mut self,
        source: &mut AudioSource,
        metadata: TrackMetadata,
        volume: Option<f32>,
    ) -> Result<()> {
        let outcome = self.stream_session(source, metadata, volume).await;
        let teardown = self.finish().await;

        if let Some(listener) = self.listener.as_ref() {
            listener.stopped();
        }

        outcome.and(teardown)
    }

    /// Everything `send_audio` does inside its `try`.
    async fn stream_session(
        &mut self,
        source: &mut AudioSource,
        metadata: TrackMetadata,
        volume: Option<f32>,
    ) -> Result<()> {
        self.context.with(StreamContext::reset);
        self.metadata = metadata;

        let (remote, context) = {
            let remote = self.connection.lock().await.http.remote_address().ip();
            (remote, self.context.snapshot())
        };

        let audio = AudioSender::connect(
            self.local,
            std::net::SocketAddr::new(remote, context.server_port),
        )
        .await?;

        if let Some(control) = self.control.as_mut() {
            control.start_sync(
                std::net::SocketAddr::new(remote, context.control_port),
                self.context.clone(),
            );
        }

        self.send_session_metadata(source, &context).await?;
        self.protocol.start_feedback(&self.connection).await?;

        if let Some(listener) = self.listener.as_ref() {
            listener.playing(&self.playback_info());
        }

        with_connection(&self.connection, async |rtsp, http| {
            rtsp.record(http).await?;
            raop_rtsp::flush(
                rtsp,
                http,
                context.rtsp_session,
                context.rtpseq,
                context.rtptime(),
            )
            .await
        })
        .await?;

        if let Some(volume) = volume {
            self.set_volume(pct_to_dbfs(volume)).await?;
        }

        self.stream_data(source, &audio).await
    }

    /// Send progress, track metadata and artwork, each gated on the receiver's `md` key.
    ///
    /// `send_audio`'s three conditional blocks (`stream_client.py:399-428`). All three read the
    /// sequence number and timestamp from before any packet has gone out, which is why they take a
    /// snapshot rather than re-reading the shared context.
    async fn send_session_metadata(
        &self,
        source: &AudioSource,
        context: &StreamContext,
    ) -> Result<()> {
        if self.metadata_types.contains(MetadataType::PROGRESS) {
            // `start` and `now` are the same value: upstream computes `context.rtptime` twice with
            // no state change in between (`stream_client.py:400-403`).
            let start = context.rtptime();
            // `end = start + source.duration * sample_rate` (`stream_client.py:403`), where
            // `AudioSource.duration` is typed `int` and `FileSource` returns
            // `round(self.src.duration)` (`audio_source.py:720-724`) — so the end tick upstream
            // sends is always a whole number of seconds past the start, never a fractional one.
            // This port knows the exact decoded length, but rounding it the same way keeps the
            // value a receiver sees identical. `round_ties_even` rather than `round` because
            // Python's `round` is banker's rounding and this port's `f64::round` is not.
            #[allow(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "a duration in RTP ticks that overflows u32 is a 27-hour track"
            )]
            let seconds = source.duration().round_ties_even() as u32;
            let end = start.wrapping_add(seconds.wrapping_mul(context.audio.sample_rate));
            let progress = format!("{start}/{start}/{end}");

            with_connection(&self.connection, async |rtsp, http| {
                raop_rtsp::set_parameter(rtsp, http, "progress", &progress).await
            })
            .await?;
        }

        let info = RtpInfo {
            session: context.rtsp_session,
            seqno: context.rtpseq,
            rtptime: context.rtptime(),
        };

        if self.metadata_types.contains(MetadataType::TEXT) {
            let metadata = self.metadata.or_placeholder();
            tracing::debug!(title = ?metadata.title, "playing with metadata");
            with_connection(&self.connection, async |rtsp, http| {
                raop_rtsp::set_metadata(rtsp, http, info, &metadata).await
            })
            .await?;
        }

        if self.metadata_types.contains(MetadataType::ARTWORK)
            && let Some(artwork) = self.metadata.artwork.clone()
        {
            tracing::debug!(bytes = artwork.len(), "sending artwork");
            with_connection(&self.connection, async |rtsp, http| {
                raop_rtsp::set_artwork(rtsp, http, info, &artwork).await
            })
            .await?;
        }

        Ok(())
    }
}

/// Stops a running stream from outside the loop that drives it.
#[derive(Debug, Clone)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    /// Ask the pacing loop to finish after the packet in flight.
    pub fn stop(&self) {
        self.0.store(false, Ordering::SeqCst);
    }

    /// Whether a stream is running.
    #[must_use]
    pub fn is_playing(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use pyatv_core::airplay::EncryptionType;

    use super::{PlaybackInfo, SUPPORTED_ENCRYPTIONS, StopHandle};
    use crate::raop::metadata::{MISSING_TITLE, TrackMetadata};

    fn properties(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn the_supported_encryptions_are_unencrypted_and_mfisap() {
        assert!(SUPPORTED_ENCRYPTIONS.contains(EncryptionType::UNENCRYPTED));
        assert!(SUPPORTED_ENCRYPTIONS.contains(EncryptionType::MFI_SAP));
        assert!(!SUPPORTED_ENCRYPTIONS.contains(EncryptionType::FAIR_PLAY));
    }

    /// The live test device's `et=0,3,5` intersects the supported set, so nothing is logged.
    #[test]
    fn the_test_devices_encryption_set_is_supported() {
        let types = pyatv_core::airplay::get_encryption_types(&properties(&[("et", "0,3,5")]));

        assert!(!(types & SUPPORTED_ENCRYPTIONS).is_empty());
    }

    #[test]
    fn the_stop_handle_flips_the_flag() {
        let handle = StopHandle(std::sync::Arc::new(std::sync::atomic::AtomicBool::new(
            true,
        )));

        assert!(handle.is_playing());
        handle.stop();
        assert!(!handle.is_playing());
    }

    /// The placeholder identity reaches a listener rather than an empty `Playing`.
    #[test]
    fn playback_info_substitutes_the_placeholder() {
        let info = PlaybackInfo {
            metadata: TrackMetadata::default().or_placeholder(),
            position: 0.0,
        };

        assert_eq!(info.metadata.title.as_deref(), Some(MISSING_TITLE));
    }
}
