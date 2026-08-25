//! Session ownership: who is allowed to stream, and what the facade can see while they do.
//!
//! Port of `RaopPlaybackManager` (`pyatv/protocols/raop/__init__.py:108-178`) plus the body of
//! `RaopStream.stream_file` (`__init__.py:334-406`), which is where the session lifecycle actually
//! lives.
//!
//! Two locks, for two different jobs. The `tokio` one serialises streaming: only one `stream_file`
//! runs at a time and it holds the RTSP connection across `await` points. The `std` one guards the
//! handful of scalars the synchronous facade accessors read — `Audio::volume` and
//! `Features::get_feature` are not `async` and cannot wait on anything.

pub mod listener;

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use pyatv_core::airplay::{AirPlayVersion, get_protocol_version};
use pyatv_core::models::BaseService;
use pyatv_pairing::HapCredentials;

use crate::audio::{PcmFormat, Source, open_source};
use crate::raop::connection::{self, SharedConnection, with_connection};
use crate::raop::context::StreamContext;
use crate::raop::metadata::TrackMetadata;
use crate::raop::protocol::StreamProtocol;
use crate::raop::rtsp as raop_rtsp;
use crate::raop::stream::{PlaybackInfo, RaopListener, StopHandle, StreamClient};
use crate::raop::volume::{INITIAL_VOLUME, dbfs_to_pct, format_dbfs, pct_to_dbfs};
use crate::{Error, Result};

pub use listener::ManagerListener;

/// What the synchronous facade accessors can see.
#[derive(Debug, Default)]
struct SharedState {
    /// `_is_acquired` (`__init__.py:131-136`).
    acquired: bool,
    /// `context.volume`, in dBFS, surviving between sessions exactly as upstream's long-lived
    /// `StreamContext` does.
    volume: Option<f32>,
    /// `playback_info`, set on `playing()` and cleared on `stopped()`.
    playback_info: Option<PlaybackInfo>,
    /// The live connection, so a volume change during playback reaches the receiver.
    connection: Option<SharedConnection>,
    /// Stops the pacing loop.
    stop: Option<StopHandle>,
}

/// Owns one device's RAOP streaming session.
#[derive(Debug)]
pub struct RaopPlaybackManager {
    address: IpAddr,
    service: BaseService,
    /// Which stream protocol to use, from `settings.protocols.raop.protocol_version`
    /// (`raop/__init__.py:148-151`). [`AirPlayVersion::Auto`] resolves from the TXT record.
    version: AirPlayVersion,
    state: Mutex<SharedState>,
    streaming: tokio::sync::Mutex<()>,
}

impl RaopPlaybackManager {
    /// A manager for one device, with no session open.
    #[must_use]
    pub fn new(address: IpAddr, service: BaseService) -> Self {
        Self {
            address,
            service,
            version: AirPlayVersion::Auto,
            state: Mutex::new(SharedState::default()),
            streaming: tokio::sync::Mutex::new(()),
        }
    }

    /// The same, pinned to a caller-chosen protocol version.
    #[must_use]
    pub fn with_protocol_version(mut self, version: AirPlayVersion) -> Self {
        self.version = version;
        self
    }

    /// Whether a stream is running, which is what gates `Stop` and `Pause`.
    ///
    /// `self.playback_manager.stream_client is not None` (`__init__.py:246-250`).
    #[must_use]
    pub fn is_streaming(&self) -> bool {
        self.locked().connection.is_some()
    }

    /// What is currently playing, or `None` when nothing is.
    #[must_use]
    pub fn playback_info(&self) -> Option<PlaybackInfo> {
        self.locked().playback_info.clone()
    }

    /// Whether the volume has been set to anything since this manager was created.
    ///
    /// `has_changed_volume` (`__init__.py:281-284`) — the flag that decides whether the receiver's
    /// own `initialVolume` is adopted at stream start.
    #[must_use]
    pub fn has_changed_volume(&self) -> bool {
        self.locked().volume.is_some()
    }

    /// Current volume as a percentage.
    ///
    /// `RaopAudio.volume` (`__init__.py:286-293`): the device's value mapped back to percent, or
    /// the flat client-side [`INITIAL_VOLUME`] when nothing is known.
    #[must_use]
    pub fn volume(&self) -> f32 {
        self.locked().volume.map_or(INITIAL_VOLUME, dbfs_to_pct)
    }

    /// Record a volume seen from another protocol.
    ///
    /// `RaopAudio._volume_changed` (`__init__.py:274-279`), whose comment is "we blindly trust any
    /// volume we see here as it's a much better guess than we have". No wire traffic.
    pub fn observe_volume(&self, percent: f32) {
        self.locked().volume = Some(pct_to_dbfs(percent));
    }

    /// Change the volume, on the receiver if one is streaming and locally otherwise.
    ///
    /// `RaopAudio.set_volume` (`__init__.py:295-307`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if a streaming receiver refuses the change.
    pub async fn set_volume(&self, percent: f32) -> Result<()> {
        let dbfs = pct_to_dbfs(percent);
        let connection = self.locked().connection.clone();

        let Some(connection) = connection else {
            self.locked().volume = Some(dbfs);
            return Ok(());
        };

        with_connection(&connection, async |rtsp, http| {
            raop_rtsp::set_parameter(rtsp, http, "volume", &format_dbfs(dbfs)).await
        })
        .await?;
        self.locked().volume = Some(dbfs);
        Ok(())
    }

    /// Stop whatever is streaming.
    ///
    /// `RaopRemoteControl.stop`/`pause` (`__init__.py:419-427`), both of which are the same flag
    /// flip on the stream client.
    pub fn stop(&self) {
        if let Some(stop) = self.locked().stop.as_ref() {
            stop.stop();
        }
    }

    /// Stream a source to the device.
    ///
    /// `RaopStream.stream_file` (`__init__.py:334-406`) end to end. The exclusive-session guard is
    /// upstream's `acquire()`: a second concurrent call fails immediately rather than queueing.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidState`] if a stream is already running, [`Error::Audio`] if the
    /// source cannot be decoded, and whatever the RTSP and streaming layers return.
    pub async fn stream(
        &self,
        source: Source,
        credentials: &HapCredentials,
        metadata: Option<TrackMetadata>,
        override_missing_metadata: bool,
        listener: Option<Arc<dyn RaopListener>>,
    ) -> Result<()> {
        // `try_lock` rather than `lock`: upstream raises rather than queueing, and a caller that
        // waited would be surprised by an unbounded delay.
        let Ok(_guard) = self.streaming.try_lock() else {
            return Err(Error::InvalidState(
                "already streaming to device".to_owned(),
            ));
        };
        self.acquire()?;

        let outcome = Box::pin(self.run_session(
            source,
            credentials,
            metadata,
            override_missing_metadata,
            listener,
        ))
        .await;
        self.release();
        outcome
    }

    /// Everything between `acquire()` and the `finally` block.
    async fn run_session(
        &self,
        source: Source,
        credentials: &HapCredentials,
        metadata: Option<TrackMetadata>,
        override_missing_metadata: bool,
        listener: Option<Arc<dyn RaopListener>>,
    ) -> Result<()> {
        let connection =
            connection::connect(SocketAddr::new(self.address, self.service.port)).await?;
        self.locked().connection = Some(connection.clone());

        let local = connection.lock().await.http.local_address()?.ip();
        let version = get_protocol_version(&self.service, self.version);
        tracing::debug!(?version, "using this AirPlay version for RAOP");

        let mut client = StreamClient::new(connection.clone(), StreamProtocol::new(version), local);
        if let Some(listener) = listener {
            client.set_listener(listener);
        }
        let stored_volume = self.locked().volume;
        client
            .context()
            .with(|context: &mut StreamContext| context.volume = stored_volume);

        client
            .initialize(
                &self.service.properties,
                credentials,
                self.service.password.as_deref(),
            )
            .await?;
        self.locked().stop = Some(client.stop_handle());

        let format = target_format(&client);
        // Boxed because the decode pipeline's future is large enough for clippy's `large_futures`
        // to object to inlining it into this one.
        let mut audio = Box::pin(open_source(source, format)).await?;
        let metadata = resolve_metadata(&audio, metadata, override_missing_metadata);

        let deferred = self.negotiate_volume(&client).await;
        client.send_audio(&mut audio, metadata, deferred).await
    }

    /// Decide the volume to start with, and whether it has to be deferred.
    ///
    /// `stream_file`'s volume block (`__init__.py:384-399`): adopt the receiver's `initialVolume`
    /// when the user has not set one, otherwise push the current value now — and if the receiver
    /// refuses, hand it to `send_audio` to retry once streaming has started. Some receivers really
    /// do answer `500` to a volume set before `FLUSH` (`tests/fake_device/raop.py:59-64`).
    ///
    /// # Two divergences, both in the direction of doing what the user asked
    ///
    /// - **A deferred volume of zero is still applied.** `send_audio` guards its retry with
    ///   `if volume:` (`stream_client.py:450`), and `0.0` is falsy in Python — so upstream silently
    ///   drops a deferred *mute*, which is the one deferred value a user is most likely to have
    ///   meant. This port returns `Some(0.0)` and [`StreamClient::send_audio`] applies it, because
    ///   the option is "was a volume deferred", not "was a non-zero volume deferred".
    /// - **A non-`real` `initialVolume` is read anyway.** Upstream does
    ///   `initial_volume = self.playback_manager.stream_client.initial_volume` and compares it
    ///   with `is not None`, so a receiver that encodes the key as a plist *integer* — `0` and
    ///   `-30` both round-trip that way through several encoders — is honoured there. Reading it
    ///   only as [`plist::Value::as_real`] would silently fall through to the client-side default
    ///   instead, so an integer is accepted here too.
    async fn negotiate_volume(&self, client: &StreamClient) -> Option<f32> {
        let initial = client.info().get("initialVolume").and_then(|value| {
            value.as_real().or_else(|| {
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "a dBFS volume is a small number; precision is irrelevant at this scale"
                )]
                value.as_signed_integer().map(|volume| volume as f64)
            })
        });

        if !self.has_changed_volume()
            && let Some(initial) = initial
        {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "a dBFS volume is a small number; the wire value is a float either way"
            )]
            let initial = initial as f32;
            tracing::debug!(initial, "adopting the receiver's initial volume");
            self.locked().volume = Some(initial);
            client
                .context()
                .with(|context| context.volume = Some(initial));
            return None;
        }

        let percent = self.volume();
        match self.set_volume(percent).await {
            Ok(()) => None,
            Err(error) => {
                tracing::debug!(%error, "failed to set volume, delaying call");
                Some(percent)
            }
        }
    }

    /// Take the exclusive streaming slot.
    fn acquire(&self) -> Result<()> {
        let mut state = self.locked();
        if state.acquired {
            return Err(Error::InvalidState(
                "already streaming to device".to_owned(),
            ));
        }
        state.acquired = true;
        Ok(())
    }

    /// `RaopPlaybackManager.teardown` (`__init__.py:167-178`), minus the socket closing the
    /// stream client already did. The volume deliberately survives.
    fn release(&self) {
        let mut state = self.locked();
        state.acquired = false;
        state.connection = None;
        state.stop = None;
        state.playback_info = None;
    }

    /// Record what a listener reported.
    pub(crate) fn set_playback_info(&self, info: Option<PlaybackInfo>) {
        self.locked().playback_info = info;
    }

    /// The shared scalars, recovered from poisoning — every critical section is one assignment.
    fn locked(&self) -> std::sync::MutexGuard<'_, SharedState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The PCM format a decoded source has to be conformed to.
fn target_format(client: &StreamClient) -> PcmFormat {
    let audio = client.context().snapshot().audio;

    PcmFormat {
        sample_rate: audio.sample_rate,
        channels: audio.channels,
        bytes_per_sample: audio.sample_size / 8,
    }
}

/// Combine caller-supplied metadata with what the source carried.
///
/// `stream_file`'s three-way branch (`__init__.py:367-375`): no metadata given uses the source's,
/// `override_missing_metadata` fills the caller's gaps from the source, and metadata given without
/// that flag replaces the source's outright.
#[must_use]
pub fn resolve_metadata(
    source: &crate::audio::AudioSource,
    metadata: Option<TrackMetadata>,
    override_missing_metadata: bool,
) -> TrackMetadata {
    match metadata {
        None => source.metadata().clone(),
        Some(metadata) if override_missing_metadata => metadata.merged_over(source.metadata()),
        Some(metadata) => metadata,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use pyatv_core::consts::Protocol;
    use pyatv_core::models::BaseService;

    use super::{RaopPlaybackManager, resolve_metadata};
    use crate::audio::{AudioSource, PcmFormat};
    use crate::raop::metadata::TrackMetadata;
    use crate::raop::volume::INITIAL_VOLUME;

    fn manager() -> RaopPlaybackManager {
        RaopPlaybackManager::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            BaseService::new(Protocol::Raop, 7000),
        )
    }

    fn source(metadata: TrackMetadata) -> AudioSource {
        AudioSource::from_pcm(
            vec![0u8; 4],
            PcmFormat {
                sample_rate: 44_100,
                channels: 2,
                bytes_per_sample: 2,
            },
            metadata,
        )
    }

    fn track(title: &str) -> TrackMetadata {
        TrackMetadata {
            title: Some(title.to_owned()),
            ..TrackMetadata::default()
        }
    }

    /// Before anything has set a volume, the flat client-side constant is reported.
    #[test]
    fn the_initial_volume_is_the_client_side_constant() {
        let manager = manager();

        assert!(!manager.has_changed_volume());
        assert!((manager.volume() - INITIAL_VOLUME).abs() < 1e-4);
        assert!(!manager.is_streaming());
        assert_eq!(manager.playback_info(), None);
    }

    /// A volume seen from another protocol is adopted without any wire traffic.
    #[test]
    fn an_observed_volume_is_adopted() {
        let manager = manager();

        manager.observe_volume(60.0);

        assert!(manager.has_changed_volume());
        assert!((manager.volume() - 60.0).abs() < 1e-3);
    }

    /// With no session open, `set_volume` is purely local and cannot fail.
    #[tokio::test]
    async fn setting_a_volume_without_a_session_is_local() {
        let manager = manager();

        manager.set_volume(80.0).await.expect("local only");

        assert!((manager.volume() - 80.0).abs() < 1e-3);
    }

    /// Stopping with nothing running is a no-op rather than an error.
    #[test]
    fn stopping_without_a_session_does_nothing() {
        manager().stop();
    }

    #[test]
    fn metadata_without_an_override_replaces_the_sources() {
        let source = source(track("from file"));

        assert_eq!(
            resolve_metadata(&source, Some(track("mine")), false).title,
            Some("mine".to_owned())
        );
    }

    #[test]
    fn no_metadata_uses_the_sources() {
        let source = source(track("from file"));

        assert_eq!(
            resolve_metadata(&source, None, false).title,
            Some("from file".to_owned())
        );
    }

    /// With the override flag, the caller's values win and the source's fill the gaps.
    #[test]
    fn overriding_missing_metadata_merges_the_two() {
        let source = source(TrackMetadata {
            title: Some("from file".to_owned()),
            album: Some("album".to_owned()),
            ..TrackMetadata::default()
        });

        let merged = resolve_metadata(&source, Some(track("mine")), true);

        assert_eq!(merged.title, Some("mine".to_owned()));
        assert_eq!(merged.album, Some("album".to_owned()));
    }
}
