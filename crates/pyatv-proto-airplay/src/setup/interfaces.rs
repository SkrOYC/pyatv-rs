//! The capability traits the AirPlay protocol implements itself.
//!
//! Port of `AirPlayFeatures` (`pyatv/protocols/airplay/__init__.py:57-76`), `AirPlayStream`
//! (`__init__.py:77-166`) and `AirPlayRemoteControl` (`__init__.py:168-177`). These are AirPlay's
//! *own* contributions — the tunnelled MRP session registers a separate, much larger set under
//! `Protocol::MRP`, and the facade's relayer decides which answers a given call.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pyatv_core::airplay::AirPlayFlags;
use pyatv_core::consts::InputAction;
use pyatv_core::facade::{FacadeTakeover, Interface};
use pyatv_core::features::{FeatureInfo, FeatureName, FeatureState};
use pyatv_core::interface::{BoxFuture, Features, RemoteControl, Stream};
use pyatv_core::models::{MediaMetadata, MediaSource};
use tokio::sync::Notify;

use crate::stream::{AirPlayPlayer, PlayOptions};

/// Live feature reporting for the AirPlay protocol itself.
///
/// `AirPlayFeatures.get_feature` (`__init__.py:65-76`) answers exactly two names and reports
/// everything else `Unavailable` — including names other protocols serve, because the facade asks
/// each registered protocol in priority order.
#[derive(Debug, Clone)]
pub struct AirPlayFeatures {
    flags: AirPlayFlags,
}

impl AirPlayFeatures {
    /// Report against a service's parsed `features` TXT value.
    #[must_use]
    pub fn new(flags: AirPlayFlags) -> Self {
        Self { flags }
    }
}

impl Features for AirPlayFeatures {
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        match feature {
            FeatureName::PlayUrl
                if self.flags.intersects(
                    AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V1
                        | AirPlayFlags::SUPPORTS_AIRPLAY_VIDEO_V2,
                ) =>
            {
                FeatureInfo::available()
            }
            FeatureName::Stop => FeatureInfo::available(),
            _ => FeatureInfo::unavailable(),
        }
    }

    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        FeatureName::ALL
            .iter()
            .map(|feature| (*feature, self.get_feature(*feature)))
            .filter(|(_, info)| include_unsupported || info.state != FeatureState::Unsupported)
            .collect()
    }
}

/// AirPlay's streaming surface.
///
/// `AirPlayStream` (`__init__.py:77-166`). One instance can serve many `play_url` calls; each one
/// opens its own connection, pair-verifies afresh and closes on the way out, which is exactly what
/// upstream does — its `finally` closes the connection every time and nothing is reused across
/// calls (`__init__.py:133-139`, `docs/research/airplay-playurl-raop-port-spec.md` §0 point 6).
///
/// [`Clone`] shares the stop signal, so the [`AirPlayRemoteControl`] built from a clone stops the
/// playback this one started.
#[derive(Debug, Clone, Default)]
pub struct AirPlayStream {
    options: Option<PlayOptions>,
    /// The running playback's stop signal, shared with every clone.
    ///
    /// Present only while a `play_url` is in flight, which is what makes a stop raised with nothing
    /// playing a no-op rather than a permit the *next* playback would consume immediately.
    /// Upstream's equivalent is `self._play_task`, which is likewise `None` between calls
    /// (`__init__.py:86,138`).
    playing: Arc<Mutex<Option<Arc<Notify>>>>,
    /// How this stream claims [`RemoteControl`] for the duration of a playback.
    ///
    /// `self.core.takeover` (`__init__.py:125`). `None` for a stream built outside a facade — a
    /// test, or the `airplay_tunnel_probe` example — in which case there is nothing to claim from
    /// and `play_url` simply runs without it.
    takeover: Option<FacadeTakeover>,
}

impl AirPlayStream {
    /// A stream that can play to `options.address`.
    #[must_use]
    pub fn new(options: PlayOptions) -> Self {
        Self {
            options: Some(options),
            playing: Arc::default(),
            takeover: None,
        }
    }

    /// The same, claiming [`RemoteControl`] from `takeover` while a playback runs.
    #[must_use]
    pub fn with_takeover(mut self, takeover: Option<FacadeTakeover>) -> Self {
        self.takeover = takeover;
        self
    }

    /// A stream with nowhere to play to, which reports every call unsupported.
    ///
    /// The registration `setup()` yields is unconditional upstream — it is produced before anything
    /// is connected and cannot fail (`__init__.py:322-336`) — so a caller that has no address or
    /// credentials to offer still gets a `Stream`, and finds out at call time.
    #[must_use]
    pub fn unconfigured() -> Self {
        Self::default()
    }

    /// Play `url`, starting `position` seconds in, and do not return until it has finished.
    ///
    /// The position argument [`Stream::play_url`] has no room for. Upstream takes it through
    /// `**kwargs` and truncates it with `int(...)` (`__init__.py:130`), so the trait method below
    /// passes zero and this is the way to ask for anything else.
    ///
    /// Starting a second playback while one is running replaces the first one's stop signal, so
    /// [`AirPlayStream::stop`] then reaches only the second. Upstream has the same single-slot
    /// `_play_task` and the same behaviour; the facade's `RemoteControl` takeover is what actually
    /// keeps two callers apart.
    ///
    /// # Errors
    ///
    /// Returns [`pyatv_core::Error::NotSupported`] if this stream was built by
    /// [`AirPlayStream::unconfigured`], [`pyatv_core::Error::Authentication`] if the device refuses
    /// the credentials or the `/play`, and [`pyatv_core::Error::Command`] if the device reports a
    /// playback error.
    pub async fn play_url_at(&self, url: &str, position: f64) -> pyatv_core::Result<()> {
        let Some(options) = self.options.as_ref() else {
            return Err(pyatv_core::Error::NotSupported(
                "this AirPlay service was registered without an address to play to".to_owned(),
            ));
        };

        // `takeover_release = self.core.takeover(RemoteControl)` (`__init__.py:125`), released by
        // the `finally` at `__init__.py:139` — here, by dropping the guard on the way out of this
        // function, on every path including an early `?`. For as long as a URL is playing,
        // `stop()` has to reach *this* stream rather than MRP's remote control, because closing
        // the play connection is the only way an AirPlay playback ends.
        //
        // A refused claim is logged rather than fatal: someone else holding the remote control
        // means the playback is still perfectly playable, just not stoppable through the facade,
        // and upstream would raise `InvalidStateError` out of `play_url` for it.
        let _takeover = match self.takeover.as_ref() {
            Some(takeover) => takeover
                .claim(&[Interface::RemoteControl])
                .inspect_err(|error| {
                    tracing::warn!(%error, "playing without the remote control takeover");
                })
                .ok(),
            None => None,
        };

        let mut player = AirPlayPlayer::connect(options).await?;

        let stop = Arc::new(Notify::new());
        *lock(&self.playing) = Some(Arc::clone(&stop));

        let outcome = player.play_url(url, position, &stop).await;

        *lock(&self.playing) = None;
        if let Err(error) = player.close().await {
            tracing::debug!(%error, "the play connection did not close cleanly");
        }

        Ok(outcome?)
    }

    /// Stop whatever this stream is playing, if anything.
    ///
    /// `AirPlayStream.stop` (`__init__.py:96-99`). There is no `/stop` request in upstream's play
    /// path — the whole mechanism is closing the connection under the `/playback-info` poll — so
    /// nothing goes on the wire here either; the poll is cancelled and the connection closed on the
    /// way out of [`AirPlayStream::play_url_at`].
    pub fn stop(&self) {
        if let Some(stop) = lock(&self.playing).as_ref() {
            // `notify_one`, not `notify_waiters`: a stop raised while the poll is mid-request has
            // to be seen when it comes back round rather than lost.
            stop.notify_one();
        }
    }
}

/// Take the stop-signal lock, ignoring poisoning.
///
/// The guarded value is one `Option<Arc<Notify>>` and nothing between the lock and the unlock can
/// panic, so a poisoned lock can only mean an unrelated thread died holding it — and refusing to
/// stop a playback because of that would be worse than proceeding.
fn lock(playing: &Mutex<Option<Arc<Notify>>>) -> MutexGuard<'_, Option<Arc<Notify>>> {
    playing.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Stream for AirPlayStream {
    fn play_url(&self, url: &str) -> BoxFuture<'_, pyatv_core::Result<()>> {
        let url = url.to_owned();
        Box::pin(async move { self.play_url_at(&url, 0.0).await })
    }

    /// Never reached through the facade — `AirPlay` does not declare `StreamFile`, so
    /// [`pyatv_core::facade::FacadeStream`] routes the call to RAOP. Kept explicit for a caller
    /// holding this registration directly.
    fn stream_file(
        &self,
        source: &MediaSource,
        _metadata: Option<&MediaMetadata>,
        _override_missing_metadata: bool,
    ) -> BoxFuture<'_, pyatv_core::Result<()>> {
        let source = format!("{source:?}");
        Box::pin(async move {
            Err(pyatv_core::Error::NotSupported(format!(
                "AirPlay cannot stream {source}; RAOP does that"
            )))
        })
    }

    fn close(&self) {
        // `AirPlayStream.close` cancels the play task and closes the connection
        // (`__init__.py:88-95`), which is what the stop signal does here.
        self.stop();
    }
}

/// AirPlay's one remote-control method.
///
/// `AirPlayRemoteControl` (`__init__.py:168-177`) implements `stop()` alone, and its whole body is
/// `self.stream.stop()` — close the play-url connection if one is open. With nothing playing it
/// does nothing and succeeds.
///
/// Every other method reports [`pyatv_core::Error::NotSupported`]; the facade's relayer prefers
/// MRP, DMAP and Companion over AirPlay for all of them anyway
/// (`pyatv_core::facade::DEFAULT_PRIORITIES`).
#[derive(Debug, Default, Clone)]
pub struct AirPlayRemoteControl {
    stream: AirPlayStream,
}

impl AirPlayRemoteControl {
    /// Stop whatever `stream` is playing.
    ///
    /// Upstream holds the `AirPlayStream` itself (`__init__.py:170-173`); the clone here shares its
    /// stop signal, so it reaches the same playback.
    #[must_use]
    pub fn new(stream: AirPlayStream) -> Self {
        Self { stream }
    }

    /// The answer every unimplemented button gives.
    fn unsupported(name: &'static str) -> BoxFuture<'static, pyatv_core::Result<()>> {
        Box::pin(async move {
            Err(pyatv_core::Error::NotSupported(format!(
                "AirPlay does not implement {name}"
            )))
        })
    }
}

macro_rules! airplay_unsupported {
    ($($method:ident($($argument:ident : $type:ty),*)),* $(,)?) => {
        $(
            fn $method(&self $(, $argument: $type)*) -> BoxFuture<'_, pyatv_core::Result<()>> {
                $(let _ = $argument;)*
                Self::unsupported(stringify!($method))
            }
        )*
    };
}

impl RemoteControl for AirPlayRemoteControl {
    fn stop(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        // `self.stream.stop()` (`__init__.py:175-177`), which never fails.
        Box::pin(async {
            self.stream.stop();
            Ok(())
        })
    }

    airplay_unsupported!(
        up(action: InputAction),
        down(action: InputAction),
        left(action: InputAction),
        right(action: InputAction),
        select(action: InputAction),
        menu(action: InputAction),
        home(action: InputAction),
        home_hold(),
        top_menu(),
        guide(),
        control_center(),
        screensaver(),
        play(),
        play_pause(),
        pause(),
        next(),
        previous(),
        skip_forward(interval: f32),
        skip_backward(interval: f32),
        set_position(position: f32),
        set_shuffle(state: pyatv_core::consts::ShuffleState),
        set_repeat(state: pyatv_core::consts::RepeatState),
        channel_up(),
        channel_down(),
    );
}
