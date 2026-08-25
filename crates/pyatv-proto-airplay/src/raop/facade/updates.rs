//! The read-only half of RAOP's facade: what is playing, the two buttons that work, and the push
//! updates that carry them.
//!
//! Split out of [`super`] purely for size; upstream keeps `RaopMetadata`, `RaopRemoteControl` and
//! `RaopPushUpdater` in the same `raop/__init__.py` as the rest.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use pyatv_core::consts::{DeviceState, InputAction, MediaType, RepeatState, ShuffleState};
use pyatv_core::interface::{BoxFuture, Metadata, PlaybackListener, PushUpdater, RemoteControl};
use pyatv_core::models::{App, ArtworkInfo, Playing};

use crate::raop::manager::RaopPlaybackManager;

/// RAOP's now-playing view.
#[derive(Debug)]
pub struct RaopMetadata {
    manager: Arc<RaopPlaybackManager>,
}

impl RaopMetadata {
    /// Report on the device `manager` owns.
    #[must_use]
    pub fn new(manager: Arc<RaopPlaybackManager>) -> Self {
        Self { manager }
    }

    /// The current snapshot.
    ///
    /// `RaopMetadata.playing` (`raop/__init__.py:188-205`): idle with an unknown media type when
    /// nothing is streaming, and otherwise `Playing`/`Music` with the position and total time both
    /// truncated to whole seconds.
    #[must_use]
    pub fn snapshot(&self) -> Playing {
        let Some(info) = self.manager.playback_info() else {
            return Playing {
                device_state: DeviceState::Idle,
                media_type: MediaType::Unknown,
                ..Playing::default()
            };
        };

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "upstream truncates both to int; a track longer than 2^32 seconds is not real"
        )]
        let total_time = info
            .metadata
            .duration
            .filter(|duration| *duration > 0.0)
            .map(|duration| duration as u32);
        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "as above; upstream is `int(position)`"
        )]
        let position = Some(info.position.max(0.0) as u32);

        Playing {
            device_state: DeviceState::Playing,
            media_type: MediaType::Music,
            title: info.metadata.title,
            artist: info.metadata.artist,
            album: info.metadata.album,
            position,
            total_time,
            ..Playing::default()
        }
    }
}

impl Metadata for RaopMetadata {
    fn device_id(&self) -> Option<&str> {
        None
    }

    fn playing(&self) -> BoxFuture<'_, pyatv_core::Result<Playing>> {
        Box::pin(async move { Ok(self.snapshot()) })
    }

    fn artwork(
        &self,
        _width: Option<u32>,
        _height: Option<u32>,
    ) -> BoxFuture<'_, pyatv_core::Result<Option<ArtworkInfo>>> {
        // RAOP *sends* artwork to the receiver; it can never read any back.
        Box::pin(async { Ok(None) })
    }

    fn artwork_id(&self) -> Option<String> {
        None
    }

    fn app(&self) -> Option<App> {
        None
    }
}

/// RAOP's two remote-control buttons.
///
/// `RaopRemoteControl` (`raop/__init__.py:409-435`). Upstream also duplicates `volume_up` and
/// `volume_down` here, byte for byte with `RaopAudio`'s; this workspace's `RemoteControl` has no
/// volume methods, so the duplication simply does not arise.
#[derive(Debug)]
pub struct RaopRemoteControl {
    manager: Arc<RaopPlaybackManager>,
}

impl RaopRemoteControl {
    /// Control the device `manager` owns.
    #[must_use]
    pub fn new(manager: Arc<RaopPlaybackManager>) -> Self {
        Self { manager }
    }
}

macro_rules! raop_unsupported {
    ($($method:ident($($argument:ident : $type:ty),*)),* $(,)?) => {
        $(
            fn $method(&self $(, $argument: $type)*) -> BoxFuture<'_, pyatv_core::Result<()>> {
                $(let _ = $argument;)*
                unsupported(stringify!($method))
            }
        )*
    };
}

impl RemoteControl for RaopRemoteControl {
    /// `pause` stops rather than pausing, with the source comment "at the moment, pause will stop
    /// playback until it is properly implemented" (`raop/__init__.py:415-419`).
    fn pause(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        self.manager.stop();
        Box::pin(async { Ok(()) })
    }

    fn stop(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        self.manager.stop();
        Box::pin(async { Ok(()) })
    }

    raop_unsupported!(
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
        next(),
        previous(),
        skip_forward(interval: f32),
        skip_backward(interval: f32),
        set_position(position: f32),
        set_shuffle(state: ShuffleState),
        set_repeat(state: RepeatState),
        channel_up(),
        channel_down(),
    );
}

/// RAOP's push updates.
///
/// `RaopPushUpdater` (`raop/__init__.py:70-106`). There is no push channel from the device: an
/// update is posted when *this* client's own listener fires, and only once `start` has been called
/// — upstream's `if push_updater.active` guard.
#[derive(Debug)]
pub struct RaopPushUpdater {
    manager: Arc<RaopPlaybackManager>,
    active: AtomicBool,
    listener: Mutex<Option<Weak<dyn PlaybackListener>>>,
}

impl RaopPushUpdater {
    /// Push updates for the device `manager` owns.
    #[must_use]
    pub fn new(manager: Arc<RaopPlaybackManager>) -> Self {
        Self {
            manager,
            active: AtomicBool::new(false),
            listener: Mutex::new(None),
        }
    }

    /// Post the current state to the listener, if updates have been started.
    ///
    /// `RaopStateListener._trigger` (`raop/__init__.py:538-543`), which fires only when the
    /// updater is active — a `stream_file` running before anyone called `start` posts nothing.
    pub fn state_changed(&self) {
        if !self.active.load(Ordering::SeqCst) {
            return;
        }

        let listener = self
            .listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(Weak::upgrade);

        if let Some(listener) = listener {
            listener.playstatus_update(&RaopMetadata::new(Arc::clone(&self.manager)).snapshot());
        }
    }
}

impl PushUpdater for RaopPushUpdater {
    fn active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    fn set_listener(&self, listener: &Arc<dyn PlaybackListener>) {
        *self
            .listener
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::downgrade(listener));
    }

    /// `RaopPushUpdater.start` (`raop/__init__.py:86-93`): mark active and post once immediately.
    /// The delay upstream accepts is ignored there too.
    fn start(&self, _initial_delay_ms: u64) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move {
            self.active.store(true, Ordering::SeqCst);
            self.state_changed();
            Ok(())
        })
    }

    fn stop(&self) {
        self.active.store(false, Ordering::SeqCst);
    }
}

/// The answer every method RAOP does not implement gives.
///
/// Shared with [`super`], whose `RaopAudio` has the same four unimplemented output-device methods.
pub(crate) fn unsupported(name: &'static str) -> BoxFuture<'static, pyatv_core::Result<()>> {
    Box::pin(async move {
        Err(pyatv_core::Error::NotSupported(format!(
            "RAOP does not implement {name}"
        )))
    })
}
