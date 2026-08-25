//! Now-playing metadata, push updates and media streaming.

use std::path::Path;
use std::sync::Arc;

use crate::Result;
use crate::interface::BoxFuture;
use crate::models::{App, ArtworkInfo, Playing};

/// Pull-based access to what the device is playing.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] when no connected protocol reports metadata, and
/// [`crate::Error::ConnectionLost`] if the transport dropped mid-request.
pub trait Metadata: Send + Sync + std::fmt::Debug {
    /// Stable identifier of the device this metadata came from.
    fn device_id(&self) -> Option<&str>;

    /// A snapshot of the current playback state.
    fn playing(&self) -> BoxFuture<'_, Result<Playing>>;

    /// Artwork for the current item, scaled to at most `width` x `height` when the device supports
    /// scaling. Returns `Ok(None)` when the item genuinely has no artwork.
    fn artwork(
        &self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> BoxFuture<'_, Result<Option<ArtworkInfo>>>;

    /// An opaque token that changes whenever the artwork changes, for cache invalidation.
    fn artwork_id(&self) -> Option<String>;

    /// The app that owns the current item.
    fn app(&self) -> Option<App>;
}

/// Receives push-based playback updates.
///
/// Implemented by the caller and registered with [`PushUpdater::add_listener`].
pub trait PlaybackListener: Send + Sync + std::fmt::Debug {
    /// A new playback state arrived.
    fn playstatus_update(&self, playing: &Playing);
    /// The push channel failed; the updater will attempt to recover.
    fn playstatus_error(&self, error: &crate::Error);
}

/// Push-based now-playing updates.
///
/// # Errors
///
/// [`PushUpdater::start`] returns [`crate::Error::NotSupported`] when no connected protocol can
/// push updates.
pub trait PushUpdater: Send + Sync + std::fmt::Debug {
    /// Whether updates are currently flowing.
    fn active(&self) -> bool;
    /// Register the listener, replacing whatever was registered before.
    ///
    /// One slot, not a list, and held **weakly** — pyatv's `PushUpdater.listener` is a property
    /// backed by a single `weakref.ref` (`pyatv/protocols/mrp/player_state.py:229-235`). Two
    /// consequences follow, and both are contract rather than implementation detail: registering
    /// twice does not deliver twice, and the caller must keep its own `Arc` alive for as long as
    /// it wants updates, because dropping the last one is what unsubscribes.
    fn set_listener(&self, listener: &Arc<dyn PlaybackListener>);
    /// Begin pushing updates after an optional initial delay in milliseconds.
    fn start(&self, initial_delay_ms: u64) -> BoxFuture<'_, Result<()>>;
    /// Stop pushing updates.
    fn stop(&self);
}

/// Video and audio streaming to the device.
///
/// # Errors
///
/// Methods return [`crate::Error::NotSupported`] when neither `AirPlay` nor RAOP is connected, and
/// [`crate::Error::Command`] if the device rejects the stream.
pub trait Stream: Send + Sync + std::fmt::Debug {
    /// Play a video URL via `AirPlay`.
    fn play_url(&self, url: &str) -> BoxFuture<'_, Result<()>>;

    /// Stream an audio file to the device over RAOP.
    fn stream_file(&self, path: &Path) -> BoxFuture<'_, Result<()>>;

    /// Stop any stream this handle started.
    fn close(&self);
}
