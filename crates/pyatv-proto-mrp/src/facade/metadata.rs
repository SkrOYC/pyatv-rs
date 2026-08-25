//! `Metadata` and `PushUpdater`: now-playing state, artwork and app identity.
//!
//! Port of `MrpMetadata` (`pyatv/protocols/mrp/__init__.py:481-622`) and `MrpPushUpdater`
//! (`__init__.py:698-743`).
//!
//! # Artwork, and the one thing this crate cannot do
//!
//! There is no artwork message type. Artwork is fetched by re-issuing
//! `PLAYBACK_QUEUE_REQUEST_MESSAGE` with a width and height and reading `artworkData` off the
//! returned content item (`__init__.py:583-598`). Upstream tries a **remote** strategy first: if
//! the metadata carries an `artworkIdentifier` it is treated as an iTunes CDN URL template and
//! fetched over plain HTTPS (`__init__.py:539-581`).
//!
//! That remote strategy needs an HTTP client with TLS, which a protocol crate has no business
//! pulling in — so it is a caller-supplied [`ArtworkFetcher`] instead. Without one, only the local
//! strategy runs, which is the path the hermetic tests exercise and the only one that speaks MRP at
//! all.

use std::sync::{Arc, Mutex};

use pyatv_core::interface::{BoxFuture, Metadata, PlaybackListener, PushUpdater};
use pyatv_core::models::{App, ArtworkInfo, Playing};
use pyatv_core::{Error as CoreError, Result as CoreResult};

use crate::player_state::queue_index;
use crate::protobuf::extensions;
use crate::protocol::MrpProtocol;
use crate::{Result, messages};

/// Fetches artwork from a URL the device advertised.
///
/// Supplied by the umbrella crate, which already owns an HTTP client; see the module docs.
pub trait ArtworkFetcher: Send + Sync + std::fmt::Debug {
    /// Fetch `url`, returning the bytes and the response's content type.
    ///
    /// Returning `Ok(None)` means "not available", which makes the caller fall through to the next
    /// strategy — upstream's behaviour for a non-200 response or a client error.
    ///
    /// # Errors
    ///
    /// Returns an error only for a failure the caller should see; a plain fetch miss is
    /// `Ok(None)`.
    fn fetch(&self, url: &str) -> BoxFuture<'_, Result<FetchedArtwork>>;
}

/// The bytes and content type of a fetched image, or `None` when the URL yielded nothing.
pub type FetchedArtwork = Option<(Vec<u8>, String)>;

/// How many artwork entries are cached (`Cache(limit=4)`, `__init__.py:497`).
pub const ARTWORK_CACHE_LIMIT: usize = 4;

/// The sentinel width/height the iTunes CDN reads as "no constraint, preserve aspect ratio".
pub const ARTWORK_UNCONSTRAINED: u32 = 999_999;

/// A cache hit, which may itself be "this item has no artwork".
///
/// A distinct type rather than `Option<Option<ArtworkInfo>>`, because the two layers mean entirely
/// different things and the nesting reads as an accident.
#[derive(Debug, Clone)]
struct Cached(Option<ArtworkInfo>);

/// A tiny insertion-ordered cache, as upstream's `Cache` is.
#[derive(Debug, Default)]
struct ArtworkCache {
    entries: Vec<(String, Option<ArtworkInfo>)>,
}

impl ArtworkCache {
    fn get(&self, key: &str) -> Option<Cached> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| Cached(value.clone()))
    }

    fn put(&mut self, key: String, value: Option<ArtworkInfo>) {
        self.entries.retain(|(candidate, _)| candidate != &key);
        self.entries.push((key, value));
        if self.entries.len() > ARTWORK_CACHE_LIMIT {
            self.entries.remove(0);
        }
    }
}

/// MRP's now-playing metadata.
#[derive(Debug)]
pub struct MrpMetadata {
    protocol: Arc<MrpProtocol>,
    identifier: Option<String>,
    fetcher: Option<Arc<dyn ArtworkFetcher>>,
    cache: Mutex<ArtworkCache>,
}

impl MrpMetadata {
    /// Wrap a connected protocol.
    #[must_use]
    pub fn new(
        protocol: Arc<MrpProtocol>,
        identifier: Option<String>,
        fetcher: Option<Arc<dyn ArtworkFetcher>>,
    ) -> Self {
        Self {
            protocol,
            identifier,
            fetcher,
            cache: Mutex::new(ArtworkCache::default()),
        }
    }

    /// The URLs upstream would try, in order (`_fetch_remote_artwork`, `__init__.py:539-566`).
    ///
    /// `artworkIdentifier` is a `str.format` template with `w`/`h`/`c`/`f` keys; a template that
    /// does not contain them formats to itself, which upstream tolerates and so does this. The
    /// fixed-size `artworkURL` is appended as a fallback.
    fn remote_urls(&self, width: u32, height: u32) -> Vec<String> {
        let mut urls = Vec::new();
        let metadata = self
            .protocol
            .state()
            .with_playing(|playing| playing.metadata().cloned());
        let Some(metadata) = metadata else {
            return urls;
        };

        if let Some(template) = metadata.artwork_identifier.as_deref() {
            let url = template
                .replace("{w}", &width.to_string())
                .replace("{h}", &height.to_string())
                .replace("{c}", "bb")
                .replace("{f}", "png");
            if url.starts_with("http://") || url.starts_with("https://") {
                urls.push(url);
            }
        }
        if let Some(url) = metadata.artwork_url.as_deref() {
            urls.push(url.to_owned());
        }

        urls
    }

    /// `_fetch_remote_artwork` (`__init__.py:539-581`), delegated to the caller's fetcher.
    async fn fetch_remote(&self, width: u32, height: u32) -> Option<ArtworkInfo> {
        let fetcher = self.fetcher.as_ref()?;

        for url in self.remote_urls(width, height) {
            match fetcher.fetch(&url).await {
                Ok(Some((bytes, mimetype))) => {
                    return Some(ArtworkInfo {
                        bytes,
                        mimetype,
                        // Upstream records the *requested* size here with its own
                        // `TODO: get actual image size` (`__init__.py:576-578`).
                        width: Some(width),
                        height: Some(height),
                    });
                }
                Ok(None) => {}
                Err(error) => tracing::debug!(%error, url, "could not fetch remote artwork"),
            }
        }

        None
    }

    /// `_fetch_local_artwork` (`__init__.py:583-598`) — the only strategy that speaks MRP.
    async fn fetch_local(&self, width: f64, height: f64) -> Result<Option<ArtworkInfo>> {
        let state = self.protocol.state();
        let location = state.location();
        let mimetype = state.with_playing(|playing| {
            playing
                .metadata()
                .and_then(|it| it.artwork_mime_type.clone())
        });

        // Sent verbatim, as upstream sends `playing.location` (`__init__.py:587`), negative or
        // not: normalising it here would ask the device about a different queue entry.
        let response = self
            .protocol
            .send_and_receive(messages::playback_queue_request(location, width, height)?)
            .await?;

        // `if not resp.HasField("type"): return None` (`__init__.py:590-591`).
        if response.envelope().r#type.is_none() {
            return Ok(None);
        }

        let inner = response.inner(&extensions::SET_STATE_MESSAGE)?;
        let items = inner
            .playback_queue
            .map(|queue| queue.content_items)
            .unwrap_or_default();
        // `contentItems[playing.location]` (`__init__.py:592`) — the same Python subscript the
        // player state uses, so the same resolution applies.
        let Some(item) =
            queue_index(location, items.len()).and_then(|index| items.into_iter().nth(index))
        else {
            return Ok(None);
        };

        Ok(Some(ArtworkInfo {
            bytes: item.artwork_data.unwrap_or_default(),
            mimetype: mimetype.unwrap_or_default(),
            width: item
                .artwork_data_width
                .and_then(|it| u32::try_from(it).ok()),
            height: item
                .artwork_data_height
                .and_then(|it| u32::try_from(it).ok()),
        }))
    }
}

impl Metadata for MrpMetadata {
    fn device_id(&self) -> Option<String> {
        self.identifier.clone()
    }

    fn playing(&self) -> BoxFuture<'_, CoreResult<Playing>> {
        Box::pin(async move { Ok(self.protocol.state().playing()) })
    }

    /// Cached, then remote, then local (`__init__.py:504-537`).
    ///
    /// The default request size is upstream's: `width or 0` and `height or -1`, which the local
    /// path passes straight into the message and the remote path turns into the CDN's
    /// unconstrained sentinel.
    fn artwork(
        &self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> BoxFuture<'_, CoreResult<Option<ArtworkInfo>>> {
        Box::pin(async move {
            let Some(identifier) = self.artwork_id() else {
                tracing::debug!("no artwork available");
                return Ok(None);
            };

            if let Some(Cached(artwork)) = self
                .cache
                .lock()
                .ok()
                .and_then(|cache| cache.get(&identifier))
            {
                tracing::debug!(identifier, "retrieved artwork from cache");
                return Ok(artwork);
            }

            let remote_width = width.filter(|it| *it > 0).unwrap_or(ARTWORK_UNCONSTRAINED);
            let remote_height = height.filter(|it| *it > 0).unwrap_or(ARTWORK_UNCONSTRAINED);

            let artwork = match self.fetch_remote(remote_width, remote_height).await {
                Some(artwork) => Some(artwork),
                None => self
                    .fetch_local(
                        f64::from(width.unwrap_or(0)),
                        height.map_or(-1.0, f64::from),
                    )
                    .await
                    .map_err(CoreError::from)?,
            };

            if let Ok(mut cache) = self.cache.lock() {
                cache.put(identifier, artwork.clone());
            }
            Ok(artwork)
        })
    }

    /// `artwork_id` (`__init__.py:600-610`).
    ///
    /// Only meaningful when the item advertises artwork at all; then it prefers
    /// `artworkIdentifier`, falls back to `contentIdentifier`, and finally to the item's own
    /// identifier.
    fn artwork_id(&self) -> Option<String> {
        self.protocol.state().with_playing(|playing| {
            let metadata = playing.metadata()?;
            if !metadata.artwork_available.unwrap_or_default() && metadata.artwork_url.is_none() {
                return None;
            }
            metadata
                .artwork_identifier
                .clone()
                .or_else(|| metadata.content_identifier.clone())
                .or_else(|| playing.item_identifier().map(str::to_owned))
        })
    }

    fn app(&self) -> Option<App> {
        self.protocol.state().app()
    }
}

/// MRP's push updates.
///
/// `MrpPushUpdater` (`__init__.py:698-743`). `start` immediately schedules one synthetic update
/// rather than waiting for the device — `initial_delay` is accepted for interface compatibility
/// and, as upstream, never actually used.
#[derive(Debug)]
pub struct MrpPushUpdater {
    protocol: Arc<MrpProtocol>,
}

impl MrpPushUpdater {
    /// Wrap a connected protocol.
    #[must_use]
    pub const fn new(protocol: Arc<MrpProtocol>) -> Self {
        Self { protocol }
    }
}

impl PushUpdater for MrpPushUpdater {
    fn active(&self) -> bool {
        self.protocol.state().push_active()
    }

    fn set_listener(&self, listener: &Arc<dyn PlaybackListener>) {
        self.protocol.state().set_push_listener(listener);
    }

    fn start(&self, _initial_delay_ms: u64) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            if self.active() {
                return Ok(());
            }
            self.protocol.state().set_push_active(true);
            self.protocol.state().post_update();
            Ok(())
        })
    }

    fn stop(&self) {
        self.protocol.state().set_push_active(false);
    }
}
