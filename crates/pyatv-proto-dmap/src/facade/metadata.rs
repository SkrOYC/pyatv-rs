//! `DmapMetadata`: now-playing state and artwork, with the small artwork cache.
//!
//! Port of `pyatv/protocols/dmap/__init__.py:395-446`.

use std::sync::{Arc, Mutex, PoisonError};

use pyatv_core::Result as CoreResult;
use pyatv_core::interface::{BoxFuture, Metadata};
use pyatv_core::models::{App, ArtworkInfo, Playing};

use crate::client::BaseDmapAppleTV;

/// How many artwork images to keep (`Cache(limit=4)`, `__init__.py:402`).
pub const ARTWORK_CACHE_LIMIT: usize = 4;

/// The MIME type DMAP artwork is always reported as (`__init__.py:432`).
///
/// Hardcoded upstream. The device sends no `Content-Type` worth trusting and the images are PNG in
/// practice, so the claim is asserted rather than sniffed.
pub const ARTWORK_MIMETYPE: &str = "image/png";

/// A tiny insertion-ordered bounded cache, evicting oldest-first.
///
/// `pyatv/support/cache.py`'s `Cache` is an `OrderedDict` with a size limit and no expiry, used
/// here and nowhere else in DMAP. Four entries do not justify a crate.
#[derive(Debug, Default)]
struct ArtworkCache {
    entries: Vec<(String, ArtworkInfo)>,
}

impl ArtworkCache {
    fn get(&self, key: &str) -> Option<ArtworkInfo> {
        self.entries
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, info)| info.clone())
    }

    fn put(&mut self, key: String, info: ArtworkInfo) {
        self.entries.retain(|(candidate, _)| *candidate != key);
        if self.entries.len() >= ARTWORK_CACHE_LIMIT {
            self.entries.remove(0);
        }
        self.entries.push((key, info));
    }
}

/// Now-playing metadata for one device.
#[derive(Debug)]
pub struct DmapMetadata {
    identifier: Option<String>,
    apple_tv: Arc<BaseDmapAppleTV>,
    cache: Mutex<ArtworkCache>,
}

impl DmapMetadata {
    /// Metadata for the device `apple_tv` is connected to, reporting `identifier` as its id.
    #[must_use]
    pub fn new(identifier: Option<String>, apple_tv: Arc<BaseDmapAppleTV>) -> Self {
        Self {
            identifier,
            apple_tv,
            cache: Mutex::new(ArtworkCache::default()),
        }
    }

    /// `artwork` (`__init__.py:409-436`).
    ///
    /// The play status is fetched first purely to get a cache key — upstream's own comment is
    /// "Having to fetch 'playing' here is not ideal, but an identifier is needed and we cannot
    /// trust any previous identifiers" — and the fetched image is cached against it.
    async fn artwork_inner(
        &self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> crate::Result<Option<ArtworkInfo>> {
        let identifier = self.apple_tv.playstatus(false).await?.hash;

        if let Some(key) = identifier.as_deref()
            && let Some(cached) = self.cached(key)
        {
            tracing::debug!(key, "retrieved artwork from cache");
            return Ok(Some(cached));
        }

        tracing::debug!("fetching artwork");
        let Some(bytes) = self.apple_tv.artwork(width, height).await? else {
            return Ok(None);
        };

        let info = ArtworkInfo {
            bytes,
            mimetype: ARTWORK_MIMETYPE.to_owned(),
            // **Divergence in representation, not in meaning.** Upstream hardcodes `width=-1,
            // height=-1` because DMAP artwork responses carry no dimensions and its `ArtworkInfo`
            // has no way to say "unknown". `pyatv_core::ArtworkInfo` uses `Option`, so the same
            // fact is `None`. Upstream's own comment notes that reading them out of the PNG header
            // would be feasible and that nobody has done it.
            width: None,
            height: None,
        };

        if let Some(key) = identifier {
            self.locked().put(key, info.clone());
        }
        Ok(Some(info))
    }

    fn cached(&self, key: &str) -> Option<ArtworkInfo> {
        self.locked().get(key)
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, ArtworkCache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Metadata for DmapMetadata {
    /// `device_id` (`__init__.py:404-407`): whatever `core.config.identifier` was at setup.
    fn device_id(&self) -> Option<&str> {
        self.identifier.as_deref()
    }

    /// `playing` (`__init__.py:443-445`): a fresh `playstatusupdate` from revision zero.
    fn playing(&self) -> BoxFuture<'_, CoreResult<Playing>> {
        Box::pin(async move { self.apple_tv.playstatus(false).await.map_err(Into::into) })
    }

    fn artwork(
        &self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> BoxFuture<'_, CoreResult<Option<ArtworkInfo>>> {
        Box::pin(async move { self.artwork_inner(width, height).await.map_err(Into::into) })
    }

    /// `artwork_id` (`__init__.py:438-441`) returns `apple_tv.latest_hash` — the hash from whenever
    /// a play status was *last* fetched, not a freshly computed one. A caller polling this without
    /// calling `playing()` therefore sees the previous track's id, which is upstream's behaviour and
    /// is what makes the value usable as a cache key at all.
    fn artwork_id(&self) -> Option<String> {
        self.apple_tv.state().latest_hash
    }

    /// DMAP has no notion of which app is playing.
    ///
    /// Upstream raises `NotSupportedError` from the base class, which
    /// `test_app_not_supported` covers (`tests/protocols/dmap/test_dmap_functional.py:92-94`).
    /// This trait returns an `Option`, so absence is `None` and the facade reports the feature as
    /// unsupported rather than failing on use.
    fn app(&self) -> Option<App> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::{ARTWORK_CACHE_LIMIT, ArtworkCache};
    use pyatv_core::models::ArtworkInfo;

    fn artwork(bytes: &[u8]) -> ArtworkInfo {
        ArtworkInfo {
            bytes: bytes.to_vec(),
            mimetype: super::ARTWORK_MIMETYPE.to_owned(),
            width: None,
            height: None,
        }
    }

    #[test]
    fn the_cache_returns_what_was_put_in() {
        let mut cache = ArtworkCache::default();
        cache.put("a".to_owned(), artwork(b"one"));

        assert_eq!(cache.get("a").map(|it| it.bytes), Some(b"one".to_vec()));
        assert!(cache.get("b").is_none());
    }

    /// Four entries, oldest evicted first (`Cache(limit=4)`).
    #[test]
    fn the_cache_evicts_the_oldest_entry() {
        let mut cache = ArtworkCache::default();
        for index in 0..=ARTWORK_CACHE_LIMIT {
            cache.put(
                index.to_string(),
                artwork(&[u8::try_from(index).unwrap_or(0)]),
            );
        }

        assert_eq!(cache.entries.len(), ARTWORK_CACHE_LIMIT);
        assert!(cache.get("0").is_none(), "the first entry should be gone");
        assert!(cache.get(&ARTWORK_CACHE_LIMIT.to_string()).is_some());
    }

    /// Re-putting a key replaces it rather than growing the cache.
    #[test]
    fn re_caching_a_key_replaces_it() {
        let mut cache = ArtworkCache::default();
        cache.put("a".to_owned(), artwork(b"one"));
        cache.put("a".to_owned(), artwork(b"two"));

        assert_eq!(cache.entries.len(), 1);
        assert_eq!(cache.get("a").map(|it| it.bytes), Some(b"two".to_vec()));
    }
}
