//! `FacadeStream`: video URLs go to `AirPlay`, audio files go to RAOP.
//!
//! Port of `FacadeStream` (`pyatv/core/facade.py:356-395`). This is the clearest case for relaying
//! per method rather than per trait: both `AirPlay` and RAOP register a `Stream`, `AirPlay`
//! implements only `play_url` and RAOP only `stream_file`, and `AirPlay` outranks RAOP. Picking one
//! instance for the whole trait would make `stream_file` unreachable on any device that advertises
//! both — which is every modern Apple TV.
//!
//! The `play_url` availability gate is upstream's too (`facade.py:369-375`): it raises
//! `NotSupportedError` *before* relaying if `FeatureName::PlayUrl` is not `Available`, so a device
//! whose feature bits say it cannot play video reports that cleanly instead of failing somewhere
//! inside an RTSP exchange.

use std::sync::Arc;

use crate::features::{FeatureName, FeatureState};
use crate::interface::{BoxFuture, Features, Stream};
use crate::models::{MediaMetadata, MediaSource};
use crate::relayer::Relayer;
use crate::{Error, Result};

/// Relays each streaming call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeStream {
    relayer: Arc<Relayer<dyn Stream>>,
    features: Arc<dyn Features>,
}

impl FacadeStream {
    /// Relay through `relayer`, gating `play_url` on `features`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn Stream>>, features: Arc<dyn Features>) -> Self {
        Self { relayer, features }
    }

    fn target(&self, feature: FeatureName) -> Result<Arc<dyn Stream>> {
        self.relayer
            .instance_for(feature)
            .ok_or_else(|| Error::NotSupported(format!("{feature} is not supported")))
    }
}

impl Stream for FacadeStream {
    fn play_url(&self, url: &str) -> BoxFuture<'_, Result<()>> {
        // `if not self._features.in_state(FeatureState.Available, FeatureName.PlayUrl)`
        // (`facade.py:372-373`).
        if self.features.get_feature(FeatureName::PlayUrl).state != FeatureState::Available {
            return Box::pin(async {
                Err(Error::NotSupported("play_url is not supported".to_owned()))
            });
        }

        let url = url.to_owned();
        match self.target(FeatureName::PlayUrl) {
            Ok(target) => Box::pin(async move { target.play_url(&url).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn stream_file(
        &self,
        source: &MediaSource,
        metadata: Option<&MediaMetadata>,
        override_missing_metadata: bool,
    ) -> BoxFuture<'_, Result<()>> {
        let source = source.clone();
        let metadata = metadata.cloned();
        match self.target(FeatureName::StreamFile) {
            Ok(target) => Box::pin(async move {
                target
                    .stream_file(&source, metadata.as_ref(), override_missing_metadata)
                    .await
            }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    /// Close every registered stream, not only the highest-priority one.
    ///
    /// Upstream relays `close` like any other method (`facade.py:364-367`), which on a device with
    /// both protocols reaches `AirPlay`'s and leaves a RAOP stream running. Both implementations
    /// are no-ops when nothing is playing, so closing all of them costs nothing and does what
    /// "close the stream I started" plainly means.
    fn close(&self) {
        for instance in self.relayer.instances() {
            instance.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::{Arc, Mutex};

    use super::FacadeStream;
    use crate::consts::Protocol;
    use crate::facade::DEFAULT_PRIORITIES;
    use crate::features::{FeatureInfo, FeatureName};
    use crate::interface::{BoxFuture, Features, Stream};
    use crate::models::{MediaMetadata, MediaSource};
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    #[derive(Debug)]
    struct Recorder {
        name: &'static str,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl Stream for Recorder {
        fn play_url(&self, url: &str) -> BoxFuture<'_, Result<()>> {
            self.calls
                .lock()
                .expect("uncontended")
                .push(format!("{}:play_url:{url}", self.name));
            Box::pin(async { Ok(()) })
        }

        fn stream_file(
            &self,
            source: &MediaSource,
            _metadata: Option<&MediaMetadata>,
            _override_missing_metadata: bool,
        ) -> BoxFuture<'_, Result<()>> {
            self.calls
                .lock()
                .expect("uncontended")
                .push(format!("{}:stream_file:{source:?}", self.name));
            Box::pin(async { Ok(()) })
        }

        fn close(&self) {
            self.calls
                .lock()
                .expect("uncontended")
                .push(format!("{}:close", self.name));
        }
    }

    /// Reports one named feature available and everything else unavailable.
    #[derive(Debug)]
    struct OneFeature(Option<FeatureName>);

    impl Features for OneFeature {
        fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
            if self.0 == Some(feature) {
                FeatureInfo::available()
            } else {
                FeatureInfo::unavailable()
            }
        }

        fn all_features(&self, _include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
            Vec::new()
        }
    }

    fn setup(available: Option<FeatureName>) -> (FacadeStream, Arc<Mutex<Vec<String>>>) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let relayer: Arc<Relayer<dyn Stream>> = Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));

        relayer
            .register(
                Protocol::AirPlay,
                Arc::new(Recorder {
                    name: "airplay",
                    calls: Arc::clone(&calls),
                }),
                [FeatureName::PlayUrl, FeatureName::Stop]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            )
            .expect("the protocol is in the priority list");
        relayer
            .register(
                Protocol::Raop,
                Arc::new(Recorder {
                    name: "raop",
                    calls: Arc::clone(&calls),
                }),
                [FeatureName::StreamFile, FeatureName::Volume]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            )
            .expect("the protocol is in the priority list");

        (
            FacadeStream::new(relayer, Arc::new(OneFeature(available))),
            calls,
        )
    }

    /// The bug this module exists to fix: `AirPlay` outranks RAOP, but only RAOP declared
    /// `StreamFile`.
    #[tokio::test]
    async fn stream_file_reaches_raop_even_though_airplay_outranks_it() {
        let (stream, calls) = setup(Some(FeatureName::PlayUrl));

        stream
            .stream_file(&MediaSource::from_str_source("/tmp/a.mp3"), None, false)
            .await
            .expect("RAOP declared StreamFile");
        stream
            .play_url("http://host/v.mp4")
            .await
            .expect("AirPlay declared PlayUrl");

        assert_eq!(
            *calls.lock().expect("uncontended"),
            vec![
                "raop:stream_file:File(\"/tmp/a.mp3\")".to_owned(),
                "airplay:play_url:http://host/v.mp4".to_owned(),
            ]
        );
    }

    /// `test_stream_play_url_not_available` (`tests/core/test_facade.py:520-527`).
    #[tokio::test]
    async fn play_url_is_refused_when_the_feature_is_unavailable() {
        let (stream, calls) = setup(None);

        let error = stream
            .play_url("http://host/v.mp4")
            .await
            .expect_err("PlayUrl is not available");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");
        assert!(calls.lock().expect("uncontended").is_empty());
    }

    /// A stream nobody declared is not supported rather than silently relayed.
    #[tokio::test]
    async fn an_undeclared_method_is_not_supported() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let relayer: Arc<Relayer<dyn Stream>> = Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        relayer
            .register(
                Protocol::AirPlay,
                Arc::new(Recorder {
                    name: "airplay",
                    calls: Arc::clone(&calls),
                }),
                [FeatureName::PlayUrl].into_iter().collect::<BTreeSet<_>>(),
            )
            .expect("the protocol is in the priority list");
        let stream = FacadeStream::new(relayer, Arc::new(OneFeature(None)));

        let error = stream
            .stream_file(&MediaSource::from_str_source("/tmp/a.mp3"), None, false)
            .await
            .expect_err("nobody declared StreamFile");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");
    }

    #[test]
    fn close_reaches_every_registered_stream() {
        let (stream, calls) = setup(None);
        stream.close();

        let calls = calls.lock().expect("uncontended");
        assert!(calls.contains(&"airplay:close".to_owned()));
        assert!(calls.contains(&"raop:close".to_owned()));
    }
}
