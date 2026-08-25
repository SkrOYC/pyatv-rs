//! `FacadeMetadata`: now-playing metadata relayed per method.
//!
//! Port of `FacadeMetadata` (`pyatv/core/facade.py:213-259`), whose five members are each
//! `self.relay("name")`.
//!
//! # Which protocol answers which method
//!
//! Upstream's `relay` picks the first protocol in priority order whose class *overrides* the
//! method. Two of the five members carry a `@feature(...)` decorator and three do not
//! (`pyatv/interface.py:605-660`), which splits them into two groups here:
//!
//! * [`Metadata::artwork`] and [`Metadata::app`] resolve through
//!   [`crate::relayer::Relayer::instance_for`] on [`FeatureName::Artwork`] and [`FeatureName::App`].
//!   That is the difference this wrapper exists for: RAOP registers a [`Metadata`] but declares
//!   neither, exactly as `RaopMetadata` overrides `playing` and nothing else
//!   (`pyatv/protocols/raop/__init__.py:181-206`), so during a RAOP takeover artwork still comes
//!   from MRP rather than becoming `None` for the length of a stream.
//! * [`Metadata::playing`] has no feature and is the whole point of a takeover, so it goes to
//!   [`crate::relayer::Relayer::main_instance`].
//! * [`Metadata::device_id`] and [`Metadata::artwork_id`] have no feature either, but both return
//!   an [`Option`] that a protocol with no answer fills with `None` — which is indistinguishable
//!   from "does not implement it". They therefore fall through the priority order to the first
//!   protocol that answers, which reproduces upstream's outcome: `RaopMetadata` overrides neither,
//!   so upstream skips RAOP and reaches MRP, and so does this.

use std::sync::Arc;

use crate::features::FeatureName;
use crate::interface::{BoxFuture, Metadata};
use crate::models::{App, ArtworkInfo, Playing};
use crate::relayer::Relayer;
use crate::{Error, Result};

/// Relays each metadata call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeMetadata {
    relayer: Arc<Relayer<dyn Metadata>>,
}

impl FacadeMetadata {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn Metadata>>) -> Self {
        Self { relayer }
    }

    /// The instance that declared `feature`, or the error upstream's `_find_instance` raises.
    fn target(&self, feature: FeatureName) -> Result<Arc<dyn Metadata>> {
        self.relayer
            .instance_for(feature)
            .ok_or_else(|| Error::NotSupported(format!("{feature} is not supported")))
    }

    /// The first protocol, in priority order, that has an answer for `read`.
    fn first_answer<T>(&self, read: impl Fn(&Arc<dyn Metadata>) -> Option<T>) -> Option<T> {
        self.relayer.instances().iter().find_map(read)
    }
}

impl Metadata for FacadeMetadata {
    fn device_id(&self) -> Option<String> {
        self.first_answer(|instance| instance.device_id())
    }

    fn playing(&self) -> BoxFuture<'_, Result<Playing>> {
        match self.relayer.main_instance() {
            Some(target) => Box::pin(async move { target.playing().await }),
            None => Box::pin(async {
                Err(Error::NotSupported(
                    "no protocol reports metadata".to_owned(),
                ))
            }),
        }
    }

    fn artwork(
        &self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> BoxFuture<'_, Result<Option<ArtworkInfo>>> {
        match self.target(FeatureName::Artwork) {
            Ok(target) => Box::pin(async move { target.artwork(width, height).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn artwork_id(&self) -> Option<String> {
        self.first_answer(|instance| instance.artwork_id())
    }

    fn app(&self) -> Option<App> {
        self.relayer
            .instance_for(FeatureName::App)
            .and_then(|target| target.app())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::FacadeMetadata;
    use crate::consts::Protocol;
    use crate::facade::DEFAULT_PRIORITIES;
    use crate::features::FeatureName;
    use crate::interface::{BoxFuture, Metadata};
    use crate::models::{App, ArtworkInfo, Playing};
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    /// Reports its own name everywhere, so a test can see which protocol answered.
    #[derive(Debug)]
    struct Named {
        name: &'static str,
        identifier: Option<&'static str>,
    }

    impl Metadata for Named {
        fn device_id(&self) -> Option<String> {
            self.identifier.map(str::to_owned)
        }

        fn playing(&self) -> BoxFuture<'_, Result<Playing>> {
            Box::pin(async move {
                Ok(Playing {
                    title: Some(self.name.to_owned()),
                    ..Playing::default()
                })
            })
        }

        fn artwork(
            &self,
            _width: Option<u32>,
            _height: Option<u32>,
        ) -> BoxFuture<'_, Result<Option<ArtworkInfo>>> {
            Box::pin(async move {
                Ok(Some(ArtworkInfo {
                    bytes: self.name.as_bytes().to_vec(),
                    mimetype: "image/png".to_owned(),
                    width: None,
                    height: None,
                }))
            })
        }

        fn artwork_id(&self) -> Option<String> {
            self.identifier.map(str::to_owned)
        }

        fn app(&self) -> Option<App> {
            Some(App {
                name: self.name.to_owned(),
                identifier: self.name.to_owned(),
            })
        }
    }

    /// One MRP registration declaring the metadata features, one RAOP registration declaring none
    /// of them — the shape `pyatv::connect` produces on a modern device.
    fn setup() -> (FacadeMetadata, Arc<Relayer<dyn Metadata>>) {
        let relayer: Arc<Relayer<dyn Metadata>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        relayer
            .register(
                Protocol::Mrp,
                Arc::new(Named {
                    name: "mrp",
                    identifier: Some("device-id"),
                }),
                [FeatureName::Artwork, FeatureName::App]
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
            )
            .expect("the protocol is in the priority list");
        relayer
            .register(
                Protocol::Raop,
                Arc::new(Named {
                    name: "raop",
                    identifier: None,
                }),
                [FeatureName::Title].into_iter().collect::<BTreeSet<_>>(),
            )
            .expect("the protocol is in the priority list");

        (FacadeMetadata::new(Arc::clone(&relayer)), relayer)
    }

    /// `test_takeover_and_release` (`tests/core/test_facade.py:544-566`) applied to metadata: the
    /// handle was taken before the takeover and has to follow it.
    #[tokio::test]
    async fn a_takeover_redirects_playing_on_a_handle_taken_earlier() {
        let (metadata, relayer) = setup();

        assert_eq!(
            metadata.playing().await.expect("MRP answers").title,
            Some("mrp".to_owned())
        );

        relayer.takeover(Protocol::Raop).expect("free relayer");
        assert_eq!(
            metadata.playing().await.expect("RAOP answers").title,
            Some("raop".to_owned())
        );

        relayer.release();
        assert_eq!(
            metadata.playing().await.expect("MRP again").title,
            Some("mrp".to_owned())
        );
    }

    /// ...but a takeover does not widen what the holder answers, because RAOP never declared
    /// `Artwork` — the same rule `FacadeStream` applies to `stream_file`.
    #[tokio::test]
    async fn a_takeover_does_not_move_undeclared_methods() {
        let (metadata, relayer) = setup();
        relayer.takeover(Protocol::Raop).expect("free relayer");

        let artwork = metadata
            .artwork(None, None)
            .await
            .expect("MRP declared Artwork")
            .expect("some artwork");
        assert_eq!(artwork.bytes, b"mrp");
        assert_eq!(
            metadata.app().map(|app| app.identifier),
            Some("mrp".to_owned())
        );
    }

    /// The `Option`-returning accessors skip a protocol with no answer, as upstream skips one that
    /// does not override the property at all.
    #[test]
    fn an_identifier_falls_through_to_the_protocol_that_has_one() {
        let (metadata, relayer) = setup();
        relayer.takeover(Protocol::Raop).expect("free relayer");

        assert_eq!(metadata.device_id(), Some("device-id".to_owned()));
        assert_eq!(metadata.artwork_id(), Some("device-id".to_owned()));
    }

    /// A method nobody declared is `NotSupportedError` upstream (`relayer.py:114-115`).
    #[tokio::test]
    async fn an_undeclared_method_is_not_supported() {
        let relayer: Arc<Relayer<dyn Metadata>> =
            Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        relayer
            .register(
                Protocol::Raop,
                Arc::new(Named {
                    name: "raop",
                    identifier: None,
                }),
                BTreeSet::new(),
            )
            .expect("the protocol is in the priority list");
        let metadata = FacadeMetadata::new(relayer);

        let error = metadata
            .artwork(None, None)
            .await
            .expect_err("nobody declared Artwork");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");
        assert!(metadata.app().is_none());
        assert!(metadata.device_id().is_none());
    }
}
