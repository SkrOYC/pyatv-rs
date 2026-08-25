//! `FacadeAudio`: volume and output-device control across protocols.
//!
//! Port of `FacadeAudio`'s relaying half (`pyatv/core/facade.py:434-543`). Its *listening* half —
//! remembering the last volume and playback group so a change can be told from a repeat — lives in
//! [`crate::facade::ListenerHub`], for the reason that module documents.
//!
//! Both range checks come from upstream and both raise `ProtocolError`: a device that reports a
//! volume outside `0.0..=100.0` is not trusted (`facade.py:505-512`), and a caller that asks for
//! one is refused before anything goes on the wire (`facade.py:514-522`).

use std::sync::Arc;

use crate::features::FeatureName;
use crate::interface::{Audio, BoxFuture};
use crate::models::OutputDevice;
use crate::relayer::Relayer;
use crate::{Error, Result};

/// The percentage range every volume in the public API lives in.
const VOLUME_RANGE: std::ops::RangeInclusive<f32> = 0.0..=100.0;

/// Relays each audio call to whichever protocol declared it.
#[derive(Debug)]
pub struct FacadeAudio {
    relayer: Arc<Relayer<dyn Audio>>,
}

impl FacadeAudio {
    /// Relay through `relayer`.
    #[must_use]
    pub fn new(relayer: Arc<Relayer<dyn Audio>>) -> Self {
        Self { relayer }
    }

    fn target(&self, feature: FeatureName) -> Result<Arc<dyn Audio>> {
        self.relayer
            .instance_for(feature)
            .ok_or_else(|| Error::NotSupported(format!("{feature} is not supported")))
    }

    /// [`Audio::volume`] with the out-of-range check upstream applies.
    ///
    /// The trait method cannot report it — it returns a bare `f32`, as upstream's property does
    /// until it raises — so this is the way to see the failure rather than a clamped guess.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotSupported`] if no protocol declared `Volume`, and [`Error::Protocol`] if
    /// the protocol reported a level outside `0.0..=100.0`.
    pub fn checked_volume(&self) -> Result<f32> {
        let volume = self.target(FeatureName::Volume)?.volume();
        if VOLUME_RANGE.contains(&volume) {
            Ok(volume)
        } else {
            Err(Error::Protocol(format!("volume {volume} is out of range")))
        }
    }
}

impl Audio for FacadeAudio {
    /// The relayed level, or `0.0` when it is unavailable or out of range.
    ///
    /// Upstream raises in both of those cases (`facade.py:505-512`); the trait's signature has
    /// nowhere to put an error, so the value a device could not sensibly have is reported as the
    /// bottom of the range and [`FacadeAudio::checked_volume`] is what a caller uses to see why.
    fn volume(&self) -> f32 {
        self.checked_volume().unwrap_or_else(|error| {
            tracing::debug!(%error, "reporting volume 0.0");
            0.0
        })
    }

    fn set_volume(
        &self,
        level: f32,
        output_device: Option<&OutputDevice>,
    ) -> BoxFuture<'_, Result<()>> {
        if !VOLUME_RANGE.contains(&level) {
            return Box::pin(async move {
                Err(Error::Protocol(format!("volume {level} is out of range")))
            });
        }
        let output_device = output_device.cloned();
        match self.target(FeatureName::SetVolume) {
            Ok(target) => {
                Box::pin(async move { target.set_volume(level, output_device.as_ref()).await })
            }
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn volume_up(&self) -> BoxFuture<'_, Result<()>> {
        match self.target(FeatureName::VolumeUp) {
            Ok(target) => Box::pin(async move { target.volume_up().await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn volume_down(&self) -> BoxFuture<'_, Result<()>> {
        match self.target(FeatureName::VolumeDown) {
            Ok(target) => Box::pin(async move { target.volume_down().await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    /// The playback group, or empty when no protocol declared `OutputDevices`.
    ///
    /// Upstream raises `NotSupportedError` here (`facade.py:524-528`); an empty group says the
    /// same thing to a caller that cannot catch, and is what every non-MRP protocol returns anyway.
    fn output_devices(&self) -> Vec<OutputDevice> {
        self.target(FeatureName::OutputDevices)
            .map(|target| target.output_devices())
            .unwrap_or_default()
    }

    fn add_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
        let identifiers = identifiers.to_vec();
        match self.target(FeatureName::AddOutputDevices) {
            Ok(target) => Box::pin(async move { target.add_output_devices(&identifiers).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn remove_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
        let identifiers = identifiers.to_vec();
        match self.target(FeatureName::RemoveOutputDevices) {
            Ok(target) => Box::pin(async move { target.remove_output_devices(&identifiers).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }

    fn set_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
        let identifiers = identifiers.to_vec();
        match self.target(FeatureName::SetOutputDevices) {
            Ok(target) => Box::pin(async move { target.set_output_devices(&identifiers).await }),
            Err(error) => Box::pin(async move { Err(error) }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Arc;

    use super::FacadeAudio;
    use crate::consts::Protocol;
    use crate::facade::DEFAULT_PRIORITIES;
    use crate::features::FeatureName;
    use crate::interface::{Audio, BoxFuture};
    use crate::models::OutputDevice;
    use crate::relayer::Relayer;
    use crate::{Error, Result};

    /// An audio implementation that reports whatever level it was built with.
    #[derive(Debug)]
    struct Dummy {
        level: f32,
    }

    impl Audio for Dummy {
        fn volume(&self) -> f32 {
            self.level
        }

        fn set_volume(
            &self,
            _level: f32,
            _output_device: Option<&OutputDevice>,
        ) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn volume_up(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn volume_down(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn output_devices(&self) -> Vec<OutputDevice> {
            Vec::new()
        }

        fn add_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn remove_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn set_output_devices(&self, _identifiers: &[String]) -> BoxFuture<'_, Result<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn relayer_with(levels: &[(Protocol, f32)]) -> Arc<Relayer<dyn Audio>> {
        let relayer: Arc<Relayer<dyn Audio>> = Arc::new(Relayer::new(DEFAULT_PRIORITIES.to_vec()));
        let declared: BTreeSet<_> = [FeatureName::Volume, FeatureName::SetVolume]
            .into_iter()
            .collect();
        for (protocol, level) in levels {
            relayer
                .register(
                    *protocol,
                    Arc::new(Dummy { level: *level }),
                    declared.clone(),
                )
                .expect("the protocol is in the priority list");
        }
        relayer
    }

    /// `test_takeover_and_release` (`tests/core/test_facade.py:544-566`), whose whole point is that
    /// `audio` was captured before the takeover.
    #[test]
    fn a_takeover_redirects_a_handle_taken_earlier() {
        let relayer = relayer_with(&[(Protocol::Raop, 100.0), (Protocol::Mrp, 0.0)]);
        let audio = FacadeAudio::new(Arc::clone(&relayer));

        assert!((audio.volume() - 0.0).abs() < f32::EPSILON);

        relayer.takeover(Protocol::Raop).expect("free relayer");
        assert!((audio.volume() - 100.0).abs() < f32::EPSILON);

        relayer.release();
        assert!((audio.volume() - 0.0).abs() < f32::EPSILON);
    }

    /// `test_audio_get_volume_out_of_range` (`test_facade.py:354-362`).
    #[test]
    fn a_volume_outside_the_range_is_a_protocol_error() {
        for level in [-0.1, 100.1] {
            let audio = FacadeAudio::new(relayer_with(&[(Protocol::Raop, level)]));
            let error = audio.checked_volume().expect_err("out of range");
            assert!(matches!(error, Error::Protocol(_)), "{error}");
        }
    }

    /// `test_audio_set_volume_out_of_range` (`test_facade.py:364-370`): refused before the relay,
    /// so a protocol never sees the bad value.
    #[tokio::test]
    async fn setting_a_volume_outside_the_range_is_refused() {
        let audio = FacadeAudio::new(relayer_with(&[(Protocol::Raop, 50.0)]));
        for level in [-0.1, 100.1] {
            let error = audio
                .set_volume(level, None)
                .await
                .expect_err("out of range");
            assert!(matches!(error, Error::Protocol(_)), "{error}");
        }
        assert!(audio.set_volume(50.0, None).await.is_ok());
    }

    /// Nothing registered means nothing is supported.
    #[tokio::test]
    async fn an_empty_relayer_supports_nothing() {
        let audio = FacadeAudio::new(relayer_with(&[]));
        let error = audio.checked_volume().expect_err("nothing registered");
        assert!(matches!(error, Error::NotSupported(_)), "{error}");
        assert!(audio.output_devices().is_empty());
        assert!(matches!(
            audio.volume_up().await,
            Err(Error::NotSupported(_))
        ));
    }
}
