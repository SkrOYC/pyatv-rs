//! `DmapAudio`: the two volume buttons, and nothing else.
//!
//! Port of `pyatv/protocols/dmap/__init__.py:561-574`, which is a two-method class.
//!
//! # The duplication is upstream's
//!
//! `DmapAudio.volume_up` and `DmapRemoteControl.volume_up` send byte-identical requests
//! (`__init__.py:348-354` and `:568-573`). Two public surfaces, one command. This workspace's
//! `RemoteControl` trait has no volume methods at all — the same choice RAOP's facade documents —
//! so here the duplication simply does not arise and the buttons live only on [`DmapAudio`].

use std::sync::Arc;

use pyatv_core::interface::{Audio, BoxFuture};
use pyatv_core::models::OutputDevice;
use pyatv_core::{Error as CoreError, Result as CoreResult};

use crate::client::BaseDmapAppleTV;

/// Volume control over DAAP.
#[derive(Debug)]
pub struct DmapAudio {
    apple_tv: Arc<BaseDmapAppleTV>,
}

impl DmapAudio {
    /// Volume control for the device `apple_tv` is connected to.
    #[must_use]
    pub const fn new(apple_tv: Arc<BaseDmapAppleTV>) -> Self {
        Self { apple_tv }
    }
}

/// The answer for the parts of [`Audio`] DMAP has no command for.
fn unsupported(name: &'static str) -> BoxFuture<'static, CoreResult<()>> {
    Box::pin(async move {
        Err(CoreError::NotSupported(format!(
            "DMAP does not implement {name}"
        )))
    })
}

impl Audio for DmapAudio {
    /// DMAP reports no volume *level*, only whether the buttons work (`cmst.cavc`).
    ///
    /// Upstream inherits `interface.Audio.volume`, which raises `NotSupportedError`. This trait
    /// returns a plain `f32`, so the answer is zero — and the facade never routes here anyway,
    /// because DMAP does not declare [`pyatv_core::FeatureName::Volume`] in its `SetupData`.
    fn volume(&self) -> f32 {
        0.0
    }

    fn set_volume(
        &self,
        level: f32,
        output_device: Option<&OutputDevice>,
    ) -> BoxFuture<'_, CoreResult<()>> {
        let _ = (level, output_device);
        unsupported("set_volume")
    }

    /// `volume_up` (`__init__.py:568-570`).
    fn volume_up(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .ctrl_int_cmd("volumeup")
                .await
                .map_err(Into::into)
        })
    }

    /// `volume_down` (`__init__.py:572-574`).
    fn volume_down(&self) -> BoxFuture<'_, CoreResult<()>> {
        Box::pin(async move {
            self.apple_tv
                .ctrl_int_cmd("volumedown")
                .await
                .map_err(Into::into)
        })
    }

    /// Output-device grouping is an `AirPlay` 2 concept; gen 1-3 hardware predates it entirely.
    fn output_devices(&self) -> Vec<OutputDevice> {
        Vec::new()
    }

    fn add_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, CoreResult<()>> {
        let _ = identifiers;
        unsupported("add_output_devices")
    }

    fn remove_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, CoreResult<()>> {
        let _ = identifiers;
        unsupported("remove_output_devices")
    }

    fn set_output_devices(&self, identifiers: &[String]) -> BoxFuture<'_, CoreResult<()>> {
        let _ = identifiers;
        unsupported("set_output_devices")
    }
}
