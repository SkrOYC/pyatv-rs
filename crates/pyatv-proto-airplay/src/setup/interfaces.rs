//! The capability traits the AirPlay protocol implements itself.
//!
//! Port of `AirPlayFeatures` (`pyatv/protocols/airplay/__init__.py:57-76`), `AirPlayStream`
//! (`__init__.py:77-166`) and `AirPlayRemoteControl` (`__init__.py:168-177`). These are AirPlay's
//! *own* contributions — the tunnelled MRP session registers a separate, much larger set under
//! `Protocol::MRP`, and the facade's relayer decides which answers a given call.

use std::path::Path;

use pyatv_core::airplay::AirPlayFlags;
use pyatv_core::consts::InputAction;
use pyatv_core::features::{FeatureInfo, FeatureName, FeatureState};
use pyatv_core::interface::{BoxFuture, Features, RemoteControl, Stream};

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
/// `AirPlayStream` (`__init__.py:77-166`) with `play_url` left for Step 5. `stream_file` is
/// unimplemented upstream too — `AirPlayStream` does not override it, so the abstract base raises
/// `NotSupportedError`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AirPlayStream;

impl Stream for AirPlayStream {
    fn play_url(&self, url: &str) -> BoxFuture<'_, pyatv_core::Result<()>> {
        let url = url.to_owned();
        Box::pin(async move {
            // TODO(step-5): the AirPlay 1/2 `/play` and RTSP paths, plus the `RemoteControl`
            // takeover `play_url` performs around them (`__init__.py:106-146`).
            Err(pyatv_core::Error::NotSupported(format!(
                "play_url({url}) is not implemented yet"
            )))
        })
    }

    fn stream_file(&self, path: &Path) -> BoxFuture<'_, pyatv_core::Result<()>> {
        let path = path.display().to_string();
        Box::pin(async move {
            Err(pyatv_core::Error::NotSupported(format!(
                "AirPlay cannot stream {path}; RAOP does that"
            )))
        })
    }

    fn close(&self) {}
}

/// AirPlay's one remote-control method.
///
/// `AirPlayRemoteControl` (`__init__.py:168-177`) implements `stop()` alone, and its whole body is
/// "close the play-url connection if one is open". With no connection open it does nothing and
/// succeeds, which is exactly the state this stub is always in until Step 5 lands `play_url`.
///
/// Every other method reports [`pyatv_core::Error::NotSupported`]; the facade's relayer prefers
/// MRP, DMAP and Companion over AirPlay for all of them anyway
/// (`pyatv_core::facade::DEFAULT_PRIORITIES`).
#[derive(Debug, Default, Clone, Copy)]
pub struct AirPlayRemoteControl;

impl AirPlayRemoteControl {
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
        // `self.stream.stop()` with no connection open (`__init__.py:96-99,175-177`).
        Box::pin(async { Ok(()) })
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
