//! `Features`: what MRP declares, and what is usable right now.
//!
//! Port of `MrpFeatures.get_feature` (`pyatv/protocols/mrp/__init__.py:955-1022`) and the feature
//! set `create_with_connection` returns (`__init__.py:1151-1166`).
//!
//! Two things are worth keeping straight. The **declared** set is a static property of the
//! protocol: it is what the facade's relayer files MRP under, so a feature outside it is never even
//! asked about. **Availability** is a live per-call answer, and most of it is driven by the
//! device's own `CommandInfo` entries rather than by anything this client knows.

use std::collections::BTreeSet;
use std::sync::Arc;

use pyatv_core::features::{FeatureInfo, FeatureName, FeatureState};
use pyatv_core::interface::Features;

use crate::protobuf::{Command, playback_state};
use crate::protocol::MrpProtocol;
use crate::state::MrpState;

/// Features MRP asserts unconditionally (`_FEATURES_SUPPORTED`, `__init__.py:99-116`).
pub const ALWAYS_AVAILABLE: [FeatureName; 16] = [
    FeatureName::Down,
    FeatureName::Home,
    FeatureName::HomeHold,
    FeatureName::Left,
    FeatureName::Menu,
    FeatureName::Right,
    FeatureName::Select,
    FeatureName::TopMenu,
    FeatureName::Up,
    FeatureName::TurnOn,
    FeatureName::TurnOff,
    FeatureName::PowerState,
    FeatureName::OutputDevices,
    FeatureName::AddOutputDevices,
    FeatureName::RemoveOutputDevices,
    FeatureName::SetOutputDevices,
];

/// Features whose availability is the device's `CommandInfo.enabled` for a command
/// (`_FEATURE_COMMAND_MAP`, `__init__.py:118-132`).
///
/// Note `Shuffle`/`Repeat` share a command with `SetShuffle`/`SetRepeat`: reading the mode and
/// changing it are the same capability as far as the device is concerned.
pub const COMMAND_FEATURES: [(FeatureName, Command); 13] = [
    (FeatureName::Next, Command::NextTrack),
    (FeatureName::Pause, Command::Pause),
    (FeatureName::Play, Command::Play),
    (FeatureName::PlayPause, Command::TogglePlayPause),
    (FeatureName::Previous, Command::PreviousTrack),
    (FeatureName::Stop, Command::Stop),
    (FeatureName::SetPosition, Command::SeekToPlaybackPosition),
    (FeatureName::SetRepeat, Command::ChangeRepeatMode),
    (FeatureName::SetShuffle, Command::ChangeShuffleMode),
    (FeatureName::Shuffle, Command::ChangeShuffleMode),
    (FeatureName::Repeat, Command::ChangeRepeatMode),
    (FeatureName::SkipForward, Command::SkipForward),
    (FeatureName::SkipBackward, Command::SkipBackward),
];

/// Which metadata field's presence decides a feature (`_FIELD_FEATURES`, `__init__.py:135-147`).
///
/// Availability is "the field is set", not "the field is non-empty" — a title of `""` still counts
/// as available, because upstream's `HasField` check is about presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataField {
    /// `title`.
    Title,
    /// `trackArtistName`.
    Artist,
    /// `albumName`.
    Album,
    /// `genre`.
    Genre,
    /// `duration`.
    Duration,
    /// `seriesName`.
    SeriesName,
    /// `elapsedTimeTimestamp` — the field `Position` really depends on.
    ElapsedTimeTimestamp,
    /// `seasonNumber`.
    SeasonNumber,
    /// `episodeNumber`.
    EpisodeNumber,
    /// `contentIdentifier`.
    ContentIdentifier,
    /// `iTunesStoreIdentifier`.
    ItunesStoreIdentifier,
}

/// `_FIELD_FEATURES` in upstream's order.
pub const FIELD_FEATURES: [(FeatureName, MetadataField); 11] = [
    (FeatureName::Title, MetadataField::Title),
    (FeatureName::Artist, MetadataField::Artist),
    (FeatureName::Album, MetadataField::Album),
    (FeatureName::Genre, MetadataField::Genre),
    (FeatureName::TotalTime, MetadataField::Duration),
    (FeatureName::SeriesName, MetadataField::SeriesName),
    (FeatureName::Position, MetadataField::ElapsedTimeTimestamp),
    (FeatureName::SeasonNumber, MetadataField::SeasonNumber),
    (FeatureName::EpisodeNumber, MetadataField::EpisodeNumber),
    (
        FeatureName::ContentIdentifier,
        MetadataField::ContentIdentifier,
    ),
    (
        FeatureName::ItunesStoreIdentifier,
        MetadataField::ItunesStoreIdentifier,
    ),
];

/// Features MRP declares beyond the three tables (`__init__.py:1151-1159`).
pub const EXTRA_FEATURES: [FeatureName; 6] = [
    FeatureName::Artwork,
    FeatureName::VolumeDown,
    FeatureName::VolumeUp,
    FeatureName::SetVolume,
    FeatureName::Volume,
    FeatureName::App,
];

/// Everything MRP declares it can serve.
///
/// The union of [`EXTRA_FEATURES`], [`ALWAYS_AVAILABLE`], [`COMMAND_FEATURES`]'s keys and
/// [`FIELD_FEATURES`]'s keys, which is exactly how `create_with_connection` builds it. Note
/// `PushUpdates` is **not** in it: upstream registers the `PushUpdater` interface without declaring
/// the feature, and the facade's own relayer is what reports push support.
#[must_use]
pub fn supported_features() -> BTreeSet<FeatureName> {
    EXTRA_FEATURES
        .into_iter()
        .chain(ALWAYS_AVAILABLE)
        .chain(COMMAND_FEATURES.into_iter().map(|(feature, _)| feature))
        .chain(FIELD_FEATURES.into_iter().map(|(feature, _)| feature))
        .collect()
}

/// `FeatureInfo(state=Available if available else Unavailable)`, upstream's recurring idiom.
///
/// Note the negative case is *unavailable*, not *unsupported*: the feature exists on MRP, the
/// device just cannot serve it right now.
#[must_use]
pub const fn availability(available: bool) -> FeatureInfo {
    if available {
        FeatureInfo::available()
    } else {
        FeatureInfo::unavailable()
    }
}

/// MRP's live feature reporting.
#[derive(Debug)]
pub struct MrpFeatures {
    state: Arc<MrpState>,
}

impl MrpFeatures {
    /// Wrap a connected protocol's state.
    #[must_use]
    pub fn new(protocol: &Arc<MrpProtocol>) -> Self {
        Self {
            state: Arc::clone(protocol.state()),
        }
    }

    /// Whether the current item's metadata has `field` set.
    fn has_field(&self, field: MetadataField) -> bool {
        self.state.with_playing(|playing| {
            let Some(metadata) = playing.metadata() else {
                return false;
            };
            match field {
                MetadataField::Title => metadata.title.is_some(),
                MetadataField::Artist => metadata.track_artist_name.is_some(),
                MetadataField::Album => metadata.album_name.is_some(),
                MetadataField::Genre => metadata.genre.is_some(),
                MetadataField::Duration => metadata.duration.is_some(),
                MetadataField::SeriesName => metadata.series_name.is_some(),
                MetadataField::ElapsedTimeTimestamp => metadata.elapsed_time_timestamp.is_some(),
                MetadataField::SeasonNumber => metadata.season_number.is_some(),
                MetadataField::EpisodeNumber => metadata.episode_number.is_some(),
                MetadataField::ContentIdentifier => metadata.content_identifier.is_some(),
                MetadataField::ItunesStoreIdentifier => metadata.i_tunes_store_identifier.is_some(),
            }
        })
    }

    /// Whether the device reports `command` as enabled on the active player.
    fn command_enabled(&self, command: Command) -> bool {
        self.state.with_playing(|playing| {
            playing
                .command_info(command)
                .is_some_and(|info| info.enabled.unwrap_or_default())
        })
    }

    /// `PlayPause`'s emulation rule (`__init__.py:988-999`).
    ///
    /// Based on the `YouTube` app's behaviour: only the *opposite* of the current state is offered,
    /// so a playing item reports pause as available and play as not. Falls through to the plain
    /// command lookup when neither branch matches.
    fn play_pause(&self) -> Option<FeatureInfo> {
        let state = self.state.playback_state()?;
        match state {
            playback_state::Enum::Playing if self.command_enabled(Command::Pause) => {
                Some(FeatureInfo::available())
            }
            playback_state::Enum::Paused if self.command_enabled(Command::Play) => {
                Some(FeatureInfo::available())
            }
            _ => None,
        }
    }
}

impl Features for MrpFeatures {
    /// Resolve one feature, branch for branch and **in upstream's order**
    /// (`__init__.py:960-1022`).
    ///
    /// The order matters: `PlayPause` is intercepted by the emulation branch before the plain
    /// command lookup, and the unconditional set is checked before everything else, so a feature in
    /// both tables answers from the unconditional one.
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        if ALWAYS_AVAILABLE.contains(&feature) {
            return FeatureInfo::available();
        }

        if feature == FeatureName::Artwork {
            let available = self.state.with_playing(|playing| {
                playing
                    .metadata()
                    .is_some_and(|it| it.artwork_available.unwrap_or_default())
            });
            return availability(available);
        }

        if let Some((_, field)) = FIELD_FEATURES
            .iter()
            .find(|(candidate, _)| *candidate == feature)
        {
            return availability(self.has_field(*field));
        }

        if feature == FeatureName::PlayPause
            && let Some(info) = self.play_pause()
        {
            return info;
        }

        if let Some((_, command)) = COMMAND_FEATURES
            .iter()
            .find(|(candidate, _)| *candidate == feature)
        {
            return availability(self.command_enabled(*command));
        }

        if feature == FeatureName::App {
            return availability(self.state.app().is_some());
        }

        if matches!(feature, FeatureName::VolumeUp | FeatureName::VolumeDown) {
            return availability(self.state.volume_available());
        }

        if matches!(feature, FeatureName::Volume | FeatureName::SetVolume) {
            let volume = self.state.volume();
            return availability(self.state.volume_available() && volume.absolute);
        }

        FeatureInfo::unsupported()
    }

    /// Every feature, filtered on the reported state rather than on membership.
    ///
    /// `Features.all_features` (`pyatv/interface.py:1088-1095`), which `MrpFeatures` does not
    /// override.
    fn all_features(&self, include_unsupported: bool) -> Vec<(FeatureName, FeatureInfo)> {
        FeatureName::ALL
            .into_iter()
            .map(|feature| (feature, self.get_feature(feature)))
            .filter(|(_, info)| include_unsupported || info.state != FeatureState::Unsupported)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALWAYS_AVAILABLE, COMMAND_FEATURES, EXTRA_FEATURES, FIELD_FEATURES, supported_features,
    };
    use pyatv_core::features::FeatureName;

    /// 16 + 13 + 11 + 6 entries, minus the two commands that appear twice under different feature
    /// names — the set is keyed by feature, and `Shuffle`/`SetShuffle` are distinct features.
    #[test]
    fn the_declared_set_is_the_union_of_upstreams_four_sources() {
        let declared = supported_features();
        assert_eq!(
            declared.len(),
            ALWAYS_AVAILABLE.len()
                + COMMAND_FEATURES.len()
                + FIELD_FEATURES.len()
                + EXTRA_FEATURES.len()
        );

        for feature in ALWAYS_AVAILABLE {
            assert!(declared.contains(&feature), "{feature:?} must be declared");
        }
        for (feature, _) in COMMAND_FEATURES {
            assert!(declared.contains(&feature), "{feature:?} must be declared");
        }
    }

    /// What MRP must *not* claim: streaming, apps, accounts, keyboard and gestures are other
    /// protocols' business.
    #[test]
    fn mrp_declares_nothing_it_cannot_serve() {
        let declared = supported_features();
        for feature in [
            FeatureName::PlayUrl,
            FeatureName::StreamFile,
            FeatureName::AppList,
            FeatureName::LaunchApp,
            FeatureName::AccountList,
            FeatureName::TextSet,
            FeatureName::Swipe,
            FeatureName::Guide,
            FeatureName::ControlCenter,
            FeatureName::ChannelUp,
        ] {
            assert!(
                !declared.contains(&feature),
                "{feature:?} must not be declared"
            );
        }
    }
}
