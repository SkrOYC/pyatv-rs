//! `DmapFeatures`: which capabilities are usable right now.
//!
//! Port of `pyatv/protocols/dmap/__init__.py:66-102,527-558`. Three static groups plus one
//! field-presence check against the most recent `playstatusupdate` response.

use std::sync::Arc;

use pyatv_core::interface::Features;
use pyatv_core::{FeatureInfo, FeatureName, FeatureState};

use crate::client::BaseDmapAppleTV;
use crate::parser::{DmapEntry, first};

/// Always [`FeatureState::Available`], with no device query at all.
///
/// `_AVAILABLE_FEATURES` (`__init__.py:66-74`). Navigation works on every DMAP device by
/// construction, since it is a synthetic trackpad drag rather than a capability the device
/// advertises. `test_always_available_features` covers it
/// (`tests/protocols/dmap/test_dmap_functional.py:197-207`).
pub const AVAILABLE_FEATURES: [FeatureName; 7] = [
    FeatureName::Down,
    FeatureName::Left,
    FeatureName::Menu,
    FeatureName::Right,
    FeatureName::Select,
    FeatureName::TopMenu,
    FeatureName::Up,
];

/// Always [`FeatureState::Unknown`].
///
/// `_UNKNOWN_FEATURES` (`__init__.py:76-90`), whose own comment is "supported by the device but we
/// don't now if available". DMAP has no capability advertisement for transport commands, so this
/// is an honest "we cannot tell" rather than a guess in either direction.
/// `test_always_unknown_features` covers it (`test_dmap_functional.py:222-237`).
pub const UNKNOWN_FEATURES: [FeatureName; 12] = [
    FeatureName::Artwork,
    FeatureName::Next,
    FeatureName::Pause,
    FeatureName::Play,
    FeatureName::PlayPause,
    FeatureName::Previous,
    FeatureName::SetPosition,
    FeatureName::SetRepeat,
    FeatureName::SetShuffle,
    FeatureName::Stop,
    FeatureName::SkipForward,
    FeatureName::SkipBackward,
];

/// Available only if the named field was present in the most recent play status.
///
/// `_FIELD_FEATURES` (`__init__.py:92-102`).
///
/// # `Title` is gated on `caps`, not `cann`
///
/// Every other row's field matches its own meaning; [`FeatureName::Title`]'s does not — it is
/// gated on `cmst.caps`, the *play state*. Re-read twice against the source at commit `b277a4c`:
/// `_FIELD_FEATURES = {FeatureName.Title: ("cmst", "caps"), ...}` is literally what
/// `__init__.py:94` says. It looks like an upstream copy-paste slip and is flagged as one in
/// `docs/research/dmap-port-spec.md` §6.4, but it is reproduced rather than "fixed": a device
/// sending `caps` and no `cann` reports `Title` as available under real pyatv, and silently
/// disagreeing about that would be a parity bug this port could not detect.
pub const FIELD_FEATURES: [(FeatureName, [&str; 2]); 8] = [
    (FeatureName::Title, ["cmst", "caps"]),
    (FeatureName::Artist, ["cmst", "cana"]),
    (FeatureName::Album, ["cmst", "canl"]),
    (FeatureName::Genre, ["cmst", "cang"]),
    (FeatureName::TotalTime, ["cmst", "cast"]),
    (FeatureName::Position, ["cmst", "cant"]),
    (FeatureName::Shuffle, ["cmst", "cash"]),
    (FeatureName::Repeat, ["cmst", "carp"]),
];

/// The field the volume buttons are gated on: `dacp.volumecontrollable`.
pub const VOLUME_FIELD: [&str; 2] = ["cmst", "cavc"];

/// DMAP's live feature reporting.
#[derive(Debug)]
pub struct DmapFeatures {
    apple_tv: Arc<BaseDmapAppleTV>,
}

impl DmapFeatures {
    /// Report on the device `apple_tv` is connected to.
    #[must_use]
    pub const fn new(apple_tv: Arc<BaseDmapAppleTV>) -> Self {
        Self { apple_tv }
    }
}

/// `_is_available` (`__init__.py:552-558`).
///
/// Three conditions, all required: a play status has been fetched at least once, the field is
/// present in it, and — when `expected` is given — the field's value equals it. `expected` is only
/// ever `true`, for the volume buttons, and upstream's guard is `if not expected_value or
/// expected_value == value`, so passing `None` means "presence is enough".
fn is_available(
    playstatus: Option<&Vec<DmapEntry>>,
    path: &[&str],
    expected: Option<bool>,
) -> FeatureState {
    let Some(playstatus) = playstatus else {
        return FeatureState::Unavailable;
    };
    // A tag that is present but typed `ignore` or unknown parses to no value at all, which is the
    // Python `None` upstream tests for.
    let Some(value) = first(playstatus, path).filter(|value| !value.is_none()) else {
        return FeatureState::Unavailable;
    };

    match expected {
        None => FeatureState::Available,
        Some(expected) if value.as_bool() == Some(expected) => FeatureState::Available,
        Some(_) => FeatureState::Unavailable,
    }
}

impl Features for DmapFeatures {
    /// `get_feature` (`__init__.py:535-550`), branch for branch and in order.
    ///
    /// The final fall-through is [`FeatureState::Unsupported`], which is what
    /// `test_unsupported_features` asserts for `Home`, `PowerState`, `App` and the rest
    /// (`tests/protocols/dmap/test_dmap_functional.py:209-220`).
    fn get_feature(&self, feature: FeatureName) -> FeatureInfo {
        if AVAILABLE_FEATURES.contains(&feature) {
            return FeatureInfo::available();
        }
        if UNKNOWN_FEATURES.contains(&feature) {
            return FeatureInfo {
                state: FeatureState::Unknown,
                reason: None,
            };
        }

        let state = self.apple_tv.state();
        let playstatus = state.latest_playstatus.as_ref();

        if let Some((_, path)) = FIELD_FEATURES
            .iter()
            .find(|(candidate, _)| *candidate == feature)
        {
            return FeatureInfo {
                state: is_available(playstatus, path, None),
                reason: None,
            };
        }

        if matches!(feature, FeatureName::VolumeUp | FeatureName::VolumeDown) {
            return FeatureInfo {
                state: is_available(playstatus, &VOLUME_FIELD, Some(true)),
                reason: None,
            };
        }

        FeatureInfo::unsupported()
    }

    /// `Features.all_features` (`pyatv/interface.py:1088-1095`), which `DmapFeatures` does not
    /// override: every feature, filtered on the reported **state** rather than on membership.
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
    use super::{AVAILABLE_FEATURES, FIELD_FEATURES, UNKNOWN_FEATURES, VOLUME_FIELD, is_available};
    use pyatv_core::{FeatureName, FeatureState};

    use crate::parser::parse;
    use crate::tags::{container_tag, string_tag, uint8_tag, uint32_tag};

    fn playstatus(body: &[Vec<u8>]) -> Vec<crate::parser::DmapEntry> {
        parse(&container_tag("cmst", &body.concat())).expect("well formed")
    }

    /// The three groups are disjoint, or `get_feature`'s ordered branches would shadow each other.
    #[test]
    fn the_three_groups_do_not_overlap() {
        for feature in AVAILABLE_FEATURES {
            assert!(!UNKNOWN_FEATURES.contains(&feature), "{feature}");
            assert!(
                !FIELD_FEATURES.iter().any(|(it, _)| *it == feature),
                "{feature}"
            );
        }
        for feature in UNKNOWN_FEATURES {
            assert!(
                !FIELD_FEATURES.iter().any(|(it, _)| *it == feature),
                "{feature}"
            );
        }
    }

    /// Nothing fetched yet means nothing is available, however the device is configured.
    #[test]
    fn without_a_play_status_every_field_feature_is_unavailable() {
        for (_, path) in FIELD_FEATURES {
            assert_eq!(is_available(None, &path, None), FeatureState::Unavailable);
        }
        assert_eq!(
            is_available(None, &VOLUME_FIELD, Some(true)),
            FeatureState::Unavailable
        );
    }

    /// `test_features_shuffle_repeat` (`test_dmap_functional.py:239-258`): absent fields are
    /// unavailable, present ones are available.
    #[test]
    fn a_field_feature_follows_the_fields_presence() {
        let idle = playstatus(&[]);
        for (_, path) in [FIELD_FEATURES[6], FIELD_FEATURES[7]] {
            assert_eq!(
                is_available(Some(&idle), &path, None),
                FeatureState::Unavailable
            );
        }

        let music = playstatus(&[
            uint32_tag("caps", 4),
            uint8_tag("cash", 1),
            uint8_tag("carp", 1),
        ]);
        for (_, path) in [FIELD_FEATURES[6], FIELD_FEATURES[7]] {
            assert_eq!(
                is_available(Some(&music), &path, None),
                FeatureState::Available
            );
        }
    }

    /// A field whose value is zero is still *present*, so presence-only checks pass.
    #[test]
    fn a_zero_valued_field_is_still_present() {
        let response = playstatus(&[uint8_tag("cash", 0)]);
        assert_eq!(
            is_available(Some(&response), &["cmst", "cash"], None),
            FeatureState::Available
        );
    }

    /// The volume buttons need `cavc` present **and** true, not merely present
    /// (`__init__.py:545-548`).
    #[test]
    fn the_volume_buttons_need_cavc_to_be_true() {
        assert_eq!(
            is_available(
                Some(&playstatus(&[uint8_tag("cavc", 1)])),
                &VOLUME_FIELD,
                Some(true)
            ),
            FeatureState::Available
        );
        assert_eq!(
            is_available(
                Some(&playstatus(&[uint8_tag("cavc", 0)])),
                &VOLUME_FIELD,
                Some(true)
            ),
            FeatureState::Unavailable
        );
        assert_eq!(
            is_available(Some(&playstatus(&[])), &VOLUME_FIELD, Some(true)),
            FeatureState::Unavailable
        );
    }

    /// `Title` is gated on `caps`, not on `cann`. Verified against the source; see [`FIELD_FEATURES`].
    #[test]
    fn title_availability_follows_the_play_state_field() {
        assert_eq!(FIELD_FEATURES[0].0, FeatureName::Title);
        assert_eq!(FIELD_FEATURES[0].1, ["cmst", "caps"]);

        // A response with a play state but no title reports `Title` available anyway.
        let titleless = playstatus(&[uint32_tag("caps", 4)]);
        assert_eq!(
            is_available(Some(&titleless), &FIELD_FEATURES[0].1, None),
            FeatureState::Available
        );

        // And a response with a title but no play state does not.
        let stateless = playstatus(&[string_tag("cann", "something")]);
        assert_eq!(
            is_available(Some(&stateless), &FIELD_FEATURES[0].1, None),
            FeatureState::Unavailable
        );
    }
}
