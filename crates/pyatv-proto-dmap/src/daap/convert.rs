//! The three wire-value conversions: media kind, play state, and milliseconds to seconds.
//!
//! Port of `pyatv/protocols/dmap/daap.py:31-72`.

use pyatv_core::consts::{DeviceState, MediaType};

use crate::{Error, Result};

/// The `cmst.cmmk` sentinel that means "really large / buffering", special-cased by [`ms_to_s`].
///
/// `2**32 - 1` (`daap.py:70`), whose own source comment is "Happens in some special cases, just
/// return 0". A `cast` or `cant` of exactly this many milliseconds is not a 49-day track.
pub const INVALID_TIME_MS: u64 = u32::MAX as u64;

/// `media_kind` (`daap.py:31-42`): an iTunes media kind to a [`MediaType`].
///
/// The numeric values come from `ITLibMediaItem.h` and a third-party DACP reference, both cited by
/// pyatv's own test file (`tests/protocols/dmap/test_daap.py:9-12`). Note what is *not* in any
/// group — audiobook (5), PDF booklet (6), interactive booklet (9), digital booklet (15), iOS
/// application (16), book (19), PDF book (20) — those are errors upstream, not silent unknowns.
///
/// # Errors
///
/// Returns [`Error::UnknownMediaKind`] for a value in none of the four groups.
pub fn media_kind(kind: u64) -> Result<MediaType> {
    match kind {
        1 | 32_770 => Ok(MediaType::Unknown),
        3 | 7 | 11..=13 | 18 | 32 => Ok(MediaType::Video),
        2 | 4 | 10 | 14 | 17 | 21 | 36 => Ok(MediaType::Music),
        8 | 64 => Ok(MediaType::Tv),
        other => Err(Error::UnknownMediaKind(other)),
    }
}

/// `playstate` (`daap.py:45-61`): a `dacp.playstatus` value to a [`DeviceState`].
///
/// `None` — the field absent from the response — is [`DeviceState::Idle`], not an error. pyatv's
/// own test says why: "None means that the field is not included in a server response, which
/// matches the behavior of dmap.first" (`test_daap.py:213-218`).
///
/// # Errors
///
/// Returns [`Error::UnknownPlayState`] for a value above 6.
pub fn playstate(state: Option<u64>) -> Result<DeviceState> {
    match state {
        None | Some(0) => Ok(DeviceState::Idle),
        Some(1) => Ok(DeviceState::Loading),
        Some(2) => Ok(DeviceState::Stopped),
        Some(3) => Ok(DeviceState::Paused),
        Some(4) => Ok(DeviceState::Playing),
        Some(5 | 6) => Ok(DeviceState::Seeking),
        Some(other) => Err(Error::UnknownPlayState(other)),
    }
}

/// `ms_to_s` (`daap.py:64-72`): milliseconds to whole seconds, or `0` for absent or sentinel.
///
/// # Rounding is round-half-to-even, deliberately
///
/// Upstream is `round(time / 1000.0)`, and Python 3's `round` is banker's rounding: `round(1.5)` is
/// `2`, `round(2.5)` is also `2`, `round(0.5)` is `0`. Integer division would disagree with all
/// three, and round-half-away-from-zero would disagree with two of them.
///
/// `docs/research/dmap-port-spec.md` §6.5 flags this as a parity risk with **no upstream test
/// coverage** — none of `test_daap.py`'s three cases lands on a half-millisecond boundary — so the
/// tests below were derived independently from `CPython`'s documented behaviour rather than ported.
#[must_use]
pub fn ms_to_s(time: Option<u64>) -> u32 {
    let Some(time) = time else {
        return 0;
    };
    if time >= INVALID_TIME_MS {
        return 0;
    }

    let seconds = time / 1000;
    let remainder = time % 1000;
    let round_up = match remainder.cmp(&500) {
        core::cmp::Ordering::Less => false,
        core::cmp::Ordering::Greater => true,
        // Exactly half a second: round to even, which rounds up only from an odd second.
        core::cmp::Ordering::Equal => seconds % 2 == 1,
    };
    let rounded = seconds + u64::from(round_up);

    // `time < 2**32 - 1`, so `rounded <= 4294967`, well inside `u32`.
    u32::try_from(rounded).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::{INVALID_TIME_MS, media_kind, ms_to_s, playstate};
    use crate::Error;
    use pyatv_core::consts::{DeviceState, MediaType};

    /// `MEDIA_KIND_*` (`tests/protocols/dmap/test_daap.py:14-38`), every value upstream names.
    const MEDIA_KINDS: &[(u64, &str)] = &[
        (1, "unknown"),
        (32_770, "unknown2, reported in pyatv issue #182"),
        (2, "song"),
        (3, "movie"),
        (4, "podcast"),
        (5, "audiobook"),
        (6, "pdf booklet"),
        (7, "music video"),
        (8, "tv show"),
        (9, "interactive booklet"),
        (10, "coached audio"),
        (11, "video pass"),
        (12, "home video"),
        (13, "future video"),
        (14, "ringtone"),
        (15, "digital booklet"),
        (16, "ios application"),
        (17, "voice memo"),
        (18, "itunes u"),
        (19, "book"),
        (20, "pdf book"),
        (21, "alert tone"),
        (32, "music video 2"),
        (36, "podcast 2"),
        (64, "tv show 2"),
    ];

    /// `test_unknown_media_kind` (`test_daap.py:175-177`).
    #[test]
    fn the_two_unknown_kinds_map_to_unknown() {
        assert_eq!(media_kind(1).expect("in table"), MediaType::Unknown);
        assert_eq!(media_kind(32_770).expect("in table"), MediaType::Unknown);
    }

    /// `test_video_media_kinds` (`test_daap.py:180-187`).
    #[test]
    fn the_video_kinds_map_to_video() {
        for kind in [3, 7, 32, 11, 12, 13, 18] {
            assert_eq!(
                media_kind(kind).expect("in table"),
                MediaType::Video,
                "{kind}"
            );
        }
    }

    /// `test_music_media_kinds` (`test_daap.py:190-197`).
    #[test]
    fn the_music_kinds_map_to_music() {
        for kind in [2, 4, 36, 10, 14, 17, 21] {
            assert_eq!(
                media_kind(kind).expect("in table"),
                MediaType::Music,
                "{kind}"
            );
        }
    }

    /// `test_tv_kinds` (`test_daap.py:200-202`).
    #[test]
    fn the_tv_kinds_map_to_tv() {
        for kind in [8, 64] {
            assert_eq!(media_kind(kind).expect("in table"), MediaType::Tv, "{kind}");
        }
    }

    /// `test_unknown_media_kind_throws` (`test_daap.py:205-207`), extended to every value upstream
    /// names but does not classify — those are errors, not silent unknowns.
    #[test]
    fn an_out_of_table_kind_is_an_error() {
        for kind in [99_999u64, 0, 5, 6, 9, 15, 16, 19, 20, 22, 63, 65] {
            assert!(
                matches!(media_kind(kind), Err(Error::UnknownMediaKind(reported)) if reported == kind),
                "{kind} should be unknown"
            );
        }
    }

    /// Every kind upstream names is either classified or an error, and never panics.
    #[test]
    fn every_documented_kind_is_accounted_for() {
        for (kind, label) in MEDIA_KINDS {
            let outcome = media_kind(*kind);
            assert!(
                outcome.is_ok() || matches!(outcome, Err(Error::UnknownMediaKind(_))),
                "{kind} ({label})"
            );
        }
    }

    /// `test_device_state_no_media` (`test_daap.py:213-218`) and `test_regular_playstates`
    /// (`test_daap.py:221-228`).
    #[test]
    fn play_states_map_the_way_upstream_maps_them() {
        assert_eq!(playstate(None).expect("absent is idle"), DeviceState::Idle);
        for (state, expected) in [
            (0, DeviceState::Idle),
            (1, DeviceState::Loading),
            (2, DeviceState::Stopped),
            (3, DeviceState::Paused),
            (4, DeviceState::Playing),
            (5, DeviceState::Seeking),
            (6, DeviceState::Seeking),
        ] {
            assert_eq!(
                playstate(Some(state)).expect("in table"),
                expected,
                "{state}"
            );
        }
    }

    /// `test_unknown_playstate_throws` (`test_daap.py:231-233`).
    #[test]
    fn an_out_of_table_play_state_is_an_error() {
        assert!(matches!(
            playstate(Some(99_999)),
            Err(Error::UnknownPlayState(99_999))
        ));
        assert!(matches!(
            playstate(Some(7)),
            Err(Error::UnknownPlayState(7))
        ));
    }

    /// `test_no_time_returns_zero`, `test_time_in_seconds` and `test_invalid_time`
    /// (`test_daap.py:239-251`).
    #[test]
    fn milliseconds_convert_the_way_upstream_converts_them() {
        assert_eq!(ms_to_s(None), 0);
        assert_eq!(ms_to_s(Some(400)), 0);
        assert_eq!(ms_to_s(Some(501)), 1);
        assert_eq!(ms_to_s(Some(36_000)), 36);
        assert_eq!(ms_to_s(Some(INVALID_TIME_MS)), 0);
        assert_eq!(ms_to_s(Some(INVALID_TIME_MS + 1)), 0);
    }

    /// The boundary pyatv's own suite never touches: Python 3's `round` is round-half-to-even.
    ///
    /// `round(0.5) == 0`, `round(1.5) == 2`, `round(2.5) == 2`, `round(3.5) == 4`. Truncating
    /// integer division would give 0, 1, 2, 3; rounding half away from zero would give 1, 2, 3, 4.
    /// Both disagree with `CPython`, which is what a device's timings were interpreted by.
    #[test]
    fn half_millisecond_boundaries_round_to_even() {
        for (milliseconds, expected) in [
            (500u64, 0u32),
            (1_500, 2),
            (2_500, 2),
            (3_500, 4),
            (4_500, 4),
            (499, 0),
            (1_499, 1),
            (1_501, 2),
        ] {
            assert_eq!(ms_to_s(Some(milliseconds)), expected, "{milliseconds}ms");
        }
    }

    /// Just below the sentinel is a real, very long duration and must not be zeroed.
    #[test]
    fn a_time_just_below_the_sentinel_still_converts() {
        assert_eq!(ms_to_s(Some(INVALID_TIME_MS - 1)), 4_294_967);
    }
}
