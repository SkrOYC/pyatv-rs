//! `build_playing_instance` known-answers, built from the same tag shapes the fake device sends.

use pyatv_core::consts::{DeviceState, MediaType, RepeatState, ShuffleState};

use super::{build_playing_instance, content_hash};
use crate::parser::parse;
use crate::tags::{container_tag, string_tag, uint8_tag, uint32_tag};
use crate::{Error, Result};

/// Build a `cmst` container from the tags a fake `handle_playstatus` would emit
/// (`tests/fake_device/dmap.py:211-278`).
fn playstatus(body: &[Vec<u8>]) -> Result<pyatv_core::models::Playing> {
    let parsed = parse(&container_tag("cmst", &body.concat()))?;
    build_playing_instance(&parsed)
}

/// `example_video()` (`tests/fake_device/dmap.py:377-405`): paused, 123s long, 3s in, kind 3.
#[test]
fn a_paused_video_reads_back_field_for_field() {
    let playing = playstatus(&[
        uint32_tag("caps", 3),
        string_tag("cann", "dummy"),
        uint32_tag("cast", 123_000),
        uint32_tag("cant", 120_000),
        uint32_tag("cmmk", 3),
        uint8_tag("cavc", 1),
        uint32_tag("cmsr", 1),
    ])
    .expect("well formed");

    assert_eq!(playing.media_type, MediaType::Video);
    assert_eq!(playing.device_state, DeviceState::Paused);
    assert_eq!(playing.title.as_deref(), Some("dummy"));
    assert_eq!(playing.total_time, Some(123));
    assert_eq!(playing.position, Some(3));
    assert_eq!(playing.shuffle, Some(ShuffleState::Off));
    assert_eq!(playing.repeat, Some(RepeatState::Off));
}

/// `example_music()` (`tests/fake_device/dmap.py:407-432`).
#[test]
fn playing_music_reads_back_every_text_field() {
    let playing = playstatus(&[
        uint32_tag("caps", 4),
        string_tag("cann", "music"),
        string_tag("cana", "artist"),
        string_tag("canl", "album"),
        string_tag("cang", "genre"),
        uint32_tag("cast", 49_000),
        uint32_tag("cant", 27_000),
        uint32_tag("cmmk", 2),
    ])
    .expect("well formed");

    assert_eq!(playing.media_type, MediaType::Music);
    assert_eq!(playing.device_state, DeviceState::Playing);
    assert_eq!(playing.artist.as_deref(), Some("artist"));
    assert_eq!(playing.album.as_deref(), Some("album"));
    assert_eq!(playing.genre.as_deref(), Some("genre"));
    assert_eq!(playing.total_time, Some(49));
    assert_eq!(playing.position, Some(22));
}

/// `nothing_playing()` — an empty `cmst` — is idle and unknown, not an error.
#[test]
fn an_empty_playstatus_is_idle_and_unknown() {
    let playing = playstatus(&[]).expect("an empty response is valid");

    assert_eq!(playing.media_type, MediaType::Unknown);
    assert_eq!(playing.device_state, DeviceState::Idle);
    assert!(playing.title.is_none());
    assert_eq!(playing.position, None);
    // `ms_to_s(None)` is `0`, not "absent", so upstream's `total_time` is `0` here too.
    assert_eq!(playing.total_time, Some(0));
}

/// The state gate comes *before* the media kind (`__init__.py:113-120`): idle wins over `cmmk`.
#[test]
fn an_idle_device_is_unknown_even_when_it_reports_a_media_kind() {
    for caps in [None, Some(uint32_tag("caps", 0))] {
        let mut body = vec![uint32_tag("cmmk", 3)];
        body.extend(caps);
        assert_eq!(
            playstatus(&body).expect("valid").media_type,
            MediaType::Unknown
        );
    }
}

/// With no `cmmk`, artist or album means music and their absence means video
/// (`__init__.py:122-127`).
#[test]
fn the_media_kind_falls_back_to_an_artist_album_heuristic() {
    assert_eq!(
        playstatus(&[uint32_tag("caps", 4), string_tag("cana", "artist")])
            .expect("valid")
            .media_type,
        MediaType::Music
    );
    assert_eq!(
        playstatus(&[uint32_tag("caps", 4), string_tag("canl", "album")])
            .expect("valid")
            .media_type,
        MediaType::Music
    );
    assert_eq!(
        playstatus(&[uint32_tag("caps", 4), string_tag("cann", "title")])
            .expect("valid")
            .media_type,
        MediaType::Video
    );
}

/// Python truthiness: an empty artist string is not an artist.
#[test]
fn an_empty_artist_does_not_make_it_music() {
    assert_eq!(
        playstatus(&[
            uint32_tag("caps", 4),
            string_tag("cana", ""),
            string_tag("canl", ""),
        ])
        .expect("valid")
        .media_type,
        MediaType::Video
    );
}

/// The position is derived by subtraction, and a zero on either side collapses to "unknown"
/// (`__init__.py:154-160`).
#[test]
fn a_zero_time_makes_the_position_unknown() {
    for body in [
        vec![uint32_tag("caps", 4), uint32_tag("cast", 123_000)],
        vec![
            uint32_tag("caps", 4),
            uint32_tag("cast", 123_000),
            uint32_tag("cant", 0),
        ],
        vec![
            uint32_tag("caps", 4),
            uint32_tag("cast", 0),
            uint32_tag("cant", 5_000),
        ],
    ] {
        assert_eq!(playstatus(&body).expect("valid").position, None, "{body:?}");
    }
}

/// More time remaining than the track is long is nonsense; upstream would report it as negative.
#[test]
fn a_remaining_time_past_the_duration_saturates_at_zero() {
    let playing = playstatus(&[
        uint32_tag("caps", 4),
        uint32_tag("cast", 10_000),
        uint32_tag("cant", 20_000),
    ])
    .expect("valid");

    assert_eq!(playing.position, Some(0));
}

/// `test_shuffle_state_albums` (`test_dmap_functional.py:167-172`): every non-zero `cash` is songs.
#[test]
fn every_non_zero_shuffle_value_reads_back_as_songs() {
    for (wire, expected) in [
        (0u8, ShuffleState::Off),
        (1, ShuffleState::Songs),
        (2, ShuffleState::Songs),
    ] {
        let playing = playstatus(&[uint32_tag("caps", 4), uint8_tag("cash", wire)]).expect("valid");
        assert_eq!(playing.shuffle, Some(expected), "cash={wire}");
    }
}

/// `carp` maps one to one onto `RepeatState`; anything else is upstream's `ValueError`.
#[test]
fn repeat_maps_one_to_one_and_rejects_the_rest() {
    for (wire, expected) in [
        (0u8, RepeatState::Off),
        (1, RepeatState::Track),
        (2, RepeatState::All),
    ] {
        let playing = playstatus(&[uint32_tag("caps", 4), uint8_tag("carp", wire)]).expect("valid");
        assert_eq!(playing.repeat, Some(expected), "carp={wire}");
    }

    assert!(matches!(
        playstatus(&[uint32_tag("caps", 4), uint8_tag("carp", 3)]),
        Err(Error::Malformed(_))
    ));
}

/// A play state or media kind outside the tables fails the whole response, as upstream does.
#[test]
fn an_out_of_table_value_fails_the_response() {
    assert!(matches!(
        playstatus(&[uint32_tag("caps", 9)]),
        Err(Error::UnknownPlayState(9))
    ));
    assert!(matches!(
        playstatus(&[uint32_tag("caps", 4), uint32_tag("cmmk", 99_999)]),
        Err(Error::UnknownMediaKind(99_999))
    ));
}

/// The device is free to change integer widths between firmwares, so nothing may assume one.
#[test]
fn field_widths_do_not_matter() {
    let wide = playstatus(&[uint32_tag("caps", 4), uint32_tag("carp", 2)]).expect("valid");
    let narrow = playstatus(&[uint8_tag("caps", 4), uint8_tag("carp", 2)]).expect("valid");

    assert_eq!(wide.device_state, narrow.device_state);
    assert_eq!(wide.repeat, narrow.repeat);
}

/// `Playing.hash`'s fallback is `sha256(f"{title}{artist}{album}{total_time}")`, and an absent
/// field interpolates as the literal `None` (`pyatv/interface.py:601-612`).
#[test]
fn the_content_hash_matches_pyatvs_derivation() {
    let playing = playstatus(&[]).expect("valid");

    // sha256("NoneNoneNone0"), computed with coreutils rather than with this code.
    assert_eq!(
        playing.hash.as_deref(),
        Some("909eeb4ec7d64c3362212b46c2e6d19d5598185652efe0ed9a120fb0b54316bd"),
        "an idle device hashes the literal Nones"
    );
    assert_eq!(content_hash(&playing), playing.hash.expect("set"));
}

/// The hash has to change when the content does, or the artwork cache never invalidates.
#[test]
fn the_content_hash_tracks_the_content() {
    let first = playstatus(&[uint32_tag("caps", 4), string_tag("cann", "one")]).expect("valid");
    let second = playstatus(&[uint32_tag("caps", 4), string_tag("cann", "two")]).expect("valid");
    let again = playstatus(&[uint32_tag("caps", 4), string_tag("cann", "one")]).expect("valid");

    assert_ne!(first.hash, second.hash);
    assert_eq!(first.hash, again.hash);
}
