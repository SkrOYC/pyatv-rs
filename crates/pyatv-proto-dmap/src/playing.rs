//! Turning a `playstatusupdate` response into a [`Playing`].
//!
//! Port of `build_playing_instance` (`pyatv/protocols/dmap/__init__.py:105-190`). Every field lives
//! inside the outer `cmst` (`dmcp.playstatus`) container, so every read is a two-element path.

use pyatv_core::consts::{MediaType, RepeatState, ShuffleState};
use pyatv_core::models::Playing;
use sha2::{Digest, Sha256};

use crate::daap::{media_kind, ms_to_s, playstate};
use crate::parser::{DmapEntry, first_str, first_uint};
use crate::{Error, Result};

/// Build a [`Playing`] from a parsed `playstatusupdate` response.
///
/// # Errors
///
/// Returns [`Error::UnknownMediaKind`] or [`Error::UnknownPlayState`] for a `cmmk`/`caps` value
/// outside pyatv's tables, and [`Error::Malformed`] for a `carp` outside `RepeatState`'s range —
/// upstream raises `ValueError` from `RepeatState(state)` there and does not catch it
/// (`__init__.py:172-177`), so the failure is reproduced rather than smoothed over.
pub fn build_playing_instance(playstatus: &[DmapEntry]) -> Result<Playing> {
    let title = first_str(playstatus, &["cmst", "cann"]).map(ToOwned::to_owned);
    let artist = first_str(playstatus, &["cmst", "cana"]).map(ToOwned::to_owned);
    let album = first_str(playstatus, &["cmst", "canl"]).map(ToOwned::to_owned);
    let genre = first_str(playstatus, &["cmst", "cang"]).map(ToOwned::to_owned);

    let total_time = ms_to_s(first_uint(playstatus, &["cmst", "cast"]));
    let remaining = ms_to_s(first_uint(playstatus, &["cmst", "cant"]));

    let playing = Playing {
        media_type: media_type(playstatus, artist.as_deref(), album.as_deref())?,
        device_state: playstate(first_uint(playstatus, &["cmst", "caps"]))?,
        title,
        artist,
        album,
        genre,
        total_time: Some(total_time),
        position: position(total_time, remaining),
        shuffle: Some(shuffle(first_uint(playstatus, &["cmst", "cash"]))),
        repeat: Some(repeat(first_uint(playstatus, &["cmst", "carp"]))?),
        ..Playing::default()
    };

    Ok(Playing {
        hash: Some(content_hash(&playing)),
        ..playing
    })
}

/// `media_type()` (`__init__.py:112-127`): a three-tier fallback, and the order matters.
///
/// 1. If `caps` is absent or zero, [`MediaType::Unknown`] — decided *before* `cmmk` is even looked
///    at, so a device that reports a media kind while idle still reads as unknown.
/// 2. Otherwise, if `cmmk` is present, whatever [`media_kind`] says.
/// 3. Otherwise a heuristic: music if there is an artist or an album, video if not. Upstream's own
///    comment is "if artist or album exists we assume music (not present for video)".
///
/// Truthiness is Python's throughout: an *empty* artist string does not count as an artist.
fn media_type(
    playstatus: &[DmapEntry],
    artist: Option<&str>,
    album: Option<&str>,
) -> Result<MediaType> {
    if first_uint(playstatus, &["cmst", "caps"]).unwrap_or(0) == 0 {
        return Ok(MediaType::Unknown);
    }

    if let Some(kind) = first_uint(playstatus, &["cmst", "cmmk"]) {
        return media_kind(kind);
    }

    let has_text = |value: Option<&str>| value.is_some_and(|it| !it.is_empty());
    Ok(if has_text(artist) || has_text(album) {
        MediaType::Music
    } else {
        MediaType::Video
    })
}

/// `position()` (`__init__.py:154-160`): derived, because DMAP reports time *remaining*.
///
/// Two upstream quirks are reproduced rather than fixed:
///
/// * a zero `cast` or `cant` is indistinguishable from the field being absent, because the guard is
///   `if not total or not remaining_time`, so a track at its very last second reports no position
///   at all;
/// * that guard means the position is `None`, not `0`.
///
/// **Divergence:** upstream computes `total - remaining` as a signed Python integer, so a device
/// reporting more time remaining than the track is long yields a negative position. That cannot be
/// represented in [`Playing::position`] and is not a meaningful value anyway, so it saturates at
/// zero.
fn position(total_time: u32, remaining: u32) -> Option<u32> {
    if total_time == 0 || remaining == 0 {
        return None;
    }
    Some(total_time.saturating_sub(remaining))
}

/// `shuffle()` (`__init__.py:162-170`).
///
/// DMAP has no wire representation for shuffling by album, so any non-zero `cash` reads back as
/// [`ShuffleState::Songs`] — including the `1` that [`ShuffleState::Albums`] is written as. Setting
/// `Albums` and reading it back therefore yields `Songs`, which
/// `test_shuffle_state_albums`/`test_set_shuffle_albums` pin down
/// (`tests/protocols/dmap/test_dmap_functional.py:167-181`).
fn shuffle(state: Option<u64>) -> ShuffleState {
    match state {
        None | Some(0) => ShuffleState::Off,
        Some(_) => ShuffleState::Songs,
    }
}

/// `repeat()` (`__init__.py:172-177`): the wire value *is* the enum value, one to one.
fn repeat(state: Option<u64>) -> Result<RepeatState> {
    match state {
        None | Some(0) => Ok(RepeatState::Off),
        Some(1) => Ok(RepeatState::Track),
        Some(2) => Ok(RepeatState::All),
        Some(other) => Err(Error::Malformed(format!("unknown repeat state: {other}"))),
    }
}

/// `Playing.hash`'s fallback (`pyatv/interface.py:601-612`).
///
/// `sha256(f"{title}{artist}{album}{total_time}")`, hex-digested. `pyatv-core` deliberately leaves
/// [`Playing::hash`] as `None` when a protocol has no identifier of its own rather than putting a
/// hashing dependency in the core crate, so DMAP computes it here — it needs the value regardless,
/// as the artwork cache key ([`crate::facade::metadata`]) and as `artwork_id`'s return.
///
/// The interpolation is Python's, so an absent field contributes the literal `None` and
/// `total_time` is always a number. Getting that wrong would produce a *different* but still stable
/// hash, which no test would catch and which would silently disagree with pyatv's for the same
/// track.
#[must_use]
pub fn content_hash(playing: &Playing) -> String {
    fn optional(value: Option<&str>) -> &str {
        value.unwrap_or("None")
    }

    let base = format!(
        "{}{}{}{}",
        optional(playing.title.as_deref()),
        optional(playing.artist.as_deref()),
        optional(playing.album.as_deref()),
        playing.total_time.unwrap_or(0),
    );

    hex::encode(Sha256::digest(base.as_bytes()))
}

#[cfg(test)]
mod tests;
