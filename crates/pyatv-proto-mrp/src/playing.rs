//! Deriving a [`Playing`] snapshot from the tracked player state.
//!
//! Port of `build_playing_instance` (`pyatv/protocols/mrp/__init__.py:158-293`). Everything here is
//! a pure function of an [`ActivePlayer`] plus the current time, which is what makes the
//! position arithmetic testable without a clock.

use std::time::{SystemTime, UNIX_EPOCH};

use pyatv_core::consts::{DeviceState, MediaType, RepeatState, ShuffleState};
use pyatv_core::models::Playing;

use crate::player_state::ActivePlayer;
use crate::protobuf::{Command, content_item_metadata, playback_state, repeat_mode, shuffle_mode};

/// Seconds between the Unix epoch and Apple's `NSDate` epoch of 2001-01-01.
///
/// `_cocoa_to_timestamp` (`__init__.py:152-155`) computes this as a `timedelta`; both sides of the
/// subtraction upstream are naive local datetimes, so the local offset cancels and the arithmetic
/// is purely in Unix seconds.
pub const COCOA_EPOCH_OFFSET: f64 = 978_307_200.0;

/// Build the caller-facing snapshot for `state`, extrapolating position against `now`.
///
/// `now` is Unix seconds. [`build_playing`] passes the wall clock; tests pass a fixed value.
#[must_use]
pub fn build_playing_at(state: ActivePlayer<'_>, now: f64) -> Playing {
    let metadata = state.metadata();
    let device_state = device_state(state);

    Playing {
        media_type: media_type(state),
        device_state,
        title: metadata.and_then(|it| it.title.clone()),
        artist: metadata.and_then(|it| it.track_artist_name.clone()),
        album: metadata.and_then(|it| it.album_name.clone()),
        genre: metadata.and_then(|it| it.genre.clone()),
        total_time: total_time(state),
        position: position(state, device_state, now),
        shuffle: Some(shuffle(state)),
        repeat: Some(repeat(state)),
        series_name: metadata.and_then(|it| it.series_name.clone()),
        season_number: metadata
            .and_then(|it| it.season_number)
            .and_then(|it| u32::try_from(it).ok()),
        episode_number: metadata
            .and_then(|it| it.episode_number)
            .and_then(|it| u32::try_from(it).ok()),
        content_identifier: metadata.and_then(|it| it.content_identifier.clone()),
        itunes_store_identifier: metadata.and_then(|it| it.i_tunes_store_identifier),
    }
}

/// Build the caller-facing snapshot against the wall clock.
#[must_use]
pub fn build_playing(state: ActivePlayer<'_>) -> Playing {
    build_playing_at(state, unix_now())
}

/// The current time in Unix seconds, as a float.
fn unix_now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |it| it.as_secs_f64())
}

/// `cim.Audio` → `Music`, `cim.Video` → `Video`, anything else → `Unknown`.
fn media_type(state: ActivePlayer<'_>) -> MediaType {
    match state.metadata().and_then(|it| it.media_type) {
        Some(value) if value == content_item_metadata::MediaType::Audio as i32 => MediaType::Music,
        Some(value) if value == content_item_metadata::MediaType::Video as i32 => MediaType::Video,
        _ => MediaType::Unknown,
    }
}

/// Map the already-re-derived playback state onto [`DeviceState`] (`__init__.py:174-185`).
///
/// The `None` entry means *idle*; the dictionary's `.get(..., DeviceState.Paused)` default catches
/// `PlaybackState.Unknown`, which is why an unrecognised state reports paused rather than idle.
fn device_state(state: ActivePlayer<'_>) -> DeviceState {
    match state.playback_state() {
        None => DeviceState::Idle,
        Some(playback_state::Enum::Playing) => DeviceState::Playing,
        Some(playback_state::Enum::Stopped) => DeviceState::Stopped,
        Some(playback_state::Enum::Interrupted) => DeviceState::Loading,
        Some(playback_state::Enum::Seeking) => DeviceState::Seeking,
        // `Unknown` shares `Paused`'s answer because it is the dictionary's `.get(..., Paused)`
        // default, not because the two states mean the same thing.
        Some(playback_state::Enum::Paused | playback_state::Enum::Unknown) => DeviceState::Paused,
    }
}

/// `duration`, dropped when absent or `NaN` (`__init__.py:200-206`).
fn total_time(state: ActivePlayer<'_>) -> Option<u32> {
    let duration = state.metadata()?.duration?;
    if duration.is_nan() {
        return None;
    }
    truncate(duration)
}

/// Position, live-extrapolated only while genuinely playing at a non-zero rate.
///
/// `__init__.py:208-227`. Two conditions gate the extrapolation and both matter: the derived
/// device state must be `Playing` **and** `playbackRate` must not be zero. A `Playing` state at
/// rate zero — which [`crate::player_state::PlayerState::playback_state`] deliberately keeps as
/// `Playing` — falls through to the raw elapsed time instead.
fn position(state: ActivePlayer<'_>, device_state: DeviceState, now: f64) -> Option<u32> {
    let metadata = state.metadata()?;

    // `if not elapsed_timestamp` — a zero timestamp is falsy upstream and reports no position.
    let timestamp = metadata.elapsed_time_timestamp.filter(|it| *it != 0.0)?;
    let elapsed = metadata.elapsed_time.unwrap_or(0.0);
    let rate = metadata.playback_rate.unwrap_or(0.0);

    if device_state == DeviceState::Playing && rate != 0.0 {
        let diff = now - (timestamp + COCOA_EPOCH_OFFSET);
        truncate(elapsed + diff)
    } else {
        truncate(elapsed)
    }
}

/// Shuffle mode, read off the `ChangeShuffleMode` command info (`__init__.py:229-239`).
///
/// There is no dedicated shuffle field: the current mode lives on whichever `CommandInfo` entry
/// matches that command, and an absent entry means off.
fn shuffle(state: ActivePlayer<'_>) -> ShuffleState {
    match state
        .command_info(Command::ChangeShuffleMode)
        .and_then(|it| it.shuffle_mode)
    {
        Some(value) if value == shuffle_mode::Enum::Albums as i32 => ShuffleState::Albums,
        Some(value) if value == shuffle_mode::Enum::Songs as i32 => ShuffleState::Songs,
        _ => ShuffleState::Off,
    }
}

/// Repeat mode, read off the `ChangeRepeatMode` command info (`__init__.py:241-251`).
fn repeat(state: ActivePlayer<'_>) -> RepeatState {
    match state
        .command_info(Command::ChangeRepeatMode)
        .and_then(|it| it.repeat_mode)
    {
        Some(value) if value == repeat_mode::Enum::One as i32 => RepeatState::Track,
        Some(value) if value == repeat_mode::Enum::All as i32 => RepeatState::All,
        _ => RepeatState::Off,
    }
}

/// Python's `int(x)`: truncate toward zero.
///
/// Upstream's return type is a signed `int` and a clock skew can make an extrapolated position
/// negative; [`Playing::position`] is unsigned here, so a negative result is reported as no
/// position rather than wrapping to something enormous.
fn truncate(value: f64) -> Option<u32> {
    let truncated = value.trunc();
    if !(0.0..=f64::from(u32::MAX)).contains(&truncated) {
        return None;
    }

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "the value is range-checked against u32 on the line above and has already been \
                  truncated toward zero, so the conversion is exact; there is no fallible f64 -> \
                  u32 conversion in std to use instead"
    )]
    Some(truncated as u32)
}

#[cfg(test)]
mod tests {
    use super::{COCOA_EPOCH_OFFSET, build_playing_at};
    use pyatv_core::consts::{DeviceState, MediaType, RepeatState, ShuffleState};

    use crate::player_state::{Client, DEFAULT_PLAYER_ID};
    use crate::protobuf::{
        Command, CommandInfo, ContentItem, ContentItemMetadata, NowPlayingClient, NowPlayingPlayer,
        PlaybackQueue, SetStateMessage, SupportedCommands, content_item_metadata, playback_state,
        repeat_mode, shuffle_mode,
    };

    /// A client with one default player carrying `metadata`, `state` and `commands`.
    fn client(
        metadata: ContentItemMetadata,
        state: Option<playback_state::Enum>,
        commands: Vec<CommandInfo>,
    ) -> Client {
        let mut client = Client::new(&NowPlayingClient {
            bundle_identifier: Some("app".to_owned()),
            ..NowPlayingClient::default()
        });
        client
            .player_mut(&NowPlayingPlayer {
                identifier: Some(DEFAULT_PLAYER_ID.to_owned()),
                ..NowPlayingPlayer::default()
            })
            .handle_set_state(&SetStateMessage {
                playback_state: state.map(|it| it as i32),
                supported_commands: Some(SupportedCommands {
                    supported_commands: commands,
                }),
                playback_queue: Some(PlaybackQueue {
                    location: Some(0),
                    content_items: vec![ContentItem {
                        identifier: Some("item".to_owned()),
                        metadata: Some(metadata),
                        ..ContentItem::default()
                    }],
                    ..PlaybackQueue::default()
                }),
                ..SetStateMessage::default()
            });
        client
    }

    #[test]
    fn a_music_track_maps_every_field() {
        let client = client(
            ContentItemMetadata {
                media_type: Some(content_item_metadata::MediaType::Audio as i32),
                title: Some("Never Gonna Give You Up".to_owned()),
                track_artist_name: Some("Rick Astley".to_owned()),
                album_name: Some("Whenever You Need Somebody".to_owned()),
                genre: Some("Pop".to_owned()),
                duration: Some(213.0),
                ..ContentItemMetadata::default()
            },
            Some(playback_state::Enum::Playing),
            Vec::new(),
        );

        let playing = build_playing_at(client.active_player(), 0.0);
        assert_eq!(playing.media_type, MediaType::Music);
        assert_eq!(playing.device_state, DeviceState::Playing);
        assert_eq!(playing.title.as_deref(), Some("Never Gonna Give You Up"));
        assert_eq!(playing.artist.as_deref(), Some("Rick Astley"));
        assert_eq!(playing.album.as_deref(), Some("Whenever You Need Somebody"));
        assert_eq!(playing.genre.as_deref(), Some("Pop"));
        assert_eq!(playing.total_time, Some(213));
        assert_eq!(playing.position, None, "no timestamp, so no position");
    }

    #[test]
    fn an_idle_player_reports_unknown_and_idle() {
        let client = client(ContentItemMetadata::default(), None, Vec::new());
        let playing = build_playing_at(client.active_player(), 0.0);

        assert_eq!(playing.media_type, MediaType::Unknown);
        assert_eq!(playing.device_state, DeviceState::Idle);
        assert_eq!(playing.shuffle, Some(ShuffleState::Off));
        assert_eq!(playing.repeat, Some(RepeatState::Off));
    }

    /// Playing at rate 1: the position advances with the clock.
    #[test]
    fn position_is_extrapolated_while_playing() {
        let client = client(
            ContentItemMetadata {
                elapsed_time: Some(30.0),
                elapsed_time_timestamp: Some(1000.0),
                playback_rate: Some(1.0),
                ..ContentItemMetadata::default()
            },
            Some(playback_state::Enum::Playing),
            Vec::new(),
        );

        let now = COCOA_EPOCH_OFFSET + 1000.0 + 7.0;
        assert_eq!(
            build_playing_at(client.active_player(), now).position,
            Some(37)
        );
    }

    /// Paused, or playing at rate zero: the raw elapsed time, never extrapolated.
    #[test]
    fn position_is_not_extrapolated_when_not_really_playing() {
        for (state, rate) in [
            (playback_state::Enum::Paused, 1.0),
            (playback_state::Enum::Playing, 0.0),
        ] {
            let client = client(
                ContentItemMetadata {
                    elapsed_time: Some(30.0),
                    elapsed_time_timestamp: Some(1000.0),
                    playback_rate: Some(rate),
                    ..ContentItemMetadata::default()
                },
                Some(state),
                Vec::new(),
            );

            let now = COCOA_EPOCH_OFFSET + 1000.0 + 7.0;
            assert_eq!(
                build_playing_at(client.active_player(), now).position,
                Some(30),
                "state {state:?} at rate {rate}"
            );
        }
    }

    #[test]
    fn a_nan_duration_is_dropped() {
        let client = client(
            ContentItemMetadata {
                duration: Some(f64::NAN),
                ..ContentItemMetadata::default()
            },
            Some(playback_state::Enum::Playing),
            Vec::new(),
        );

        assert_eq!(
            build_playing_at(client.active_player(), 0.0).total_time,
            None
        );
    }

    #[test]
    fn shuffle_and_repeat_come_off_their_command_info_entries() {
        let client = client(
            ContentItemMetadata::default(),
            Some(playback_state::Enum::Playing),
            vec![
                CommandInfo {
                    command: Some(Command::ChangeShuffleMode as i32),
                    shuffle_mode: Some(shuffle_mode::Enum::Songs as i32),
                    ..CommandInfo::default()
                },
                CommandInfo {
                    command: Some(Command::ChangeRepeatMode as i32),
                    repeat_mode: Some(repeat_mode::Enum::All as i32),
                    ..CommandInfo::default()
                },
            ],
        );

        let playing = build_playing_at(client.active_player(), 0.0);
        assert_eq!(playing.shuffle, Some(ShuffleState::Songs));
        assert_eq!(playing.repeat, Some(RepeatState::All));
    }

    #[test]
    fn a_video_maps_series_metadata() {
        let client = client(
            ContentItemMetadata {
                media_type: Some(content_item_metadata::MediaType::Video as i32),
                series_name: Some("Show".to_owned()),
                season_number: Some(2),
                episode_number: Some(5),
                content_identifier: Some("cid".to_owned()),
                i_tunes_store_identifier: Some(1234),
                ..ContentItemMetadata::default()
            },
            Some(playback_state::Enum::Playing),
            Vec::new(),
        );

        let playing = build_playing_at(client.active_player(), 0.0);
        assert_eq!(playing.media_type, MediaType::Video);
        assert_eq!(playing.series_name.as_deref(), Some("Show"));
        assert_eq!(playing.season_number, Some(2));
        assert_eq!(playing.episode_number, Some(5));
        assert_eq!(playing.content_identifier.as_deref(), Some("cid"));
        assert_eq!(playing.itunes_store_identifier, Some(1234));
    }
}
