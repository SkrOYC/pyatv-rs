//! Playback state and the small value types that hang off it.
//!
//! Ports the data-carrying half of `pyatv/interface.py`: `Playing` (`pyatv/interface.py:469-700`),
//! `App` (`:703-729`), `UserAccount` (`:746-772`) and `ArtworkInfo` (`:65-73`). Only the fields are
//! reproduced here; the behaviour built on top of them lives in [`crate::interface`].

use serde::{Deserialize, Serialize};

use crate::consts::{DeviceState, MediaType, RepeatState, ShuffleState};

/// An installed application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    /// Display name.
    pub name: String,
    /// Bundle identifier, e.g. `com.apple.TVMovies`.
    pub identifier: String,
}

/// A user account on the device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAccount {
    /// Display name.
    pub name: String,
    /// Opaque account identifier.
    pub identifier: String,
}

/// Artwork for the currently playing item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtworkInfo {
    /// Raw encoded image bytes.
    pub bytes: Vec<u8>,
    /// MIME type of [`ArtworkInfo::bytes`].
    pub mimetype: String,
    /// Pixel width, when the device reports it.
    pub width: Option<u32>,
    /// Pixel height, when the device reports it.
    pub height: Option<u32>,
}

/// A snapshot of what the device is playing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Playing {
    /// Kind of media.
    pub media_type: MediaType,
    /// Transport state.
    pub device_state: DeviceState,
    /// Item title.
    pub title: Option<String>,
    /// Performing artist.
    pub artist: Option<String>,
    /// Album name.
    pub album: Option<String>,
    /// Genre.
    pub genre: Option<String>,
    /// Total duration in seconds.
    pub total_time: Option<u32>,
    /// Current position in seconds.
    pub position: Option<u32>,
    /// Shuffle mode.
    pub shuffle: Option<ShuffleState>,
    /// Repeat mode.
    pub repeat: Option<RepeatState>,
    /// Series name for TV content.
    pub series_name: Option<String>,
    /// Season number for TV content.
    pub season_number: Option<u32>,
    /// Episode number for TV content.
    pub episode_number: Option<u32>,
    /// Opaque content identifier.
    pub content_identifier: Option<String>,
    /// iTunes Store identifier, added upstream in v0.16.0.
    pub itunes_store_identifier: Option<i64>,
}
