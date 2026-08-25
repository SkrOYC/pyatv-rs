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
    /// An identifier for the content, stable while the same thing is playing.
    ///
    /// `Playing.hash`, one of the fields `__eq__` compares (`interface.py:483,595-612`). MRP fills
    /// it with the active player's `item_identifier` (`__init__.py:250-252,283`); a protocol that
    /// has no such notion leaves it `None`.
    ///
    /// **Not printed by [`Display`](std::fmt::Display)** — `__str__` omits it
    /// (`interface.py:540-589`), so `atvremote playing` never shows it and neither does this.
    ///
    /// # Divergence: no derived fallback
    ///
    /// Upstream's `hash` is a property, not a field: when the constructor was passed nothing it
    /// returns `sha256(f"{title}{artist}{album}{total_time}")` instead of `None`
    /// (`interface.py:601-612`), so a caller always gets a string. That fallback is deliberately
    /// **not** reproduced here, because it would put a hashing dependency into `pyatv-core` for a
    /// value nothing in this workspace consumes yet. A caller that wants pyatv's exact semantics
    /// has every input to compute it. Revisit if a protocol or the CLI starts reading this.
    pub hash: Option<String>,
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

impl std::fmt::Display for Playing {
    /// `Playing.__str__` (`pyatv/interface.py:540-589`), line for line.
    ///
    /// This is the block `atvremote playing` and `atvremote push_updates` print, so the label
    /// column widths, the field order and the omission rules are all load-bearing: someone diffing
    /// the two tools' output should see nothing. Absent fields are skipped entirely rather than
    /// printed as `None`, `content_identifier` is skipped when *empty* as well as when absent
    /// (upstream tests it for truthiness, not for `is not None`), and the position line has three
    /// mutually exclusive shapes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut lines = Vec::with_capacity(16);
        lines.push(format!("  Media type: {}", self.media_type));
        lines.push(format!("Device state: {}", self.device_state));

        for (label, value) in [
            ("       Title", self.title.as_deref()),
            ("      Artist", self.artist.as_deref()),
            ("       Album", self.album.as_deref()),
            ("       Genre", self.genre.as_deref()),
            (" Series Name", self.series_name.as_deref()),
        ] {
            if let Some(value) = value {
                lines.push(format!("{label}: {value}"));
            }
        }
        if let Some(season) = self.season_number {
            lines.push(format!("      Season: {season}"));
        }
        if let Some(episode) = self.episode_number {
            lines.push(format!("     Episode: {episode}"));
        }
        if let Some(identifier) = self
            .content_identifier
            .as_deref()
            .filter(|it| !it.is_empty())
        {
            lines.push(format!("  Identifier: {identifier}"));
        }

        if let Some(line) = self.position_line() {
            lines.push(line);
        }
        if let Some(repeat) = self.repeat {
            lines.push(format!("      Repeat: {repeat}"));
        }
        if let Some(shuffle) = self.shuffle {
            lines.push(format!("     Shuffle: {shuffle}"));
        }
        if let Some(identifier) = self.itunes_store_identifier {
            lines.push(format!("iTunes Store Identifier: {identifier}"));
        }

        f.write_str(&lines.join("\n"))
    }
}

impl Playing {
    /// The one line of [`Playing`]'s rendering with three shapes.
    ///
    /// `interface.py:569-577`. With both values and a non-zero duration it is
    /// `position/totals (pct)`; with only a non-zero position it is `positions`; and the third
    /// branch reproduces an upstream quirk exactly — `elif total_time is not None and position !=
    /// 0` tests *position* rather than `total_time`, so a total time with an unknown position does
    /// print (`None != 0`) while a total time alongside `position == 0` does not.
    fn position_line(&self) -> Option<String> {
        match (self.position, self.total_time) {
            (Some(position), Some(total)) if total != 0 => {
                let percent = f64::from(position) / f64::from(total) * 100.0;
                Some(format!("    Position: {position}/{total}s ({percent:.1}%)"))
            }
            (Some(position), _) if position != 0 => Some(format!("    Position: {position}s")),
            (position, Some(total)) if position != Some(0) => {
                Some(format!("  Total time: {total}s"))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Playing;
    use crate::consts::{DeviceState, MediaType, RepeatState, ShuffleState};

    /// Nothing playing: two lines, and not one more.
    #[test]
    fn an_empty_snapshot_prints_only_the_two_mandatory_lines() {
        assert_eq!(
            Playing::default().to_string(),
            "  Media type: Unknown\nDevice state: Idle"
        );
    }

    /// The full block, with the label column widths upstream uses.
    #[test]
    fn a_full_snapshot_matches_pyatvs_layout() {
        let playing = Playing {
            media_type: MediaType::Tv,
            device_state: DeviceState::Playing,
            title: Some("Pilot".to_owned()),
            artist: Some("Someone".to_owned()),
            album: Some("Season 1".to_owned()),
            genre: Some("Drama".to_owned()),
            total_time: Some(1234),
            position: Some(617),
            shuffle: Some(ShuffleState::Songs),
            repeat: Some(RepeatState::All),
            hash: Some("an-item-identifier".to_owned()),
            series_name: Some("A Show".to_owned()),
            season_number: Some(1),
            episode_number: Some(2),
            content_identifier: Some("abc".to_owned()),
            itunes_store_identifier: Some(99),
        };

        assert_eq!(
            playing.to_string(),
            concat!(
                "  Media type: TV\n",
                "Device state: Playing\n",
                "       Title: Pilot\n",
                "      Artist: Someone\n",
                "       Album: Season 1\n",
                "       Genre: Drama\n",
                " Series Name: A Show\n",
                "      Season: 1\n",
                "     Episode: 2\n",
                "  Identifier: abc\n",
                "    Position: 617/1234s (50.0%)\n",
                "      Repeat: All\n",
                "     Shuffle: Songs\n",
                "iTunes Store Identifier: 99",
            )
        );
    }

    /// A position with no duration prints on its own (`interface.py:574-575`).
    #[test]
    fn a_position_without_a_duration_prints_alone() {
        let playing = Playing {
            position: Some(42),
            ..Playing::default()
        };

        assert!(playing.to_string().ends_with("\n    Position: 42s"));
    }

    /// The third branch only fires for an *unknown* position, and a position of zero is a known
    /// one — `position is not None` is what the first branch tests, not truthiness
    /// (`interface.py:569-577`).
    #[test]
    fn an_unknown_position_still_prints_the_duration() {
        let unknown = Playing {
            total_time: Some(300),
            ..Playing::default()
        };
        assert!(unknown.to_string().ends_with("\n  Total time: 300s"));

        let at_zero = Playing {
            total_time: Some(300),
            position: Some(0),
            ..Playing::default()
        };
        assert!(
            at_zero
                .to_string()
                .ends_with("\n    Position: 0/300s (0.0%)")
        );
    }

    /// Neither value known, and a zero duration, both print nothing at all.
    #[test]
    fn a_position_line_is_omitted_when_there_is_nothing_to_say() {
        for playing in [
            Playing::default(),
            Playing {
                position: Some(0),
                ..Playing::default()
            },
            Playing {
                position: Some(0),
                total_time: Some(0),
                ..Playing::default()
            },
        ] {
            assert_eq!(
                playing.to_string(),
                "  Media type: Unknown\nDevice state: Idle",
                "{playing:?}"
            );
        }
    }

    /// `hash` is compared but never printed: `__str__` has no branch for it
    /// (`interface.py:540-589`), so neither does this.
    #[test]
    fn the_hash_is_never_printed() {
        let playing = Playing {
            hash: Some("an-item-identifier".to_owned()),
            ..Playing::default()
        };

        assert_eq!(
            playing.to_string(),
            "  Media type: Unknown\nDevice state: Idle"
        );
        assert_ne!(playing, Playing::default(), "but it does affect equality");
    }

    /// `if self.content_identifier:` is a truthiness test, so an empty string is skipped.
    #[test]
    fn an_empty_content_identifier_is_skipped() {
        let playing = Playing {
            content_identifier: Some(String::new()),
            ..Playing::default()
        };

        assert!(!playing.to_string().contains("Identifier"));
    }
}
