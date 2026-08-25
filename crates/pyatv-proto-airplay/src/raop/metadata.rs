//! Track metadata and the DAAP framing a receiver wants it in.
//!
//! Port of `MediaMetadata` (`pyatv/support/metadata.py`) plus the two `tags.py` helpers
//! `RtspSession.set_metadata` uses (`pyatv/protocols/dmap/tags.py:75-88`). The DMAP framing is the
//! same `Key(4) | Length(4, big-endian) | Data` TLV the DMAP protocol uses everywhere; only three
//! keys ever appear in a RAOP metadata body.

/// The placeholder identity a stream with no extractable metadata reports.
///
/// `MISSING_METADATA` (`stream_client.py:50-52`). Substituted whenever the real metadata is
/// entirely empty, so a `Playing` while streaming is never blank — reproducing the exact strings
/// matters because they are what a user sees on the device's screen.
pub const MISSING_TITLE: &str = "Streaming with pyatv";

/// Artist of [`MISSING_TITLE`].
pub const MISSING_ARTIST: &str = "pyatv";

/// Album of [`MISSING_TITLE`].
pub const MISSING_ALBUM: &str = "AirPlay";

/// What is known about the track being streamed.
///
/// `MediaMetadata` (`pyatv/support/metadata.py:10-19`). Every field is optional, and `duration` is
/// in seconds with a fraction.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrackMetadata {
    /// Track title, DAAP key `minm`.
    pub title: Option<String>,
    /// Artist, DAAP key `asar`.
    pub artist: Option<String>,
    /// Album, DAAP key `asal`.
    pub album: Option<String>,
    /// Duration in seconds.
    pub duration: Option<f64>,
    /// Cover artwork, sent verbatim under `image/jpeg`.
    pub artwork: Option<Vec<u8>>,
}

impl TrackMetadata {
    /// Whether nothing at all is known.
    ///
    /// `self._metadata == EMPTY_METADATA` (`stream_client.py:268-270`). Artwork is deliberately
    /// part of the comparison: upstream compares whole dataclasses, so a source that yielded only
    /// artwork is *not* empty and does not get the placeholder identity.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Substitute the placeholder identity when nothing is known.
    ///
    /// `StreamClient.playback_info` (`stream_client.py:266-272`).
    #[must_use]
    pub fn or_placeholder(&self) -> Self {
        if !self.is_empty() {
            return self.clone();
        }

        Self {
            title: Some(MISSING_TITLE.to_owned()),
            artist: Some(MISSING_ARTIST.to_owned()),
            album: Some(MISSING_ALBUM.to_owned()),
            duration: Some(0.0),
            artwork: None,
        }
    }

    /// Fill in whatever `other` knows and this does not.
    ///
    /// `merge_into` (`pyatv/support/metadata.py`), which backs `stream_file`'s
    /// `override_missing_metadata` argument: the *caller's* values win, and the source's fill the
    /// gaps.
    #[must_use]
    pub fn merged_over(&self, base: &Self) -> Self {
        Self {
            title: self.title.clone().or_else(|| base.title.clone()),
            artist: self.artist.clone().or_else(|| base.artist.clone()),
            album: self.album.clone().or_else(|| base.album.clone()),
            duration: self.duration.or(base.duration),
            artwork: self.artwork.clone().or_else(|| base.artwork.clone()),
        }
    }

    /// The `mlit` container a receiver expects.
    ///
    /// `tags.container_tag("mlit", payload)` over title, **album, then artist** — album before
    /// artist, which is the order the dict literal has and is what a receiver parses positionally
    /// in no way at all, but is reproduced so a byte comparison against pyatv succeeds
    /// (`pyatv/support/rtsp.py:210-217`).
    #[must_use]
    pub fn to_daap(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        for (key, value) in [
            (b"minm", self.title.as_deref()),
            (b"asal", self.album.as_deref()),
            (b"asar", self.artist.as_deref()),
        ] {
            // `if metadata.title:` — an empty string is falsy in Python, so it is skipped just as
            // a missing one is.
            if let Some(value) = value.filter(|value| !value.is_empty()) {
                payload.extend_from_slice(&string_tag(key, value));
            }
        }

        raw_tag(b"mlit", &payload)
    }
}

/// `Key(4) | Length(4, big-endian) | Data`.
///
/// `raw_tag`/`container_tag` (`pyatv/protocols/dmap/tags.py:86-88`). The length is the byte length
/// of the payload, not a character count.
#[must_use]
pub fn raw_tag(key: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(key);
    out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The same framing over a UTF-8 string.
///
/// # A deliberate divergence from pyatv
///
/// `string_tag` (`pyatv/protocols/dmap/tags.py:77-83`) is
/// `name + len(value).to_bytes(4) + value.encode("utf-8")`, and `len()` on a Python `str` is a
/// **character** count. Any non-ASCII title therefore ships a length that undercounts the bytes
/// that follow, and a receiver walking the `mlit` container resumes from the wrong offset for
/// every remaining tag. DMAP lengths are byte counts, so this writes the byte count.
///
/// The divergence is pinned by `tests/raop_packets_kat.rs`'s
/// `the_daap_length_is_a_byte_count_unlike_pyatvs`, against a vector generated from pyatv itself.
#[must_use]
pub fn string_tag(key: &[u8; 4], value: &str) -> Vec<u8> {
    raw_tag(key, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{MISSING_ALBUM, MISSING_ARTIST, MISSING_TITLE, TrackMetadata, raw_tag, string_tag};

    fn track(title: &str, artist: &str, album: &str) -> TrackMetadata {
        TrackMetadata {
            title: Some(title.to_owned()),
            artist: Some(artist.to_owned()),
            album: Some(album.to_owned()),
            ..TrackMetadata::default()
        }
    }

    #[test]
    fn a_tag_is_a_four_byte_key_and_a_big_endian_length() {
        assert_eq!(
            string_tag(b"minm", "hi"),
            b"minm\x00\x00\x00\x02hi".to_vec()
        );
        assert_eq!(raw_tag(b"mlit", b""), b"mlit\x00\x00\x00\x00".to_vec());
    }

    /// The length counts UTF-8 bytes, not characters.
    #[test]
    fn the_length_is_the_utf8_byte_count() {
        let tag = string_tag(b"minm", "é");

        assert_eq!(tag, b"minm\x00\x00\x00\x02\xc3\xa9".to_vec());
    }

    /// Title, then album, then artist — not alphabetical, and not the order of the struct fields.
    #[test]
    fn the_daap_body_orders_album_before_artist() {
        let body = track("T", "AR", "AL").to_daap();

        assert_eq!(
            body,
            [
                b"mlit\x00\x00\x00\x1d".as_slice(),
                b"minm\x00\x00\x00\x01T",
                b"asal\x00\x00\x00\x02AL",
                b"asar\x00\x00\x00\x02AR",
            ]
            .concat()
        );
    }

    /// A field that is absent, or present but empty, is omitted entirely.
    #[test]
    fn empty_fields_are_omitted_rather_than_sent_empty() {
        let metadata = TrackMetadata {
            title: Some("T".to_owned()),
            artist: Some(String::new()),
            album: None,
            ..TrackMetadata::default()
        };

        assert_eq!(
            metadata.to_daap(),
            b"mlit\x00\x00\x00\x09minm\x00\x00\x00\x01T".to_vec()
        );
    }

    #[test]
    fn an_empty_track_gets_the_placeholder_identity() {
        let placeholder = TrackMetadata::default().or_placeholder();

        assert_eq!(placeholder.title.as_deref(), Some(MISSING_TITLE));
        assert_eq!(placeholder.artist.as_deref(), Some(MISSING_ARTIST));
        assert_eq!(placeholder.album.as_deref(), Some(MISSING_ALBUM));
        assert_eq!(placeholder.duration, Some(0.0));
    }

    /// Anything at all known keeps the real values, including artwork alone.
    #[test]
    fn a_partly_known_track_keeps_its_own_values() {
        let metadata = TrackMetadata {
            title: Some("Real".to_owned()),
            ..TrackMetadata::default()
        };

        assert_eq!(metadata.or_placeholder(), metadata);

        let artwork_only = TrackMetadata {
            artwork: Some(vec![0xFF]),
            ..TrackMetadata::default()
        };
        assert_eq!(artwork_only.or_placeholder(), artwork_only);
    }

    /// The caller's values win; the source's fill the gaps.
    #[test]
    fn merging_prefers_the_overriding_values() {
        let source = track("source title", "source artist", "source album");
        let over = TrackMetadata {
            title: Some("mine".to_owned()),
            ..TrackMetadata::default()
        };

        let merged = over.merged_over(&source);

        assert_eq!(merged.title.as_deref(), Some("mine"));
        assert_eq!(merged.artist.as_deref(), Some("source artist"));
        assert_eq!(merged.album.as_deref(), Some("source album"));
    }
}
