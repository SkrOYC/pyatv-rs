//! Audio-side data models: output devices, track metadata and stream sources.
//!
//! Ports `interface.OutputDevice` (`pyatv/interface.py:1116-1136`) and `interface.MediaMetadata`
//! (`pyatv/interface.py:74-84`). Both are plain data the public [`crate::interface::Audio`] and
//! [`crate::interface::Stream`] traits hand back or take in, so they live in `models` rather than
//! in any protocol crate — before this they existed only as protocol-internal types
//! (`pyatv_proto_mrp::state::volume::OutputDevice`, `pyatv_proto_airplay::raop::TrackMetadata`)
//! and callers could not see the names or per-device volumes at all.

use std::path::{Path, PathBuf};

/// One speaker in the playback group.
///
/// `OutputDevice` (`interface.py:1116-1136`): an identifier, an optional display name, and a volume
/// that defaults to zero. Upstream's `__eq__` compares all three fields, which is what
/// [`PartialEq`] gives here, and is what the facade's change detection relies on
/// (`facade.py:463-473`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OutputDevice {
    /// Stable identifier, the value `add_output_devices` and friends take.
    pub identifier: String,
    /// Display name, absent when the device only reported an identifier.
    pub name: Option<String>,
    /// Volume as a percentage in `0.0..=100.0`.
    pub volume: f32,
}

impl OutputDevice {
    /// A device known only by identifier, with no name and zero volume.
    ///
    /// `OutputDevice(device_state.identifier)` (`facade.py:487`), the fallback the facade builds
    /// when a per-device volume push names a speaker that was never in the group list.
    #[must_use]
    pub fn new(identifier: impl Into<String>) -> Self {
        Self {
            identifier: identifier.into(),
            name: None,
            volume: 0.0,
        }
    }

    /// The same, with a display name.
    #[must_use]
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// The same, with a volume level.
    #[must_use]
    pub fn with_volume(mut self, volume: f32) -> Self {
        self.volume = volume;
        self
    }
}

impl std::fmt::Display for OutputDevice {
    /// `f"Device: {self.name} ({self.identifier})"` (`interface.py:1124-1126`).
    ///
    /// A device with no name renders `None` where upstream's f-string would, because upstream's
    /// `name` is `Optional[str]` and formats the same way.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.name {
            Some(name) => write!(formatter, "Device: {name} ({})", self.identifier),
            None => write!(formatter, "Device: None ({})", self.identifier),
        }
    }
}

/// What is known about a track being streamed.
///
/// `MediaMetadata` (`interface.py:74-84`). Every field is optional and `duration` is in seconds
/// with a fraction; `artwork` is raw JPEG, as upstream's comment says.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MediaMetadata {
    /// Track title.
    pub title: Option<String>,
    /// Performing artist.
    pub artist: Option<String>,
    /// Album name.
    pub album: Option<String>,
    /// Cover artwork, raw JPEG bytes.
    pub artwork: Option<Vec<u8>>,
    /// Duration in seconds.
    pub duration: Option<f64>,
}

impl MediaMetadata {
    /// Whether nothing at all is known.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// Where [`crate::interface::Stream::stream_file`] reads its audio from.
///
/// The three shapes upstream's `open_source` dispatches on (`audio_source.py:727-739`), which
/// `stream_file` accepts as `Union[str, io.BufferedIOBase, asyncio.streams.StreamReader]`
/// (`interface.py:886-890`). Rust models the union as a closed enum instead of by duck typing, so
/// `atvremote stream_file -` reads standard input into [`MediaSource::Bytes`] rather than passing a
/// file object along.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaSource {
    /// A local file.
    File(PathBuf),
    /// An `http://` or `https://` URL the receiver's own decoder never sees — the bytes are
    /// fetched here and streamed on.
    Url(String),
    /// Encoded bytes already in memory.
    Bytes(Vec<u8>),
}

impl MediaSource {
    /// Classify a caller-supplied string the way upstream does.
    ///
    /// `if re.match("^http(|s)://", source)` picks the network source and anything else is a path
    /// (`audio_source.py:731-735`).
    #[must_use]
    pub fn from_str_source(source: &str) -> Self {
        let lowercase = source.to_ascii_lowercase();
        if lowercase.starts_with("http://") || lowercase.starts_with("https://") {
            Self::Url(source.to_owned())
        } else {
            Self::File(PathBuf::from(source))
        }
    }

    /// A local path, whatever it looks like.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        Self::File(path.to_path_buf())
    }
}

impl From<&Path> for MediaSource {
    fn from(path: &Path) -> Self {
        Self::from_path(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{MediaMetadata, MediaSource, OutputDevice};
    use std::path::PathBuf;

    /// `__str__` (`interface.py:1124-1126`).
    #[test]
    fn an_output_device_renders_like_upstream() {
        let device = OutputDevice::new("id-1").with_name("Kitchen");
        assert_eq!(device.to_string(), "Device: Kitchen (id-1)");
        assert_eq!(OutputDevice::new("id-1").to_string(), "Device: None (id-1)");
    }

    /// `__eq__` compares name, identifier *and* volume (`interface.py:1128-1136`), which is what
    /// makes the facade's "did the group change" check notice a volume-only difference.
    #[test]
    fn output_device_equality_includes_volume() {
        let device = OutputDevice::new("id-1").with_name("Kitchen");
        assert_eq!(device, OutputDevice::new("id-1").with_name("Kitchen"));
        assert_ne!(device, device.clone().with_volume(50.0));
        assert_ne!(device, OutputDevice::new("id-2").with_name("Kitchen"));
    }

    #[test]
    fn empty_metadata_is_recognised() {
        assert!(MediaMetadata::default().is_empty());
        assert!(
            !MediaMetadata {
                title: Some("Song".to_owned()),
                ..MediaMetadata::default()
            }
            .is_empty()
        );
    }

    /// `^http(|s)://` and nothing else (`audio_source.py:731-735`).
    #[test]
    fn a_string_source_is_a_url_only_when_it_says_http() {
        assert_eq!(
            MediaSource::from_str_source("http://host/a.mp3"),
            MediaSource::Url("http://host/a.mp3".to_owned())
        );
        assert_eq!(
            MediaSource::from_str_source("https://host/a.mp3"),
            MediaSource::Url("https://host/a.mp3".to_owned())
        );
        assert_eq!(
            MediaSource::from_str_source("/tmp/a.mp3"),
            MediaSource::File(PathBuf::from("/tmp/a.mp3"))
        );
        assert_eq!(
            MediaSource::from_str_source("ftp://host/a.mp3"),
            MediaSource::File(PathBuf::from("ftp://host/a.mp3"))
        );
    }
}
