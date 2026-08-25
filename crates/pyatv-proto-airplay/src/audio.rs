//! Turning a file, a URL or a buffer into the raw PCM a RAOP stream sends.
//!
//! Port of `pyatv/protocols/raop/audio_source.py`'s public shape: an [`AudioSource`] with
//! `read_frames`, `metadata` and `duration`, and an [`open_source`] that dispatches on what it was
//! handed (`audio_source.py:64-101, 727-739`).
//!
//! # Divergences from upstream, and why
//!
//! - **Everything is decoded up front.** `FileSource` already does this — it calls
//!   `miniaudio.decode_file` and keeps `self.samples` in memory (`audio_source.py:661-724`) — but
//!   `InternetSource` and `BufferedIOBaseSource` decode incrementally behind a background thread
//!   and a hand-rolled `SemiSeekableBuffer`. This port decodes every source the way `FileSource`
//!   does, on a blocking thread, and serves frames from the result. That trades memory for the
//!   whole `SemiSeekableBuffer`/`_buffering_task` apparatus — including the byte-length-versus-
//!   frame-count comparison at `audio_source.py:393` that this port's research flagged as a
//!   probable upstream bug — and it removes the "skip the first 44 bytes and hope it was a WAV
//!   header" hack at `audio_source.py:354-358` entirely, because `symphonia` decodes to samples
//!   rather than round-tripping through a synthetic WAV container.
//! - **Metadata comes from the same decode.** Upstream reads tags in a second pass with `TinyTag`.
//! - **`https://` is refused.** See [`fetch`].
//!
//! Everything blocking runs on [`tokio::task::spawn_blocking`], so a decode never occupies a
//! runtime worker.

pub mod convert;
pub mod decode;
pub mod fetch;

use std::path::{Path, PathBuf};

pub use convert::PcmFormat;

use crate::raop::metadata::TrackMetadata;
use crate::{Error, Result};

/// A decoded, conformed audio stream, read a packet at a time.
///
/// The `AudioSource` interface (`audio_source.py:64-101`), minus the abstract-base machinery:
/// `read_frames` is `readframes`, and the format properties live on [`AudioSource::format`].
#[derive(Debug, Clone, PartialEq)]
pub struct AudioSource {
    samples: Vec<u8>,
    position: usize,
    format: PcmFormat,
    metadata: TrackMetadata,
    duration: f64,
}

impl AudioSource {
    /// Wrap PCM bytes that are already in the receiver's format.
    ///
    /// The [`BufferedIOBaseSource`](https://pyatv.dev) equivalent for callers holding raw samples:
    /// no decode, no resample, just framing. `samples` must be interleaved, big-endian, and
    /// `format.frame_size()` bytes per frame — which is what [`convert::pack`] produces.
    #[must_use]
    pub fn from_pcm(samples: Vec<u8>, format: PcmFormat, metadata: TrackMetadata) -> Self {
        let frame_size = format.frame_size().max(1);
        #[allow(
            clippy::cast_precision_loss,
            reason = "a frame count large enough to lose f64 precision is thousands of years"
        )]
        let duration = (samples.len() / frame_size) as f64 / f64::from(format.sample_rate.max(1));

        Self {
            samples,
            position: 0,
            format,
            metadata,
            duration,
        }
    }

    /// The format the frames are in, which is the one the receiver negotiated.
    #[must_use]
    pub fn format(&self) -> PcmFormat {
        self.format
    }

    /// Total length in seconds.
    ///
    /// `AudioSource.duration` (`audio_source.py:95-101`).
    #[must_use]
    pub fn duration(&self) -> f64 {
        self.duration
    }

    /// Whatever the container's tags said.
    ///
    /// `AudioSource.get_metadata` (`audio_source.py:83-85`).
    #[must_use]
    pub fn metadata(&self) -> &TrackMetadata {
        &self.metadata
    }

    /// How many frames are left.
    #[must_use]
    pub fn remaining_frames(&self) -> usize {
        let frame_size = self.format.frame_size().max(1);
        self.samples.len().saturating_sub(self.position) / frame_size
    }

    /// Read up to `frames` frames, returning fewer — or none — at the end of the stream.
    ///
    /// `AudioSource.readframes` (`audio_source.py:73-81`), whose contract is that an empty return
    /// means the stream is exhausted. The final chunk really can be short; padding it to a full
    /// packet is the caller's job, and [`crate::raop::stream`] does it exactly where upstream does.
    pub fn read_frames(&mut self, frames: usize) -> &[u8] {
        let frame_size = self.format.frame_size().max(1);
        let wanted = frames * frame_size;
        let end = (self.position + wanted).min(self.samples.len());
        let chunk = &self.samples[self.position..end];
        self.position = end;
        chunk
    }
}

/// Where a stream's audio comes from.
///
/// The three shapes `open_source` dispatches on (`audio_source.py:727-739`), as a closed set
/// rather than as `isinstance` checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A local path.
    File(PathBuf),
    /// An `http://` URL.
    Url(String),
    /// Encoded bytes already in memory.
    Bytes(Vec<u8>),
}

impl Source {
    /// Classify a caller-supplied string the way upstream does.
    ///
    /// `if re.match("^http(|s)://", source)` selects the network source, and anything else that is
    /// a string is a path (`audio_source.py:731-735`).
    #[must_use]
    pub fn from_str_source(source: &str) -> Self {
        if fetch::is_url(source) {
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

/// Open a source and conform it to `target`.
///
/// `open_source(source, sample_rate, channels, sample_size)` (`audio_source.py:727-739`), except
/// that `sample_size` here is bytes per sample rather than bits — matching
/// `context.bytes_per_channel`, which is what upstream actually passes.
///
/// The decode and the resample both run on a blocking thread. A URL is downloaded first, on the
/// runtime, because that is I/O and belongs there.
///
/// # Errors
///
/// Returns [`Error::Audio`] if the file cannot be opened, the container or codec is not supported,
/// or the target format is one nothing can be conformed to. Returns [`Error::Io`] if a download
/// fails mid-transfer.
pub async fn open_source(source: Source, target: PcmFormat) -> Result<AudioSource> {
    let (bytes, hint, path) = match source {
        Source::File(path) => {
            let hint = path
                .extension()
                .and_then(|extension| extension.to_str())
                .map(str::to_owned);
            (None, hint, Some(path))
        }
        Source::Url(url) => {
            let url = fetch::parse_url(&url)?;
            let hint = url.extension().map(str::to_owned);
            (Some(Box::pin(fetch::download(&url)).await?), hint, None)
        }
        Source::Bytes(bytes) => (Some(bytes), None, None),
    };

    let decoded = tokio::task::spawn_blocking(move || {
        let decoded = match (bytes, path) {
            (Some(bytes), _) => decode::decode_bytes(bytes, hint.as_deref())?,
            (None, Some(path)) => {
                let file = std::fs::File::open(&path).map_err(|error| {
                    Error::audio_source(format!("could not open {}: {error}", path.display()))
                })?;
                decode::decode(Box::new(file), hint.as_deref())?
            }
            (None, None) => {
                return Err(Error::audio_source("no audio source was given".to_owned()));
            }
        };

        let samples = convert::conform(&decoded, target)?;
        Ok::<_, Error>((samples, decoded.metadata))
    })
    .await
    .map_err(|error| Error::audio_source(format!("the audio decoder task failed: {error}")))??;

    let (samples, metadata) = decoded;
    let mut audio = AudioSource::from_pcm(samples, target, metadata);
    // Upstream reports the *tagged* duration, which for a file with no tags is zero; deriving it
    // from what was actually decoded is both more accurate and always available.
    audio.metadata.duration = Some(audio.duration);
    Ok(audio)
}

#[cfg(test)]
mod tests {
    use super::{AudioSource, PcmFormat, Source, open_source};
    use crate::raop::metadata::TrackMetadata;

    fn stereo() -> PcmFormat {
        PcmFormat {
            sample_rate: 44_100,
            channels: 2,
            bytes_per_sample: 2,
        }
    }

    fn source(frames: usize) -> AudioSource {
        AudioSource::from_pcm(vec![0u8; frames * 4], stereo(), TrackMetadata::default())
    }

    #[test]
    fn frames_come_out_in_the_requested_size() {
        let mut audio = source(1000);

        assert_eq!(audio.read_frames(352).len(), 352 * 4);
        assert_eq!(audio.remaining_frames(), 648);
    }

    /// The last chunk is short, and the one after it is empty — which is how the streaming loop
    /// learns the source is exhausted.
    #[test]
    fn the_final_chunk_is_short_and_then_empty() {
        let mut audio = source(400);

        assert_eq!(audio.read_frames(352).len(), 352 * 4);
        assert_eq!(audio.read_frames(352).len(), 48 * 4);
        assert!(audio.read_frames(352).is_empty());
        assert_eq!(audio.remaining_frames(), 0);
    }

    #[test]
    fn the_duration_follows_the_frame_count() {
        assert!((source(44_100).duration() - 1.0).abs() < 1e-6);
        assert!((source(0).duration() - 0.0).abs() < 1e-6);
    }

    /// A `str` source is classified the way upstream's regex classifies it.
    #[test]
    fn a_string_source_is_a_url_or_a_path() {
        assert!(matches!(
            Source::from_str_source("http://h/a.mp3"),
            Source::Url(_)
        ));
        assert!(matches!(
            Source::from_str_source("/tmp/a.mp3"),
            Source::File(_)
        ));
    }

    /// The whole pipeline over an in-memory WAV, ending in big-endian stereo bytes.
    #[tokio::test]
    async fn a_wav_buffer_opens_as_conformed_pcm() {
        // 100 frames of full-scale mono at 44100 Hz.
        let mut wav = Vec::new();
        let data: Vec<u8> = (0..100).flat_map(|_| i16::MAX.to_le_bytes()).collect();
        let data_len = u32::try_from(data.len()).expect("small");
        wav.extend_from_slice(b"RIFF");
        wav.extend_from_slice(&(36 + data_len).to_le_bytes());
        wav.extend_from_slice(b"WAVEfmt ");
        wav.extend_from_slice(&16u32.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&1u16.to_le_bytes());
        wav.extend_from_slice(&44_100u32.to_le_bytes());
        wav.extend_from_slice(&88_200u32.to_le_bytes());
        wav.extend_from_slice(&2u16.to_le_bytes());
        wav.extend_from_slice(&16u16.to_le_bytes());
        wav.extend_from_slice(b"data");
        wav.extend_from_slice(&data_len.to_le_bytes());
        wav.extend_from_slice(&data);

        let mut audio = open_source(Source::Bytes(wav), stereo())
            .await
            .expect("opens");

        assert_eq!(audio.format(), stereo());
        assert_eq!(audio.remaining_frames(), 100);
        // Mono duplicated to stereo, packed big-endian at full scale.
        assert_eq!(&audio.read_frames(1), &[0x7F, 0xFF, 0x7F, 0xFF]);
    }

    #[tokio::test]
    async fn an_undecodable_buffer_is_an_error() {
        assert!(
            open_source(Source::Bytes(b"nope".to_vec()), stereo())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_missing_file_is_an_error_naming_the_path() {
        let error = open_source(Source::File("/nonexistent/track.mp3".into()), stereo())
            .await
            .expect_err("fails");

        assert!(
            error.to_string().contains("/nonexistent/track.mp3"),
            "{error}"
        );
    }
}
