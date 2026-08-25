//! Decoding an encoded audio file into interleaved `f32` samples.
//!
//! Replaces pyatv's `miniaudio.decode_file` (`pyatv/protocols/raop/audio_source.py:661-724`) with
//! `symphonia`, and its separate `TinyTag` pass (`pyatv/support/metadata.py:21-40`) with
//! `symphonia`'s own container metadata — one decode instead of two file reads.
//!
//! Formats enabled in `Cargo.toml`: WAV, FLAC, OGG/Vorbis, MKV, ADPCM and PCM by default, plus
//! MP3, AAC, ALAC, ISO/MP4, CAF and AIFF. That covers what `miniaudio`'s bundled `dr_libs`
//! decoders handle and rather more besides.
//!
//! Synchronous and blocking on purpose. [`super::open_source`] runs it on a blocking thread; a
//! whole-file decode has no business on an async runtime's worker.

use std::io::Cursor;

use symphonia::core::audio::{Channels, GenericAudioBufferRef};
use symphonia::core::codecs::CodecParameters;
use symphonia::core::codecs::audio::AudioDecoderOptions;
use symphonia::core::errors::Error as SymphoniaError;
use symphonia::core::formats::{FormatOptions, TrackType, probe::Hint};
use symphonia::core::io::{MediaSource, MediaSourceStream, MediaSourceStreamOptions};
use symphonia::core::meta::{MetadataOptions, StandardTag};

use crate::raop::metadata::TrackMetadata;
use crate::{Error, Result};

/// One fully decoded input, in the format it was encoded at.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    /// Interleaved samples, one `f32` per sample per channel.
    pub samples: Vec<f32>,
    /// How many channels the samples are interleaved across.
    pub channels: usize,
    /// The rate the samples are at, before any resampling.
    pub sample_rate: u32,
    /// Whatever the container's tags said.
    pub metadata: TrackMetadata,
}

impl Decoded {
    /// How many frames — sample groups, one per channel — were decoded.
    #[must_use]
    pub fn frames(&self) -> usize {
        if self.channels == 0 {
            return 0;
        }
        self.samples.len() / self.channels
    }
}

/// Decode a whole file or buffer.
///
/// `hint` is a file extension, which lets the probe skip straight to the right demuxer. It is only
/// a hint: a wrong or absent one costs a little scanning, never a wrong answer.
///
/// # Errors
///
/// Returns [`Error::Audio`] if no container or codec could be recognised, if the input has no
/// audio track, or if decoding fails outright. Individual corrupt packets are skipped rather than
/// failing the whole decode, which is what a player does and what `miniaudio` does.
pub fn decode(source: Box<dyn MediaSource + 'static>, hint: Option<&str>) -> Result<Decoded> {
    let stream = MediaSourceStream::new(source, MediaSourceStreamOptions::default());

    let mut probe_hint = Hint::new();
    if let Some(extension) = hint {
        probe_hint.with_extension(extension);
    }

    let mut reader = symphonia::default::get_probe()
        .probe(
            &probe_hint,
            stream,
            FormatOptions::default(),
            MetadataOptions::default(),
        )
        .map_err(|error| Error::Audio(format!("could not recognise the audio: {error}")))?;

    let track = reader
        .default_track(TrackType::Audio)
        .ok_or_else(|| Error::Audio("the input has no audio track".to_owned()))?;
    let track_id = track.id;
    let Some(CodecParameters::Audio(parameters)) = track.codec_params.clone() else {
        return Err(Error::Audio(
            "the audio track has no codec parameters".to_owned(),
        ));
    };

    let mut decoder = symphonia::default::get_codecs()
        .make_audio_decoder(&parameters, &AudioDecoderOptions::default())
        .map_err(|error| Error::Audio(format!("unsupported audio codec: {error}")))?;

    let mut samples: Vec<f32> = Vec::new();
    let mut chunk: Vec<f32> = Vec::new();
    let mut channels = parameters.channels.as_ref().map_or(0, Channels::count);
    let mut sample_rate = parameters.sample_rate.unwrap_or(0);

    loop {
        let packet = match reader.next_packet() {
            Ok(Some(packet)) => packet,
            Ok(None) => break,
            Err(SymphoniaError::IoError(error))
                if error.kind() == std::io::ErrorKind::UnexpectedEof =>
            {
                break;
            }
            Err(error) => return Err(Error::Audio(format!("could not read the audio: {error}"))),
        };
        if packet.track_id != track_id {
            continue;
        }

        match decoder.decode(&packet) {
            Ok(buffer) => {
                update_spec(&buffer, &mut channels, &mut sample_rate);
                buffer.copy_to_vec_interleaved(&mut chunk);
                samples.extend_from_slice(&chunk);
            }
            // A single undecodable packet is skipped; the stream continues. Anything else is fatal.
            Err(SymphoniaError::DecodeError(reason)) => {
                tracing::debug!(reason, "skipping an undecodable audio packet");
            }
            Err(error) => return Err(Error::Audio(format!("could not decode the audio: {error}"))),
        }
    }

    if channels == 0 || sample_rate == 0 {
        return Err(Error::Audio(
            "the audio track declares no channel layout or sample rate".to_owned(),
        ));
    }

    let mut metadata = read_tags(reader.as_mut());
    metadata.duration = Some(duration_seconds(samples.len(), channels, sample_rate));

    Ok(Decoded {
        samples,
        channels,
        sample_rate,
        metadata,
    })
}

/// Decode from bytes already in memory.
///
/// # Errors
///
/// As [`decode`].
pub fn decode_bytes(bytes: Vec<u8>, hint: Option<&str>) -> Result<Decoded> {
    decode(Box::new(Cursor::new(bytes)), hint)
}

/// Take the channel count and rate from the first decoded buffer.
///
/// A container may declare neither — `AudioCodecParameters::channels` and `sample_rate` are both
/// `Option` — but the decoded buffer's `AudioSpec` always knows.
fn update_spec(buffer: &GenericAudioBufferRef<'_>, channels: &mut usize, sample_rate: &mut u32) {
    let spec = buffer.spec();
    if *channels == 0 {
        *channels = spec.channels().count();
    }
    if *sample_rate == 0 {
        *sample_rate = spec.rate();
    }
}

/// Seconds of audio in a decoded sample count.
fn duration_seconds(samples: usize, channels: usize, sample_rate: u32) -> f64 {
    if channels == 0 || sample_rate == 0 {
        return 0.0;
    }

    #[allow(
        clippy::cast_precision_loss,
        reason = "a frame count large enough to lose f64 precision is 2^53 frames, over 6000 years"
    )]
    let frames = (samples / channels) as f64;
    frames / f64::from(sample_rate)
}

/// Pull title, artist and album out of whatever tags the container carried.
///
/// pyatv reads these with `TinyTag` in a second pass over the file
/// (`pyatv/support/metadata.py:21-40`); taking them from the demuxer that is already open is the
/// same information for one read instead of two. Artwork is deliberately not taken from embedded
/// visuals: pyatv's `MediaMetadata.artwork` is only ever set by a caller, never by the source
/// (`audio_source.py` never touches it).
fn read_tags(reader: &mut dyn symphonia::core::formats::FormatReader) -> TrackMetadata {
    let mut metadata = TrackMetadata::default();

    let mut log = reader.metadata();
    let Some(revision) = log.skip_to_latest() else {
        return metadata;
    };

    for tag in &revision.media.tags {
        match &tag.std {
            Some(StandardTag::TrackTitle(value)) => metadata.title = Some(value.to_string()),
            Some(StandardTag::Artist(value)) => metadata.artist = Some(value.to_string()),
            Some(StandardTag::Album(value)) => metadata.album = Some(value.to_string()),
            _ => {}
        }
    }

    metadata
}

#[cfg(test)]
mod tests {
    use super::{decode_bytes, duration_seconds};

    /// A 16-bit PCM WAV, written by hand so the test does not depend on an encoder.
    fn wav(sample_rate: u32, channels: u16, frames: &[i16]) -> Vec<u8> {
        let bytes_per_frame = u32::from(channels) * 2;
        let data: Vec<u8> = frames.iter().flat_map(|it| it.to_le_bytes()).collect();
        let data_len = u32::try_from(data.len()).expect("small fixture");

        let mut out = Vec::new();
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data_len).to_le_bytes());
        out.extend_from_slice(b"WAVEfmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes()); // PCM
        out.extend_from_slice(&channels.to_le_bytes());
        out.extend_from_slice(&sample_rate.to_le_bytes());
        out.extend_from_slice(&(sample_rate * bytes_per_frame).to_le_bytes());
        out.extend_from_slice(&u16::try_from(bytes_per_frame).expect("small").to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data_len.to_le_bytes());
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn a_wav_decodes_to_its_own_format() {
        let source = wav(44_100, 2, &[0, 0, i16::MAX, i16::MIN, 1000, -1000]);

        let decoded = decode_bytes(source, Some("wav")).expect("decodes");

        assert_eq!(decoded.channels, 2);
        assert_eq!(decoded.sample_rate, 44_100);
        assert_eq!(decoded.frames(), 3);
        assert!((decoded.samples[2] - 1.0).abs() < 0.001);
        assert!((decoded.samples[3] - (-1.0)).abs() < 0.001);
    }

    /// The probe works without the extension hint too, which is what a URL with no filename gives.
    #[test]
    fn a_wav_decodes_without_a_hint() {
        let source = wav(48_000, 1, &[100, 200, 300]);

        let decoded = decode_bytes(source, None).expect("decodes");

        assert_eq!(decoded.channels, 1);
        assert_eq!(decoded.sample_rate, 48_000);
        assert_eq!(decoded.frames(), 3);
    }

    /// Duration comes from the decoded frame count, not from a tag that may be absent.
    #[test]
    fn the_duration_is_the_decoded_length() {
        let frames: Vec<i16> = vec![0; 44_100 * 2];
        let decoded = decode_bytes(wav(44_100, 2, &frames), Some("wav")).expect("decodes");

        assert_eq!(
            decoded.metadata.duration.map(|it| (it * 1000.0).round()),
            Some(1000.0)
        );
    }

    #[test]
    fn a_non_audio_input_is_an_error_not_a_panic() {
        assert!(decode_bytes(b"this is not audio at all".to_vec(), Some("wav")).is_err());
        assert!(decode_bytes(Vec::new(), None).is_err());
    }

    #[test]
    fn an_empty_stream_has_no_duration() {
        assert!((duration_seconds(0, 2, 44_100) - 0.0).abs() < f64::EPSILON);
        assert!((duration_seconds(100, 0, 44_100) - 0.0).abs() < f64::EPSILON);
        assert!((duration_seconds(100, 2, 0) - 0.0).abs() < f64::EPSILON);
    }
}
