//! Conforming decoded audio to what the receiver negotiated.
//!
//! This is the second half of what `miniaudio.decode_file(..., output_format, nchannels,
//! sample_rate)` does in one call (`pyatv/protocols/raop/audio_source.py:661-724`): map the channel
//! count, resample to the receiver's rate, and pack to big-endian integer samples.
//!
//! # Samples on the wire are big-endian
//!
//! pyatv byte-swaps its decoded samples with `if sys.byteorder == "little": output.byteswap()`
//! and its own comment says the author is not sure why that is the right condition
//! (`audio_source.py:36-49`, quoting issue #2057). The *requirement* is not in doubt, though: the
//! SDP says `L16`, and RTP's `L16` is big-endian by definition. So this converts to big-endian
//! unconditionally rather than porting a host-endianness test whose author flags it as uncertain
//! (`airplay-playurl-raop-port-spec.md` §11).

use std::borrow::Cow;

use rubato::audioadapter_buffers::direct::InterleavedSlice;
use rubato::{Fft, FixedSync, Resampler as _};

use crate::{Error, Result};

use super::decode::Decoded;

/// Chunk size the resampler works in. Any value works; upstream's own guidance is "start with 1024".
const RESAMPLE_CHUNK: usize = 1024;

/// The format a receiver negotiated, from its `sr`/`ch`/`ss` TXT keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcmFormat {
    /// Samples per second.
    pub sample_rate: u32,
    /// Channel count.
    pub channels: u8,
    /// Bytes per sample per channel — the `ss` TXT value divided by eight.
    pub bytes_per_sample: u8,
}

impl PcmFormat {
    /// Bytes in one frame.
    #[must_use]
    pub fn frame_size(self) -> usize {
        usize::from(self.channels) * usize::from(self.bytes_per_sample)
    }
}

/// Conform decoded audio to `target`, returning interleaved big-endian PCM bytes.
///
/// A whole track's samples are a large buffer — an hour of 44.1 kHz stereo is 1.27 GB as `f32` —
/// so each stage borrows through a [`Cow`] and only allocates when it genuinely changes the data.
/// A source that already matches the receiver's channel count and rate, which is the overwhelmingly
/// common case, therefore reaches [`pack`] without a single intermediate copy.
///
/// # Errors
///
/// Returns [`Error::Audio`] if the target format is degenerate — no channels, no rate, or a sample
/// width other than one, two, three or four bytes, which is exactly the set `_int2sf` accepts
/// (`audio_source.py:52-61`) — or if the resampler refuses the ratio.
pub fn conform(decoded: &Decoded, target: PcmFormat) -> Result<Vec<u8>> {
    if target.channels == 0 || target.sample_rate == 0 {
        return Err(Error::audio_format(format!(
            "the receiver negotiated an unusable format: {target:?}"
        )));
    }
    if !matches!(target.bytes_per_sample, 1..=4) {
        return Err(Error::audio_format(format!(
            "unsupported sample size: {}",
            target.bytes_per_sample
        )));
    }

    let mapped = map_channels(&decoded.samples, decoded.channels, target.channels);
    let resampled = resample(
        &mapped,
        usize::from(target.channels),
        decoded.sample_rate,
        target.sample_rate,
    )?;

    Ok(pack(&resampled, target.bytes_per_sample))
}

/// Fold or spread interleaved samples into `to` channels.
///
/// `miniaudio` is handed `nchannels` and does this internally; the rules here are the obvious ones
/// and are the ones a listener expects: a mono source is duplicated to every output channel, a
/// multi-channel source is averaged down to mono, and anything else takes the first `to` channels
/// of each frame. Nothing in RAOP negotiates more than two channels in practice.
///
/// Borrowed straight through when the counts already match, which is the usual case for a stereo
/// file streamed to a stereo receiver.
#[must_use]
pub fn map_channels(samples: &[f32], from: usize, to: u8) -> Cow<'_, [f32]> {
    let to = usize::from(to);
    if from == to || from == 0 {
        return Cow::Borrowed(samples);
    }

    let frames = samples.len() / from;
    let mut out = Vec::with_capacity(frames * to);

    for frame in samples.chunks_exact(from) {
        if to == 1 {
            #[allow(
                clippy::cast_precision_loss,
                reason = "a channel count is a handful, far inside f32's exact range"
            )]
            out.push(frame.iter().sum::<f32>() / from as f32);
            continue;
        }
        for channel in 0..to {
            // A mono source fills every output channel; a wider one is truncated.
            out.push(frame[channel.min(from - 1)]);
        }
    }

    Cow::Owned(out)
}

/// Resample interleaved `f32` audio.
///
/// Uses rubato's FFT resampler, which is the fixed-ratio case: a file's rate and the receiver's
/// rate are both known and constant, so there is no clock drift to track. `process_all` handles the
/// chunking and trims the resampler's own startup delay, so the output lines up with the input.
///
/// Borrowed straight through when the rates already match — no filter runs and nothing is copied.
///
/// # Errors
///
/// Returns [`Error::Audio`] if rubato refuses the ratio or the buffer shape.
pub fn resample(samples: &[f32], channels: usize, from: u32, to: u32) -> Result<Cow<'_, [f32]>> {
    if from == to || samples.is_empty() {
        return Ok(Cow::Borrowed(samples));
    }

    let frames = samples.len() / channels;
    let mut resampler = Fft::<f32>::new(
        usize::try_from(from).unwrap_or(usize::MAX),
        usize::try_from(to).unwrap_or(usize::MAX),
        RESAMPLE_CHUNK,
        channels,
        FixedSync::Both,
    )
    .map_err(|error| {
        Error::audio_format(format!("cannot resample {from} Hz to {to} Hz: {error}"))
    })?;

    let input = InterleavedSlice::new(samples, channels, frames)
        .map_err(|error| Error::audio_format(format!("malformed audio buffer: {error}")))?;

    let output = resampler
        .process_all(&input, frames, None)
        .map_err(|error| Error::audio_format(format!("resampling failed: {error}")))?;

    Ok(Cow::Owned(output.take_data()))
}

/// Pack `f32` samples in `-1.0..=1.0` into big-endian integer samples of `bytes_per_sample` width.
///
/// One byte per sample is *unsigned* and everything wider is signed, matching `_int2sf`'s
/// `UNSIGNED8`/`SIGNED16`/`SIGNED24`/`SIGNED32` mapping (`audio_source.py:52-61`).
#[must_use]
pub fn pack(samples: &[f32], bytes_per_sample: u8) -> Vec<u8> {
    let width = usize::from(bytes_per_sample);
    let mut out = Vec::with_capacity(samples.len() * width);

    for sample in samples {
        let clamped = sample.clamp(-1.0, 1.0);
        match bytes_per_sample {
            // Unsigned 8-bit: silence sits at 0x80, so the signed value is biased by 128.
            1 => out.push(unsigned_byte(scale(clamped, 7))),
            2 => out.extend_from_slice(
                &i16::try_from(scale(clamped, 15))
                    .unwrap_or(i16::MAX)
                    .to_be_bytes(),
            ),
            // The low three bytes of the big-endian representation, i.e. the sign-extended top
            // byte dropped.
            3 => out.extend_from_slice(&scale(clamped, 23).to_be_bytes()[1..4]),
            _ => out.extend_from_slice(&scale(clamped, 31).to_be_bytes()),
        }
    }

    out
}

/// Scale a clamped `-1.0..=1.0` sample to a signed integer of `bits` magnitude bits.
///
/// The multiplicand is `2^bits`, not `2^bits - 1`, and the result is clamped afterwards. That is
/// the inverse of the `sample / 2^bits` a decoder uses going the other way, so a 16-bit source
/// decoded to `f32` and packed back to 16 bits is bit-identical — with `2^bits - 1` a full-scale
/// sample comes back one LSB short. Only the single value `+1.0` needs the clamp, and it saturates
/// to the same positive maximum either way.
fn scale(sample: f32, bits: u32) -> i32 {
    #[allow(
        clippy::cast_precision_loss,
        reason = "the multiplicand is a power of two no larger than 2^31, exact in f64"
    )]
    let full = f64::from(sample) * ((1i64 << bits) as f64);

    #[allow(
        clippy::cast_possible_truncation,
        reason = "bounded by 2^31 because the caller clamps the input to +/-1.0"
    )]
    let rounded = full.round() as i64;
    let ceiling = (1i64 << bits) - 1;
    i32::try_from(rounded.clamp(-(1i64 << bits), ceiling)).unwrap_or(i32::MAX)
}

/// Bias a signed 8-bit-magnitude sample into the unsigned byte 8-bit PCM uses.
fn unsigned_byte(value: i32) -> u8 {
    u8::try_from(value.clamp(-128, 127) + 128).unwrap_or(0x80)
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{PcmFormat, conform, map_channels, pack, resample};
    use crate::audio::decode::Decoded;
    use crate::raop::metadata::TrackMetadata;

    fn decoded(samples: Vec<f32>, channels: usize, sample_rate: u32) -> Decoded {
        Decoded {
            samples,
            channels,
            sample_rate,
            metadata: TrackMetadata::default(),
        }
    }

    /// `L16` is big-endian, so full scale is `0x7FFF` and not `0xFF7F`. The negative extreme is
    /// `0x8000`, one further out than the positive one, because the scale is `2^15` and only the
    /// positive side saturates.
    #[test]
    fn sixteen_bit_samples_are_packed_big_endian() {
        assert_eq!(pack(&[1.0], 2), vec![0x7F, 0xFF]);
        assert_eq!(pack(&[-1.0], 2), vec![0x80, 0x00]);
        assert_eq!(pack(&[0.0], 2), vec![0x00, 0x00]);
    }

    /// A 16-bit source decoded to `f32` and packed back must survive unchanged, which is what the
    /// `2^bits` scale buys over `2^bits - 1`.
    #[test]
    fn a_full_scale_sixteen_bit_sample_round_trips_exactly() {
        let decoded = f32::from(i16::MAX) / 32_768.0;

        assert_eq!(pack(&[decoded], 2), i16::MAX.to_be_bytes().to_vec());
    }

    /// Anything outside the nominal range is clamped rather than wrapping to the opposite sign.
    #[test]
    fn out_of_range_samples_clamp_rather_than_wrap() {
        assert_eq!(pack(&[4.0], 2), vec![0x7F, 0xFF]);
        assert_eq!(pack(&[-4.0], 2), vec![0x80, 0x00]);
    }

    /// The other three widths `_int2sf` accepts, including the unsigned 8-bit case.
    #[test]
    fn the_other_sample_widths_follow_upstreams_mapping() {
        assert_eq!(pack(&[0.0], 1), vec![0x80]);
        assert_eq!(pack(&[1.0], 1), vec![0xFF]);
        assert_eq!(pack(&[1.0], 3), vec![0x7F, 0xFF, 0xFF]);
        assert_eq!(pack(&[1.0], 4), vec![0x7F, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn mono_is_duplicated_to_every_output_channel() {
        assert_eq!(*map_channels(&[0.5, -0.5], 1, 2), [0.5, 0.5, -0.5, -0.5]);
    }

    #[test]
    fn a_stereo_source_is_averaged_down_to_mono() {
        assert_eq!(*map_channels(&[1.0, 0.0, -1.0, 1.0], 2, 1), [0.5, 0.0]);
    }

    #[test]
    fn a_matching_channel_count_is_left_alone() {
        let samples = [0.1, 0.2, 0.3, 0.4];

        let mapped = map_channels(&samples, 2, 2);

        assert_eq!(*mapped, samples);
        assert!(
            matches!(mapped, Cow::Borrowed(_)),
            "a matching channel count must not copy the samples"
        );
    }

    /// A wider source is truncated to the first `to` channels of each frame.
    #[test]
    fn a_wider_source_is_truncated() {
        let samples = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0];

        assert_eq!(*map_channels(&samples, 3, 2), [1.0, 2.0, 4.0, 5.0]);
    }

    /// A matching rate skips the resampler entirely, so nothing is filtered or delayed.
    #[test]
    fn a_matching_rate_is_a_no_op() {
        let samples = [0.1, 0.2, 0.3, 0.4];

        let output = resample(&samples, 2, 44_100, 44_100).expect("no-op");

        assert_eq!(*output, samples);
        assert!(
            matches!(output, Cow::Borrowed(_)),
            "a matching rate must not copy the samples"
        );
    }

    /// Doubling the rate roughly doubles the frame count.
    #[test]
    fn resampling_changes_the_frame_count_by_the_ratio() {
        let samples: Vec<f32> = (0..8820u32)
            .map(|it| f32::from(u8::try_from(it % 100).unwrap_or(0)) / 100.0)
            .collect();

        let output = resample(&samples, 2, 22_050, 44_100).expect("resamples");

        let in_frames = samples.len() / 2;
        let out_frames = output.len() / 2;
        assert!(
            out_frames.abs_diff(in_frames * 2) < 64,
            "{out_frames} frames is not about {} frames",
            in_frames * 2
        );
    }

    /// The whole pipeline: a mono 22050 Hz source becomes stereo 44100 Hz big-endian bytes.
    #[test]
    fn conforming_maps_channels_resamples_and_packs() {
        let source = decoded(vec![0.0; 22_050], 1, 22_050);
        let target = PcmFormat {
            sample_rate: 44_100,
            channels: 2,
            bytes_per_sample: 2,
        };

        let bytes = conform(&source, target).expect("conforms");

        let frames = bytes.len() / target.frame_size();
        assert!(
            frames.abs_diff(44_100) < 64,
            "{frames} frames is not about 44100"
        );
        assert!(bytes.iter().all(|byte| *byte == 0), "silence stays silent");
    }

    /// A format the receiver cannot really have asked for is refused rather than producing
    /// nonsense bytes.
    #[test]
    fn a_degenerate_target_format_is_refused() {
        let source = decoded(vec![0.0; 8], 2, 44_100);

        for target in [
            PcmFormat {
                sample_rate: 44_100,
                channels: 0,
                bytes_per_sample: 2,
            },
            PcmFormat {
                sample_rate: 0,
                channels: 2,
                bytes_per_sample: 2,
            },
            PcmFormat {
                sample_rate: 44_100,
                channels: 2,
                bytes_per_sample: 5,
            },
        ] {
            assert!(conform(&source, target).is_err(), "{target:?}");
        }
    }
}
