//! NTP and RTP clock arithmetic.
//!
//! Full port of `pyatv/protocols/raop/timing.py` (41 lines), which pyatv in turn credits to
//! RAOP-Player. Every function here is load-bearing on the wire: the sync packets
//! ([`super::packets::SyncPacket`]) carry `ts2ntp` output verbatim, and the RTP stream's zero point
//! is `ntp2ts(ntp_now())`.
//!
//! # Why the shifts are reproduced rather than simplified
//!
//! `ntp2ts` and `ts2ntp` shift by 16 bits *around* the multiply and divide instead of operating on
//! the whole 64-bit fixed-point value. Python needs that to keep intermediate values small; Rust
//! does not. The order is kept anyway, because integer truncation happens at each shift and not
//! only at the end, so a "simplified" version produces different low bits — and those low bits are
//! what a receiver's playback clock is slaved to.
//!
//! # Divergence: `ts2ntp` divides in floating point
//!
//! `int(int(timestamp << 16) / rate) << 16` uses Python's `/`, which is float division even
//! between two integers, and `int()` then truncates toward zero. At the magnitudes involved
//! (`timestamp << 16` is around 2^63 for a present-day NTP clock) that loses the low bits below
//! `f64`'s 53-bit mantissa. Replicated exactly, with `f64`, rather than "fixed" to integer
//! division: a receiver is comparing these against what an iOS sender produces, and matching pyatv
//! byte-for-byte is the only claim this port can actually test.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
///
/// `0x83AA7E80` (`timing.py:14`), the standard offset.
pub const NTP_UNIX_OFFSET: u64 = 0x83AA_7E80;

/// Convert a Unix timestamp in microseconds to 64-bit NTP fixed point.
///
/// Split out of [`ntp_now`] so the conversion is testable without a clock.
#[must_use]
pub fn ntp_from_unix_micros(now_us: u64) -> u64 {
    let seconds = now_us / 1_000_000;
    let frac = now_us % 1_000_000;

    // `frac < 10^6`, so `frac << 32 < 2^52` and the shift cannot overflow.
    ((seconds + NTP_UNIX_OFFSET) << 32) | ((frac << 32) / 1_000_000)
}

/// The current time in NTP format.
///
/// `ntp_now` (`timing.py:11-16`). A clock set before the Unix epoch reads as the epoch itself
/// rather than panicking; nothing downstream can do anything useful with a negative time.
#[must_use]
pub fn ntp_now() -> u64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    // `time_ns() / 1000`, i.e. microseconds. Python's float division is truncated by the `int()`
    // calls that follow it, so integer division is equivalent here.
    let micros = u64::try_from(since_epoch.as_micros()).unwrap_or(u64::MAX);
    ntp_from_unix_micros(micros)
}

/// Split an NTP timestamp into its seconds and fraction halves.
///
/// `ntp2parts` (`timing.py:19-21`).
#[must_use]
pub fn ntp2parts(ntp: u64) -> (u32, u32) {
    // Both halves are 32 bits wide by construction, so neither cast can lose information.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the shift and the mask each leave exactly 32 bits"
    )]
    ((ntp >> 32) as u32, (ntp & 0xFFFF_FFFF) as u32)
}

/// Convert an NTP timestamp into RTP clock ticks at `rate`.
///
/// `ntp2ts` (`timing.py:24-26`): `int((ntp >> 16) * rate) >> 16`. Computed through `u128` because
/// the intermediate product is within a factor of two of `u64::MAX` for a present-day clock at
/// 44100 Hz and would overflow outright at a higher rate.
#[must_use]
pub fn ntp2ts(ntp: u64, rate: u32) -> u64 {
    let scaled = (u128::from(ntp >> 16) * u128::from(rate)) >> 16;
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

/// Convert RTP clock ticks at `rate` back into an NTP timestamp.
///
/// `ts2ntp` (`timing.py:29-31`), floating-point division and all — see this module's header.
#[must_use]
pub fn ts2ntp(timestamp: u64, rate: u32) -> u64 {
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "replicating Python's float division and int() truncation exactly; see the \
                  module header"
    )]
    let divided = ((timestamp << 16) as f64 / f64::from(rate)) as u64;
    divided << 16
}

/// Convert an NTP timestamp into whole milliseconds.
///
/// `ntp2ms` (`timing.py:34-36`): `((ntp >> 10) * 1000) >> 22`.
#[must_use]
pub fn ntp2ms(ntp: u64) -> u64 {
    let scaled = (u128::from(ntp >> 10) * 1000) >> 22;
    u64::try_from(scaled).unwrap_or(u64::MAX)
}

/// Convert RTP clock ticks at `rate` into whole milliseconds.
///
/// `ts2ms` (`timing.py:39-41`).
#[must_use]
pub fn ts2ms(timestamp: u64, rate: u32) -> u64 {
    ntp2ms(ts2ntp(timestamp, rate))
}

#[cfg(test)]
mod tests {
    use super::{
        NTP_UNIX_OFFSET, ntp_from_unix_micros, ntp_now, ntp2ms, ntp2parts, ntp2ts, ts2ms, ts2ntp,
    };

    /// The Unix epoch itself is the NTP offset with an empty fraction.
    #[test]
    fn the_unix_epoch_is_the_ntp_offset() {
        assert_eq!(ntp_from_unix_micros(0), NTP_UNIX_OFFSET << 32);
    }

    /// Half a second is exactly half the fractional range, as `(frac << 32) / 10^6` gives.
    #[test]
    fn a_half_second_fraction_is_half_the_range() {
        let ntp = ntp_from_unix_micros(500_000);
        let (seconds, frac) = ntp2parts(ntp);

        assert_eq!(u64::from(seconds), NTP_UNIX_OFFSET);
        assert_eq!(frac, 0x8000_0000);
    }

    /// `ntp2ts` and `ts2ntp` are near-inverses; the round trip loses only the low 16 bits the
    /// shifts discard.
    #[test]
    fn the_ntp_and_timestamp_conversions_round_trip() {
        let ntp = ntp_from_unix_micros(1_700_000_000_000_000);
        let ticks = ntp2ts(ntp, 44_100);

        let back = ts2ntp(ticks, 44_100);
        let difference = ntp.abs_diff(back);

        assert!(difference < 1 << 20, "round trip drifted by {difference}");
    }

    /// One second of ticks at the sample rate is one second of NTP time.
    #[test]
    fn a_second_of_ticks_is_a_second_of_ntp() {
        let one_second = ts2ntp(44_100, 44_100);
        assert_eq!(one_second >> 32, 1);
    }

    /// `ntp2ms` is the millisecond view of the same fixed point.
    #[test]
    fn one_ntp_second_is_a_thousand_milliseconds() {
        // `((1 << 32) >> 10) * 1000 >> 22` == 1000, exactly.
        assert_eq!(ntp2ms(1 << 32), 1000);
        assert_eq!(ntp2ms(0), 0);
    }

    /// Positions are derived from this, so a whole second of frames must read as a whole second.
    #[test]
    fn a_second_of_frames_is_a_thousand_milliseconds() {
        assert_eq!(ts2ms(44_100, 44_100), 1000);
        assert_eq!(ts2ms(22_050, 44_100), 500);
    }

    /// The clock has to be past the NTP epoch or every timestamp on the wire is nonsense.
    #[test]
    fn the_current_time_is_after_the_unix_epoch() {
        assert!(ntp_now() >> 32 > NTP_UNIX_OFFSET);
    }

    /// The 44100 Hz product is close enough to `u64::MAX` that a naive `u64` multiply overflows;
    /// this pins the widened arithmetic.
    #[test]
    fn a_present_day_clock_does_not_overflow_the_tick_conversion() {
        let ntp = ntp_from_unix_micros(1_800_000_000_000_000);

        assert!(ntp2ts(ntp, 44_100) > 0);
        assert!(ntp2ts(ntp, 192_000) > 0);
    }
}
