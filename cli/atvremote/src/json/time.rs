//! The `datetime` field.
//!
//! `datetime.datetime.now(timezone.utc).astimezone().isoformat()` (`atvscript.py:194`) — an
//! ISO-8601 timestamp with microsecond precision and an explicit UTC offset. This renders the same
//! instant in UTC, so the offset is always `+00:00`; see [`super`] for why the local offset is not
//! reproduced.

use std::time::{SystemTime, UNIX_EPOCH};

/// Seconds in a day.
const SECONDS_PER_DAY: i64 = 86_400;

/// The current time as `YYYY-MM-DDTHH:MM:SS.ffffff+00:00`.
#[must_use]
pub fn now_iso8601() -> String {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH);
    let (seconds, microseconds) = match since_epoch {
        Ok(duration) => (
            i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            duration.subsec_micros(),
        ),
        // A clock set before 1970. Nothing useful to print, and no reason to fail a command over
        // it, so the epoch itself stands in.
        Err(_) => (0, 0),
    };

    format_unix(seconds, microseconds)
}

/// Render a Unix timestamp as pyatv's ISO-8601.
///
/// Split out from [`now_iso8601`] so it can be tested against known instants; the clock is the
/// only thing that is not.
#[must_use]
pub fn format_unix(seconds: i64, microseconds: u32) -> String {
    let days = seconds.div_euclid(SECONDS_PER_DAY);
    let time_of_day = seconds.rem_euclid(SECONDS_PER_DAY);

    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60,
    );

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{microseconds:06}+00:00"
    )
}

/// Days since 1970-01-01 to a calendar date.
///
/// Howard Hinnant's `civil_from_days`
/// (<https://howardhinnant.github.io/date_algorithms.html#civil_from_days>), which is the
/// standard branch-free proleptic-Gregorian conversion and is what `chrono` and `time` implement
/// internally. Reproduced here rather than taking a dependency for one timestamp.
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // Shift the epoch to 0000-03-01, which puts the leap day at the end of the year.
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // Month index counting from March, so 0 is March and 11 is February.
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = month_from_march + if month_from_march < 10 { 3 } else { -9 };

    (year + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::{format_unix, now_iso8601};

    #[test]
    fn the_epoch_renders_as_midnight_on_new_years_day() {
        assert_eq!(format_unix(0, 0), "1970-01-01T00:00:00.000000+00:00");
    }

    /// Known instants, cross-checked against `date -u -d @<seconds>`.
    #[test]
    fn known_instants_round_trip() {
        for (seconds, expected) in [
            (1_000_000_000, "2001-09-09T01:46:40.000000+00:00"),
            (1_234_567_890, "2009-02-13T23:31:30.000000+00:00"),
            (1_700_000_000, "2023-11-14T22:13:20.000000+00:00"),
            // 2024-02-29, so the leap-year branch is covered.
            (1_709_164_800, "2024-02-29T00:00:00.000000+00:00"),
            // 2000-02-29: a century year that *is* a leap year.
            (951_782_400, "2000-02-29T00:00:00.000000+00:00"),
            // 1900-03-01, the day after a century year that is *not* a leap year.
            (-2_203_891_200, "1900-03-01T00:00:00.000000+00:00"),
        ] {
            assert_eq!(format_unix(seconds, 0), expected, "at {seconds}");
        }
    }

    #[test]
    fn microseconds_are_zero_padded_to_six_digits() {
        assert_eq!(format_unix(0, 5), "1970-01-01T00:00:00.000005+00:00");
        assert_eq!(format_unix(0, 123_456), "1970-01-01T00:00:00.123456+00:00");
    }

    /// The shape `atvscript.md:29` documents, minus the local offset.
    #[test]
    fn the_current_time_has_the_documented_shape() {
        let now = now_iso8601();
        assert_eq!(now.len(), "2020-04-06T18:51:04.758569+00:00".len(), "{now}");
        assert!(now.ends_with("+00:00"), "{now}");
        assert!(now.starts_with("20"), "{now}");
    }
}
