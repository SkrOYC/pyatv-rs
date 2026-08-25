//! The percentage-to-decibel mapping RAOP volume uses.
//!
//! Port of `pct_to_dbfs`/`dbfs_to_pct` and the `map_range` they share
//! (`pyatv/protocols/airplay/utils.py:281-302`). The wire value in a `SET_PARAMETER volume` body is
//! decibels full scale; every public interface in this workspace speaks percent.

/// Quietest audible level, in dBFS.
pub const DBFS_MIN: f32 = -30.0;

/// Loudest level, in dBFS.
pub const DBFS_MAX: f32 = 0.0;

/// The dBFS value that means "muted".
///
/// Not simply the bottom of the linear range: `pct_to_dbfs(0)` short-circuits to this, well below
/// [`DBFS_MIN`] (`utils.py:288-291`).
pub const DBFS_MUTED: f32 = -144.0;

/// Bottom of the percentage range.
pub const PERCENTAGE_MIN: f32 = 0.0;

/// Top of the percentage range.
pub const PERCENTAGE_MAX: f32 = 100.0;

/// The volume reported before any real value is known.
///
/// `INITIAL_VOLUME = 33.0` (`pyatv/protocols/raop/__init__.py:67`) — a flat client-side constant,
/// not anything the device said.
pub const INITIAL_VOLUME: f32 = 33.0;

/// One volume step, in percentage points.
///
/// `min(self.volume + 5.0, 100.0)` (`raop/__init__.py:309-315`), duplicated between `RaopAudio` and
/// `RaopRemoteControl` upstream and shared here.
pub const VOLUME_STEP: f32 = 5.0;

/// Convert a percentage to the dBFS value the wire carries.
///
/// `pct_to_dbfs` (`utils.py:286-291`). Zero maps to [`DBFS_MUTED`] rather than to [`DBFS_MIN`].
///
/// The comparison is against exact zero, because that is what upstream's
/// `math.isclose(level, 0.0)` amounts to: `isclose` scales its default relative tolerance by the
/// larger operand, and with the other operand fixed at `0.0` the product is `0.0`, so only an
/// exact zero passes — `math.isclose(1e-300, 0.0)` is `False`. An `abs() <= f32::EPSILON` test
/// would instead mute every percentage below about `1.2e-7`, which upstream does not.
#[must_use]
pub fn pct_to_dbfs(level: f32) -> f32 {
    if level == 0.0 {
        return DBFS_MUTED;
    }

    map_range(level, PERCENTAGE_MIN, PERCENTAGE_MAX, DBFS_MIN, DBFS_MAX)
}

/// Render a dBFS level the way `SET_PARAMETER volume` expects it.
///
/// Upstream's body is `f"volume: {value}"` where `value` came through `str(volume)` on a Python
/// float (`stream_client.py:372`, `rtsp.py:194-200`) — and `str` of a float **always** carries a
/// decimal point: `str(-12.0)` is `"-12.0"`, not `"-12"`. Rust's `Display` for `f32` drops it, so
/// the naive `dbfs.to_string()` puts `volume: -12` on the wire where pyatv puts `volume: -12.0`.
///
/// A non-integral value is left as Rust's shortest round-tripping representation, which is the
/// same algorithm `repr`/`str` uses in Python — so `-29.7` and `-20.1` render identically in both.
/// The two differ only where an f32 and an f64 computation of the same expression land on
/// different decimal expansions, which the volume mapping's small multiples of `0.3` do not.
#[must_use]
pub fn format_dbfs(level: f32) -> String {
    let rendered = level.to_string();

    // `is_finite` guards the `inf`/`NaN` renderings, which must not gain a `.0` suffix.
    if level.is_finite() && !rendered.contains(['.', 'e', 'E']) {
        return format!("{rendered}.0");
    }

    rendered
}

/// The full `SET_PARAMETER` body for a volume change.
///
/// `f"{parameter}: {value}"` with `parameter = "volume"` (`rtsp.py:194-200`) — one space after the
/// colon and no trailing newline.
#[must_use]
pub fn volume_body(level: f32) -> String {
    format!("volume: {}", format_dbfs(level))
}

/// Convert a dBFS value back to a percentage.
///
/// `dbfs_to_pct` (`utils.py:294-302`). The guard is `level < DBFS_MIN`, strictly less than, and it
/// does **not** look for the [`DBFS_MUTED`] sentinel specifically — so `-144.0`, `-50.0` and
/// `-30.0001` all read as zero percent, and only `-30.0` and above map linearly.
#[must_use]
pub fn dbfs_to_pct(level: f32) -> f32 {
    if level < DBFS_MIN {
        return PERCENTAGE_MIN;
    }

    map_range(level, DBFS_MIN, DBFS_MAX, PERCENTAGE_MIN, PERCENTAGE_MAX)
}

/// Linear interpolation between two ranges (`pyatv/support/__init__.py::map_range`).
fn map_range(value: f32, in_min: f32, in_max: f32, out_min: f32, out_max: f32) -> f32 {
    (value - in_min) * (out_max - out_min) / (in_max - in_min) + out_min
}

/// One volume step up, clamped at the top of the range.
#[must_use]
pub fn step_up(volume: f32) -> f32 {
    (volume + VOLUME_STEP).min(PERCENTAGE_MAX)
}

/// One volume step down, clamped at the bottom of the range.
#[must_use]
pub fn step_down(volume: f32) -> f32 {
    (volume - VOLUME_STEP).max(PERCENTAGE_MIN)
}

#[cfg(test)]
mod tests {
    use super::{
        DBFS_MUTED, INITIAL_VOLUME, dbfs_to_pct, format_dbfs, pct_to_dbfs, step_down, step_up,
        volume_body,
    };

    /// `pct_to_dbfs(60) == -12.0` (`tests/protocols/raop/test_raop_functional.py:391-431`).
    #[test]
    fn the_percentage_map_matches_upstreams_test_vectors() {
        assert!((pct_to_dbfs(60.0) - (-12.0)).abs() < 1e-4);
        assert!((pct_to_dbfs(100.0) - 0.0).abs() < 1e-4);
        assert!((pct_to_dbfs(50.0) - (-15.0)).abs() < 1e-4);
    }

    /// The receiver's own `-15.0` default reads back as fifty percent.
    #[test]
    fn the_decibel_map_is_the_inverse_within_range() {
        assert!((dbfs_to_pct(-15.0) - 50.0).abs() < 1e-4);
        assert!((dbfs_to_pct(0.0) - 100.0).abs() < 1e-4);
        assert!((dbfs_to_pct(-30.0) - 0.0).abs() < 1e-4);
    }

    /// Zero percent is the mute sentinel, not the bottom of the linear range.
    #[test]
    fn zero_percent_is_muted_rather_than_minimum() {
        assert!((pct_to_dbfs(0.0) - DBFS_MUTED).abs() < 1e-4);
    }

    /// Everything below `-30.0` collapses to zero percent, sentinel or not.
    #[test]
    fn everything_below_the_minimum_reads_as_zero_percent() {
        for level in [DBFS_MUTED, -50.0, -30.001] {
            assert!(
                (dbfs_to_pct(level) - 0.0).abs() < 1e-4,
                "{level} did not read as zero"
            );
        }
    }

    /// Only an exact zero is the mute sentinel; a tiny but non-zero percentage maps linearly, as
    /// `math.isclose(level, 0.0)` does upstream.
    #[test]
    fn a_tiny_non_zero_percentage_is_not_muted() {
        assert!((pct_to_dbfs(f32::MIN_POSITIVE) - (-30.0)).abs() < 1e-4);
        assert!(pct_to_dbfs(f32::MIN_POSITIVE) > DBFS_MUTED);
    }

    /// `str(float)` always has a decimal point, so an integral dBFS level must not render as a
    /// bare integer.
    #[test]
    fn an_integral_level_keeps_its_decimal_point() {
        assert_eq!(format_dbfs(-12.0), "-12.0");
        assert_eq!(format_dbfs(-144.0), "-144.0");
        assert_eq!(format_dbfs(0.0), "0.0");
        assert_eq!(format_dbfs(-30.0), "-30.0");
    }

    /// A non-integral level is the shortest representation that round-trips, which is what Python
    /// `str` produces too.
    #[test]
    fn a_non_integral_level_is_the_shortest_representation() {
        assert_eq!(format_dbfs(-29.7), "-29.7");
        assert_eq!(format_dbfs(-20.1), "-20.1");
        assert_eq!(format_dbfs(-22.5), "-22.5");
        assert_eq!(format_dbfs(-14.7), "-14.7");
    }

    /// The full body, exactly as `f"{parameter}: {value}"` renders it: one space, no newline.
    #[test]
    fn the_volume_body_has_one_space_and_no_newline() {
        assert_eq!(volume_body(pct_to_dbfs(60.0)), "volume: -12.0");
        assert_eq!(volume_body(pct_to_dbfs(0.0)), "volume: -144.0");
        assert_eq!(volume_body(pct_to_dbfs(100.0)), "volume: 0.0");
        assert!(!volume_body(-15.0).ends_with('\n'));
    }

    #[test]
    fn the_steps_clamp_at_the_ends_of_the_range() {
        assert!((step_up(INITIAL_VOLUME) - 38.0).abs() < 1e-4);
        assert!((step_down(INITIAL_VOLUME) - 28.0).abs() < 1e-4);
        assert!((step_up(98.0) - 100.0).abs() < 1e-4);
        assert!((step_down(2.0) - 0.0).abs() < 1e-4);
    }
}
