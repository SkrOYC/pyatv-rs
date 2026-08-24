//! Per-protocol round trips, ported from `tests/protocols/*/test_*_scan.py`.
//!
//! One module per protocol, each named after the upstream file it comes from. The constants below
//! are shared because several of the tests deliberately put two protocols on one device.

mod airplay;
mod companion;
mod dmap;
mod mrp;
mod raop;

/// `tests/protocols/mrp/test_mrp_scan.py:13-18`.
pub(super) const MRP_ID: &str = "mrp_id_1";
pub(super) const MRP_NAME: &str = "MRP ATV";
pub(super) const MRP_SERVICE_NAME: &str = "MRP Service";
pub(super) const MRP_PORT: u16 = 49152;

/// `tests/protocols/airplay/test_airplay_scan.py:13-14`.
pub(super) const AIRPLAY_NAME: &str = "AirPlay ATV";
pub(super) const AIRPLAY_ID: &str = "AA:BB:CC:DD:EE:FF";

/// `tests/protocols/raop/test_raop_scan.py:13-17`.
pub(super) const RAOP_ID: &str = "AABBCCDDEEFF";
pub(super) const RAOP_NAME: &str = "RAOP ATV";
pub(super) const RAOP_PORT: u16 = 4567;

/// `tests/protocols/dmap/test_dmap_scan.py:15-19`.
pub(super) const DMAP_SERVICE_NAME: &str = "DMAP service";
pub(super) const DMAP_NAME: &str = "DMAP ATV";
pub(super) const DMAP_HSGID: &str = "hsgid";

/// `tests/protocols/companion/test_companion_scan.py:13-19`.
pub(super) const COMPANION_NAME: &str = "Companion";
pub(super) const COMPANION_PORT: u16 = 1234;
