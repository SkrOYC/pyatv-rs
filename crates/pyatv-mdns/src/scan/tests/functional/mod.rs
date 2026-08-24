//! Cross-cutting scan behaviour, ported from `tests/test_scan_functional.py` and
//! `tests/core/test_scan.py`.
//!
//! Upstream's own module docstring explains the naming: MRP, `AirPlay` and RAOP stand in as
//! "service1/2/3" to emphasise that the specific protocols are irrelevant here — what is being
//! tested is grouping, merging, filtering and device-info precedence.

mod device_info;
mod filters;
mod grouping;
mod ohana;

/// `tests/test_scan_functional.py:21-33`.
pub(super) const SERVICE_1_ID: &str = "mrp_id_1";
pub(super) const SERVICE_1_NAME: &str = "MRP ATV";
pub(super) const SERVICE_1_SERVICE_NAME: &str = "MRP Service";
pub(super) const SERVICE_2_ID: &str = "AA:BB:CC:DD:EE:FF";
pub(super) const SERVICE_2_NAME: &str = "AirPlay ATV";
pub(super) const SERVICE_3_ID: &str = "raopid";
