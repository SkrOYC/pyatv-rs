//! Device discovery.
//!
//! Equivalent to `pyatv.scan()`. Browses the multicast group by default, or queries the hosts named
//! in [`ScanOptions::hosts`] by unicast when the caller supplies them — the latter matters on
//! networks where multicast does not work, which includes most Docker bridges and a good share of
//! consumer mesh Wi-Fi.

use pyatv_core::{BaseConfig, Result};
use pyatv_mdns::{MulticastScanner, ScanOptions};

/// Discover devices on the local network.
///
/// # Errors
///
/// Returns [`pyatv_core::Error::Io`] if no socket could be opened for discovery.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> pyatv::Result<()> {
/// let devices = pyatv::scan(pyatv::ScanOptions::default()).await?;
/// for device in &devices {
///     println!("{} at {}", device.name, device.address);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn scan(options: ScanOptions) -> Result<Vec<BaseConfig>> {
    // TODO(step-1): when `options.hosts` is non-empty, knock and then run the unicast scanner
    // instead, and merge results when both paths are requested.
    MulticastScanner::new(options).discover().await
}
