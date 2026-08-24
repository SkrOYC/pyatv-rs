//! Device discovery.
//!
//! Equivalent to `pyatv.scan()` (`pyatv/__init__.py:33-95`). Browses the multicast group by
//! default, or queries the hosts named in [`ScanOptions::hosts`] by unicast when the caller
//! supplies them — the latter matters on networks where multicast does not work, which includes
//! most Docker bridges and a good share of consumer mesh Wi-Fi.
//!
//! This is a one-line delegate on purpose. Every scan rule — which service types to ask for, how
//! responses group into devices, which protocol claims a contested device-info field — lives in
//! `pyatv-mdns`, where it is tested against pyatv's own fixtures without a socket.

use pyatv_core::{BaseConfig, Result};
use pyatv_mdns::ScanOptions;

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
///     println!("{device}");
/// }
/// # Ok(())
/// # }
/// ```
pub async fn scan(options: ScanOptions) -> Result<Vec<BaseConfig>> {
    pyatv_mdns::scan(options).await
}
