//! TCP "knocking" to wake sleeping devices before a unicast scan.
//!
//! Ported from `pyatv/support/knock.py`. Apple TVs and HomePods hand their Bonjour registrations to
//! a sleep proxy when they doze off, and the proxy answers mDNS on their behalf but does not wake
//! them. Opening and immediately closing a TCP connection to a port the device itself owns does
//! wake it, so pyatv knocks before querying.
//!
//! The port list is fixed upstream and reproduced here.

use std::net::IpAddr;
use std::time::Duration;

use pyatv_core::Result;

/// Ports pyatv knocks on, from `pyatv/support/knock.py`.
///
/// 3689 is DAAP, 7000 is AirPlay's conventional port, and 49152/32498 are the low ends of the
/// ephemeral ranges MRP and Companion typically land in.
pub const KNOCK_PORTS: [u16; 4] = [3689, 7000, 49152, 32498];

/// How long to wait for a knock to connect before giving up on that port.
pub const KNOCK_TIMEOUT: Duration = Duration::from_millis(500);

/// Connect and immediately disconnect on every [`KNOCK_PORTS`] entry for each host.
///
/// Failures are expected and ignored: the point is the SYN, not a usable connection.
///
/// # Errors
///
/// Infallible in practice — individual connection failures are swallowed by design. The [`Result`]
/// is kept so a future implementation can report a socket that could not be created at all.
// TODO(step-1): `tokio::net::TcpStream::connect` per (host, port) under a `tokio::time::timeout`,
// joined concurrently, dropping every result.
pub async fn knock(hosts: &[IpAddr]) -> Result<()> {
    let _ = hosts;
    todo!("knock::knock")
}

#[cfg(test)]
mod tests {
    use super::KNOCK_PORTS;

    /// These exact ports are what makes a sleeping device answer; guard them against edits.
    #[test]
    fn knock_ports_match_pyatv() {
        assert_eq!(KNOCK_PORTS, [3689, 7000, 49152, 32498]);
    }
}
