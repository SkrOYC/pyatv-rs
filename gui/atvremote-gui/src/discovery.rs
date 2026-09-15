//! Network candidate host discovery for environments with multicast filtering.

use std::collections::HashSet;
use std::net::IpAddr;

/// Discover potential local host IPs where Apple TVs might reside.
#[must_use]
pub fn discover_candidate_hosts() -> Vec<IpAddr> {
    let mut hosts = HashSet::new();

    // 1. Linux ARP table (/proc/net/arp)
    #[cfg(target_os = "linux")]
    if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
        for line in content.lines().skip(1) {
            if let Some(ip_str) = line.split_whitespace().next()
                && let Ok(ip) = ip_str.parse::<IpAddr>()
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
            {
                hosts.insert(ip);
            }
        }
    }

    // 2. Query ip neighbor on Linux if ARP table had no results
    #[cfg(target_os = "linux")]
    if hosts.is_empty()
        && let Ok(output) = std::process::Command::new("ip")
            .args(["-4", "neigh", "show"])
            .output()
        && let Ok(text) = std::str::from_utf8(&output.stdout)
    {
        for line in text.lines() {
            if let Some(ip_str) = line.split_whitespace().next()
                && let Ok(ip) = ip_str.parse::<IpAddr>()
                && !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
            {
                hosts.insert(ip);
            }
        }
    }

    // 3. Resolve common Apple TV .local hostnames only if ARP/neigh discovery found nothing
    if hosts.is_empty() {
        for name in &["apple-tv.local", "appletv.local", "Sala.local"] {
            if let Ok(addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(*name, 7000)) {
                for addr in addrs {
                    if !addr.ip().is_loopback() && !addr.ip().is_unspecified() {
                        hosts.insert(addr.ip());
                    }
                }
            }
        }
    }

    // 4. Command line arguments (e.g. atvremote-gui 192.168.1.2)
    for arg in std::env::args().skip(1) {
        if let Ok(ip) = arg.parse::<IpAddr>() {
            hosts.insert(ip);
        }
    }

    hosts.into_iter().collect()
}
