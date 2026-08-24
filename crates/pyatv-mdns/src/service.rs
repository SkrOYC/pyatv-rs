//! The transport-independent view of one mDNS answer.
//!
//! Mirrors `Service` and `Response` in `pyatv/core/mdns.py:39-54` (see
//! `docs/research/discovery-port-spec.md` §2.1). The scanners in this crate produce these; the
//! per-protocol scan handlers consume them. Keeping the two sides behind this plain data type is
//! what lets the handlers be tested from fixtures without any socket.

use std::net::IpAddr;

use crate::dns::Properties;

/// One DNS-SD service instance as advertised by a host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// Service type, e.g. `_airplay._tcp.local` (no trailing dot, as pyatv stores it).
    pub service_type: String,
    /// Instance name, i.e. the first label of the PTR target with DNS-SD escaping undone.
    pub name: String,
    /// Address from the A record, if one was answered. `None` for a sleeping device whose
    /// records are being held by a sleep proxy.
    pub address: Option<IpAddr>,
    /// Port from the SRV record; `0` when no SRV record was answered.
    pub port: u16,
    /// Decoded TXT record, case-insensitive keys.
    pub properties: Properties,
}

/// Everything one host answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Every service instance found for this host.
    pub services: Vec<Service>,
    /// True when the host is in deep sleep and a sleep proxy answered on its behalf
    /// (`pyatv/core/mdns.py`: every non-sleep-proxy service has port 0).
    pub deep_sleep: bool,
    /// Model string from the `_device-info._tcp.local` TXT record, when present.
    pub model: Option<String>,
}

/// Service type carrying the `model=` TXT key used to enrich every other service.
pub const DEVICE_INFO_SERVICE: &str = "_device-info._tcp.local";

/// Service type answered by a Bonjour sleep proxy on behalf of a sleeping host.
pub const SLEEP_PROXY_SERVICE: &str = "_sleep-proxy._udp.local";
