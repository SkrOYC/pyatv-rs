//! mDNS/DNS-SD discovery.
//!
//! Discovery is where a device first becomes visible, and it drives everything downstream: each protocol's service type carries the TXT records that decide which capabilities exist, and — critically — the SRV record carries the port, which is never hardcoded because Apple TVs bind MRP and Companion to ephemeral high ports.
//!
//! Backed by `mdns-sd`, chosen in `docs/research/rust-crates.md` §2 as the only pure-Rust, actively maintained candidate that both browses and publishes. `zeroconf-rs` was rejected for wrapping Avahi/Bonjour in C, `libmdns` for being publish-only, and `searchlight` for being unmaintained.
//!
//! `docs/research/pyatv-architecture.md` §3 documents the scan flow this crate reproduces: browse every service type, group responses by IP, merge each protocol's device-info extractor output, and materialise one config per physical device.

//! The [`dns`] module is the sans-io half of all of this: a hand-written DNS/DNS-SD codec ported from pyatv's `pyatv/support/dns.py`, with no sockets and no dependency on the rest of the crate.

pub mod browse;
pub mod dns;
pub mod knock;
pub mod service_types;
pub mod unicast;

pub use browse::{MulticastScanner, ScanOptions};
pub use dns::{DnsError, DnsMessage, DnsQuestion, DnsResource, QueryType, ServiceInstanceName};
pub use service_types::ServiceType;
