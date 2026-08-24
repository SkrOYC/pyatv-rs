//! mDNS/DNS-SD discovery.
//!
//! Discovery is where a device first becomes visible, and it drives everything downstream: each protocol's service type carries the TXT records that decide which capabilities exist, and — critically — the SRV record carries the port, which is never hardcoded because Apple TVs bind MRP and Companion to ephemeral high ports.
//!
//! Backed by `mdns-sd`, chosen in `docs/research/rust-crates.md` §2 as the only pure-Rust, actively maintained candidate that both browses and publishes. `zeroconf-rs` was rejected for wrapping Avahi/Bonjour in C, `libmdns` for being publish-only, and `searchlight` for being unmaintained.
//!
//! `docs/research/pyatv-architecture.md` §3 documents the scan flow this crate reproduces: browse every service type, group responses by IP, merge each protocol's device-info extractor output, and materialise one config per physical device.

pub mod browse;
pub mod knock;
pub mod service_types;
pub mod unicast;

pub use browse::{MulticastScanner, ScanOptions};
pub use service_types::ServiceType;
