//! mDNS/DNS-SD discovery.
//!
//! Discovery is where a device first becomes visible, and it drives everything downstream: each protocol's service type carries the TXT records that decide which capabilities exist, and — critically — the SRV record carries the port, which is never hardcoded because Apple TVs bind MRP and Companion to ephemeral high ports.
//!
//! Hand-rolled rather than backed by a general-purpose crate. `docs/research/rust-crates.md` §2 originally proposed `mdns-sd`, but `docs/research/discovery-port-spec.md` makes the case that won: pyatv's client deviates from RFC 6762 in several places Apple devices depend on (QU-bit PTR questions, a `_sleep-proxy._udp` question bundled into every datagram, blind one-second resends instead of the RFC backoff), and reproducing those on top of a strict library means fighting it. [`dns`] is therefore a sans-io DNS/DNS-SD codec ported from pyatv's `pyatv/support/dns.py`, [`mdns`] is the client transport, and [`publish`] is a small responder for the one case where this workspace has to be discoverable rather than discovering — DMAP pairing.
//!
//! `docs/research/pyatv-architecture.md` §3 documents the scan flow this crate reproduces: browse every service type, group responses by IP, merge each protocol's device-info extractor output, and materialise one config per physical device.
//!
//! The [`dns`] module is the sans-io half of all of this: a hand-written DNS/DNS-SD codec ported from pyatv's `pyatv/support/dns.py`, with no sockets and no dependency on the rest of the crate.

#![warn(missing_docs)]

pub mod browse;
pub mod dns;
pub mod knock;
pub mod mdns;
pub mod publish;
pub mod scan;
pub mod service;
pub mod service_types;

pub use browse::{MulticastScanner, ScanOptions, UnicastScanner, scan};
pub use dns::{DnsError, DnsMessage, DnsQuestion, DnsResource, QueryType, ServiceInstanceName};
pub use publish::{Responder, ServiceRegistration};
pub use scan::build_configs;
pub use service_types::ServiceType;
