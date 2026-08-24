//! Unicast mDNS against a known host.
//!
//! `mdns-sd` sends queries to the multicast group only — it has no API for addressing a query to a
//! specific host's port 5353. pyatv needs that path for `--scan-hosts`, and for networks where
//! multicast is unreliable or blocked outright, which covers Docker bridges, most VLAN setups and a
//! good share of consumer mesh Wi-Fi.
//!
//! `docs/research/rust-crates.md` §2 leaves the implementation open between two options, and calls
//! it an architecture decision rather than a crate pick:
//!
//! 1. A plain `tokio::net::UdpSocket` plus `hickory-proto`'s `Message`/`Record` types purely as a
//!    wire codec. Correct and well-tested, at the cost of a large dependency used for a fraction of
//!    its surface. Gated behind this crate's `unicast` feature so the cost is opt-in while the
//!    decision is open.
//! 2. A hand-rolled DNS message codec. The record types actually needed are PTR, SRV, TXT, A and
//!    AAAA — a small, static surface, and the same argument that justified hand-writing OPACK and
//!    TLV8 applies here.
//!
//! Nothing is implemented until that decision is made. Guessing would mean writing a codec twice.

use std::net::IpAddr;

use pyatv_core::{BaseConfig, Result};

use crate::browse::ScanOptions;

/// The mDNS port. Unicast queries go to this port on the target host directly, bypassing the
/// multicast group.
pub const MDNS_PORT: u16 = 5353;

/// Queries specific hosts directly rather than browsing the multicast group.
#[derive(Debug)]
pub struct UnicastScanner {
    options: ScanOptions,
}

impl UnicastScanner {
    /// Build a scanner for the hosts named in `options`.
    #[must_use]
    pub fn new(options: ScanOptions) -> Self {
        Self { options }
    }

    /// The hosts this scanner will query.
    #[must_use]
    pub fn hosts(&self) -> &[IpAddr] {
        &self.options.hosts
    }

    /// Query each host and return whatever answers.
    ///
    /// # Errors
    ///
    /// Returns [`pyatv_core::Error::Io`] if the socket cannot be bound.
    // TODO(step-1): blocked on the codec decision in this module's documentation. Once made:
    // knock (see crate::knock), send one query per service type to <host>:5353, and parse the
    // answers into the same BaseConfig shape MulticastScanner produces.
    pub async fn discover(&self) -> Result<Vec<BaseConfig>> {
        let _ = &self.options;
        todo!("UnicastScanner::discover")
    }
}
