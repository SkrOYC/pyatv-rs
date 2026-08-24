//! The scan-handler layer: mDNS responses in, one [`pyatv_core::BaseConfig`] per device out.
//!
//! Ports `pyatv/core/scan.py`'s `BaseScanner` together with the five protocol modules'
//! `scan()`/`device_info()`/`service_info()` triples. Everything here is sans-io — the transport
//! lives in [`crate::mdns`] and the scanners that drive it in [`crate::browse`] — because the
//! interesting behaviour is all in the grouping, merging and precedence rules, and those are only
//! worth trusting if they can be tested against pyatv's own fixtures without a network.
//!
//! [`registry::build_configs`] is the entry point.

pub mod handlers;
pub mod registry;

#[cfg(test)]
pub(crate) mod tests;

pub use handlers::{
    DevInfoExtractor, ProtocolHandlers, ScanHandler, ServiceInfoFn, get_unique_id,
    unique_identifiers,
};
pub use registry::{ScanRegistry, build_configs};
