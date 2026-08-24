//! Connecting to a device.
//!
//! Equivalent to `pyatv.connect()`. Every enabled service on the config is set up in turn; each
//! protocol that connects successfully contributes a `SetupData` describing which capability traits
//! it can serve, and those are filed into the facade's relayers. The caller receives one
//! [`AppleTV`] that presents all of them as a single device.
//!
//! A protocol that fails to connect is skipped rather than failing the whole call, matching pyatv:
//! a device with working AirPlay but unpaired Companion should still give you video streaming.

use std::sync::Arc;

use pyatv_core::facade::FacadeAppleTV;
use pyatv_core::interface::AppleTV;
use pyatv_core::storage::Storage;
use pyatv_core::{BaseConfig, Error, Protocol, Result};

/// Connect to a device over every enabled protocol.
///
/// When `protocol` is `Some`, only that protocol is used.
///
/// # Errors
///
/// Returns [`Error::NoService`] if the device has no usable service, or
/// [`Error::ConnectionFailed`] if every protocol failed to connect.
pub async fn connect(
    config: &BaseConfig,
    protocol: Option<Protocol>,
    storage: Arc<dyn Storage>,
) -> Result<Box<dyn AppleTV>> {
    let service = match protocol {
        Some(wanted) => config.get_service(wanted).ok_or(Error::NoService(wanted))?,
        None => config
            .main_service()
            .ok_or_else(|| Error::NotSupported("device advertises no usable service".to_owned()))?,
    };

    let _facade = FacadeAppleTV::new(service.clone());
    let _ = storage;

    // TODO(step-1): for each enabled service, call that protocol crate's setup(), await its
    // connect(), and on success hand the resulting SetupData to `facade.add_protocol`. Skip
    // protocols that fail rather than aborting. See docs/research/pyatv-architecture.md §3.
    todo!("pyatv::connect")
}
