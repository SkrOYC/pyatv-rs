//! Pairing.
//!
//! Equivalent to `pyatv.pair()`. Returns a [`PairingHandler`] the caller drives: `begin`, then
//! `pin` if the device displays one, then `finish`. On success the credentials are written to the
//! supplied [`Storage`], so callers never handle credential strings themselves.
//!
//! Which exchange runs depends on the protocol. MRP, Companion and modern AirPlay all use the same
//! HAP pair-setup from `pyatv-pairing`, differing only in how the TLV8 is enveloped; DMAP instead
//! runs the inverted flow where this process acts as the server. See
//! `docs/research/crypto-pairing.md` §2 and `docs/research/airplay-raop-dmap.md` §11.6.

use std::sync::Arc;

use pyatv_core::interface::PairingHandler;
use pyatv_core::storage::Storage;
use pyatv_core::{BaseConfig, Error, Protocol, Result};

/// Begin pairing with one protocol on a device.
///
/// # Errors
///
/// Returns [`Error::NoService`] if the device does not advertise the requested protocol, or
/// [`Error::UnsupportedProtocol`] if pairing is not implemented for it.
pub async fn pair(
    config: &BaseConfig,
    protocol: Protocol,
    storage: Arc<dyn Storage>,
) -> Result<Box<dyn PairingHandler>> {
    let _service = config
        .get_service(protocol)
        .ok_or(Error::NoService(protocol))?;
    let _ = storage;

    // TODO(step-1): dispatch to each protocol crate's pairing handler:
    //   Mrp       -> pyatv_proto_mrp, CryptoPairingMessage envelope
    //   Companion -> pyatv_proto_companion::pairing, PS_*/PV_* frames
    //   AirPlay   -> pyatv_proto_airplay, /pair-setup over RTSP
    //   Dmap      -> pyatv_proto_dmap::pairing, inverted client-as-server flow
    //   Raop      -> shares AirPlay's handler
    todo!("pyatv::pair")
}
