//! Pairing.
//!
//! Equivalent to `pyatv.pair()` (`pyatv/__init__.py:160-192`). Returns a [`PairingHandler`] the
//! caller drives: `begin`, then `pin` if the device displays one, then `finish`. On success the
//! credentials are written to the supplied [`Storage`], so callers never handle credential strings
//! themselves.
//!
//! Which exchange runs depends on the protocol. MRP, Companion and modern AirPlay all use the same
//! HAP pair-setup from `pyatv-pairing`, differing only in how the TLV8 is enveloped; DMAP instead
//! runs the inverted flow where this process acts as the server. See
//! `docs/research/crypto-pairing.md` §2 and `docs/research/airplay-raop-dmap.md` §11.6.
//!
//! AirPlay and RAOP share one handler, exactly as upstream does — see
//! [`pyatv_proto_airplay::AirPlayPairingHandler`].

use std::sync::Arc;

use pyatv_core::airplay::{AirPlayVersion, get_protocol_version};
use pyatv_core::interface::PairingHandler;
use pyatv_core::storage::Storage;
use pyatv_core::{BaseConfig, Error, Protocol, Result};
use pyatv_proto_airplay::{AirPlayPairingHandler, AirPlayPairingOptions};

/// Begin pairing with one protocol on a device.
///
/// # Errors
///
/// Returns [`Error::NoService`] if the device does not advertise the requested protocol,
/// [`Error::NotSupported`] if the device has no stable identifier to file credentials under, or
/// [`Error::UnsupportedProtocol`] if pairing is not implemented for the protocol yet.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # async fn example(config: &pyatv::BaseConfig) -> pyatv::Result<()> {
/// let storage = Arc::new(pyatv::MemoryStorage::new());
/// let handler = pyatv::pair(config, pyatv::Protocol::AirPlay, storage).await?;
///
/// handler.begin().await?;
/// handler.pin(1234)?;
/// handler.finish().await?;
/// # Ok(())
/// # }
/// ```
pub async fn pair(
    config: &BaseConfig,
    protocol: Protocol,
    storage: Arc<dyn Storage>,
) -> Result<Box<dyn PairingHandler>> {
    let service = config
        .get_service(protocol)
        .ok_or(Error::NoService(protocol))?;

    let device_identifier = config
        .identifier()
        .ok_or_else(|| {
            Error::NotSupported("device has no identifier to store credentials under".to_owned())
        })?
        .to_owned();

    match protocol {
        Protocol::AirPlay | Protocol::Raop => {
            // `AirPlayVersion::Auto` reads the version off the service's own feature bits, which is
            // what `pyatv/protocols/airplay/__init__.py` does when no override is configured.
            let airplay_version = get_protocol_version(service, AirPlayVersion::Auto);
            tracing::debug!(
                ?protocol,
                ?airplay_version,
                port = service.port,
                "creating AirPlay pairing handler"
            );

            Ok(Box::new(AirPlayPairingHandler::new(
                AirPlayPairingOptions {
                    address: config.address,
                    service: service.clone(),
                    airplay_version,
                    device_identifier,
                    device_name: Some(config.name.clone()),
                },
                storage,
            )))
        }
        // TODO(step-1): dispatch the remaining protocols:
        //   Mrp       -> pyatv_proto_mrp, CryptoPairingMessage envelope
        //   Companion -> pyatv_proto_companion::pairing, PS_*/PV_* frames
        //   Dmap      -> pyatv_proto_dmap::pairing, inverted client-as-server flow
        Protocol::Mrp | Protocol::Companion | Protocol::Dmap => {
            Err(Error::UnsupportedProtocol(protocol))
        }
    }
}
