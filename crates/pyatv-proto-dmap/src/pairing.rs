//! DMAP pairing, in which this process is the *server*.
//!
//! Port of `pyatv/protocols/dmap/pairing.py`. Every other protocol in this workspace dials the
//! Apple TV and proves itself; DMAP inverts that. The controller starts a small HTTP server on an
//! ephemeral port, publishes `_touch-remote._tcp.local` so the device's "Add Remote" screen can
//! find it, and shows the user a PIN. The device then calls *back* with an MD5 of the pairing GUID
//! interleaved with the PIN digits, and a matching one completes the exchange.
//!
//! # The three pieces
//!
//! * [`code`] — the GUID and the MD5, pure functions with known-answer vectors.
//! * [`server`] — the `GET /pair` route and its DMAP reply.
//! * [`DmapPairingHandler`] — the [`PairingHandler`] lifecycle around both, plus the mDNS
//!   advertisement.
//!
//! # Why this crate depends on `pyatv-mdns`
//!
//! Being discoverable is not optional here: the device cannot call back to a port it has not been
//! told about. The responder that publishes it is
//! [`pyatv_mdns::publish`] — a protocol-agnostic primitive in the crate that
//! already owns every byte of DNS wire format in this workspace, which is where
//! `docs/research/dmap-port-spec.md` §2.5 argues it belongs. `pyatv-mdns` is discovery
//! infrastructure rather than a protocol crate and depends only on `pyatv-core`, so
//! `pyatv-proto-dmap` -> `pyatv-mdns` -> `pyatv-core` stays acyclic and does not breach the
//! workspace's "protocol crates do not depend on each other" rule.

pub mod code;
pub mod server;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, PoisonError};

use pyatv_core::consts::Protocol;
use pyatv_core::interface::{BoxFuture, PairingHandler};
use pyatv_core::models::BaseService;
use pyatv_core::storage::Storage;
use pyatv_mdns::publish::responder::publishable_addresses;
use pyatv_mdns::publish::{Responder, ServiceRegistration};

use crate::{Error, Result};

pub use code::{
    PAIRING_GUID_DIGITS, RESPONSE_DEVICE_TYPE, credentials, expected_code, generate_pairing_guid,
    normalise_pairing_guid, pairing_guid_from, verify,
};
pub use server::{
    DEVICE_TYPE, PAIR_PATH, PairingServer, PairingState, REMOTE_NAME, REMOTE_SERVICE_TYPE,
    REMOTE_VERSION, TXT_VERSION,
};

/// The default name this client advertises and returns as `cmnm`.
///
/// Upstream defaults to `core.settings.info.name` (`pairing.py:230`), which is the controller's own
/// configured display name.
pub const DEFAULT_REMOTE_NAME: &str = "pyatv-rs remote";

/// The host name published in the `SRV` record and the `A` records.
///
/// Any name resolvable through the same responder will do — the device follows the `SRV` target to
/// the `A` records this responder also answers — so a fixed one avoids depending on the host's own
/// `.local` name being advertised by anything else.
pub const PAIRING_HOST: &str = "pyatv-rs-pairing.local";

/// Everything [`DmapPairingHandler::new`] needs that is not the storage backend.
#[derive(Debug, Clone)]
pub struct DmapPairingOptions {
    /// The service being paired. Its credentials are replaced on success.
    pub service: BaseService,
    /// Identifier the credentials are filed under in storage.
    pub device_identifier: String,
    /// The name the device shows in its remote list, published as `DvNm`.
    pub name: String,
    /// A fixed pairing GUID, or `None` to generate one.
    ///
    /// `kwargs.get("pairing_guid")` (`pairing.py:237-239`), which exists so tests can be
    /// deterministic. Accepted with or without a `0x` prefix.
    pub pairing_guid: Option<String>,
    /// Addresses to advertise, or `None` for every private non-loopback IPv4 address.
    ///
    /// `kwargs.get("addresses")` (`pairing.py:240-242`), defaulting to
    /// `get_private_addresses(include_loopback=False)`.
    pub addresses: Option<Vec<Ipv4Addr>>,
}

impl DmapPairingOptions {
    /// Options for pairing `service`, filing credentials under `device_identifier`.
    #[must_use]
    pub fn new(service: BaseService, device_identifier: impl Into<String>) -> Self {
        Self {
            service,
            device_identifier: device_identifier.into(),
            name: DEFAULT_REMOTE_NAME.to_owned(),
            pairing_guid: None,
            addresses: None,
        }
    }
}

/// What `begin` brought up, torn down together by `close`.
#[derive(Debug, Default)]
struct Session {
    server: Option<PairingServer>,
    responders: Vec<Responder>,
}

/// Pairs one DMAP service, acting as the server the Apple TV connects to.
#[derive(Debug)]
pub struct DmapPairingHandler {
    state: Arc<PairingState>,
    device_identifier: String,
    addresses: Option<Vec<Ipv4Addr>>,
    storage: Arc<dyn Storage>,
    service: Mutex<BaseService>,
    session: Mutex<Session>,
}

impl DmapPairingHandler {
    /// Build a handler that will write its credentials into `storage`.
    #[must_use]
    pub fn new(options: DmapPairingOptions, storage: Arc<dyn Storage>) -> Self {
        let pairing_guid = options
            .pairing_guid
            .as_deref()
            .map_or_else(generate_pairing_guid, normalise_pairing_guid);

        Self {
            state: Arc::new(PairingState::new(pairing_guid, options.name)),
            device_identifier: options.device_identifier,
            addresses: options.addresses,
            storage,
            service: Mutex::new(options.service),
            session: Mutex::new(Session::default()),
        }
    }

    /// The GUID this session will persist on success, uppercase hex without the `0x`.
    #[must_use]
    pub fn pairing_guid(&self) -> &str {
        self.state.pairing_guid()
    }

    /// The port the pairing server bound, once [`PairingHandler::begin`] has run.
    ///
    /// Only meaningful to a test driving the device side directly; a real Apple TV learns it from
    /// the published `SRV` record.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.locked_session()
            .server
            .as_ref()
            .map(PairingServer::port)
    }

    /// The service registrations currently published, one per advertised address.
    #[must_use]
    pub fn registrations(&self) -> Vec<ServiceRegistration> {
        self.locked_session()
            .responders
            .iter()
            .map(|responder| responder.registration().clone())
            .collect()
    }

    /// The mDNS service describing this pairing server on one address.
    ///
    /// `_publish_service` (`pairing.py:288-308`). The six TXT keys are upstream's, verbatim and
    /// case-sensitively: an Apple TV browsing for `_touch-remote._tcp` reads `DvNm`, not `dvnm`.
    ///
    /// The instance name is `f"{int(address):040d}"` — the IPv4 address as a 32-bit integer,
    /// zero-padded to **forty** decimal digits. It is not human-meaningful and no upstream test
    /// asserts it, but it is what anything parsing the DNS-SD instance name would expect, so it is
    /// reproduced rather than replaced with something readable.
    #[must_use]
    pub fn registration(&self, address: Ipv4Addr, port: u16) -> ServiceRegistration {
        ServiceRegistration::new(
            REMOTE_SERVICE_TYPE,
            format!("{:040}", u32::from(address)),
            PAIRING_HOST,
            port,
        )
        .with_address(address)
        .with_property("DvNm", self.state.name())
        .with_property("RemV", REMOTE_VERSION)
        .with_property("DvTy", DEVICE_TYPE)
        .with_property("RemN", REMOTE_NAME)
        .with_property("txtvers", TXT_VERSION)
        .with_property("Pair", self.state.pairing_guid())
    }

    /// `begin` (`pairing.py:258-269`): bind the server, then publish it on every address.
    async fn begin_inner(&self) -> Result<()> {
        let server = PairingServer::bind(Arc::clone(&self.state)).await?;
        let port = server.port();

        let addresses = self.addresses.clone().unwrap_or_else(publishable_addresses);
        tracing::debug!(port, ?addresses, "publishing the DMAP pairing service");

        let mut responders = Vec::with_capacity(addresses.len());
        for address in addresses {
            // One responder per address, each bound to that address and answering only for the
            // instance naming it. Upstream publishes one zeroconf service per address for the same
            // reason, all pointing at the same port; binding per interface is also what gets
            // `IP_MULTICAST_IF` set, so the announcement leaves by the interface whose address it
            // advertises rather than by whichever one the routing table prefers.
            match Responder::bind(address, self.registration(address, port)) {
                Ok(responder) => responders.push(responder),
                // A failed bind on one interface must not stop the others: the device only has to
                // find us on the one it is actually on.
                Err(error) => {
                    tracing::warn!(%address, %error, "could not publish on this address");
                }
            }
        }

        let mut session = self.locked_session();
        session.server = Some(server);
        session.responders = responders;
        Ok(())
    }

    /// `finish` (`pairing.py:87-92`): persist, but only if the device actually paired.
    ///
    /// # Divergence: finishing without a pairing is an error, not a silent no-op
    ///
    /// Upstream's whole body is `if self._has_paired:` with no `else`, so calling `finish()` after
    /// a pairing that never happened returns successfully and writes nothing. The caller is then
    /// holding a handler that reports success while `service.credentials` still contains whatever
    /// it did before — for a first-time pairing, `None` — and the failure only surfaces later as
    /// an unexplained login failure.
    ///
    /// [`PairingHandler::has_paired`] is public and is how a caller is meant to find this out, so
    /// no information is lost by refusing; what changes is that the mistake is reported at the
    /// point it is made. `atvremote`'s pairing flow checks `has_paired` first either way, so the
    /// divergence is invisible to it.
    async fn finish_inner(&self) -> pyatv_core::Result<()> {
        if !self.state.has_paired() {
            return Err(Error::Pairing(
                "the device has not sent a matching pairing code".to_owned(),
            )
            .into());
        }

        let credential = credentials(self.state.pairing_guid());
        self.locked_service().credentials = Some(credential.clone());
        self.persist(&credential).await
    }

    /// Write the credential into storage under this device's identifier.
    ///
    /// Upstream sets `self.service.credentials` and
    /// `self._core.settings.protocols.dmap.credentials` together (`pairing.py:273-276`); this is
    /// the second. [`Storage::save`] is the call that touches the disk, so it goes to a blocking
    /// task rather than being run inline on the caller's runtime.
    async fn persist(&self, credential: &str) -> pyatv_core::Result<()> {
        tracing::debug!(identifier = %self.device_identifier, "storing DMAP credentials");
        self.storage
            .store_credentials(&self.device_identifier, Protocol::Dmap, credential)?;

        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || storage.save())
            .await
            .map_err(|error| {
                pyatv_core::Error::Storage(format!("saving credentials panicked: {error}"))
            })?
    }

    fn locked_session(&self) -> std::sync::MutexGuard<'_, Session> {
        self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn locked_service(&self) -> std::sync::MutexGuard<'_, BaseService> {
        self.service.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PairingHandler for DmapPairingHandler {
    /// **`false`**, uniquely among this workspace's handlers.
    ///
    /// `device_provides_pin` (`pairing.py:283-286`). Every other protocol has the accessory display
    /// a PIN for the user to type into the controller; DMAP is the other way round. The controller
    /// picks the PIN, the user types it on the Apple TV, and [`PairingHandler::pin`] is how the
    /// caller tells this handler which one it showed.
    fn device_provides_pin(&self) -> bool {
        false
    }

    fn has_paired(&self) -> bool {
        self.state.has_paired()
    }

    fn service(&self) -> BaseService {
        self.locked_service().clone()
    }

    /// Set the PIN this handler will expect the device to prove.
    ///
    /// Because [`PairingHandler::device_provides_pin`] is `false`, this is not "the PIN the device
    /// showed me" but "the PIN I am showing the user". Until it is called the handler is in
    /// upstream's accept-anything state (`_pin_code is None`, `pairing.py:147-148`), which is not a
    /// bug: it is what makes a pairing possible before a caller has decided on a PIN.
    ///
    /// # Errors
    ///
    /// Never; the signature is the trait's.
    fn pin(&self, pin: u32) -> pyatv_core::Result<()> {
        self.state.set_pin(pin);
        Ok(())
    }

    fn begin(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move { self.begin_inner().await.map_err(Into::into) })
    }

    fn finish(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(self.finish_inner())
    }

    /// `close` (`pairing.py:244-248`): withdraw the advertisement, then stop the server.
    ///
    /// The goodbye records go out first so a device that is mid-browse stops seeing a service that
    /// is about to refuse it.
    fn close(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move {
            let (server, responders) = {
                let mut session = self.locked_session();
                (
                    session.server.take(),
                    std::mem::take(&mut session.responders),
                )
            };

            for responder in responders {
                if let Err(error) = responder.unregister().await {
                    tracing::debug!(%error, "could not send an mDNS goodbye");
                }
            }
            drop(server);
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
