//! The [`pyatv_core::interface::PairingHandler`] implementation for MRP.
//!
//! Port of `MrpPairingHandler` (`pyatv/protocols/mrp/pairing.py:18-86`). The exchange itself is
//! [`crate::auth`]; this is the lifecycle around it — one connection opened on
//! [`PairingHandler::begin`], the PIN taken in between, credentials written to both the in-memory
//! service and [`Storage`] on [`PairingHandler::finish`].
//!
//! # Direct transport only, and why that is still worth having
//!
//! Pair-setup rides on `CryptoPairingMessage`, which only reaches a device that speaks MRP on its
//! own socket. A tvOS 15+ device does not: it has no `_mediaremotetv._tcp` service to dial, and the
//! tunnel that replaces it is established by AirPlay pairing instead. So this handler is for older
//! Apple TVs and `HomePod`s — and for the hermetic tests, which is the other reason to keep it: it
//! exercises the whole `CryptoPairingMessage` framing against a reference accessory without a
//! device in the room.
//!
//! # `finish` proves the credentials before reporting success
//!
//! Unusually for pyatv, MRP's own handler already does this: after pair-setup returns it runs a
//! full pair-verify against the fresh credentials **on the same connection**, and only then stores
//! them (`pairing.py:69-75`). That is preserved exactly, including the connection reuse.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use pyatv_core::consts::Protocol;
use pyatv_core::interface::{BoxFuture, PairingHandler};
use pyatv_core::models::BaseService;
use pyatv_core::storage::{InfoSettings, Storage};
use tokio::sync::Mutex;

use crate::auth::{MrpPairSetupProcedure, verify_credentials};
use crate::protocol::{MrpProtocol, MrpProtocolOptions};
use crate::transport::DirectTransport;
use crate::{Error, Result};

/// Everything [`MrpPairingHandler::new`] needs that is not the storage backend.
#[derive(Debug, Clone)]
pub struct MrpPairingOptions {
    /// The device's IP address, from the config rather than from the service.
    pub address: IpAddr,
    /// The service being paired. Its `port` is the mDNS SRV port, never a hardcoded one.
    pub service: BaseService,
    /// Identifier the credentials are filed under in storage.
    pub device_identifier: String,
    /// This controller's persisted identity, sent in `DEVICE_INFO_MESSAGE`.
    pub info: InfoSettings,
}

/// Mutable state, behind one lock because the trait methods all take `&self`.
#[derive(Debug)]
struct Session {
    protocol: Option<Arc<MrpProtocol>>,
    procedure: Option<MrpPairSetupProcedure>,
    pin: Option<u32>,
    has_paired: bool,
    service: BaseService,
}

/// Pairs one MRP service.
#[derive(Debug)]
pub struct MrpPairingHandler {
    address: IpAddr,
    device_identifier: String,
    info: InfoSettings,
    storage: Arc<dyn Storage>,
    session: Mutex<Session>,
}

impl MrpPairingHandler {
    /// Build a handler that will write its credentials into `storage`.
    #[must_use]
    pub fn new(options: MrpPairingOptions, storage: Arc<dyn Storage>) -> Self {
        Self {
            address: options.address,
            device_identifier: options.device_identifier,
            info: options.info,
            storage,
            session: Mutex::new(Session {
                protocol: None,
                procedure: None,
                pin: None,
                has_paired: false,
                service: options.service,
            }),
        }
    }

    /// Open the connection and ask the device to show its PIN.
    ///
    /// `begin` (`pairing.py:44-49`) via `MrpPairSetupProcedure.start_pairing`. The heartbeat is
    /// disabled for the pairing connection: it is short-lived, and upstream never starts one here
    /// either — `enable_heartbeat` is only called from `create_with_connection`'s `_connect`.
    async fn begin_inner(&self) -> Result<()> {
        let mut session = self.session.lock().await;
        let peer = SocketAddr::new(self.address, session.service.port);

        let transport = Arc::new(DirectTransport::connect(peer).await?);
        let protocol = Arc::new(MrpProtocol::connect(
            transport,
            MrpProtocolOptions {
                info: self.info.clone(),
                heartbeat_interval: None,
                ..MrpProtocolOptions::default()
            },
        ));

        tracing::debug!(%peer, "starting MRP pairing");
        let procedure = MrpPairSetupProcedure::start(&protocol).await?;

        session.protocol = Some(protocol);
        session.procedure = Some(procedure);
        session.has_paired = false;
        Ok(())
    }

    /// Complete the exchange, prove the credentials, then persist them.
    async fn finish_inner(&self) -> pyatv_core::Result<()> {
        let mut session = self.session.lock().await;

        let pin = session
            .pin
            .ok_or(Error::InvalidState("no PIN has been given"))?;
        let (Some(protocol), Some(procedure)) =
            (session.protocol.clone(), session.procedure.take())
        else {
            return Err(Error::InvalidState("pairing has not been started").into());
        };

        let credentials = procedure.finish(&protocol, pin).await?;

        // `pairing.py:69-72` — pairing is only successful if pair-verify against the fresh
        // credentials succeeds too, on this same connection.
        tracing::debug!("verifying the credentials MRP pair-setup produced");
        verify_credentials(&protocol, credentials.clone()).await?;

        let rendered = credentials.to_string();
        session.service.credentials = Some(rendered.clone());
        session.has_paired = true;
        self.persist(&rendered).await
    }

    /// Write the credentials into storage under this device's identifier.
    ///
    /// Upstream sets `self.service.credentials` and `self._settings.protocols.mrp.credentials`
    /// together (`pairing.py:74-75`); the second is this. [`Storage::save`] is the one method that
    /// really touches the disk, so it goes to a blocking task rather than being run inline on the
    /// caller's runtime.
    async fn persist(&self, credentials: &str) -> pyatv_core::Result<()> {
        tracing::debug!(identifier = %self.device_identifier, "storing MRP credentials");
        self.storage
            .store_credentials(&self.device_identifier, Protocol::Mrp, credentials)?;

        let storage = Arc::clone(&self.storage);
        tokio::task::spawn_blocking(move || storage.save())
            .await
            .map_err(|error| {
                pyatv_core::Error::Storage(format!("saving credentials panicked: {error}"))
            })?
    }
}

impl PairingHandler for MrpPairingHandler {
    /// Always `true`: the accessory shows the PIN and the user types it into the controller
    /// (`pairing.py:81-84`).
    fn device_provides_pin(&self) -> bool {
        true
    }

    fn has_paired(&self) -> bool {
        self.session
            .try_lock()
            .is_ok_and(|session| session.has_paired)
    }

    fn service(&self) -> BaseService {
        // `try_lock` cannot fail in the caller loop the trait documents: `begin`, `pin` and
        // `finish` have all returned by the time anyone asks.
        self.session.try_lock().map_or_else(
            |_| BaseService::new(Protocol::Mrp, 0),
            |session| session.service.clone(),
        )
    }

    /// Store the PIN the device displayed.
    ///
    /// Upstream additionally zero-pads to four digits — `str(pin).zfill(4)` (`pairing.py:83-86`) —
    /// which matters there because its SRP layer takes the PIN as a string. Here the PIN stays a
    /// number until [`pyatv_pairing::PairSetup`] formats it with the same padding at the one point
    /// it becomes an SRP password, so `42` and `"0042"` are the same pairing either way.
    fn pin(&self, pin: u32) -> pyatv_core::Result<()> {
        // Never logged: the PIN is the pair-setup password.
        let mut session = self
            .session
            .try_lock()
            .map_err(|_| pyatv_core::Error::Pairing("pairing is busy".to_owned()))?;
        session.pin = Some(pin);
        Ok(())
    }

    fn begin(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move { self.begin_inner().await.map_err(Into::into) })
    }

    fn finish(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(self.finish_inner())
    }

    fn close(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move {
            let mut session = self.session.lock().await;
            session.procedure = None;
            if let Some(protocol) = session.protocol.take() {
                protocol.close().await.map_err(pyatv_core::Error::from)?;
            }
            Ok(())
        })
    }
}
