//! The [`pyatv_core::interface::PairingHandler`] implementation for Companion.
//!
//! Port of `CompanionPairingHandler` (`pyatv/protocols/companion/pairing.py:18-78`). The exchange
//! itself is [`crate::auth`]; this is the lifecycle around it — one connection opened on
//! [`PairingHandler::begin`], the PIN taken in between, credentials written to both the in-memory
//! service and [`Storage`] on [`PairingHandler::finish`].
//!
//! # Deliberate divergence: `finish` proves the credentials before reporting success
//!
//! pyatv's Companion handler considers pairing complete the moment pair-setup's SRP handshake
//! returns, with no check that the resulting credentials actually establish a session; its MRP
//! handler *does* run a pair-verify first. `docs/research/companion-port-spec.md` §4.4 and §12
//! finding 6 flag the difference as a decision a port has to make deliberately.
//!
//! **This port takes MRP's stricter path for Companion too**, on the lead's instruction: after
//! pair-setup succeeds, a second connection is opened and pair-verify is run against the fresh
//! credentials. Only if that succeeds are they persisted and `has_paired` set. The observable
//! consequence is that a device which completes SRP but then refuses the credentials is reported
//! as a pairing failure here and as a success by pyatv — the failure surfaces on the next connect
//! either way, but here it surfaces while the user is still looking at the PIN prompt.
//!
//! A fresh connection is used rather than the pairing one because pair-setup and pair-verify are
//! separate handshakes: the device treats a `PV_Start` on a socket that just finished pair-setup as
//! a new exchange anyway, and reconnecting is what the next real session will do.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use pyatv_core::consts::Protocol;
use pyatv_core::interface::{BoxFuture, PairingHandler};
use pyatv_core::models::BaseService;
use pyatv_core::storage::{DeviceSettings, Storage};
use pyatv_pairing::HapCredentials;
use tokio::sync::Mutex;

use crate::auth::{PairSetupOptionsCompanion, PairSetupProcedure, PairVerifyProcedure};
use crate::connection::CompanionConnection;
use crate::protocol::CompanionProtocol;
use crate::{Error, Result};

/// Everything [`CompanionPairingHandler::new`] needs that is not the storage backend.
#[derive(Debug, Clone)]
pub struct CompanionPairingOptions {
    /// The device's IP address, from the config rather than from the service.
    pub address: IpAddr,
    /// The service being paired. Its `port` is the mDNS SRV port, never a hardcoded one.
    pub service: BaseService,
    /// Identifier the credentials are filed under in storage.
    pub device_identifier: String,
    /// The device's advertised name, stored alongside the credentials for display.
    pub device_name: Option<String>,
    /// The name this controller asks the device to display while pairing.
    pub setup: PairSetupOptionsCompanion,
}

/// Mutable state, behind one lock because the trait methods all take `&self`.
#[derive(Debug)]
struct Session {
    protocol: Option<CompanionProtocol>,
    procedure: Option<PairSetupProcedure>,
    pin: Option<u32>,
    has_paired: bool,
    service: BaseService,
}

/// Pairs one Companion service.
#[derive(Debug)]
pub struct CompanionPairingHandler {
    address: IpAddr,
    device_identifier: String,
    device_name: Option<String>,
    setup: PairSetupOptionsCompanion,
    storage: Arc<dyn Storage>,
    session: Mutex<Session>,
}

impl CompanionPairingHandler {
    /// Build a handler that will write its credentials into `storage`.
    #[must_use]
    pub fn new(options: CompanionPairingOptions, storage: Arc<dyn Storage>) -> Self {
        Self {
            address: options.address,
            device_identifier: options.device_identifier,
            device_name: options.device_name,
            setup: options.setup,
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

    /// Where the pairing connection is dialled.
    fn peer(&self, port: u16) -> SocketAddr {
        SocketAddr::new(self.address, port)
    }

    /// Open the connection and ask the device to show its PIN.
    ///
    /// Mirrors `start_pairing`'s ordering (`auth.py:49-72`): the raw socket is opened first, then
    /// `CompanionProtocol.start()` runs — a no-op here, because pair-setup has no credentials to
    /// verify and therefore travels in the clear — and only then does M1 go out.
    async fn begin_inner(&self) -> Result<()> {
        let mut session = self.session.lock().await;
        let peer = self.peer(session.service.port);

        let connection = CompanionConnection::connect(peer).await?;
        let (mut protocol, _events) = CompanionProtocol::new(connection);

        tracing::debug!(%peer, "starting Companion pairing");
        // No credentials: pair-setup cannot be encrypted, since it is what establishes trust.
        protocol.start(None).await?;

        let mut procedure = PairSetupProcedure::new(&self.setup)?;
        procedure.start_pairing(&mut protocol).await?;

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
            .ok_or(Error::NotReady("no PIN has been given"))?;
        let port = session.service.port;
        let Session {
            protocol: Some(protocol),
            procedure: Some(procedure),
            ..
        } = &mut *session
        else {
            return Err(Error::NotReady("pairing has not been started").into());
        };

        let credentials = procedure.finish_pairing(protocol, pin).await?;

        // The divergence documented at the top of this module.
        self.prove(port, &credentials).await?;

        let rendered = credentials.to_string();
        session.service.credentials = Some(rendered.clone());
        session.has_paired = true;
        self.persist(&rendered)?;

        Ok(())
    }

    /// Run a pair-verify on a fresh connection, to prove credentials pair-setup just produced.
    async fn prove(&self, port: u16, credentials: &HapCredentials) -> Result<()> {
        let peer = self.peer(port);
        tracing::debug!(%peer, "verifying the credentials pair-setup produced");

        let connection = CompanionConnection::connect(peer).await?;
        let (mut protocol, _events) = CompanionProtocol::new(connection);

        // `start` with credentials is exactly pair-verify plus `enable_encryption`, so a success
        // here means the next real session will come up.
        let outcome = protocol.start(Some(credentials)).await;
        let encrypted = protocol.is_encrypted();

        // Best-effort: the proof already succeeded or failed, and a socket that will not shut down
        // cleanly must not turn a good pairing into a bad one.
        if let Err(error) = protocol.close().await {
            tracing::debug!(%error, "could not close the verification connection cleanly");
        }
        outcome?;

        if encrypted {
            Ok(())
        } else {
            Err(Error::NotReady(
                "pair-verify succeeded but left the connection unencrypted",
            ))
        }
    }

    /// Write the credentials into storage under this device's identifier.
    ///
    /// Upstream sets `self.service.credentials` and
    /// `self._settings.protocols.companion.credentials` together (`pairing.py:58-67`); the second
    /// is this. Settings for other protocols are read back and preserved rather than overwritten.
    fn persist(&self, credentials: &str) -> pyatv_core::Result<()> {
        let mut settings = self
            .storage
            .get_settings(&self.device_identifier)?
            .unwrap_or_else(|| DeviceSettings {
                identifier: self.device_identifier.clone(),
                ..DeviceSettings::default()
            });

        if settings.name.is_none() {
            settings.name.clone_from(&self.device_name);
        }
        settings
            .protocols
            .entry(Protocol::Companion)
            .or_default()
            .credentials = Some(credentials.to_owned());

        tracing::debug!(identifier = %self.device_identifier, "storing Companion credentials");
        self.storage.set_settings(settings)?;
        Ok(())
    }
}

impl PairingHandler for CompanionPairingHandler {
    /// Always `true`: every pyatv pairing handler assumes the accessory shows the PIN and the user
    /// types it into the controller (`pairing.py:70-73`).
    fn device_provides_pin(&self) -> bool {
        true
    }

    fn has_paired(&self) -> bool {
        self.session
            .try_lock()
            .is_ok_and(|session| session.has_paired)
    }

    fn service(&self) -> BaseService {
        // `try_lock` cannot fail in the caller loop this trait documents: `begin`, `pin` and
        // `finish` have all returned by the time anyone asks.
        self.session.try_lock().map_or_else(
            |_| BaseService::new(Protocol::Companion, 0),
            |session| session.service.clone(),
        )
    }

    /// Store the PIN the device displayed.
    ///
    /// Upstream additionally zero-pads to four digits — `str(pin).zfill(4)` (`pairing.py:75-78`) —
    /// which matters there because its SRP layer takes the PIN as a *string*. Here the PIN stays a
    /// number all the way into [`pyatv_pairing::PairSetup::set_pin`], which formats it with the
    /// same padding at the one point it becomes an SRP password, so `42` and `"0042"` are the same
    /// pairing either way.
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
            if let Some(mut protocol) = session.protocol.take() {
                protocol.close().await.map_err(pyatv_core::Error::from)?;
            }
            Ok(())
        })
    }
}

/// Convenience wrapper: run a Companion pair-verify and hand back an encrypted, session-ready
/// protocol.
///
/// This is what a connect path does with stored credentials, and what the pairing handler's own
/// proof step does with fresh ones.
///
/// # Errors
///
/// Returns [`Error::Connect`] if the device is unreachable and [`Error::Pairing`] if the
/// credentials are refused.
pub async fn verify(
    peer: SocketAddr,
    credentials: &HapCredentials,
) -> Result<(CompanionProtocol, crate::protocol::EventStream)> {
    let connection = CompanionConnection::connect(peer).await?;
    let (mut protocol, events) = CompanionProtocol::new(connection);

    PairVerifyProcedure::new(credentials.clone())
        .verify_credentials(&mut protocol)
        .await
        .map(|keys| protocol.enable_encryption(keys.output_key, keys.input_key))?;

    Ok((protocol, events))
}
