//! The [`pyatv_core::interface::PairingHandler`] implementation for AirPlay and RAOP.
//!
//! Port of `AirPlayPairingHandler` (`pyatv/protocols/airplay/pairing.py:19-97`). One handler serves
//! both protocols — upstream calls that out as a "HACK" (`pairing.py:80-82`) and branches on
//! `service.protocol` when deciding which settings slot the credentials belong in; the same branch
//! is here, in [`AirPlayPairingHandler::persist`].
//!
//! The exchange to run is chosen from the AirPlay major version alone
//! (`pairing.py:50-57`): AirPlay 2 devices get HAP pair-setup, AirPlay 1 devices get the legacy
//! device-authentication flow. mDNS pairing flags are not consulted here — they decide what
//! *verify* does, which is a separate axis (`docs/research/hap-pairing-port-spec.md` §9.3).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use pyatv_core::airplay::AirPlayMajorVersion;
use pyatv_core::consts::Protocol;
use pyatv_core::interface::{BoxFuture, PairingHandler};
use pyatv_core::models::BaseService;
use pyatv_core::storage::{DeviceSettings, Storage};
use pyatv_pairing::AuthenticationType;
use tokio::sync::Mutex;

use crate::auth::PairSetupProcedure;
use crate::http::HttpConnection;
use crate::{Error, Result};

/// Everything [`AirPlayPairingHandler::new`] needs that is not the storage backend.
#[derive(Debug, Clone)]
pub struct AirPlayPairingOptions {
    /// The device's IP address, from the config rather than from the service.
    pub address: IpAddr,
    /// The service being paired. Its `port` is the mDNS SRV port, never a hardcoded one.
    pub service: BaseService,
    /// Which exchange to run, from [`pyatv_core::airplay::get_protocol_version`].
    pub airplay_version: AirPlayMajorVersion,
    /// Identifier the credentials are filed under in storage.
    pub device_identifier: String,
    /// The device's advertised name, stored alongside the credentials for display.
    pub device_name: Option<String>,
}

/// Mutable state, behind one lock because the trait methods all take `&self`.
#[derive(Debug)]
struct Session {
    http: Option<HttpConnection>,
    procedure: Option<PairSetupProcedure>,
    pin: Option<u32>,
    has_paired: bool,
    service: BaseService,
}

/// Pairs one AirPlay or RAOP service.
#[derive(Debug)]
pub struct AirPlayPairingHandler {
    address: IpAddr,
    airplay_version: AirPlayMajorVersion,
    device_identifier: String,
    device_name: Option<String>,
    storage: Arc<dyn Storage>,
    session: Mutex<Session>,
}

impl AirPlayPairingHandler {
    /// Build a handler that will write its credentials into `storage`.
    #[must_use]
    pub fn new(options: AirPlayPairingOptions, storage: Arc<dyn Storage>) -> Self {
        Self {
            address: options.address,
            airplay_version: options.airplay_version,
            device_identifier: options.device_identifier,
            device_name: options.device_name,
            storage,
            session: Mutex::new(Session {
                http: None,
                procedure: None,
                pin: None,
                has_paired: false,
                service: options.service,
            }),
        }
    }

    /// The authentication type this device's AirPlay version calls for
    /// (`pyatv/protocols/airplay/pairing.py:51-55`).
    fn auth_type(&self) -> AuthenticationType {
        match self.airplay_version {
            AirPlayMajorVersion::V2 => AuthenticationType::Hap,
            AirPlayMajorVersion::V1 => AuthenticationType::Legacy,
        }
    }

    /// Open the connection and ask the device to show its PIN.
    async fn begin_inner(&self) -> Result<()> {
        let mut session = self.session.lock().await;
        let address = SocketAddr::new(self.address, session.service.port);

        let mut http = HttpConnection::connect(address).await?;
        let mut procedure = PairSetupProcedure::new(self.auth_type())?;

        tracing::debug!(
            %address,
            protocol = ?session.service.protocol,
            version = ?self.airplay_version,
            "starting AirPlay pairing"
        );
        procedure.start_pairing(&mut http).await?;

        session.http = Some(http);
        session.procedure = Some(procedure);
        session.has_paired = false;
        Ok(())
    }

    /// Complete the exchange and persist what it produced.
    async fn finish_inner(&self) -> pyatv_core::Result<()> {
        let mut session = self.session.lock().await;

        let pin = session.pin.ok_or(Error::NotStarted("PIN entry"))?;
        let Session {
            http: Some(http),
            procedure: Some(procedure),
            ..
        } = &mut *session
        else {
            return Err(Error::NotStarted("pairing").into());
        };

        let credentials = procedure.finish_pairing(http, pin).await?.to_string();

        session.service.credentials = Some(credentials.clone());
        session.has_paired = true;
        self.persist(session.service.protocol, &credentials)?;

        Ok(())
    }

    /// Write the credentials into storage under this device's identifier.
    ///
    /// Mirrors `pyatv/protocols/airplay/pairing.py:82-85`, which files them under the AirPlay slot
    /// or the RAOP slot depending on which protocol the shared handler was invoked for, and
    /// `pyatv/__init__.py:160` where the settings object came from storage in the first place.
    /// Existing settings for other protocols are read back and preserved rather than overwritten.
    fn persist(&self, protocol: Protocol, credentials: &str) -> pyatv_core::Result<()> {
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
        settings.protocols.entry(protocol).or_default().credentials = Some(credentials.to_owned());

        tracing::debug!(
            identifier = %self.device_identifier,
            ?protocol,
            "storing credentials"
        );
        self.storage.set_settings(settings)?;
        Ok(())
    }
}

impl PairingHandler for AirPlayPairingHandler {
    /// Always `true`: every pyatv pairing handler assumes the accessory shows the PIN and the user
    /// types it into the controller, never the reverse (`docs/research/hap-pairing-port-spec.md`
    /// §9.3).
    fn device_provides_pin(&self) -> bool {
        true
    }

    fn has_paired(&self) -> bool {
        self.session
            .try_lock()
            .is_ok_and(|session| session.has_paired)
    }

    fn service(&self) -> BaseService {
        // `try_lock` cannot fail here in the caller loop this trait documents: `begin`, `pin` and
        // `finish` have all returned by the time anyone asks. Falling back to a bare service rather
        // than blocking keeps this accessor free of a runtime dependency.
        self.session.try_lock().map_or_else(
            |_| BaseService::new(Protocol::AirPlay, 0),
            |session| session.service.clone(),
        )
    }

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
            if let Some(mut http) = session.http.take() {
                http.close().await.map_err(pyatv_core::Error::from)?;
            }
            Ok(())
        })
    }
}
