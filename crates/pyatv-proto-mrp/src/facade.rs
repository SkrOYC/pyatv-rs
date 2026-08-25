//! What MRP contributes to [`pyatv_core::facade::FacadeAppleTV`].
//!
//! Port of `create_with_connection` (`pyatv/protocols/mrp/__init__.py:1099-1166`) and the `setup()`
//! generator around it (`__init__.py:1169-1177`). [`setup`] takes a transport rather than building
//! one, for the same reason upstream splits those two functions: the AirPlay tunnel calls
//! `create_with_connection` directly with its own connection object and `requires_heatbeat=False`
//! (`pyatv/protocols/airplay/__init__.py:246-266`), and everything else about the setup is
//! identical.
//!
//! # What MRP registers, and what it does not
//!
//! `RemoteControl`, `Metadata`, `Power`, `PushUpdater`, `Features` and `Audio`. **No `Keyboard`**:
//! `GET_KEYBOARD_SESSION_MESSAGE` and `clientUpdatesConfig(keyboard=True)` subscribe to keyboard
//! *availability* pushes, but nothing in `pyatv/protocols/mrp/` ever constructs a
//! `TEXT_INPUT_MESSAGE`, and the only class implementing the `Keyboard` ABC upstream is
//! Companion's (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §14). **No `Apps`** and no
//! `UserAccounts` either, for the same reason: those are Companion's.

pub mod audio;
pub mod features;
pub mod metadata;
pub mod power;
pub mod remote;

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::facade::SetupData;
use pyatv_core::interface::{BoxFuture, DeviceListener, PowerListener, ProtocolHandle};
use pyatv_core::storage::InfoSettings;
use pyatv_core::{BaseService, DeviceInfo, DeviceModel, Protocol, device_info};
use pyatv_pairing::HapCredentials;

use crate::facade::audio::MrpAudio;
use crate::facade::features::{MrpFeatures, supported_features};
use crate::facade::metadata::{ArtworkFetcher, MrpMetadata, MrpPushUpdater};
use crate::facade::power::MrpPower;
use crate::facade::remote::MrpRemoteControl;
use crate::protobuf::extensions;
use crate::protocol::{HEARTBEAT_INTERVAL, MrpProtocol, MrpProtocolOptions, REQUEST_TIMEOUT};
use crate::transport::{MrpTransport, TransportEncryption};
use crate::{Error, Result};

/// Everything [`setup`] needs beyond the transport.
#[derive(Debug, Clone)]
pub struct MrpSetupOptions {
    /// The service being connected, for its credentials and TXT properties.
    pub service: BaseService,
    /// This controller's persisted identity, sent in `DEVICE_INFO_MESSAGE`.
    pub info: InfoSettings,
    /// The device identifier [`pyatv_core::interface::Metadata::device_id`] reports.
    pub identifier: Option<String>,
    /// Heartbeat interval, or `None` to disable.
    ///
    /// Defaults to [`HEARTBEAT_INTERVAL`] for a transport that does its own encryption and to
    /// `None` for a tunnel, which is exactly upstream's `requires_heatbeat` split. Left as an
    /// explicit option because heartbeat desync on recent tvOS builds is an open upstream issue.
    pub heartbeat_interval: Option<Duration>,
    /// How long a request waits for its response.
    pub request_timeout: Duration,
    /// Notified if the connection drops without the caller asking.
    pub listener: Option<Arc<dyn DeviceListener>>,
    /// Notified when the device reports a new power state.
    pub power_listener: Option<Arc<dyn PowerListener>>,
    /// Fetches artwork from URLs the device advertises; see [`ArtworkFetcher`].
    pub artwork_fetcher: Option<Arc<dyn ArtworkFetcher>>,
}

impl MrpSetupOptions {
    /// Options for `service`, with everything else left at its default.
    #[must_use]
    pub fn new(service: BaseService) -> Self {
        Self {
            service,
            info: InfoSettings::default(),
            identifier: None,
            heartbeat_interval: Some(HEARTBEAT_INTERVAL),
            request_timeout: REQUEST_TIMEOUT,
            listener: None,
            power_listener: None,
            artwork_fetcher: None,
        }
    }
}

/// The teardown hook the facade awaits on close.
#[derive(Debug)]
pub struct MrpHandle {
    protocol: Arc<MrpProtocol>,
}

impl ProtocolHandle for MrpHandle {
    /// `_close` (`__init__.py:1133-1136`): stop pushing updates, then stop the protocol.
    fn close(&self) -> BoxFuture<'_, pyatv_core::Result<()>> {
        Box::pin(async move {
            self.protocol.state().set_push_active(false);
            self.protocol.close().await.map_err(Into::into)
        })
    }
}

/// Connect MRP over `transport` and describe what it contributes.
///
/// `create_with_connection` with its `_connect` closure already run: upstream yields a `SetupData`
/// holding a not-yet-awaited coroutine and lets `FacadeAppleTV.connect()` drive it, whereas here
/// connecting is what produces the handles in the first place. The observable order is the same.
///
/// Unlike Companion's, this does **not** bail out when the service has no credentials: an
/// unpaired direct MRP connection is legal and simply stays in the clear — `_enable_encryption`
/// returns immediately and everything after it is plaintext (`protocol.py:207-210`). The tunnel
/// path relies on exactly that.
///
/// # Errors
///
/// Returns [`Error::InvalidCredentials`] if the stored credential string does not parse,
/// [`Error::Timeout`] if the device does not answer during bring-up, and [`Error::Pairing`] if it
/// refuses the credentials.
///
/// [`Error::InvalidCredentials`]: pyatv_core::Error::InvalidCredentials
pub async fn setup(
    transport: Arc<dyn MrpTransport>,
    options: MrpSetupOptions,
) -> Result<SetupData> {
    let credentials = match options
        .service
        .credentials
        .as_deref()
        .filter(|it| !it.is_empty())
    {
        Some(raw) => Some(HapCredentials::parse(raw).map_err(Error::Pairing)?),
        None => None,
    };

    // The tunnel never pair-verifies at the MRP layer, so credentials on that path would be
    // ignored anyway; dropping them here makes that explicit rather than silently inert.
    let credentials = match transport.encryption() {
        TransportEncryption::MrpLevel => credentials,
        TransportEncryption::DelegatedToTunnel => None,
    };

    let heartbeat_interval = match transport.encryption() {
        TransportEncryption::MrpLevel => options.heartbeat_interval,
        TransportEncryption::DelegatedToTunnel => None,
    };

    let protocol = Arc::new(MrpProtocol::connect(
        transport,
        MrpProtocolOptions {
            info: options.info.clone(),
            credentials,
            heartbeat_interval,
            request_timeout: options.request_timeout,
            listener: options.listener.clone(),
            ..MrpProtocolOptions::default()
        },
    ));
    protocol.state().set_power_listener(options.power_listener);
    protocol.start().await?;

    let remote = Arc::new(MrpRemoteControl::new(Arc::clone(&protocol)));

    Ok(SetupData {
        protocol: Some(Protocol::Mrp),
        features: supported_features(),
        features_impl: Some(Arc::new(MrpFeatures::new(&protocol))),
        handle: Some(Arc::new(MrpHandle {
            protocol: Arc::clone(&protocol),
        })),
        remote_control: Some(Arc::clone(&remote) as Arc<_>),
        metadata: Some(Arc::new(MrpMetadata::new(
            Arc::clone(&protocol),
            options.identifier.clone(),
            options.artwork_fetcher.clone(),
        ))),
        push_updater: Some(Arc::new(MrpPushUpdater::new(Arc::clone(&protocol)))),
        power: Some(Arc::new(MrpPower::new(Arc::clone(&protocol), remote))),
        audio: Some(Arc::new(MrpAudio::new(Arc::clone(&protocol)))),
        device_info: device_facts(&protocol, &options.service),
        ..SetupData::default()
    })
}

/// What the connection knows about the hardware.
///
/// `_device_info` (`__init__.py:1138-1149`): the build number and model come from the device's own
/// `DeviceInfoMessage`, which the bring-up sequence has already exchanged by the time this runs.
fn device_facts(protocol: &MrpProtocol, _service: &BaseService) -> DeviceInfo {
    let Some(info) = protocol.state().device_info() else {
        return DeviceInfo::default();
    };

    let mut facts = DeviceInfo::default();
    if let Some(build) = info
        .system_build_version
        .as_deref()
        .filter(|it| !it.is_empty())
    {
        facts = facts.with_build_number(build);
    }
    if let Some(model) = info.model_id.as_deref().filter(|it| !it.is_empty()) {
        facts = facts.with_raw_model(model);
        match device_info::lookup_model(Some(model)) {
            DeviceModel::Unknown => {}
            resolved => facts = facts.with_model(resolved),
        }
    }
    facts
}

/// The extension a `DEVICE_INFO_MESSAGE` carries, re-exported so the umbrella can read it without
/// reaching into [`crate::protobuf::extensions`].
pub use extensions::DEVICE_INFO_MESSAGE;
