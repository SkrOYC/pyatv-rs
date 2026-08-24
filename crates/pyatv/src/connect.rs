//! Connecting to a device.
//!
//! Port of `pyatv.connect()` (`pyatv/__init__.py:101-159`). Settings and credentials are read out
//! of [`Storage`] and applied to a copy of the config, then every enabled service whose protocol
//! this build implements is set up in turn. Each protocol that connects contributes a
//! `SetupData` describing which capability traits it can serve, and those are filed into the
//! facade's relayers; the caller receives one [`AppleTV`] presenting all of them as a single
//! device.
//!
//! A protocol that fails to connect is **skipped rather than fatal**, matching upstream: a device
//! with working `AirPlay` but unpaired Companion should still give you video streaming. The whole
//! call only fails when nothing connected at all.
//!
//! # What is wired up today
//!
//! Companion. MRP, `AirPlay`, RAOP and DMAP are recognised and skipped with a debug log until their
//! own `setup()` lands; see `docs/ROADMAP.md`.

use std::sync::Arc;

use pyatv_core::facade::{DEFAULT_PRIORITIES, FacadeAppleTV, ListenerHub};
use pyatv_core::interface::{AppleTV, DeviceListener, PowerListener};
use pyatv_core::storage::{Settings, Storage};
use pyatv_core::{BaseConfig, BaseService, Error, Protocol, Result};
use pyatv_proto_companion::facade::{CompanionSetupOptions, setup as companion_setup};

/// Connect to a device over every enabled protocol.
///
/// When `protocol` is `Some`, only that protocol is used — upstream expresses the same thing by
/// passing `protocol=` and letting the loop skip everything else.
///
/// # Errors
///
/// Returns [`Error::NoService`] if `protocol` was named and the device does not advertise it,
/// [`Error::DeviceIdMissing`] if the config has no identifier to look settings up by, and
/// [`Error::ConnectionFailed`] if every protocol that was tried failed to connect.
///
/// # Examples
///
/// ```no_run
/// # use std::sync::Arc;
/// # async fn example(config: &pyatv::BaseConfig) -> pyatv::Result<()> {
/// let storage = Arc::new(pyatv::MemoryStorage::new());
/// let atv = pyatv::connect(config, None, storage).await?;
///
/// if let Some(apps) = atv.apps() {
///     for app in apps.app_list().await? {
///         println!("{} ({})", app.name, app.identifier);
///     }
/// }
/// atv.close().await?;
/// # Ok(())
/// # }
/// ```
pub async fn connect(
    config: &BaseConfig,
    protocol: Option<Protocol>,
    storage: Arc<dyn Storage>,
) -> Result<Arc<dyn AppleTV>> {
    if config.services.is_empty() {
        return Err(Error::NotSupported(
            "device advertises no usable service".to_owned(),
        ));
    }
    if config.identifier().is_none() {
        return Err(Error::DeviceIdMissing(config.name.clone()));
    }

    // `config_copy = deepcopy(config); config_copy.apply(settings)` (`__init__.py:117-121`). The
    // caller's config is never mutated, and the credentials the protocols read come from storage
    // rather than from whatever the scan happened to know.
    let settings = storage.get_settings(config)?;
    let mut config = config.clone();
    apply_settings(&mut config, &settings);

    let service = match protocol {
        Some(wanted) => config
            .get_service(wanted)
            .ok_or(Error::NoService(wanted))?
            .clone(),
        None => config
            .main_service()
            .ok_or_else(|| Error::NotSupported("device advertises no usable service".to_owned()))?
            .clone(),
    };

    let mut facade = FacadeAppleTV::new(service);
    // Taken before anything connects: a protocol reports a dropped socket to the hub, and the hub
    // fans it out to whatever the caller registers on the returned `AppleTV` afterwards. Without
    // this the protocols were handed `None` and `connection_lost` reached nobody at all.
    let listeners = facade.listener_hub();
    let mut failures = Vec::new();

    for service in enabled_services(&config, protocol) {
        match setup_protocol(&config, service, &settings, &listeners).await {
            Ok(Some(data)) => {
                tracing::debug!(protocol = ?service.protocol, "connected to protocol");
                facade.add_protocol(data);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::debug!(protocol = ?service.protocol, %error, "protocol failed to connect");
                failures.push(format!("{:?}: {error}", service.protocol));
            }
        }
    }

    if facade.is_empty() {
        return Err(Error::ConnectionFailed {
            address: config.address.to_string(),
            reason: if failures.is_empty() {
                "no supported protocol is configured for this device".to_owned()
            } else {
                failures.join("; ")
            },
        });
    }

    // `dict_merge` (`facade.py:772`) is first-writer-wins and protocols are added in the loop's
    // order, so anything the scan already knew wins over a protocol's own guess.
    let mut device_info = config.device_info.clone();
    device_info.merge_from(facade.device_info());
    facade.set_device_info(device_info);

    Ok(Arc::new(facade) as Arc<dyn AppleTV>)
}

/// The services to try, in facade-priority order and filtered by `protocol` if one was named.
///
/// Upstream iterates `PROTOCOLS`, a dict in protocol order, rather than the config's own discovery
/// order (`__init__.py:128-131`). Using [`DEFAULT_PRIORITIES`] here is the same idea and makes the
/// device-info merge deterministic: the highest-priority protocol writes each field first.
fn enabled_services(config: &BaseConfig, protocol: Option<Protocol>) -> Vec<&BaseService> {
    DEFAULT_PRIORITIES
        .into_iter()
        .filter(|candidate| protocol.is_none_or(|wanted| wanted == *candidate))
        .filter_map(|candidate| config.get_service(candidate))
        .filter(|service| {
            if service.enabled {
                true
            } else {
                tracing::debug!(protocol = ?service.protocol, "ignoring a disabled service");
                false
            }
        })
        .collect()
}

/// Run one protocol's `setup()`, or report that this build cannot speak it yet.
///
/// `Ok(None)` means "this protocol declined to register", which for Companion is the
/// no-credentials guard clause (`pyatv/protocols/companion/__init__.py:665-668`) and is not a
/// failure.
async fn setup_protocol(
    config: &BaseConfig,
    service: &BaseService,
    settings: &Settings,
    listeners: &Arc<ListenerHub>,
) -> Result<Option<pyatv_core::facade::SetupData>> {
    match service.protocol {
        Protocol::Companion => {
            let options = CompanionSetupOptions {
                peer: std::net::SocketAddr::new(config.address, service.port),
                service: service.clone(),
                info: settings.info.clone(),
                listener: Some(Arc::clone(listeners) as Arc<dyn DeviceListener>),
                power_listener: Some(Arc::clone(listeners) as Arc<dyn PowerListener>),
            };
            companion_setup(options).await.map_err(Into::into)
        }
        // TODO(step-2): wire the remaining protocols' setup() as each lands. Skipping keeps a
        // device with one working protocol usable instead of failing the whole connect.
        other => {
            tracing::debug!(protocol = ?other, "skipping a protocol this build cannot connect yet");
            Ok(None)
        }
    }
}

/// Copy stored credentials, passwords and identifiers onto the config's services.
///
/// `config_copy.apply(settings)` (`pyatv/interface.py::BaseConfig.apply`): a stored value never
/// clears one the scan already found, so a service that carries credentials keeps them.
fn apply_settings(config: &mut BaseConfig, settings: &Settings) {
    for protocol in Protocol::ALL {
        let credentials = settings.protocols.credentials(protocol);
        let password = settings.protocols.password(protocol);
        if credentials.is_none() && password.is_none() {
            continue;
        }

        if let Some(service) = config.get_service_mut(protocol) {
            service.apply(credentials, password);
        }
    }
}
