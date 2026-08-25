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
//! # What `connect` deliberately does not do
//!
//! It does not start push updates. Upstream's does not either (`pyatv/__init__.py:101-159`): a
//! caller subscribes and starts them itself, with
//! `atv.push_updater().set_listener(&mine)` followed by `start(0)`, and that is the whole
//! sequence — [`pyatv_core::facade::FacadePushUpdater`] subscribes each protocol on `start`, so
//! nothing else is needed.
//!
//! # One protocol can contribute more than one registration
//!
//! `setup()` is a generator upstream, and `AirPlay`'s yields twice: once for `AirPlay` itself and
//! once, tagged `Protocol::MRP`, for the remote-control tunnel it hosts
//! (`pyatv/protocols/airplay/__init__.py:303-387`). That is why this module's `setup_protocol`
//! returns a `Vec<SetupData>` rather than one.
//!
//! # What is wired up today
//!
//! Companion, `AirPlay`, RAOP and MRP — the last over its own socket when the device still
//! advertises `_mediaremotetv._tcp`, and otherwise through the `AirPlay` tunnel, which is the only
//! way in on tvOS 15 and later — plus DMAP for Apple TV generations 1 to 3.

mod mrp;

use std::sync::Arc;

use pyatv_core::facade::{
    DEFAULT_PRIORITIES, FacadeAppleTV, ListenerHub, SetupData, StateDispatcher,
};
use pyatv_core::interface::{AppleTV, DeviceListener};
use pyatv_core::storage::{Settings, Storage};
use pyatv_core::{BaseConfig, BaseService, Error, Protocol, Result};
use pyatv_proto_airplay::raop::{RaopSetupOptions, setup as raop_setup};
use pyatv_proto_airplay::{AirPlaySetupOptions, setup as airplay_setup};
use pyatv_proto_companion::facade::{CompanionSetupOptions, setup as companion_setup};
use pyatv_proto_dmap::facade::{self as dmap, DmapSetupOptions, setup as dmap_setup};

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
        match setup_protocol(&config, service, &settings, &listeners, &facade).await {
            Ok(registrations) => {
                for data in registrations {
                    tracing::debug!(
                        service = ?service.protocol,
                        registered = ?data.protocol,
                        "connected to protocol"
                    );
                    facade.add_protocol(data);
                }
            }
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
/// An empty result means "this service declined to register", which for Companion is the
/// no-credentials guard clause (`pyatv/protocols/companion/__init__.py:665-668`) and for the
/// `AirPlay` tunnel is the gate in [`mrp::tunnel`]. Neither is a failure.
async fn setup_protocol(
    config: &BaseConfig,
    service: &BaseService,
    settings: &Settings,
    listeners: &Arc<ListenerHub>,
    facade: &FacadeAppleTV,
) -> Result<Vec<SetupData>> {
    match service.protocol {
        Protocol::Companion => {
            let options = CompanionSetupOptions {
                peer: std::net::SocketAddr::new(config.address, service.port),
                service: service.clone(),
                info: settings.info.clone(),
                listener: Some(Arc::clone(listeners) as Arc<dyn DeviceListener>),
                // Tagged with the protocol reporting through it, so that a device connected over
                // both MRP and Companion produces one callback per transition rather than two —
                // upstream subscribes only the main `Power` instance (`facade.py:777-781`).
                power_listener: Some(listeners.power_listener(Protocol::Companion)),
                state_dispatcher: Some(Arc::clone(listeners) as Arc<dyn StateDispatcher>),
            };
            Ok(companion_setup(options)
                .await
                .map_err(pyatv_core::Error::from)?
                .into_iter()
                .collect())
        }
        Protocol::Mrp => mrp::direct(config, service, settings, listeners).await,
        Protocol::AirPlay => {
            // `airplay.setup()` yields its own registration unconditionally and with nothing to
            // connect (`__init__.py:322-336`), so it cannot fail and is added before the tunnel is
            // even attempted — a device whose tunnel is refused still streams video.
            let mut registrations = vec![airplay_setup(&AirPlaySetupOptions {
                service: service.clone(),
                address: config.address,
                // `partial(atv.takeover, proto)` (`pyatv/__init__.py:138`): `play_url` claims
                // `RemoteControl` for the duration of a playback, so `stop()` reaches the AirPlay
                // stream rather than MRP while a URL is playing.
                takeover: Some(facade.takeover_handle(Protocol::AirPlay)),
                // `parse_credentials(service.credentials)` upstream (`__init__.py:84`); this port
                // also accepts another service's HAP pairing, for the reason
                // `pyatv_proto_airplay::setup::play_credentials` documents.
                credentials: pyatv_proto_airplay::play_credentials(config, service)
                    .inspect_err(|error| {
                        tracing::debug!(%error, "unusable AirPlay credentials, play_url disabled");
                    })
                    .ok(),
                protocol_version: settings.protocols.raop.protocol_version,
            })];

            if facade.connected_protocols().contains(&Protocol::Mrp) {
                // Upstream would set the tunnel up anyway and let the second registration replace
                // the first in every relayer. Skipping keeps the working direct connection instead
                // of silently swapping it for a second one that has to be torn down separately.
                tracing::debug!("MRP is already connected directly, not tunnelling it too");
            } else {
                // Matched rather than `?`-ed: propagating here would discard the `AirPlay`
                // registration built two lines above, so a receiver that refuses the
                // remote-control `SETUP` — an unpaired device, a firmware that dropped the
                // channel — would lose `play_url` as well as the tunnel it never had. The whole
                // point of the unconditional registration is that AirPlay survives a failed
                // tunnel; returning `Err` threw that away.
                match mrp::tunnel(config, service, settings, listeners).await {
                    Ok(Some(tunnel)) => registrations.push(tunnel),
                    Ok(None) => {}
                    Err(error) => tracing::warn!(
                        %error,
                        "the remote control tunnel failed; continuing with AirPlay only"
                    ),
                }
            }

            Ok(registrations)
        }
        Protocol::Raop => {
            // `raop.setup()` has nothing to connect either — its `_connect` is `async def … return
            // True` (`raop/__init__.py:568-570`) — so this registers unconditionally and the RTSP
            // connection is opened per `stream_file` call.
            //
            // The credentials go through the same fallback chain `play_url` uses: on a tvOS 15+
            // device the `_raop._tcp` service carries none of its own and the pairing that works is
            // the Companion one.
            Ok(vec![raop_setup(&RaopSetupOptions {
                address: config.address,
                service: service.clone(),
                credentials: pyatv_proto_airplay::play_credentials(config, service)
                    .inspect_err(|error| {
                        tracing::debug!(%error, "unusable RAOP credentials, streaming unpaired");
                    })
                    .unwrap_or_default(),
                protocol_version: settings.protocols.raop.protocol_version,
                // `core.takeover(Audio, Metadata, PushUpdater, RemoteControl)` around
                // `stream_file` (`raop/__init__.py:350-352`), so `playing()` describes the track
                // being streamed and `stop()` ends the stream.
                takeover: Some(facade.takeover_handle(Protocol::Raop)),
                state_dispatcher: Some(Arc::clone(listeners) as Arc<dyn StateDispatcher>),
            })])
        }
        Protocol::Dmap => {
            // `_device_info` re-reads the TXT records per service type after connecting
            // (`pyatv/protocols/dmap/__init__.py:696-704`), so the setup is told which of DMAP's
            // three service types this device actually answered under. `_hscp._tcp.local` is the
            // one that changes the answer: it means desktop Music, not an Apple TV.
            let service_types = dmap_service_types(config);
            Ok(vec![
                dmap_setup(DmapSetupOptions {
                    peer: std::net::SocketAddr::new(config.address, service.port),
                    service: service.clone(),
                    identifier: config.identifier().map(str::to_owned),
                    service_types,
                    listener: Some(Arc::clone(listeners) as Arc<dyn DeviceListener>),
                })
                .await
                .map_err(pyatv_core::Error::from)?,
            ])
        }
    }
}

/// Which of DMAP's three DNS-SD service types this device was seen under.
///
/// `for service_type in scan().keys(): properties = config.properties.get(service_type)`
/// (`pyatv/protocols/dmap/__init__.py:696-704`). A manually configured service has no TXT records
/// at all, so the list comes back empty and DMAP claims nothing about the hardware — which is
/// upstream's behaviour too, and better than asserting a legacy OS on no evidence.
fn dmap_service_types(config: &BaseConfig) -> Vec<String> {
    dmap::SERVICE_TYPES
        .into_iter()
        .filter(|service_type| config.has_properties(service_type))
        .map(str::to_owned)
        .collect()
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
