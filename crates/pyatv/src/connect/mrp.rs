//! Bringing MRP up, over either of its two transports.
//!
//! Port of `pyatv/protocols/mrp/__init__.py::setup` (the direct socket) and
//! `pyatv/protocols/airplay/__init__.py::_create_mrp_tunnel_data` (the AirPlay tunnel). Both end at
//! the same `pyatv_proto_mrp::setup`, differing only in which transport they hand it and whether a
//! heartbeat runs — which is exactly upstream's shape, where one `create_with_connection` is called
//! from both places with a different `AbstractMrpConnection` and a different `requires_heatbeat`.
//!
//! See `docs/research/airplay-control-mrp-tunnel-port-spec.md` §2.4 and §7.

use std::net::SocketAddr;
use std::sync::Arc;

use pyatv_core::airplay::{AirPlayMajorVersion, AirPlayVersion, get_protocol_version};
use pyatv_core::facade::{ListenerHub, SetupData};
use pyatv_core::interface::{BoxFuture, DeviceListener, PowerListener, ProtocolHandle};
use pyatv_core::storage::{MrpTunnel, Settings};
use pyatv_core::{BaseConfig, BaseService, Protocol, Result};
use pyatv_proto_airplay::ap2::InfoSettings as Ap2InfoSettings;
use pyatv_proto_airplay::{Ap2Session, SeqnoPolicy, is_tunnel_supported, tunnel_credentials};
use pyatv_proto_mrp::transport::{DirectTransport, TunnelTransport};
use pyatv_proto_mrp::{MrpSetupOptions, setup as mrp_setup};
use tokio::sync::Mutex;

use crate::tunnel::AirPlayByteChannel;

/// Connect MRP over its own TCP socket.
///
/// `pyatv/protocols/mrp/__init__.py:1169-1177`, which has no gate of its own: whether the service
/// is usable at all was decided at scan time, when a `SystemBuildVersion` of tvOS 15 or later
/// disabled it (`__init__.py:1025-1048`). This port keeps that split — the caller filters on
/// `service.enabled` before ever reaching here.
///
/// # Errors
///
/// Returns [`pyatv_core::Error::ConnectionFailed`] if the socket cannot be opened and whatever MRP
/// bring-up reports otherwise.
pub(super) async fn direct(
    config: &BaseConfig,
    service: &BaseService,
    settings: &Settings,
    listeners: &Arc<ListenerHub>,
) -> Result<Vec<SetupData>> {
    let peer = SocketAddr::new(config.address, service.port);
    let transport = DirectTransport::connect(peer).await?;

    let data = mrp_setup(
        Arc::new(transport),
        options(config, service.clone(), settings, listeners),
    )
    .await?;

    Ok(vec![data])
}

/// Connect MRP through an AirPlay 2 remote-control tunnel.
///
/// `_create_mrp_tunnel_data` (`pyatv/protocols/airplay/__init__.py:234-300`) with its `_connect_rc`
/// already run. `Ok(None)` means the gate declined, which is not a failure — upstream expresses the
/// same thing by not yielding a `SetupData` at all (`__init__.py:374-387`).
///
/// # Errors
///
/// Returns [`pyatv_core::Error::Authentication`] if the receiver answers the pair-verify with
/// `470`, and whatever the `SETUP` exchange or MRP bring-up reports otherwise. The `AP2Session` is
/// always closed on the failure path, so a refused bring-up leaves no keepalive running.
pub(super) async fn tunnel(
    config: &BaseConfig,
    service: &BaseService,
    settings: &Settings,
    listeners: &Arc<ListenerHub>,
) -> Result<Option<SetupData>> {
    let Some(credentials) = gate(config, service, settings) else {
        return Ok(None);
    };

    let (mut session, channel) = pyatv_proto_airplay::remote_control_tunnel(
        config.address,
        service.port,
        &credentials,
        Ap2InfoSettings::from(&settings.info),
        SeqnoPolicy::default(),
    )
    .await?;

    // `session.start_keep_alive(core.device_listener)` (`__init__.py:271`). Without it the receiver
    // drops the tunnel after roughly thirty seconds; with it, a keepalive that stops answering is
    // what tells the caller the device went away.
    session.start_keep_alive(Some(Arc::clone(listeners) as Arc<dyn DeviceListener>));

    let transport = Arc::new(TunnelTransport::new(AirPlayByteChannel::new(channel)));
    let mut options = options(config, dummy_service(service), settings, listeners);
    // `requires_heatbeat=False` (`__init__.py:265`, upstream's spelling): the control channel's own
    // `/feedback` already keeps the socket alive, so MRP's 30-second `GENERIC_MESSAGE` would be
    // redundant. `pyatv_proto_mrp::setup` would force this off for a tunnel transport anyway; being
    // explicit keeps the reason visible at the call site.
    options.heartbeat_interval = None;

    match mrp_setup(transport, options).await {
        Ok(mut data) => {
            let session = Arc::new(Mutex::new(Some(session)));

            // The device can end the session without anyone asking — a reboot, a sleep, a dropped
            // socket. MRP notices, because its reader sees the data channel close, and reports it
            // through the `DeviceListener` path; nothing downstream of that used to close the
            // *AirPlay* half, so the `/feedback` keepalive went on posting to a receiver that had
            // already hung up. Registering here closes it on either notification.
            //
            // The hub holds listeners weakly, so the `Arc` has to live somewhere: the handle
            // below owns it, and the facade owns the handle for as long as the protocol is
            // registered.
            let teardown = Arc::new(TunnelTeardown {
                session: Arc::clone(&session),
            });
            listeners.add_listener(&(Arc::clone(&teardown) as Arc<dyn DeviceListener>));

            data.handle = Some(Arc::new(TunnelHandle {
                mrp: data.handle.take(),
                session,
                _teardown: teardown,
            }));
            Ok(Some(data))
        }
        Err(error) => {
            // Upstream leaks the session here — `_connect_rc` lets the exception escape with the
            // keepalive still running (`__init__.py:268-285`). Closing it is a deliberate
            // improvement: a failed connect must not leave a task posting `/feedback` forever.
            if let Err(cleanup) = session.close().await {
                tracing::debug!(%cleanup, "the tunnel did not close cleanly after a failed setup");
            }
            Err(error.into())
        }
    }
}

/// Decide whether a tunnel should be attempted, and with which credentials.
///
/// The `elif` chain of `airplay.setup()` (`__init__.py:374-387`) plus one addition of this port's
/// own: the service must speak AirPlay 2. Upstream has no such check, relying on
/// `is_remote_control_supported`'s `AppleTV*` plus tvOS-13 test to imply it. That implication holds
/// on real hardware, but a receiver that fails it has no data-stream channel at all, so attempting
/// the `SETUP` could only ever fail — and failing early says why.
fn gate(
    config: &BaseConfig,
    service: &BaseService,
    settings: &Settings,
) -> Option<pyatv_pairing::HapCredentials> {
    let setting = settings.protocols.airplay.mrp_tunnel;
    if setting == MrpTunnel::Disable {
        tracing::debug!("remote control tunnel disabled by setting");
        return None;
    }

    // `extract_credentials(core.service)` upstream; see `tunnel_credentials` for why this port also
    // considers the Companion service's credentials.
    let Some(credentials) = tunnel_credentials(config) else {
        tracing::debug!("no HAP credentials are stored for the remote control tunnel");
        return None;
    };

    // `elif mrp_tunnel == MrpTunnel.Force:` (`__init__.py:378-380`) sits ahead of both remaining
    // branches upstream, so forcing skips *both* checks: `is_remote_control_supported`'s
    // model/build test and the `credentials.type in [HAP, Transient]` test. It skips both here
    // too, plus this port's own AirPlay-2 check below — that is what the setting is for. It is the
    // escape hatch for a device whose TXT record understates what it can do, which is not
    // hypothetical: the feature bits are the only evidence the checks have, and a firmware that
    // reports them differently would otherwise be unreachable with no way to override.
    //
    // What `Force` does **not** skip is the credentials lookup above, because there is nothing to
    // force without one: pair-verify needs a key pair, and upstream would reach
    // `_create_mrp_tunnel_data(core, credentials)` with a `Null` credential and fail inside the
    // handshake instead. Declining early says why.
    if setting == MrpTunnel::Force {
        tracing::debug!("remote control channel is supported (forced)");
        return Some(credentials);
    }

    if get_protocol_version(service, AirPlayVersion::Auto) != AirPlayMajorVersion::V2 {
        tracing::debug!("the AirPlay service does not advertise AirPlay 2");
        return None;
    }
    if !is_tunnel_supported(service, &credentials) {
        tracing::debug!("remote control not supported by device");
        return None;
    }

    tracing::debug!("remote control channel is supported");
    Some(credentials)
}

/// The `Protocol::MRP` service the tunnel registers under.
///
/// `MutableService(None, Protocol.MRP, core.service.port, {})` (`__init__.py:241-244`) — the
/// AirPlay port, no properties and, critically, **no credentials**: the tunnel is already encrypted
/// one layer down and MRP must not pair-verify on top of it.
///
/// Upstream reuses an existing MRP service if the config has one, which would hand the tunnel a
/// credential string it then ignores. Synthesising unconditionally says the same thing without the
/// misdirection.
fn dummy_service(airplay: &BaseService) -> BaseService {
    BaseService::new(Protocol::Mrp, airplay.port)
}

/// The options both transports share.
fn options(
    config: &BaseConfig,
    service: BaseService,
    settings: &Settings,
    listeners: &Arc<ListenerHub>,
) -> MrpSetupOptions {
    let mut options = MrpSetupOptions::new(service);
    options.info = settings.info.clone();
    // Upstream passes `core.service.identifier`, which for a tunnel is the dummy service's `None`
    // (`__init__.py:241-244`), leaving `Metadata.device_id` empty on exactly the devices where the
    // tunnel is the only transport. The device's own identifier is what a caller means by
    // "device_id", so that is what is reported.
    options.identifier = config.identifier().map(str::to_owned);
    options.listener = Some(Arc::clone(listeners) as Arc<dyn DeviceListener>);
    options.power_listener = Some(Arc::clone(listeners) as Arc<dyn PowerListener>);
    // No `ArtworkFetcher`: fetching an iTunes CDN URL needs an HTTP client with TLS, which this
    // workspace does not depend on yet. Only the local `PLAYBACK_QUEUE_REQUEST` strategy runs, and
    // it is the only one that speaks MRP at all (spec §13.1).
    options.artwork_fetcher = None;
    options
}

/// Closes the MRP protocol and then the AirPlay session that carried it.
///
/// `_close_rc` (`__init__.py:287-291`) collects both sets of tasks; the order matters, because
/// stopping the session first would take the channel out from under MRP's own shutdown.
#[derive(Debug)]
struct TunnelHandle {
    mrp: Option<Arc<dyn ProtocolHandle>>,
    session: Arc<Mutex<Option<Ap2Session>>>,
    /// Kept only so the hub's [`std::sync::Weak`] stays upgradable for the life of the protocol.
    _teardown: Arc<TunnelTeardown>,
}

/// Closes the AirPlay session when the *device* ends the connection.
///
/// `_close_rc` (`__init__.py:287-291`) is the same teardown [`TunnelHandle::close`] performs; this
/// is the path that reaches it when nobody called `close()`. It has no upstream counterpart —
/// pyatv's `AirPlayMrpConnection.connection_lost` only forwards to the device listener
/// (`mrp_connection.py:63-76`) and leaves the session's `/feedback` task running, which is a leak
/// this port declines to reproduce.
#[derive(Debug)]
struct TunnelTeardown {
    session: Arc<Mutex<Option<Ap2Session>>>,
}

impl TunnelTeardown {
    /// Close the session on a spawned task.
    ///
    /// [`DeviceListener`]'s methods are synchronous and are called from inside the MRP actor's
    /// own shutdown, so closing has to happen elsewhere: blocking here would block the actor, and
    /// the session's teardown does I/O. Taking the `Option` makes a second notification — the hub
    /// can deliver both `connection_lost` and `connection_closed` over a session's life — a no-op.
    fn tear_down(&self, why: &str) {
        tracing::debug!(
            why,
            "tearing the AirPlay tunnel down after the device ended it"
        );

        let session = Arc::clone(&self.session);
        tokio::spawn(async move {
            if let Some(mut session) = session.lock().await.take()
                && let Err(error) = session.close().await
            {
                tracing::debug!(%error, "the AirPlay control connection did not close cleanly");
            }
        });
    }
}

impl DeviceListener for TunnelTeardown {
    fn connection_lost(&self, reason: &str) {
        self.tear_down(reason);
    }

    fn connection_closed(&self) {
        self.tear_down("the device closed the connection");
    }
}

impl ProtocolHandle for TunnelHandle {
    fn close(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            let mut first_error = None;

            if let Some(mrp) = self.mrp.as_ref()
                && let Err(error) = mrp.close().await
            {
                tracing::debug!(%error, "the tunnelled MRP session did not close cleanly");
                first_error = Some(error);
            }

            // Taken rather than borrowed, so a second `close()` is a no-op rather than a second
            // teardown of an already-closed socket.
            if let Some(mut session) = self.session.lock().await.take()
                && let Err(error) = session.close().await
            {
                tracing::debug!(%error, "the AirPlay control connection did not close cleanly");
                first_error.get_or_insert_with(|| error.into());
            }

            first_error.map_or(Ok(()), Err)
        })
    }
}
