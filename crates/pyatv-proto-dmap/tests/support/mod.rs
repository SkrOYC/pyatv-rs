//! Shared harness for the DMAP end-to-end tests.
//!
//! Both `dmap_functional` and `dmap_control` stand the same device up the same way; this is the
//! part they have in common. Every test drives the real [`setup`] against the real fake device over
//! a loopback socket, so a failure means the HTTP bytes, the DMAP tags or the `_do` state machine
//! are wrong — not that a mock disagreed.
//!
//! Upstream reaches its device through the whole `pyatv.connect()` stack (`get_connected_device`,
//! `tests/protocols/dmap/test_dmap_functional.py:73-90`); this connects the DMAP protocol into a
//! bare [`FacadeAppleTV`], which is what `pyatv::connect` does for it in production and keeps these
//! tests inside this crate. The umbrella crate's `connect_dmap` test covers the other half.

#![allow(
    dead_code,
    reason = "each of the two test binaries using this harness needs a different subset of it"
)]

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use pyatv_core::facade::FacadeAppleTV;
use pyatv_core::interface::{AppleTV, DeviceListener, PlaybackListener, PushUpdater};
use pyatv_core::models::Playing;
use pyatv_core::{BaseService, Error as CoreError, Protocol};
use pyatv_proto_dmap::facade::{DmapSetupOptions, setup};
use pyatv_proto_dmap::test_support::fake_dmap::FakeDmapDevice;
use pyatv_proto_dmap::test_support::fake_state::FakeDmapUseCases;

/// How long a test waits for a background push loop to make progress before failing.
pub const DEADLINE: Duration = Duration::from_secs(5);

/// How often to re-check a condition the background loop is expected to satisfy.
pub const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Connect DMAP with the given credential and return the facade.
pub async fn connect(device: &FakeDmapDevice, credentials: &str) -> Arc<FacadeAppleTV> {
    connect_with_listener(device, credentials, None)
        .await
        .expect("connecting must succeed")
        .0
}

/// The same, with a device listener registered before the protocol connects — which is the order
/// `pyatv::connect` uses so that a socket dropped during bring-up still reaches the caller.
///
/// Also hands back DMAP's own [`PushUpdater`] alongside the facade. The push tests below use that
/// one rather than `AppleTV::push_updater()`, because the facade's updater only forwards to a
/// listener once `FacadePushUpdater::start_all` has attached its per-protocol shims, and that
/// method takes `Arc<Self>` so it is unreachable through the `Arc<dyn PushUpdater>` the trait hands
/// out. What is under test here is DMAP's long-poll loop, so this side-steps the question rather
/// than encoding an answer to it; see the report accompanying this branch.
pub async fn connect_with_listener(
    device: &FakeDmapDevice,
    credentials: &str,
    listener: Option<Arc<dyn DeviceListener>>,
) -> Result<(Arc<FacadeAppleTV>, Arc<dyn PushUpdater>), pyatv_proto_dmap::Error> {
    let mut service = BaseService::new(Protocol::Dmap, device.port());
    service.identifier = Some("dmapid".to_owned());
    service.credentials = Some(credentials.to_owned());

    let mut facade = FacadeAppleTV::new(service.clone());
    let data = setup(DmapSetupOptions {
        peer: device.address(),
        service,
        identifier: Some("dmapid".to_owned()),
        service_types: vec!["_appletv-v2._tcp.local".to_owned()],
        listener,
    })
    .await?;

    let updater = data
        .push_updater
        .clone()
        .expect("DMAP always registers a push updater");
    facade.add_protocol(data);
    Ok((Arc::new(facade), updater))
}

/// The now-playing snapshot, fetched through the facade.
pub async fn playing(atv: &Arc<FacadeAppleTV>) -> Playing {
    atv.metadata()
        .expect("DMAP provides Metadata")
        .playing()
        .await
        .expect("playstatus must succeed")
}

/// Wait until `condition` holds, or fail after [`DEADLINE`].
pub async fn until(what: &str, mut condition: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    while !condition() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Wait for a button to arrive at the device.
pub async fn wait_for_button(use_cases: &FakeDmapUseCases, expected: &str) {
    until(&format!("button {expected}"), || {
        use_cases.last_button_pressed().as_deref() == Some(expected)
    })
    .await;
}

/// Collects what a push updater delivers.
#[derive(Debug, Default)]
pub struct RecordingPushListener {
    updates: Mutex<Vec<Playing>>,
    errors: Mutex<Vec<String>>,
}

impl RecordingPushListener {
    pub fn latest_title(&self) -> Option<String> {
        self.updates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .and_then(|playing| playing.title.clone())
    }

    pub fn error_count(&self) -> usize {
        self.errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl PlaybackListener for RecordingPushListener {
    fn playstatus_update(&self, playing: &Playing) {
        self.updates
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(playing.clone());
    }

    fn playstatus_error(&self, error: &CoreError) {
        self.errors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(error.to_string());
    }
}

/// Records a lost connection.
#[derive(Debug, Default)]
pub struct RecordingDeviceListener {
    lost: Mutex<Vec<String>>,
}

impl RecordingDeviceListener {
    pub fn lost_count(&self) -> usize {
        self.lost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

impl DeviceListener for RecordingDeviceListener {
    fn connection_lost(&self, reason: &str) {
        self.lost
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(reason.to_owned());
    }

    fn connection_closed(&self) {}
}
