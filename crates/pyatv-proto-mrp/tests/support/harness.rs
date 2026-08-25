//! Connecting to the fake device, and the polling helpers every functional test needs.
//!
//! Pairing runs for real rather than being stubbed, because the credentials it produces are what
//! [`setup`] then consumes: a mismatch between the two halves is exactly the kind of bug worth
//! catching here.
//!
//! The waits are polls rather than a fixed sleep. pyatv's own tests use `until(...)` for the same
//! reason (`tests/utils.py`): the device pushes state asynchronously, so there is no point at which
//! "the update has arrived" is synchronously observable.

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::facade::SetupData;
use pyatv_core::interface::PowerListener;
use pyatv_core::models::Playing;
use pyatv_core::{BaseService, FeatureName, FeatureState, Protocol};
use pyatv_pairing::server::PIN_CODE;
use pyatv_proto_mrp::auth::MrpPairSetupProcedure;
use pyatv_proto_mrp::transport::DirectTransport;
use pyatv_proto_mrp::{MrpProtocol, MrpProtocolOptions, MrpSetupOptions, setup};

use super::fake_mrp::FakeMrpDevice;
use super::fake_state::{DEVICE_UID, FakeDeviceState};

/// How long a poll waits before giving up; generous, since it only bounds a failing test.
pub const DEADLINE: Duration = Duration::from_secs(5);

/// How often a poll re-checks.
pub const TICK: Duration = Duration::from_millis(10);

/// Pair against the fake device, then connect and hand back what MRP registered.
pub async fn connect(device: &FakeMrpDevice) -> SetupData {
    connect_with(device, None).await
}

/// As [`connect`], with a power listener attached before bring-up.
pub async fn connect_with(
    device: &FakeMrpDevice,
    power: Option<Arc<dyn PowerListener>>,
) -> SetupData {
    let credentials = pair(device).await;

    let mut service = BaseService::new(Protocol::Mrp, device.address().port());
    service.credentials = Some(credentials);

    let transport = DirectTransport::connect(device.address())
        .await
        .expect("dialling the fake device must succeed");

    let mut options = MrpSetupOptions::new(service);
    options.identifier = Some(DEVICE_UID.to_owned());
    options.power_listener = power;
    // The heartbeat interval is left at its 30-second default and every test finishes long before
    // then: this proves the task starts without making any test depend on its timing.
    setup(Arc::new(transport), options)
        .await
        .expect("MRP setup must succeed")
}

/// Open a protocol on a fresh, unpaired connection.
pub async fn open(device: &FakeMrpDevice) -> MrpProtocol {
    let transport = DirectTransport::connect(device.address())
        .await
        .expect("dialling the fake device must succeed");
    MrpProtocol::connect(Arc::new(transport), MrpProtocolOptions::default())
}

/// Run pair-setup on its own connection and return the credential string.
pub async fn pair(device: &FakeMrpDevice) -> String {
    let protocol = open(device).await;

    let procedure = MrpPairSetupProcedure::start(&protocol)
        .await
        .expect("pair-setup M1 must be answered");
    let credentials = procedure
        .finish(&protocol, PIN_CODE)
        .await
        .expect("pair-setup must complete");

    protocol.close().await.expect("closing must succeed");
    credentials.to_string()
}

/// Poll `check` until it yields a value or [`DEADLINE`] passes.
pub async fn until<T>(what: &str, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(TICK).await;
    }
}

/// Wait until the metadata facade reports something `check` accepts.
pub async fn playing(data: &SetupData, what: &str, check: impl Fn(&Playing) -> bool) -> Playing {
    let metadata = data
        .metadata
        .as_ref()
        .expect("MRP registers a Metadata implementation");

    let deadline = tokio::time::Instant::now() + DEADLINE;
    loop {
        let snapshot = metadata.playing().await.expect("playing() must not fail");
        if check(&snapshot) {
            return snapshot;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}; last snapshot was {snapshot:?}"
        );
        tokio::time::sleep(TICK).await;
    }
}

/// Wait until the device records `button` as the last one pressed.
pub async fn pressed(state: &Arc<FakeDeviceState>, button: &str) {
    until(&format!("button {button}"), || {
        state
            .with(|inner| inner.last_button_pressed.clone())
            .filter(|last| last == button)
    })
    .await;
}

/// A `Features` lookup, which every test spells out the same way.
pub fn feature(data: &SetupData, name: FeatureName) -> FeatureState {
    data.features_impl
        .as_ref()
        .expect("MRP registers a Features implementation")
        .get_feature(name)
        .state
}
