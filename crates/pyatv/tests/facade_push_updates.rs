//! Push updates delivered through nothing but the public `AppleTV` surface.
//!
//! The regression these pin is not a protocol bug: both MRP's and DMAP's updaters were correct and
//! covered by their own crates' tests, which reach the protocol's `Arc<dyn PushUpdater>` directly.
//! What was broken was the only path a *library caller* has. `FacadePushUpdater` forwards a
//! protocol's callbacks through a per-protocol shim, and attaching those shims used to require an
//! `Arc<Self>` receiver — reachable from inside `pyatv-core`, unreachable through the
//! `Arc<dyn PushUpdater>` that [`pyatv::AppleTV::push_updater`] hands out, and never called by
//! `pyatv::connect`. So `atv.push_updater().set_listener(&mine)` followed by `start(0)` connected,
//! polled, reported `active()`, and delivered nothing at all.
//!
//! Both tests below therefore go through `Arc<dyn AppleTV>` and touch no protocol type: upstream's
//! contract is `atv.push_updater.listener = mine; atv.push_updater.start()` and nothing else
//! (`pyatv/core/facade.py:620-644`), and `connect()` deliberately does not start push updates for
//! the caller — neither does pyatv's (`pyatv/__init__.py:101-159`).

mod support;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use pyatv::{AppleTV, BaseConfig, BaseService, MemoryStorage, PlaybackListener, Playing, Protocol};
use pyatv_proto_dmap::test_support::fake_dmap::FakeDmapDevice;
use pyatv_proto_dmap::test_support::fake_state::HSGID;

use support::{FakeAppleTv, until};

/// Records every title it is told about, so a test can wait for a specific one.
#[derive(Debug, Default)]
struct Recording {
    titles: Mutex<Vec<String>>,
    errors: Mutex<usize>,
}

impl Recording {
    /// Whether `title` has been pushed at least once.
    fn saw(&self, title: &str) -> bool {
        self.titles
            .lock()
            .expect("uncontended")
            .iter()
            .any(|seen| seen == title)
    }

    fn error_count(&self) -> usize {
        *self.errors.lock().expect("uncontended")
    }
}

impl PlaybackListener for Recording {
    fn playstatus_update(&self, playing: &Playing) {
        if let Some(title) = playing.title.clone() {
            self.titles.lock().expect("uncontended").push(title);
        }
    }

    fn playstatus_error(&self, _error: &pyatv::Error) {
        *self.errors.lock().expect("uncontended") += 1;
    }
}

/// Subscribe through the facade and start it, exactly as a caller would.
async fn subscribe(atv: &Arc<dyn AppleTV>) -> Arc<Recording> {
    let updater = atv
        .push_updater()
        .expect("a connected protocol must register a push updater");
    let listener = Arc::new(Recording::default());
    updater.set_listener(&(Arc::clone(&listener) as Arc<dyn PlaybackListener>));
    updater
        .start(0)
        .await
        .expect("starting through the facade must succeed");
    assert!(
        updater.active(),
        "the main protocol's updater must report itself running"
    );
    listener
}

/// A `SET_STATE_MESSAGE` pushed by the (tunnelled) MRP device reaches the caller's listener.
///
/// The push crosses the AirPlay data channel, MRP's player-state machine, the facade's shim and the
/// main-protocol filter before it gets here, so nothing about this path is stubbed.
#[tokio::test(flavor = "multi_thread")]
async fn an_mrp_push_reaches_a_listener_registered_through_the_facade() {
    let device = FakeAppleTv::start().await;
    let atv = device.connect().await;

    let listener = subscribe(&atv).await;

    // Pushed *after* the subscription, so a listener attached at construction time — which is what
    // the old code could only have managed — is not what makes this pass.
    device.arrange_mrp(|state| state.example_video());

    until("the MRP push to reach the listener", || {
        listener.saw("dummy").then_some(())
    })
    .await;
    assert_eq!(listener.error_count(), 0);

    atv.close().await.expect("closing must succeed");
}

/// The same through DMAP's long poll, which is a completely different mechanism.
///
/// MRP pushes unprompted; DMAP holds a `playstatusupdate` request open until the device has
/// something to say (`pyatv/protocols/dmap/__init__.py:246-300`). Both have to arrive at the same
/// public listener.
#[tokio::test(flavor = "multi_thread")]
async fn a_dmap_long_poll_reaches_a_listener_registered_through_the_facade() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_music();

    let mut service = BaseService::new(Protocol::Dmap, device.port());
    service.identifier = Some("dmapid".to_owned());
    service.credentials = Some(HSGID.to_owned());

    let mut config = BaseConfig::new("Apple TV", IpAddr::V4(Ipv4Addr::LOCALHOST));
    config.add_service(service);
    config.set_properties(HashMap::from([(
        "_appletv-v2._tcp.local".to_owned(),
        HashMap::new(),
    )]));

    let atv = pyatv::connect(&config, None, Arc::new(MemoryStorage::new()))
        .await
        .expect("connect must succeed against the fake");

    let listener = subscribe(&atv).await;

    until("the DMAP long poll to reach the listener", || {
        listener.saw("music").then_some(())
    })
    .await;

    use_cases.assert_no_protocol_errors();
    atv.close().await.expect("closing must succeed");
}
