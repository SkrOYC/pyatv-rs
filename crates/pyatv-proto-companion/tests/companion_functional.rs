//! Companion's capability traits, end to end against a hermetic device.
//!
//! Counterpart of `tests/protocols/companion/test_companion_functional.py`. Everything runs over a
//! real loopback socket through the real pair-verify, the real transport encryption and the real
//! OPACK framing, so a test failing here means the bytes are wrong, not that a mock disagreed.
//!
//! The device is [`support::fake_state::DeviceState`] behind the framing in
//! `support::fake_companion`, which is this crate's port of pyatv's own `FakeCompanionService`.

mod support;

use std::sync::Arc;
use std::time::Duration;

use pyatv_core::facade::{FacadeAppleTV, SetupData};
use pyatv_core::interface::{AppleTV, DeviceListener, PowerListener};
use pyatv_core::storage::InfoSettings;
use pyatv_core::{
    BaseService, FeatureName, FeatureState, InputAction, KeyboardFocusState, PowerState, Protocol,
    TouchAction,
};
use pyatv_pairing::server::PIN_CODE;
use pyatv_proto_companion::facade::{CompanionSetupOptions, setup};

use support::fake_companion::FakeCompanionDevice;
use support::fake_state::{DeviceState, INITIAL_RTI_TEXT, INITIAL_VOLUME, VOLUME_STEP};

/// Long enough for the background task to have drained a pushed event, short enough that a hung
/// test still fails inside the harness's own timeout.
const SETTLE: Duration = Duration::from_millis(200);

/// Pair against the fake device, then connect through `setup()` and hand back the facade.
///
/// Pairing runs for real rather than being stubbed because the credentials it produces are what
/// `setup()` needs, and a mismatch between the two halves is exactly the kind of bug worth
/// catching here.
async fn connect(device: &FakeCompanionDevice) -> Arc<dyn AppleTV> {
    let credentials = pair(device).await;

    let mut service = BaseService::new(Protocol::Companion, device.address().port());
    service.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
    service.credentials = Some(credentials);

    // The same wiring `pyatv::connect` does: the hub is taken before the protocol connects, so a
    // dropped socket reaches whatever the caller registers on the facade afterwards.
    let mut facade = FacadeAppleTV::new(service.clone());
    let listeners = facade.listener_hub();

    let data = setup(CompanionSetupOptions {
        peer: device.address(),
        service,
        info: InfoSettings::default(),
        listener: Some(Arc::clone(&listeners) as Arc<dyn DeviceListener>),
        power_listener: Some(listeners as Arc<dyn PowerListener>),
    })
    .await
    .expect("setup must succeed")
    .expect("credentials are present, so Companion must register");

    facade.add_protocol(data);
    Arc::new(facade)
}

/// Run the pairing exchange and return the credential string.
async fn pair(device: &FakeCompanionDevice) -> String {
    use pyatv_core::interface::PairingHandler;
    use pyatv_core::storage::MemoryStorage;
    use pyatv_proto_companion::auth::PairSetupOptionsCompanion;
    use pyatv_proto_companion::pairing::{CompanionPairingHandler, CompanionPairingOptions};

    let mut service = BaseService::new(Protocol::Companion, device.address().port());
    service.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());

    let handler = CompanionPairingHandler::new(
        CompanionPairingOptions {
            address: device.address().ip(),
            service,
            device_identifier: "AA:BB:CC:DD:EE:FF".to_owned(),
            setup: PairSetupOptionsCompanion::default(),
        },
        Arc::new(MemoryStorage::new()),
    );

    handler.begin().await.expect("pairing must begin");
    handler.pin(PIN_CODE).expect("the PIN must be accepted");
    handler.finish().await.expect("pairing must finish");
    let credentials = handler
        .service()
        .credentials
        .expect("pairing must produce credentials");
    handler.close().await.expect("closing must succeed");
    credentials
}

/// Mutate the device's state before connecting.
async fn arrange(device: &FakeCompanionDevice, mutate: impl FnOnce(&mut DeviceState)) {
    mutate(&mut *device.state().lock().await);
}

// ---- Apps (`test_companion_functional.py::test_app_list`, `test_launch_app`) ----

#[tokio::test]
async fn app_list_maps_bundle_ids_to_names() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    arrange(&device, |state| {
        state.installed_apps = vec![
            ("com.apple.TVMusic".to_owned(), "Music".to_owned()),
            ("com.netflix.Netflix".to_owned(), "Netflix".to_owned()),
        ];
    })
    .await;

    let atv = connect(&device).await;
    let apps = atv
        .apps()
        .expect("Companion provides Apps")
        .app_list()
        .await
        .expect("the app list must be readable");

    assert_eq!(apps.len(), 2);
    // The key is the identifier and the value is the name, not the other way round.
    assert_eq!(apps[0].identifier, "com.apple.TVMusic");
    assert_eq!(apps[0].name, "Music");
    assert_eq!(apps[1].identifier, "com.netflix.Netflix");

    atv.close().await.expect("closing must succeed");
}

/// A bundle identifier goes out under `_bundleID`; anything with a URL scheme under `_urlS`.
#[tokio::test]
async fn launch_app_routes_bundle_ids_and_urls_to_different_keys() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let apps = atv.apps().expect("Companion provides Apps");

    apps.launch_app("com.netflix.Netflix")
        .await
        .expect("launching by bundle id must succeed");
    assert_eq!(
        device.state().lock().await.active_app.as_deref(),
        Some("com.netflix.Netflix")
    );
    assert_eq!(device.state().lock().await.open_url, None);

    apps.launch_app("https://example.com/video")
        .await
        .expect("launching by URL must succeed");
    assert_eq!(
        device.state().lock().await.open_url.as_deref(),
        Some("https://example.com/video")
    );

    atv.close().await.expect("closing must succeed");
}

// ---- User accounts ----

#[tokio::test]
async fn accounts_can_be_listed_and_switched() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    arrange(&device, |state| {
        state.available_accounts = vec![("123".to_owned(), "Alice".to_owned())];
    })
    .await;

    let atv = connect(&device).await;
    let accounts = atv
        .user_accounts()
        .expect("Companion provides UserAccounts");

    let listed = accounts
        .account_list()
        .await
        .expect("the account list must be readable");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].identifier, "123");
    assert_eq!(listed[0].name, "Alice");

    accounts
        .switch_account("123")
        .await
        .expect("switching must succeed");
    assert_eq!(
        device.state().lock().await.active_account.as_deref(),
        Some("123")
    );

    atv.close().await.expect("closing must succeed");
}

// ---- Remote control (`test_companion_functional.py::test_button_press`) ----

/// One button press in flight, boxed so one table can hold twelve different concrete futures.
type Press<'a> = std::pin::Pin<Box<dyn Future<Output = pyatv_core::Result<()>> + 'a>>;

/// Every button the fake device records, driven through the public trait.
///
/// The device errors on an *up* with no matching *down*, so a press that reached it at all proves
/// both halves of `_press_button` went out in the right order.
#[tokio::test]
async fn button_presses_are_recorded_by_the_device() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let remote = atv
        .remote_control()
        .expect("Companion provides RemoteControl");

    let tap = InputAction::SingleTap;
    let presses: [(&str, Press<'_>); 12] = [
        ("up", Box::pin(remote.up(tap))),
        ("down", Box::pin(remote.down(tap))),
        ("left", Box::pin(remote.left(tap))),
        ("right", Box::pin(remote.right(tap))),
        ("select", Box::pin(remote.select(tap))),
        ("menu", Box::pin(remote.menu(tap))),
        ("home", Box::pin(remote.home(tap))),
        ("play_pause", Box::pin(remote.play_pause())),
        ("channel_up", Box::pin(remote.channel_up())),
        ("channel_down", Box::pin(remote.channel_down())),
        ("screensaver", Box::pin(remote.screensaver())),
        ("guide", Box::pin(remote.guide())),
    ];

    for (expected, press) in presses {
        press.await.expect("the press must be accepted");
        assert_eq!(
            device.state().lock().await.latest_button.as_deref(),
            Some(expected),
            "the device must have recorded a {expected} press"
        );
    }

    atv.close().await.expect("closing must succeed");
}

/// `control_center()` sends `PageDown`, which the device records under that name.
#[tokio::test]
async fn control_center_is_sent_as_page_down() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;

    atv.remote_control()
        .expect("Companion provides RemoteControl")
        .control_center()
        .await
        .expect("the press must be accepted");

    assert_eq!(
        device.state().lock().await.latest_button.as_deref(),
        Some("control_center")
    );
    atv.close().await.expect("closing must succeed");
}

/// A double tap is two complete down/up pairs; the device would error on an unmatched up.
#[tokio::test]
async fn a_double_tap_sends_two_complete_presses() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;

    atv.remote_control()
        .expect("Companion provides RemoteControl")
        .select(InputAction::DoubleTap)
        .await
        .expect("a double tap must be accepted");

    let shared = device.state();
    let state = shared.lock().await;
    assert_eq!(state.latest_button.as_deref(), Some("select"));
    assert_eq!(
        state.commands.iter().filter(|it| *it == "_hidC").count(),
        4,
        "a double tap is four _hidC frames"
    );
    drop(state);

    atv.close().await.expect("closing must succeed");
}

/// The media-control commands go out as `_mcc`, not as HID.
#[tokio::test]
async fn transport_commands_go_out_as_media_control() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let remote = atv
        .remote_control()
        .expect("Companion provides RemoteControl");

    remote.play().await.expect("play must be accepted");
    assert_eq!(
        device.state().lock().await.latest_button.as_deref(),
        Some("play")
    );

    remote.pause().await.expect("pause must be accepted");
    assert_eq!(
        device.state().lock().await.latest_button.as_deref(),
        Some("pause")
    );

    remote.next().await.expect("next must be accepted");
    assert_eq!(
        device.state().lock().await.latest_button.as_deref(),
        Some("next")
    );

    remote.previous().await.expect("previous must be accepted");
    assert_eq!(
        device.state().lock().await.latest_button.as_deref(),
        Some("previous")
    );

    atv.close().await.expect("closing must succeed");
}

/// `skip_forward(0.0)` uses the ten-second default and `skip_backward` negates it.
#[tokio::test]
async fn skipping_uses_the_default_interval_and_the_right_sign() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let remote = atv
        .remote_control()
        .expect("Companion provides RemoteControl");

    // The device starts at INITIAL_DURATION = 10.0.
    remote.skip_forward(0.0).await.expect("skip must succeed");
    assert!((device.state().lock().await.duration - 20.0).abs() < f64::EPSILON);

    remote.skip_backward(5.0).await.expect("skip must succeed");
    assert!((device.state().lock().await.duration - 15.0).abs() < f64::EPSILON);

    atv.close().await.expect("closing must succeed");
}

/// The six methods Companion does not implement report `NotSupported` rather than doing something.
#[tokio::test]
async fn unimplemented_remote_methods_report_not_supported() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let remote = atv
        .remote_control()
        .expect("Companion provides RemoteControl");

    for result in [
        remote.home_hold().await,
        remote.top_menu().await,
        remote.stop().await,
        remote.set_position(1.0).await,
    ] {
        assert!(
            matches!(result, Err(pyatv_core::Error::NotSupported(_))),
            "expected NotSupported, got {result:?}"
        );
    }

    atv.close().await.expect("closing must succeed");
}

// ---- Power (`test_companion_functional.py::test_power_state`) ----

#[tokio::test]
async fn the_initial_power_state_comes_from_fetch_attention_state() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    // `SystemStatus.Asleep`.
    arrange(&device, |state| state.system_status = Some(0x01)).await;

    let atv = connect(&device).await;
    let power = atv.power().expect("Companion provides Power");
    assert_eq!(power.power_state(), PowerState::Off);

    atv.close().await.expect("closing must succeed");
}

/// A device that refuses `FetchAttentionState` — as newer tvOS does — must still connect, and must
/// still report `PowerState::Unknown` rather than a guess.
#[tokio::test]
async fn a_refused_attention_state_does_not_fail_the_connection() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    arrange(&device, |state| state.system_status = None).await;

    let atv = connect(&device).await;
    assert_eq!(
        atv.power().expect("Companion provides Power").power_state(),
        PowerState::Unknown
    );

    // …and the subscriptions still went out, which is the whole point of the non-fatal handling.
    // `_interest` is an event, so the write returning says nothing about the device having read
    // it yet; the settle is for the device, not for this port.
    tokio::time::sleep(SETTLE).await;
    let shared = device.state();
    let state = shared.lock().await;
    assert!(state.interests.iter().any(|it| it == "SystemStatus"));
    assert!(state.interests.iter().any(|it| it == "TVSystemStatus"));
    drop(state);

    atv.close().await.expect("closing must succeed");
}

/// `turn_off` then `turn_on`, each awaiting the state the device pushes back.
///
/// The wait is this port's own extension — pyatv raises `NotImplementedError` for
/// `await_new_state` on Companion — so this is the test that proves the extension works rather
/// than a parity check.
#[tokio::test]
async fn turning_the_device_off_and_on_awaits_the_new_state() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let power = atv.power().expect("Companion provides Power");

    assert_eq!(power.power_state(), PowerState::On);

    power.turn_off(true).await.expect("turn_off must succeed");
    assert_eq!(power.power_state(), PowerState::Off);
    assert!(!device.state().lock().await.powered_on);

    power.turn_on(true).await.expect("turn_on must succeed");
    assert_eq!(power.power_state(), PowerState::On);
    assert!(device.state().lock().await.powered_on);

    atv.close().await.expect("closing must succeed");
}

// ---- Audio ----

/// `volume_up` sends the HID pair and resolves only once the device confirms the new level.
#[tokio::test]
async fn volume_up_is_gated_on_the_devices_confirmation() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let audio = atv.audio().expect("Companion provides Audio");

    // Bring-up subscribes to `_iMC` three times over and the device answers each with a push, so
    // several volume reports are still in flight. The wait is armed before the command goes out
    // and cannot tell one report from another — pyatv's `asyncio.Event` cannot either — so the
    // queue is allowed to settle first rather than pretending the API has causality it does not.
    tokio::time::sleep(SETTLE).await;

    audio.volume_up().await.expect("volume_up must succeed");

    let expected = INITIAL_VOLUME + VOLUME_STEP;
    assert!((f64::from(audio.volume()) - expected).abs() < 0.001);
    assert!((device.state().lock().await.volume - expected).abs() < f64::EPSILON);

    atv.close().await.expect("closing must succeed");
}

#[tokio::test]
async fn set_volume_sends_a_fraction_and_reads_back_a_percentage() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let audio = atv.audio().expect("Companion provides Audio");

    // See `volume_up_is_gated_on_the_devices_confirmation`.
    tokio::time::sleep(SETTLE).await;

    audio
        .set_volume(42.0)
        .await
        .expect("set_volume must succeed");

    assert!((device.state().lock().await.volume - 42.0).abs() < 0.001);
    assert!((f64::from(audio.volume()) - 42.0).abs() < 0.001);

    atv.close().await.expect("closing must succeed");
}

// ---- Keyboard (`test_companion_functional.py::test_text_*`) ----

#[tokio::test]
async fn text_get_reads_the_focused_fields_contents() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let keyboard = atv.keyboard().expect("Companion provides Keyboard");

    assert_eq!(keyboard.text_focus_state(), KeyboardFocusState::Focused);
    assert_eq!(
        keyboard.text_get().await.expect("text_get must succeed"),
        Some(INITIAL_RTI_TEXT.to_owned())
    );

    atv.close().await.expect("closing must succeed");
}

#[tokio::test]
async fn text_append_and_clear_round_trip_through_the_keyed_archive() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let keyboard = atv.keyboard().expect("Companion provides Keyboard");

    keyboard
        .text_append("!")
        .await
        .expect("append must succeed");
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        device.state().lock().await.rti_text.as_deref(),
        Some(format!("{INITIAL_RTI_TEXT}!").as_str())
    );

    keyboard.text_clear().await.expect("clear must succeed");
    tokio::time::sleep(SETTLE).await;
    assert_eq!(device.state().lock().await.rti_text.as_deref(), Some(""));

    keyboard.text_set("hello").await.expect("set must succeed");
    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        device.state().lock().await.rti_text.as_deref(),
        Some("hello")
    );

    atv.close().await.expect("closing must succeed");
}

/// A device with nothing focused answers `_tiStart` without a `_tiD`, which is how it says so.
#[tokio::test]
async fn an_unfocused_device_reports_no_text() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    arrange(&device, |state| state.rti_text = None).await;

    let atv = connect(&device).await;
    let keyboard = atv.keyboard().expect("Companion provides Keyboard");

    assert_eq!(keyboard.text_focus_state(), KeyboardFocusState::Unfocused);
    assert_eq!(
        keyboard.text_get().await.expect("text_get must succeed"),
        None
    );

    atv.close().await.expect("closing must succeed");
}

// ---- Touch gestures ----

#[tokio::test]
async fn a_touch_action_reaches_the_device_clamped() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;

    atv.touch_gestures()
        .expect("Companion provides TouchGestures")
        // Deliberately out of range on both axes and in both directions.
        .action(-5, 5000, TouchAction::Press)
        .await
        .expect("the action must be accepted");

    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        device.state().lock().await.touch_event,
        Some((0, 1000, TouchAction::Press as u64))
    );

    atv.close().await.expect("closing must succeed");
}

// ---- Features (`test_companion_functional.py::test_features`) ----

/// The bitfield decides availability for the eight media-control features; everything else the
/// protocol declares is asserted available.
/// The HID frames the device saw since `mark`.
///
/// The trailing `_hidT` of a click is an event, so `click()` returns as soon as it is written
/// rather than when the device has processed it; settling first is what makes the read
/// deterministic.
async fn frames_since(device: &FakeCompanionDevice, mark: usize) -> Vec<String> {
    tokio::time::sleep(SETTLE).await;
    let shared = device.state();
    let state = shared.lock().await;
    state.commands[mark..]
        .iter()
        .filter(|it| *it == "_hidC" || *it == "_hidT")
        .cloned()
        .collect()
}

/// How many commands the device has seen so far, as a starting point for [`frames_since`].
async fn mark(device: &FakeCompanionDevice) -> usize {
    device.state().lock().await.commands.len()
}

/// `TouchGestures::click` takes an [`InputAction`], so all three shapes are reachable.
///
/// The trait used to take a `TouchAction` here and fold the four touch *phases* onto two input
/// actions, which meant [`InputAction::DoubleTap`] could not be expressed through the facade at
/// all — no phase means "twice". Upstream's signature is `click(self, action: InputAction)`
/// (`pyatv/interface.py:1312`).
///
/// Each click is `_hidC` down, `_hidC` up, then one `_hidT` `Click` at the fixed `(1000, 1000)`
/// corner (`api.py:373-393`). A single tap and a hold produce the same frames and differ only in
/// how long the button stays down — 20 ms against a full second — so the hold is identified by the
/// clock.
#[tokio::test]
async fn clicking_reaches_the_device_in_all_three_input_actions() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    let touch = atv
        .touch_gestures()
        .expect("Companion provides TouchGestures");

    let single = mark(&device).await;
    let started = std::time::Instant::now();
    touch
        .click(InputAction::SingleTap)
        .await
        .expect("a single tap must be accepted");
    let single_elapsed = started.elapsed();
    assert_eq!(
        frames_since(&device, single).await,
        ["_hidC", "_hidC", "_hidT"]
    );

    let double = mark(&device).await;
    touch
        .click(InputAction::DoubleTap)
        .await
        .expect("a double tap must be accepted");
    assert_eq!(
        frames_since(&device, double).await,
        ["_hidC", "_hidC", "_hidT", "_hidC", "_hidC", "_hidT"],
        "a double tap repeats the whole down/up/touch sequence"
    );

    let hold = mark(&device).await;
    let started = std::time::Instant::now();
    touch
        .click(InputAction::Hold)
        .await
        .expect("a hold must be accepted");
    let hold_elapsed = started.elapsed();
    assert_eq!(
        frames_since(&device, hold).await,
        ["_hidC", "_hidC", "_hidT"]
    );

    // `HOLD_DELAY` is a second and `CLICK_TAP_DELAY` is 20 ms (`api.py:382,389`).
    assert!(
        hold_elapsed >= Duration::from_millis(900),
        "a hold must keep the button down for about a second; took {hold_elapsed:?}"
    );
    assert!(
        single_elapsed < Duration::from_millis(500),
        "a single tap must not hold; took {single_elapsed:?}"
    );

    let shared = device.state();
    assert_eq!(
        shared.lock().await.latest_button.as_deref(),
        Some("select"),
        "every click is a Select press"
    );

    atv.close().await.expect("closing must succeed");
}

#[tokio::test]
async fn media_control_flags_drive_feature_availability() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    // Play | Pause only: no volume, no skipping.
    arrange(&device, |state| state.media_control_flags = 0x0003).await;

    let atv = connect(&device).await;
    tokio::time::sleep(SETTLE).await;
    let features = atv.features();

    assert_eq!(
        features.get_feature(FeatureName::Play).state,
        FeatureState::Available
    );
    assert_eq!(
        features.get_feature(FeatureName::Pause).state,
        FeatureState::Available
    );
    assert_eq!(
        features.get_feature(FeatureName::Volume).state,
        FeatureState::Unavailable
    );
    assert_eq!(
        features.get_feature(FeatureName::SkipForward).state,
        FeatureState::Unavailable
    );

    // Asserted, not measured: upstream says so in as many words.
    assert_eq!(
        features.get_feature(FeatureName::AppList).state,
        FeatureState::Available
    );
    assert_eq!(
        features.get_feature(FeatureName::TextGet).state,
        FeatureState::Available
    );

    // Nothing Companion cannot serve leaks into the list.
    assert_eq!(
        features.get_feature(FeatureName::PlayUrl).state,
        FeatureState::Unsupported
    );
    assert_eq!(
        features.get_feature(FeatureName::Artwork).state,
        FeatureState::Unsupported
    );

    atv.close().await.expect("closing must succeed");
}

/// Companion's own `all_features` filters on the reported state, not on the declared set.
///
/// `Features.all_features` (`pyatv/interface.py:1088-1095`) keeps everything whose state is not
/// `Unsupported`, and `CompanionFeatures` does not override it. That is a wider list than the
/// declared set, because `CompanionFeatures.get_feature` answers `Unavailable` — not `Unsupported`
/// — for a feature it never declared (`__init__.py:610-611`); only `PowerState` before any power
/// state has been observed is genuinely `Unsupported`.
///
/// This goes through `setup()`'s `features_impl` directly rather than through the facade, because
/// the facade's own `FacadeFeatures` answers `Unsupported` for undeclared features and would hide
/// the difference.
#[tokio::test]
async fn companions_own_all_features_filters_on_state() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    // No power state ever observed, so `PowerState` stays Unsupported.
    arrange(&device, |state| state.system_status = None).await;

    let credentials = pair(&device).await;
    let mut service = BaseService::new(Protocol::Companion, device.address().port());
    service.identifier = Some("AA:BB:CC:DD:EE:FF".to_owned());
    service.credentials = Some(credentials);

    let data = setup(CompanionSetupOptions {
        peer: device.address(),
        service,
        info: InfoSettings::default(),
        listener: None,
        power_listener: None,
    })
    .await
    .expect("setup must succeed")
    .expect("credentials are present");

    let features = data
        .features_impl
        .clone()
        .expect("Companion reports features");
    let visible = features.all_features(false);

    assert_eq!(visible.len(), FeatureName::COUNT - 1);
    assert!(
        visible
            .iter()
            .all(|(_, info)| info.state != FeatureState::Unsupported)
    );
    assert!(
        !visible
            .iter()
            .any(|(feature, _)| *feature == FeatureName::PowerState),
        "PowerState is Unsupported until one is observed and must be filtered out"
    );
    assert!(
        visible
            .iter()
            .any(|(feature, _)| *feature == FeatureName::PlayUrl),
        "an undeclared feature answers Unavailable upstream, so it must survive the filter"
    );
    assert_eq!(features.all_features(true).len(), FeatureName::COUNT);

    if let Some(handle) = data.handle {
        handle.close().await.expect("closing must succeed");
    }
}

/// A device that pushes an event alongside every response must not starve the request channel.
///
/// `_handle_control_flag_update` answers an `_iMC` by sending a `GetVolume` of its own
/// (`__init__.py:439-451`). That command pumps the socket, so a device that attaches an `_iMC` to
/// every response — including the `GetVolume` response — used to keep the background task's drain
/// loop spinning for ever, and the request channel was never polled again: every subsequent
/// command hung until its own timeout. The follow-up is queued rather than sent inline now, and
/// each pass through the task's loop is bounded, so the `select!` is reached again regardless of
/// what the device does.
#[tokio::test]
async fn a_device_that_pushes_an_event_with_every_response_does_not_starve_commands() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    arrange(&device, |state| {
        state.echo_media_control = true;
        state.installed_apps = vec![("com.apple.TVMusic".to_owned(), "Music".to_owned())];
    })
    .await;

    let atv = tokio::time::timeout(Duration::from_secs(10), connect(&device))
        .await
        .expect("connecting must not hang");

    // The exact symptom: a command issued after the event storm started.
    let apps = tokio::time::timeout(
        Duration::from_secs(5),
        atv.apps().expect("Companion provides Apps").app_list(),
    )
    .await
    .expect("a command must still be served while events keep arriving")
    .expect("the app list must succeed");
    assert_eq!(apps.len(), 1);

    // And the pushed flags still reached the shared state, so nothing was dropped to get there.
    assert_eq!(
        atv.features().get_feature(FeatureName::Volume).state,
        FeatureState::Available
    );

    tokio::time::timeout(Duration::from_secs(5), atv.close())
        .await
        .expect("closing must not hang")
        .expect("closing must succeed");
}

/// `PowerState` is available only once a power state has actually been observed.
#[tokio::test]
async fn the_power_state_feature_follows_whether_one_was_observed() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    arrange(&device, |state| state.system_status = None).await;

    let atv = connect(&device).await;
    assert_eq!(
        atv.features().get_feature(FeatureName::PowerState).state,
        FeatureState::Unsupported
    );
    atv.close().await.expect("closing must succeed");

    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;
    assert_eq!(
        atv.features().get_feature(FeatureName::PowerState).state,
        FeatureState::Available
    );
    atv.close().await.expect("closing must succeed");
}

// ---- Listeners ----

/// A listener that records everything it is told, so a test can assert on it.
#[derive(Debug, Default)]
struct Recorder {
    lost: std::sync::Mutex<Vec<String>>,
    closed: std::sync::atomic::AtomicUsize,
    power: std::sync::Mutex<Vec<(PowerState, PowerState)>>,
}

impl Recorder {
    fn lost(&self) -> Vec<String> {
        self.lost.lock().expect("uncontended").clone()
    }

    fn power(&self) -> Vec<(PowerState, PowerState)> {
        self.power.lock().expect("uncontended").clone()
    }
}

impl pyatv_core::interface::DeviceListener for Recorder {
    fn connection_lost(&self, reason: &str) {
        self.lost
            .lock()
            .expect("uncontended")
            .push(reason.to_owned());
    }

    fn connection_closed(&self) {
        self.closed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
}

impl pyatv_core::interface::PowerListener for Recorder {
    fn power_state_changed(&self, old_state: PowerState, new_state: PowerState) {
        self.power
            .lock()
            .expect("uncontended")
            .push((old_state, new_state));
    }
}

/// Killing the device mid-session reaches a listener registered on the facade.
///
/// The chain is `Actor::run` seeing the socket die, `Stopped::ConnectionLost`, the Companion
/// session's listener, the facade's hub, and finally the caller's listener. It used to stop at the
/// first link: `pyatv::connect` passed `listener: None`, so nothing downstream of the actor was
/// ever called and a caller had no way to learn the device had gone.
#[tokio::test]
async fn killing_the_device_mid_session_reaches_a_registered_listener() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;

    let recorder = Arc::new(Recorder::default());
    atv.add_listener(&(Arc::clone(&recorder) as Arc<dyn DeviceListener>));
    assert!(recorder.lost().is_empty());

    device.kill_connections();

    // The actor notices on its next read, which is immediate once the socket closes.
    for _ in 0..50 {
        if !recorder.lost().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let lost = recorder.lost();
    assert_eq!(lost.len(), 1, "the drop must be reported exactly once");
    assert!(
        !lost[0].is_empty(),
        "the listener is told why the connection went away"
    );
}

/// Power-state pushes reach a listener registered on the facade.
///
/// `CompanionPower._update_power_state` forwards to `listener.powerstate_update(old, new)`
/// (`__init__.py:275-278`); this is that chain, from the device's `SystemStatus` event through the
/// session's shared state to the facade's hub.
#[tokio::test]
async fn power_state_changes_reach_a_registered_power_listener() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;

    // Registered after connecting, so the initial `FetchAttentionState` seeding is not counted.
    let recorder = Arc::new(Recorder::default());
    atv.add_power_listener(&(Arc::clone(&recorder) as Arc<dyn PowerListener>));

    let power = atv.power().expect("Companion provides Power");
    power
        .turn_off(true)
        .await
        .expect("turning off must succeed");
    power.turn_on(true).await.expect("turning on must succeed");

    tokio::time::sleep(SETTLE).await;
    assert_eq!(
        recorder.power(),
        vec![
            (PowerState::On, PowerState::Off),
            (PowerState::Off, PowerState::On),
        ],
        "both transitions are reported, with the state they came from"
    );

    atv.close().await.expect("closing must succeed");
}

// ---- Setup and teardown ----

/// The guard clause: no credentials means Companion does not exist, not that it failed.
#[tokio::test]
async fn setup_declines_without_credentials() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let service = BaseService::new(Protocol::Companion, device.address().port());

    let data = setup(CompanionSetupOptions {
        peer: device.address(),
        service,
        info: InfoSettings::default(),
        listener: None,
        power_listener: None,
    })
    .await
    .expect("declining is not an error");

    assert!(data.is_none());
}

/// Closing runs the whole teardown chain: deregister, `_sessionStop`, `_touchStop`, `_tiStop`.
#[tokio::test]
async fn closing_tears_the_session_down_in_upstreams_order() {
    let device = FakeCompanionDevice::start(PIN_CODE).await;
    let atv = connect(&device).await;

    atv.close().await.expect("closing must succeed");
    tokio::time::sleep(SETTLE).await;

    let shared = device.state();
    let state = shared.lock().await;
    let tail: Vec<&str> = state
        .commands
        .iter()
        .skip_while(|it| *it != "_sessionStop")
        .map(String::as_str)
        .collect();
    assert_eq!(tail, ["_sessionStop", "_touchStop", "_tiStop"]);

    // Every registration was withdrawn, including the two the power facade added.
    assert!(
        state.interests.is_empty(),
        "interests still registered: {:?}",
        state.interests
    );
    // …and the session id quoted back matched, which is what makes `_sessionStop` succeed at all.
    assert_eq!(state.local_sid, None);
}

/// A facade with no protocol registered reports every capability as absent, which is how the CLI
/// tells "not supported" from "failed".
#[tokio::test]
async fn an_empty_facade_offers_no_capabilities() {
    let facade = FacadeAppleTV::new(BaseService::new(Protocol::Companion, 49_153));
    assert!(facade.is_empty());
    assert!(facade.apps().is_none());
    assert!(facade.metadata().is_none());
    assert_eq!(
        facade.features().get_feature(FeatureName::AppList).state,
        FeatureState::Unsupported
    );
}

/// Registering a protocol that contributes nothing must not make the facade look connected.
#[tokio::test]
async fn a_setup_with_no_handles_registers_nothing() {
    let mut facade = FacadeAppleTV::new(BaseService::new(Protocol::Companion, 49_153));
    facade.add_protocol(SetupData::default());
    assert!(facade.is_empty());
}
