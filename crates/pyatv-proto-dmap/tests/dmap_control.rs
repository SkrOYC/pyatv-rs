//! DMAP's remote control: buttons, D-pad gestures, shuffle, repeat and seeking.
//!
//! Counterpart of `tests/protocols/dmap/test_dmap_functional.py:153-181,260-282` and the button
//! half of `tests/common_functional_tests.py`. The shared harness is in [`support`].

mod support;

use pyatv_core::interface::AppleTV;
use pyatv_core::{Error as CoreError, InputAction, RepeatState, ShuffleState};
use pyatv_proto_dmap::test_support::fake_dmap::FakeDmapDevice;
use pyatv_proto_dmap::test_support::fake_state::{HSGID, PlayingResponse, SESSION_ID};

use support::{connect, playing, wait_for_button};

/// The one URL every `controlpromptentry` POST must have: the template from `__init__.py:63` with
/// `[AUTH]` filled in, session id first (`parameters.insert(0, ...)`, `daap.py:169`).
fn control_prompt_url() -> String {
    format!("/ctrl-int/1/controlpromptentry?session-id={SESSION_ID}&prompt-id=0")
}

// ---- Remote control (`test_dmap_functional.py:153-165`) ----

/// `test_button_unsupported_raises` (`:153-157`).
#[tokio::test]
async fn buttons_gen_one_to_three_hardware_lacks_are_refused() {
    let device = FakeDmapDevice::start().await;
    let atv = connect(&device, HSGID).await;
    let remote = atv.remote_control().expect("DMAP provides RemoteControl");

    // Upstream's list is `home`, `suspend`, `wakeup` (`:154`); the latter two are power operations
    // in this port's trait split, so the equivalent set is every button `DmapRemoteControl` leaves
    // to `interface.RemoteControl`'s raising base implementation.
    for (name, result) in [
        ("home", remote.home(InputAction::SingleTap).await),
        ("home_hold", remote.home_hold().await),
        ("guide", remote.guide().await),
        ("control_center", remote.control_center().await),
        ("screensaver", remote.screensaver().await),
        ("channel_up", remote.channel_up().await),
        ("channel_down", remote.channel_down().await),
    ] {
        assert!(
            matches!(result, Err(CoreError::NotSupported(_))),
            "{name} must report NotSupported, got {result:?}"
        );
    }

    assert!(
        device.use_cases().last_button_pressed().is_none(),
        "an unsupported button must not reach the device at all"
    );
}

/// `test_button_top_menu` (`:159-161`): `topmenu` goes through `controlpromptentry`.
#[tokio::test]
async fn top_menu_is_sent_as_a_control_prompt() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    let atv = connect(&device, HSGID).await;

    atv.remote_control()
        .expect("DMAP provides RemoteControl")
        .top_menu()
        .await
        .expect("top_menu must be accepted");

    wait_for_button(&use_cases, "topmenu").await;

    // The whole URL, not just the endpoint: the session id, its position, and `prompt-id=0` are all
    // wire-visible and all easy to lose to a template edit.
    let requests = use_cases.requests();
    let prompts: Vec<&String> = requests
        .iter()
        .filter(|target| target.starts_with("/ctrl-int/1/controlpromptentry"))
        .collect();
    assert_eq!(
        prompts,
        vec![&control_prompt_url()],
        "topmenu must be exactly one control-prompt POST, requests were {requests:?}"
    );
    use_cases.assert_no_protocol_errors();
}

/// `test_button_play_pause` (`:163-165`): the transport buttons have endpoints of their own.
#[tokio::test]
async fn the_transport_buttons_have_their_own_endpoints() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    let atv = connect(&device, HSGID).await;
    let remote = atv.remote_control().expect("DMAP provides RemoteControl");

    // One at a time: the device records only the most recent button, so pressing all six first and
    // checking afterwards would only ever see the last.
    for button in ["playpause", "play", "pause", "stop", "nextitem", "previtem"] {
        match button {
            "playpause" => remote.play_pause().await,
            "play" => remote.play().await,
            "pause" => remote.pause().await,
            "stop" => remote.stop().await,
            "nextitem" => remote.next().await,
            _ => remote.previous().await,
        }
        .unwrap_or_else(|error| panic!("{button} must be accepted: {error}"));
        wait_for_button(&use_cases, button).await;
    }
    use_cases.assert_no_protocol_errors();
}

/// The volume buttons are transport commands too (`Audio::volume_up`/`volume_down`,
/// `__init__.py:594-604`).
#[tokio::test]
async fn the_volume_buttons_are_transport_commands() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    let atv = connect(&device, HSGID).await;
    let audio = atv.audio().expect("DMAP provides Audio");

    audio.volume_up().await.expect("volume up must be accepted");
    wait_for_button(&use_cases, "volumeup").await;

    audio
        .volume_down()
        .await
        .expect("volume down must be accepted");
    wait_for_button(&use_cases, "volumedown").await;
}

/// A D-pad key is seven `controlpromptentry` POSTs, and only the seventh names the direction.
///
/// The fixture only recognises the last step when six have already arrived (`dmap.py:181-195`), so
/// this asserting `"up"` is an assertion about all seven steps, in order.
#[tokio::test]
async fn a_direction_key_is_a_seven_step_gesture() {
    for (direction, press) in [("up", 0u8), ("down", 1), ("left", 2), ("right", 3)] {
        let device = FakeDmapDevice::start().await;
        let use_cases = device.use_cases();
        let atv = connect(&device, HSGID).await;
        let remote = atv.remote_control().expect("DMAP provides RemoteControl");

        let action = InputAction::SingleTap;
        match press {
            0 => remote.up(action).await,
            1 => remote.down(action).await,
            2 => remote.left(action).await,
            _ => remote.right(action).await,
        }
        .unwrap_or_else(|error| panic!("{direction} must be accepted: {error}"));

        wait_for_button(&use_cases, direction).await;
        assert_eq!(
            use_cases.state().buttons_press_count,
            7,
            "{direction} must be seven steps"
        );

        // All seven go to the same URL — the steps differ only in their bodies.
        let requests = use_cases.requests();
        let prompts: Vec<&String> = requests
            .iter()
            .filter(|target| target.starts_with("/ctrl-int/1/controlpromptentry"))
            .collect();
        assert_eq!(
            prompts,
            vec![&control_prompt_url(); 7],
            "{direction}: requests were {requests:?}"
        );
        use_cases.assert_no_protocol_errors();
    }
}

// ---- Shuffle, repeat and seeking (`test_dmap_functional.py:167-181,260-282`) ----

/// `test_shuffle_state_albums` (`:167-172`): DMAP has no album shuffle, so `cash=1` reads back as
/// `Songs`.
#[tokio::test]
async fn album_shuffle_is_reported_as_song_shuffle() {
    let device = FakeDmapDevice::start().await;
    device.use_cases().video_playing(PlayingResponse {
        shuffle: Some(ShuffleState::Albums),
        ..PlayingResponse::example_video()
    });

    let atv = connect(&device, HSGID).await;
    assert_eq!(playing(&atv).await.shuffle, Some(ShuffleState::Songs));
}

/// `test_set_shuffle_albums` (`:174-181`): asking for album shuffle sends plain shuffle.
#[tokio::test]
async fn setting_album_shuffle_sends_plain_shuffle() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();

    let atv = connect(&device, HSGID).await;
    atv.remote_control()
        .expect("DMAP provides RemoteControl")
        .set_shuffle(ShuffleState::Albums)
        .await
        .expect("set_shuffle must be accepted");

    assert_eq!(
        use_cases.properties_set(),
        vec![("dacp.shufflestate".to_owned(), "1".to_owned())]
    );
    assert_eq!(playing(&atv).await.shuffle, Some(ShuffleState::Songs));
}

/// Repeat round-trips all three states.
#[tokio::test]
async fn repeat_round_trips() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();

    let atv = connect(&device, HSGID).await;
    let remote = atv.remote_control().expect("DMAP provides RemoteControl");

    for state in [RepeatState::Track, RepeatState::All, RepeatState::Off] {
        remote
            .set_repeat(state)
            .await
            .expect("set_repeat must be accepted");
        assert_eq!(playing(&atv).await.repeat, Some(state));
    }
}

/// `test_skip_forward_backward` (`:260-282`): there is no relative seek, so each skip is a read of
/// the current position followed by an absolute `dacp.playingtime`.
#[tokio::test]
async fn skipping_seeks_to_an_absolute_position() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.example_video();

    let atv = connect(&device, HSGID).await;
    let remote = atv.remote_control().expect("DMAP provides RemoteControl");

    // `example_video` starts three seconds in; the default skip is ten seconds.
    assert_eq!(playing(&atv).await.position, Some(3));

    remote.skip_forward(0.0).await.expect("skip must work");
    assert_eq!(playing(&atv).await.position, Some(13));

    remote.skip_backward(0.0).await.expect("skip must work");
    assert_eq!(playing(&atv).await.position, Some(3));

    // A fractional interval is truncated, not rounded: `int(13.7) == 13`.
    remote.skip_forward(13.7).await.expect("skip must work");
    assert_eq!(playing(&atv).await.position, Some(16));

    remote.skip_backward(11.0).await.expect("skip must work");
    assert_eq!(playing(&atv).await.position, Some(5));

    assert!(
        use_cases
            .properties_set()
            .iter()
            .all(|(property, _)| property == "dacp.playingtime")
    );
}

/// `if current_position:` guards the whole body upstream (`__init__.py:356-378`), so a skip with
/// nothing playing sends nothing at all rather than seeking to ten seconds.
#[tokio::test]
async fn skipping_with_nothing_playing_sends_nothing() {
    let device = FakeDmapDevice::start().await;
    let use_cases = device.use_cases();
    use_cases.nothing_playing();

    let atv = connect(&device, HSGID).await;
    atv.remote_control()
        .expect("DMAP provides RemoteControl")
        .skip_forward(0.0)
        .await
        .expect("skipping must be a no-op, not an error");

    assert!(use_cases.properties_set().is_empty());
}
