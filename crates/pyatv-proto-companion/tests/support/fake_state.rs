//! The reference device's observable state and its command handlers.
//!
//! Port of `FakeCompanionState` and the `handle_*` methods of `FakeCompanionService`
//! (`tests/fake_device/companion.py:82-200,414-560`), with the socket left to
//! [`super::fake_companion`]. Splitting it this way keeps both files inside the module-size rule
//! and, more usefully, makes every handler a pure `state × request -> replies` function that a
//! test can drive without a connection.

use pyatv_opack::{Value, opack};

use super::fake_plist;

/// Volume the device starts at (`INITIAL_VOLUME`, `companion.py:25`).
pub const INITIAL_VOLUME: f64 = 10.0;
/// How much a volume button moves it (`VOLUME_STEP`, `companion.py:27`).
pub const VOLUME_STEP: f64 = 5.0;
/// Seek position the device starts at (`INITIAL_DURATION`, `companion.py:26`).
pub const INITIAL_DURATION: f64 = 10.0;
/// The text the RTI session starts with (`INITIAL_RTI_TEXT`, `companion.py:28`).
pub const INITIAL_RTI_TEXT: &str = "Fake Companion Keyboard Text";
/// The session UUID the device hands out (`companion.py:513`).
pub const RTI_SESSION_UUID: &[u8] = b"0123456789abcdef";
/// The remote half of the composite session id, hardcoded upstream (`companion.py:480`).
pub const REMOTE_SID: u64 = 5555;
/// The error code `send_handler_not_supported` uses (`companion.py:346-348`).
pub const NO_HANDLER_CODE: u64 = 58822;

/// `HID_BUTTON_MAP` (`companion.py:37-53`): the HID codes the fake device records a press for.
///
/// Deliberately partial. `Siri`, `PageUp`, `Sleep` and `Wake` are absent — the first two because
/// pyatv never sends them, the last two because they take the power branch instead of the
/// button-press branch.
pub const HID_BUTTON_MAP: [(u64, &str); 15] = [
    (1, "up"),
    (2, "down"),
    (3, "left"),
    (4, "right"),
    (6, "select"),
    (5, "menu"),
    (7, "home"),
    (9, "volume_down"),
    (8, "volume_up"),
    (14, "play_pause"),
    (15, "channel_up"),
    (16, "channel_down"),
    (11, "screensaver"),
    (17, "guide"),
    (19, "control_center"),
];

/// `MEDIA_CONTROL_MAP` (`companion.py:55-62`).
pub const MEDIA_CONTROL_MAP: [(u64, &str); 6] = [
    (1, "play"),
    (2, "pause"),
    (3, "next"),
    (4, "previous"),
    (6, "set_volume"),
    (7, "skip"),
];

/// What one handler wants the connection to do next.
#[derive(Debug)]
pub enum Reply {
    /// Answer the request with this content.
    Response(Value),
    /// Answer the request with an `_em`/`_ec`/`_ed` triple.
    Error(String, u64),
    /// Push an unsolicited event.
    Event(&'static str, Value),
    /// Say nothing, which is what an event gets.
    Nothing,
}

/// Everything the device knows and a test can assert on.
///
/// One instance is shared by every accepted connection, as `FakeCompanionState` is upstream.
#[expect(
    clippy::struct_excessive_bools,
    reason = "a test fixture mirroring upstream's FakeCompanionState field for field; grouping \
              its independent flags into sub-structs would make the port harder to check against \
              tests/fake_device/companion.py for no benefit to the tests that read them"
)]
#[derive(Debug)]
pub struct DeviceState {
    /// Whether a pair-setup completed.
    pub has_paired: bool,
    /// The `_systemInfo` content the client sent.
    pub system_info: Option<Value>,
    /// The `_sid` the client proposed in `_sessionStart`.
    pub local_sid: Option<u64>,
    /// Every command identifier the client sent, in order.
    pub commands: Vec<String>,
    /// Event names the client registered interest in.
    pub interests: Vec<String>,
    /// Whether the client's traffic was encrypted by the time it arrived.
    pub saw_encrypted_traffic: bool,
    /// `FetchAttentionState`'s answer, or `None` to make it a "No request handler" error.
    pub system_status: Option<u64>,
    /// Bundle identifier the client last launched.
    pub active_app: Option<String>,
    /// URL the client last opened.
    pub open_url: Option<String>,
    /// `{bundle_id: name}` the app list answers with.
    pub installed_apps: Vec<(String, String)>,
    /// `{account_id: name}` the account list answers with.
    pub available_accounts: Vec<(String, String)>,
    /// The account the client last switched to.
    pub active_account: Option<String>,
    /// Whether the device believes it is awake.
    pub powered_on: bool,
    /// The most recent button the client completed a press on.
    pub latest_button: Option<String>,
    /// Every `_hidC` down the client has sent and not yet released.
    pressed_buttons: Vec<u64>,
    /// The `_mcF` bitfield pushed on `_iMC`.
    pub media_control_flags: u64,
    /// Current volume, in percent.
    pub volume: f64,
    /// Current seek position, moved by `SkipBy`.
    pub duration: f64,
    /// The focused field's text, or `None` for "nothing has focus".
    pub rti_text: Option<String>,
    /// The session UUID handed out by `_tiStart`, cleared by `_tiStop`.
    pub rti_session_uuid: Option<Vec<u8>>,
    /// `(x, y, phase)` of the last `_hidT` the client sent.
    pub touch_event: Option<(u64, u64, u64)>,
    /// The `_touchStart` dimensions the client asked for.
    pub touch_size: Option<(f64, f64)>,
    /// Attach an `_iMC` push to **every** response.
    ///
    /// Not an upstream behaviour: it is the adversarial shape that used to wedge the client's
    /// event drain, since handling an `_iMC` sent a `GetVolume` whose response carried another
    /// `_iMC`, for ever. A real device pushes `_iMC` only when the flags change.
    pub echo_media_control: bool,
}

impl Default for DeviceState {
    fn default() -> Self {
        Self {
            has_paired: false,
            system_info: None,
            local_sid: None,
            commands: Vec::new(),
            interests: Vec::new(),
            saw_encrypted_traffic: false,
            // `SystemStatus.Awake`, and `SYSTEM_STATUS_SUPPORTED` on by default
            // (`companion.py:84-87`).
            system_status: Some(0x03),
            active_app: None,
            open_url: None,
            installed_apps: Vec::new(),
            available_accounts: Vec::new(),
            active_account: None,
            powered_on: true,
            latest_button: None,
            pressed_buttons: Vec::new(),
            // `MediaControlFlags.Volume` (`companion.py:101`) — a fixture default, not a
            // client-side assumption.
            media_control_flags: 0x0100,
            volume: INITIAL_VOLUME,
            duration: INITIAL_DURATION,
            rti_text: Some(INITIAL_RTI_TEXT.to_owned()),
            rti_session_uuid: None,
            touch_event: None,
            touch_size: None,
            echo_media_control: false,
        }
    }
}

impl DeviceState {
    /// Handle one decoded OPACK message, returning what the connection should send.
    ///
    /// `data_received`'s dispatch (`companion.py:296-305`): the handler is looked up by a
    /// lowercased identifier and anything unknown gets `send_handler_not_supported`.
    pub fn handle(&mut self, identifier: &str, content: &Value, is_event: bool) -> Vec<Reply> {
        self.commands.push(identifier.to_owned());

        let mut replies = self.dispatch(identifier, content, is_event);
        if self.echo_media_control && !is_event {
            replies.push(Reply::Event(
                "_iMC",
                opack! { "_mcF" => self.media_control_flags | 0x0100 },
            ));
        }
        replies
    }

    /// The dispatch table itself.
    fn dispatch(&mut self, identifier: &str, content: &Value, is_event: bool) -> Vec<Reply> {
        match identifier {
            "_interest" => self.interest(content),
            "_hidT" => {
                self.touch(content);
                vec![Reply::Nothing]
            }
            "_tiC" => {
                self.text_operation(content);
                vec![Reply::Nothing]
            }
            _ if is_event => vec![Reply::Nothing],
            "_systemInfo" => {
                self.system_info = Some(content.clone());
                vec![ok()]
            }
            "_touchStart" => self.touch_start(content),
            "_touchStop" | "TVRCSessionStart" => vec![Reply::Response(content.clone())],
            "_sessionStart" => {
                self.local_sid = content.get("_sid").and_then(Value::as_u64);
                vec![Reply::Response(opack! { "_sid" => REMOTE_SID })]
            }
            "_sessionStop" => self.session_stop(content),
            "_hidC" => self.hid_command(content),
            "_mcc" => self.media_control(content),
            "_launchApp" => self.launch_app(content),
            "FetchLaunchableApplicationsEvent" => {
                vec![Reply::Response(pairs(&self.installed_apps))]
            }
            "FetchUserAccountsEvent" => vec![Reply::Response(pairs(&self.available_accounts))],
            "SwitchUserAccountEvent" => {
                self.active_account = content
                    .get("SwitchAccountID")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned);
                vec![ok()]
            }
            "FetchAttentionState" => match self.system_status {
                Some(state) => vec![Reply::Response(opack! { "state" => state })],
                None => vec![no_handler()],
            },
            "_tiStart" => self.text_input_start(),
            "_tiStop" => self.text_input_stop(),
            _ => vec![no_handler()],
        }
    }

    /// `handle__interest` (`companion.py:497-508`): registering `_iMC` immediately pushes one.
    fn interest(&mut self, content: &Value) -> Vec<Reply> {
        if let Some(events) = content.get("_regEvents").and_then(Value::as_array) {
            for event in events.iter().filter_map(Value::as_str) {
                if !self.interests.iter().any(|known| known == event) {
                    self.interests.push(event.to_owned());
                }
            }
            if self.interests.iter().any(|event| event == "_iMC") {
                return vec![Reply::Event(
                    "_iMC",
                    opack! { "_mcF" => self.media_control_flags },
                )];
            }
        }

        if let Some(events) = content.get("_deregEvents").and_then(Value::as_array) {
            self.interests
                .retain(|known| !events.iter().any(|event| event.as_str() == Some(known)));
        }
        vec![Reply::Nothing]
    }

    /// `handle__touchstart` (`companion.py:413-437`), including its bounds check.
    fn touch_start(&mut self, content: &Value) -> Vec<Reply> {
        let width = content.get("_width").and_then(Value::as_f64).unwrap_or(0.0);
        let height = content
            .get("_height")
            .and_then(Value::as_f64)
            .unwrap_or(0.0);
        self.touch_size = Some((width, height));

        if width <= 0.0 || width > 1000.0 || height <= 0.0 || height > 1000.0 {
            return vec![Reply::Error(
                "Invalid touchpad width or height".to_owned(),
                1337,
            )];
        }
        vec![ok()]
    }

    /// `handle__hidt` (`companion.py:443-460`), which records but never answers.
    fn touch(&mut self, content: &Value) {
        let read = |key| content.get(key).and_then(Value::as_u64).unwrap_or_default();
        self.touch_event = Some((read("_cx"), read("_cy"), read("_tPh")));
    }

    /// `handle__sessionstop` (`companion.py:483-488`): the composite must match exactly.
    fn session_stop(&mut self, content: &Value) -> Vec<Reply> {
        let expected = (REMOTE_SID << 32) | self.local_sid.unwrap_or_default();
        if content.get("_sid").and_then(Value::as_u64) == Some(expected) {
            self.local_sid = None;
            vec![ok()]
        } else {
            vec![Reply::Error("Invalid SID".to_owned(), 1337)]
        }
    }

    /// `handle__hidc` (`companion.py:381-411`).
    ///
    /// The device is strict about pairing: a button *up* with no matching *down* is an error, which
    /// is what catches a port that forgets one half of `_press_button`. Sleep and Wake are the
    /// exception — they arrive as an up with no down by design.
    fn hid_command(&mut self, content: &Value) -> Vec<Reply> {
        let state = content.get("_hBtS").and_then(Value::as_u64).unwrap_or(0);
        let code = content.get("_hidC").and_then(Value::as_u64).unwrap_or(0);

        if state == 1 {
            self.pressed_buttons.push(code);
            return vec![ok()];
        }

        // 12 = Sleep, 13 = Wake.
        if code == 12 || code == 13 {
            self.powered_on = code == 13;
            let status = if self.powered_on { 0x03 } else { 0x01 };
            self.system_status = Some(status);
            return vec![
                ok(),
                Reply::Event("SystemStatus", opack! { "state" => status }),
            ];
        }

        let Some((_, name)) = HID_BUTTON_MAP.iter().find(|(known, _)| *known == code) else {
            return vec![Reply::Nothing];
        };

        let Some(index) = self.pressed_buttons.iter().position(|held| *held == code) else {
            return vec![Reply::Error(
                format!("Missing button DOWN for {code}"),
                1337,
            )];
        };
        self.pressed_buttons.remove(index);
        self.latest_button = Some((*name).to_owned());

        // 8 = VolumeUp, 9 = VolumeDown.
        match code {
            8 => vec![ok(), self.volume_changed(self.volume + VOLUME_STEP)],
            9 => vec![ok(), self.volume_changed(self.volume - VOLUME_STEP)],
            _ => vec![ok()],
        }
    }

    /// `handle__mcc` (`companion.py:462-481`).
    fn media_control(&mut self, content: &Value) -> Vec<Reply> {
        let command = content.get("_mcc").and_then(Value::as_u64).unwrap_or(0);

        match command {
            // GetVolume answers with a 0.0..=1.0 fraction.
            5 => return vec![Reply::Response(opack! { "_vol" => self.volume / 100.0 })],
            6 => {
                let level = content.get("_vol").and_then(Value::as_f64).unwrap_or(0.0) * 100.0;
                let event = self.volume_changed(level);
                return vec![ok(), event];
            }
            7 => {
                let step = content.get("_skpS").and_then(Value::as_f64).unwrap_or(0.0);
                self.duration = (self.duration + step).max(0.0);
            }
            _ => {}
        }

        if let Some((_, name)) = MEDIA_CONTROL_MAP
            .iter()
            .find(|(known, _)| *known == command)
        {
            self.latest_button = Some((*name).to_owned());
            return vec![ok()];
        }
        vec![Reply::Nothing]
    }

    /// `volume_changed` (`companion.py:349-357`): clamp, then push an `_iMC` with the volume bit on.
    fn volume_changed(&mut self, volume: f64) -> Reply {
        self.volume = volume.clamp(0.0, 100.0);
        Reply::Event(
            "_iMC",
            opack! { "_mcF" => self.media_control_flags | 0x0100 },
        )
    }

    /// `handle__launchapp` (`companion.py:359-367`).
    fn launch_app(&mut self, content: &Value) -> Vec<Reply> {
        if let Some(bundle_id) = content.get("_bundleID").and_then(Value::as_str) {
            self.active_app = Some(bundle_id.to_owned());
        } else if let Some(url) = content.get("_urlS").and_then(Value::as_str) {
            self.open_url = Some(url.to_owned());
        }
        vec![ok()]
    }

    /// `handle__tistart` (`companion.py:508-521`): a focused session answers with an RTI archive.
    fn text_input_start(&mut self) -> Vec<Reply> {
        let Some(text) = self.rti_text.clone() else {
            return vec![ok()];
        };

        self.rti_session_uuid = Some(RTI_SESSION_UUID.to_vec());
        vec![Reply::Response(opack! {
            "_tiD" => fake_plist::rti_session(RTI_SESSION_UUID, &text),
        })]
    }

    /// `handle__tistop` (`companion.py:523-531`).
    fn text_input_stop(&mut self) -> Vec<Reply> {
        self.rti_session_uuid = None;
        vec![ok()]
    }

    /// `handle__tic` (`companion.py:533-556`): decode the client's keyed archive and apply it.
    ///
    /// Reads the same three paths upstream does, with the same reader the client uses — which is
    /// what makes this a genuine round trip of this crate's encoder against its own decoder.
    fn text_operation(&mut self, content: &Value) {
        let Some(archive) = content.get("_tiD").and_then(Value::as_bytes) else {
            return;
        };

        let Ok(read) = pyatv_proto_companion::keyed_archiver::read_archive_properties(
            archive,
            &[
                &["textOperations", "targetSessionUUID", "NS.uuidbytes"],
                &["textOperations", "textToAssert"],
                &["textOperations", "keyboardOutput", "insertionText"],
            ],
        ) else {
            return;
        };

        let uuid = pyatv_proto_companion::keyed_archiver::as_data(read[0].as_ref());
        if uuid != self.rti_session_uuid.as_deref() {
            return;
        }

        if pyatv_proto_companion::keyed_archiver::as_string(read[1].as_ref()) == Some("") {
            self.rti_text = Some(String::new());
        }
        if let Some(insertion) = pyatv_proto_companion::keyed_archiver::as_string(read[2].as_ref())
        {
            self.rti_text
                .get_or_insert_with(String::new)
                .push_str(insertion);
        }
    }
}

/// An empty successful response.
fn ok() -> Reply {
    Reply::Response(opack! {})
}

/// `send_handler_not_supported` (`companion.py:346-348`).
fn no_handler() -> Reply {
    Reply::Error("No request handler".to_owned(), NO_HANDLER_CODE)
}

/// Turn an ordered association list into the flat `{id: name}` dict the device answers with.
fn pairs(entries: &[(String, String)]) -> Value {
    Value::dict(
        entries
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str())),
    )
}
