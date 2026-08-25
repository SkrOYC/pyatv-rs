//! What the fake MRP device believes, and the use-case helpers that change it.
//!
//! Port of `FakeMrpState` (`tests/fake_device/mrp.py:202-348`) and `FakeMrpUseCases`
//! (`mrp.py:653-829`). Nothing here touches a socket: state changes are broadcast as
//! [`MrpMessage`]s and [`super::fake_mrp`] is what puts them on the wire, which is the same split
//! upstream has between `FakeMrpState._send` and `FakeMrpService.send_to_client`.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use std::time::Instant;

use pyatv_core::consts::{InputAction, RepeatState, ShuffleState};
use pyatv_proto_mrp::MrpMessage;
use pyatv_proto_mrp::protobuf::{Command, content_item_metadata, playback_state};
use tokio::sync::broadcast;

use super::fake_messages as build;

/// `APP_NAME` (`mrp.py:68`).
pub const APP_NAME: &str = "Test app";
/// `DEVICE_NAME` (`mrp.py:69`).
pub const DEVICE_NAME: &str = "Fake MRP ATV";
/// `PLAYER_IDENTIFIER` (`mrp.py:70`), the bundle identifier the default player belongs to.
pub const PLAYER_IDENTIFIER: &str = "com.github.postlund.pyatv";
/// `DEFAULT_PLAYER_ID` (`mrp.py:72`).
pub const DEFAULT_PLAYER_ID: &str = "MediaRemote-DefaultPlayer";
/// `DEFAULT_PLAYER_NAME` (`mrp.py:73`).
pub const DEFAULT_PLAYER_NAME: &str = "Default Player";
/// `BUILD_NUMBER` (`mrp.py:75`).
pub const BUILD_NUMBER: &str = "18M60";
/// `DEVICE_MODEL` (`mrp.py:77`).
pub const DEVICE_MODEL: &str = "AppleTV6,2";
/// `DEVICE_UID` (`mrp.py:79`), this device's own output-device identifier.
pub const DEVICE_UID: &str = "E510C430-B01D-45DF-B558-6EA6F8251069";
/// `VOLUME_STEP` (`mrp.py:81`), the relative step the HID volume keys apply.
pub const VOLUME_STEP: f32 = 0.05;
/// The volume the device starts at (`mrp.py:215`), as a 0..1 fraction.
pub const INITIAL_VOLUME: f32 = 0.5;

/// How long a key must be held before the device calls it a hold (`mrp.py:519`).
pub const HOLD_THRESHOLD: std::time::Duration = std::time::Duration::from_millis(500);

/// One player's now-playing state (`PlayingState`, `mrp.py:172-199`).
///
/// Every field is optional because upstream's is a bag of `kwargs.get(...)`; a `None` here means
/// "the device is not reporting this", not "zero".
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PlayingState {
    /// `ContentItem.identifier`, which is what upstream reports as `Playing.hash`.
    pub identifier: Option<String>,
    /// Transport state.
    pub playback_state: Option<playback_state::Enum>,
    /// Item title.
    pub title: Option<String>,
    /// Series name, for TV content.
    pub series_name: Option<String>,
    /// Performing artist.
    pub artist: Option<String>,
    /// Album name.
    pub album: Option<String>,
    /// Genre.
    pub genre: Option<String>,
    /// Duration in seconds.
    pub total_time: Option<f64>,
    /// Elapsed time in seconds.
    pub position: Option<f64>,
    /// Season number, for TV content.
    pub season_number: Option<i32>,
    /// Episode number, for TV content.
    pub episode_number: Option<i32>,
    /// Repeat mode, reported through a `ChangeRepeatMode` command entry.
    pub repeat: Option<RepeatState>,
    /// Shuffle mode, reported through a `ChangeShuffleMode` command entry.
    pub shuffle: Option<ShuffleState>,
    /// Media type.
    pub media_type: Option<content_item_metadata::MediaType>,
    /// Playback rate; zero suppresses the client's position extrapolation.
    pub playback_rate: Option<f32>,
    /// Commands the player advertises.
    pub supported_commands: Vec<Command>,
    /// Artwork bytes returned by a `PLAYBACK_QUEUE_REQUEST_MESSAGE`.
    pub artwork: Option<Vec<u8>>,
    /// Artwork identifier, which the client uses as its cache key.
    pub artwork_identifier: Option<String>,
    /// Artwork MIME type; its presence is what sets `artworkAvailable`.
    pub artwork_mimetype: Option<String>,
    /// Remote artwork URL, for the fetch path that needs an HTTP client.
    pub artwork_url: Option<String>,
    /// Artwork width reported alongside the bytes.
    pub artwork_width: Option<i32>,
    /// Artwork height reported alongside the bytes.
    pub artwork_height: Option<i32>,
    /// Preferred skip interval, advertised on the skip commands.
    pub skip_time: Option<f64>,
    /// The owning app's display name.
    pub app_name: Option<String>,
    /// Opaque content identifier.
    pub content_identifier: Option<String>,
    /// iTunes Store identifier.
    pub itunes_store_identifier: Option<i64>,
}

impl PlayingState {
    /// Copy every field `change` sets over this one.
    ///
    /// Upstream's `setattr` loops skip falsy values (`mrp.py:269-271`); this skips `None` instead,
    /// which differs only for an explicit zero — and a zero position is a case the tests want to be
    /// able to set.
    pub(super) fn merge(&mut self, change: &Self) {
        macro_rules! take {
            ($($field:ident),* $(,)?) => {
                $(if change.$field.is_some() {
                    self.$field = change.$field.clone();
                })*
            };
        }
        take!(
            identifier,
            playback_state,
            title,
            series_name,
            artist,
            album,
            genre,
            total_time,
            position,
            season_number,
            episode_number,
            repeat,
            shuffle,
            media_type,
            playback_rate,
            artwork,
            artwork_identifier,
            artwork_mimetype,
            artwork_url,
            artwork_width,
            artwork_height,
            skip_time,
            app_name,
            content_identifier,
            itunes_store_identifier,
        );
        if !change.supported_commands.is_empty() {
            self.supported_commands
                .clone_from(&change.supported_commands);
        }
    }

    /// `paused=True/False` → the playback state and rate pair every use case sets together.
    #[must_use]
    pub fn paused(paused: bool) -> (Option<playback_state::Enum>, Option<f32>) {
        if paused {
            (Some(playback_state::Enum::Paused), Some(0.0))
        } else {
            (Some(playback_state::Enum::Playing), Some(1.0))
        }
    }
}

/// The mutable half of the device, guarded by one lock.
#[derive(Debug)]
pub struct Inner {
    /// Per-client player state, keyed by bundle identifier.
    pub states: BTreeMap<String, PlayingState>,
    /// The client the device says is playing.
    pub active_player: Option<String>,
    /// Reported as `logicalDeviceCount` on every `DeviceInfoMessage`.
    pub powered_on: bool,
    /// How many `GENERIC_MESSAGE` heartbeats have arrived.
    pub heartbeat_count: usize,
    /// Current volume as a 0..1 fraction.
    pub volume: f32,
    /// Cluster identifier, which takes precedence over `deviceUID` when set.
    pub cluster_id: Option<String>,
    /// The playback group.
    pub output_devices: Vec<String>,
    /// The last button the device decoded, by pyatv's name for it.
    pub last_button_pressed: Option<String>,
    /// How that button was pressed, for HID buttons only.
    pub last_button_action: Option<InputAction>,
    /// The `SET_CONNECTION_STATE_MESSAGE` value the client sent.
    pub connection_state: Option<i32>,
    /// Set once a client has completed pair-verify.
    pub has_authenticated: bool,
    /// Key-down times awaiting their key-up.
    pub outstanding: HashMap<(u16, u16), Instant>,
    /// Every `SEND_COMMAND_MESSAGE` command the device received, in order.
    pub commands: Vec<i32>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            states: BTreeMap::new(),
            active_player: None,
            powered_on: true,
            heartbeat_count: 0,
            volume: INITIAL_VOLUME,
            cluster_id: None,
            output_devices: vec![DEVICE_UID.to_owned()],
            last_button_pressed: None,
            last_button_action: None,
            connection_state: None,
            has_authenticated: false,
            outstanding: HashMap::new(),
            commands: Vec::new(),
        }
    }
}

/// The device, shared between the connection tasks and the test.
#[derive(Debug)]
pub struct FakeDeviceState {
    inner: Mutex<Inner>,
    outbound: broadcast::Sender<MrpMessage>,
}

impl Default for FakeDeviceState {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeDeviceState {
    /// A device with nothing playing and the volume at [`INITIAL_VOLUME`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            outbound: broadcast::Sender::new(64),
        }
    }

    /// Subscribe a connection to the device's pushes (`FakeMrpState.clients`, `mrp.py:205`).
    pub fn subscribe(&self) -> broadcast::Receiver<MrpMessage> {
        self.outbound.subscribe()
    }

    /// Read something out of the device's state.
    pub fn with<R>(&self, read: impl FnOnce(&Inner) -> R) -> R {
        read(&self.lock())
    }

    /// Mutate the device's state without announcing anything.
    pub fn update<R>(&self, apply: impl FnOnce(&mut Inner) -> R) -> R {
        apply(&mut self.lock())
    }

    /// Broadcast one message to every connected client (`FakeMrpState._send`, `mrp.py:219-221`).
    pub fn send(&self, message: MrpMessage) {
        // An error only means nobody is listening yet, which is not a fixture failure.
        let _ = self.outbound.send(message);
    }

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Re-send the current `DeviceInfoMessage` as an update (`_send_device_info`, `mrp.py:223-225`).
    pub fn announce_device_info(&self) {
        let message = {
            let inner = self.lock();
            build::device_info(
                inner.powered_on,
                inner.cluster_id.as_deref(),
                &inner.output_devices,
                None,
                true,
            )
        };
        self.send(message);
    }

    /// Push the stored state for `identifier` (`FakeMrpState.update_state`, `mrp.py:232-234`).
    pub fn update_state(&self, identifier: &str) {
        let Some(message) = self
            .lock()
            .states
            .get(identifier)
            .map(|state| build::set_state(state, identifier))
        else {
            return;
        };
        self.send(message);
    }

    /// Store a player's state and push it (`set_player_state`, `mrp.py:236-238`).
    pub fn set_player_state(&self, identifier: &str, state: PlayingState) {
        self.lock().states.insert(identifier.to_owned(), state);
        self.update_state(identifier);
    }

    /// Make `identifier` the now-playing client (`set_active_player`, `mrp.py:243-252`).
    pub fn set_active_player(&self, identifier: Option<&str>) {
        self.lock().active_player = identifier.map(str::to_owned);
        self.send(build::set_now_playing_client(identifier));
    }

    /// Merge `change` into the stored state and push it as a content-item update
    /// (`FakeMrpState.item_update`, `mrp.py:254-273`).
    pub fn item_update(&self, change: &PlayingState, identifier: &str) {
        {
            let mut inner = self.lock();
            if let Some(state) = inner.states.get_mut(identifier) {
                state.merge(change);
            }
        }
        self.send(build::item_update(change, identifier));
    }

    /// `FakeMrpState.update_client` (`mrp.py:275-281`).
    pub fn update_client(&self, display_name: Option<&str>, identifier: &str) {
        self.send(build::update_client(display_name, identifier));
    }

    /// `FakeMrpState.set_cluster_id` (`mrp.py:283-285`).
    pub fn set_cluster_id(&self, cluster_id: &str) {
        self.lock().cluster_id = Some(cluster_id.to_owned());
        self.announce_device_info();
    }

    /// `FakeMrpState.volume_control` (`mrp.py:287-307`), both halves.
    pub fn volume_control(&self, available: bool, absolute: bool, relative: bool) {
        use pyatv_proto_mrp::protobuf::volume_capabilities::Enum;

        let capabilities = match (absolute, relative) {
            (true, true) => Some(Enum::Both),
            (true, false) => Some(Enum::Absolute),
            (false, true) => Some(Enum::Relative),
            (false, false) => None,
        };

        self.send(build::volume_availability(available, capabilities));
        self.send(build::volume_capabilities_changed(available, capabilities));
    }

    /// `FakeMrpState.default_supported_commands` (`mrp.py:309-321`).
    pub fn default_supported_commands(&self, commands: &[Command]) {
        self.send(build::default_supported_commands(
            commands,
            PLAYER_IDENTIFIER,
        ));
    }

    /// `FakeMrpState.set_volume` (`mrp.py:323-333`); out-of-range values are ignored, not clamped.
    pub fn set_volume(&self, volume: f32, device_uid: &str) {
        if !(0.0..=1.0).contains(&volume) {
            return;
        }
        self.lock().volume = volume;
        self.send(build::volume_did_change(volume, device_uid));
    }

    /// `FakeMrpState.add_output_devices` (`mrp.py:335-339`).
    pub fn add_output_devices(&self, devices: &[String]) {
        {
            let mut inner = self.lock();
            for device in devices {
                if !inner.output_devices.contains(device) {
                    inner.output_devices.push(device.clone());
                }
            }
        }
        self.announce_device_info();
    }

    /// `FakeMrpState.remove_output_devices` (`mrp.py:341-344`).
    pub fn remove_output_devices(&self, devices: &[String]) {
        self.lock()
            .output_devices
            .retain(|device| !devices.contains(device));
        self.announce_device_info();
    }

    /// `FakeMrpState.set_output_devices` (`mrp.py:346-348`).
    pub fn set_output_devices(&self, devices: &[String]) {
        self.lock().output_devices = devices.to_vec();
        self.announce_device_info();
    }
}
