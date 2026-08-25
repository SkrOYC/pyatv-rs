//! The shared observation every MRP facade reads from.
//!
//! pyatv spreads this across four objects that each register their own callbacks on the protocol's
//! `MessageDispatcher`: `PlayerStateManager`, `MrpPower`, `MrpAudio` and `MrpPushUpdater`
//! (`pyatv/protocols/mrp/player_state.py:197-209`, `__init__.py:642-645,785-800,711-714`). Here
//! there is one shared object instead, updated by the protocol actor as messages arrive and read by
//! the facades. The observable behaviour is the same; a dispatcher registry whose only purpose is
//! to fan one message out to four fixed listeners buys nothing in Rust.
//!
//! Nothing in this module performs I/O. [`MrpState::handle`] is a pure state transition plus
//! listener notifications, which is what lets the player-state and push-update rules be tested
//! without a socket.

mod notify;
pub mod power;
pub mod volume;

use std::sync::{Arc, Mutex, Weak};

use pyatv_core::consts::PowerState;
use pyatv_core::facade::StateDispatcher;
use pyatv_core::interface::{PlaybackListener, PowerListener};
use pyatv_core::models::{App, Playing};
use tokio::sync::{Notify, mpsc, watch};
use tokio::task::JoinHandle;

use crate::Result;
use crate::message::MrpMessage;
use crate::player_state::{ActivePlayer, Changed, PlayerStateManager};
use crate::playing::build_playing;
use crate::protobuf::{DeviceInfoMessage, extensions, protocol_message::Type};
use crate::state::notify::Notification;
use crate::state::volume::VolumeState;

/// The registered push-update listener, and whether updates are flowing.
///
/// **One slot, held weakly.** `PlayerStateManager.listener` is a single `weakref.ref` that a
/// second registration replaces and that yields `None` once the caller drops its own reference
/// (`pyatv/protocols/mrp/player_state.py:229-235`); `PushUpdater.listener` upstream is the same
/// property. A `Vec<Arc<dyn PlaybackListener>>` diverged from that twice over — two registrations
/// delivered every update twice, and a caller that dropped its listener kept receiving updates,
/// because the `Arc` in the list was the thing keeping it alive.
#[derive(Debug, Default)]
struct PushState {
    listener: Option<Weak<dyn PlaybackListener>>,
    active: bool,
}

/// The listener slots, shared with the notifier task.
///
/// Split out of [`MrpState`] so the notifier needs no reference to the state at all: there is no
/// `Arc` cycle to break with a `Weak`, and a queued callback cannot keep a finished session alive.
#[derive(Debug, Default)]
struct Listeners {
    push: Mutex<PushState>,
    power: Mutex<Option<Arc<dyn PowerListener>>>,
    /// Where volume and output-device changes are reported.
    ///
    /// `MrpAudio.state_dispatcher` (`__init__.py:750-754`), which upstream dispatches
    /// `UpdatedState.Volume`, `UpdatedState.OutputDeviceVolume` and `UpdatedState.OutputDevices`
    /// into so the facade can turn them into `AudioListener` callbacks.
    state: Mutex<Option<Arc<dyn StateDispatcher>>>,
}

impl Listeners {
    /// The push listener, if one is registered and its owner still holds it.
    ///
    /// Prunes the slot on the way past when the caller has dropped its `Arc`, so a stale `Weak`
    /// is not re-upgraded on every subsequent update.
    fn push_listener(&self) -> Option<Arc<dyn PlaybackListener>> {
        let mut push = self.push.lock().ok()?;
        let listener = push.listener.as_ref().and_then(Weak::upgrade);
        if listener.is_none() {
            push.listener = None;
        }
        listener
    }

    /// The power listener, if one is registered.
    fn power_listener(&self) -> Option<Arc<dyn PowerListener>> {
        self.power.lock().ok()?.clone()
    }

    /// The state dispatcher, if one was supplied at setup.
    fn state_dispatcher(&self) -> Option<Arc<dyn StateDispatcher>> {
        self.state.lock().ok()?.clone()
    }
}

/// Everything the device has told us, shared between the protocol actor and the facades.
#[derive(Debug)]
pub struct MrpState {
    players: Mutex<PlayerStateManager>,
    /// The device's own `DeviceInfoMessage`, refreshed on every update
    /// (`__init__.py:642-645,764-770`). Power state and the audio device UID both read it.
    device_info: Mutex<Option<DeviceInfoMessage>>,
    volume: Mutex<VolumeState>,
    /// Fired on every `VOLUME_DID_CHANGE_MESSAGE`, the only confirmation a volume change gets.
    volume_changed: Notify,
    /// Fired whenever a `DeviceInfoMessage` re-derives the output device list.
    output_devices_changed: Notify,
    power: watch::Sender<PowerState>,
    listeners: Arc<Listeners>,
    /// Where callbacks are queued for the notifier task; see [`notify`].
    notifications: mpsc::Sender<Notification>,
    /// The other end, until [`MrpState::start_notifier`] takes it.
    inbox: Mutex<Option<mpsc::Receiver<Notification>>>,
}

impl Default for MrpState {
    fn default() -> Self {
        Self::new()
    }
}

impl MrpState {
    /// A state that has heard nothing yet.
    ///
    /// Callbacks queue from this point on but are not delivered until
    /// [`MrpState::start_notifier`] runs, which needs a Tokio runtime and so cannot happen here.
    #[must_use]
    pub fn new() -> Self {
        let (notifications, inbox) = mpsc::channel(notify::QUEUE_DEPTH);

        Self {
            players: Mutex::new(PlayerStateManager::new()),
            device_info: Mutex::new(None),
            volume: Mutex::new(VolumeState::default()),
            volume_changed: Notify::new(),
            output_devices_changed: Notify::new(),
            power: watch::Sender::new(PowerState::Unknown),
            listeners: Arc::new(Listeners::default()),
            notifications,
            inbox: Mutex::new(Some(inbox)),
        }
    }

    /// Start delivering queued callbacks, off whatever task calls into this state.
    ///
    /// Returns `None` if a notifier is already running. Must be called from inside a Tokio
    /// runtime; [`crate::protocol::MrpProtocol::connect`] does it and keeps the handle.
    pub fn start_notifier(&self) -> Option<JoinHandle<()>> {
        let receiver = self.inbox.lock().ok()?.take()?;
        Some(tokio::spawn(notify::run(
            receiver,
            Arc::clone(&self.listeners),
        )))
    }

    /// Queue one callback, dropping it with a log rather than waiting for room.
    ///
    /// See [`notify`] for why backpressure is the wrong answer here.
    fn post(&self, notification: Notification) {
        match self.notifications.try_send(notification) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(dropped)) => tracing::warn!(
                ?dropped,
                depth = notify::QUEUE_DEPTH,
                "dropping an MRP listener callback: the listener is not keeping up"
            ),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                tracing::debug!("the MRP notifier has stopped; dropping a callback");
            }
        }
    }

    /// Deliver everything queued so far on the calling thread.
    ///
    /// Only for tests, which want a deterministic point at which "the callback has happened" is
    /// true instead of a sleep. It runs [`notify::deliver`], the same dispatch the task uses.
    #[cfg(test)]
    pub(crate) fn deliver_pending(&self) {
        let Ok(mut inbox) = self.inbox.lock() else {
            return;
        };
        let Some(receiver) = inbox.as_mut() else {
            return;
        };
        while let Ok(notification) = receiver.try_recv() {
            notify::deliver(&notification, &self.listeners);
        }
    }

    /// Register the listener notified when the device reports a new power state.
    pub fn set_power_listener(&self, listener: Option<Arc<dyn PowerListener>>) {
        if let Ok(mut slot) = self.listeners.power.lock() {
            *slot = listener;
        }
    }

    /// Register where volume and output-device changes are reported.
    pub fn set_state_dispatcher(&self, dispatcher: Option<Arc<dyn StateDispatcher>>) {
        if let Ok(mut slot) = self.listeners.state.lock() {
            *slot = dispatcher;
        }
    }

    /// A snapshot of what the active player is playing.
    ///
    /// `MrpMetadata.playing` (`__init__.py:576-578`). Never fails: an idle device yields a
    /// zero-valued [`Playing`] rather than an error.
    #[must_use]
    pub fn playing(&self) -> Playing {
        self.with_playing(build_playing)
    }

    /// The app that owns the current item (`MrpMetadata.app`, `__init__.py:612-618`).
    ///
    /// `None` when no client is active. The display name falls back to the bundle identifier,
    /// because it is `Optional[str]` upstream and [`App`] requires a name here.
    #[must_use]
    pub fn app(&self) -> Option<App> {
        let players = self.players.lock().ok()?;
        let client = players.client()?;
        Some(App {
            name: client
                .display_name
                .clone()
                .unwrap_or_else(|| client.bundle_identifier.clone()),
            identifier: client.bundle_identifier.clone(),
        })
    }

    /// Read something off the active player, e.g. its `CommandInfo` for a feature check.
    ///
    /// Takes a closure because [`ActivePlayer`] borrows the manager, which is behind a lock;
    /// handing the borrow out would keep the lock alive for the caller's lifetime.
    pub fn with_playing<T: Default>(&self, read: impl FnOnce(ActivePlayer<'_>) -> T) -> T {
        self.players
            .lock()
            .map_or_else(|_| T::default(), |players| read(players.playing()))
    }

    /// The active player's playback state, with the re-derivations in
    /// [`crate::player_state::PlayerState::playback_state`] applied.
    ///
    /// A named accessor rather than a `with_playing` closure because passing the method itself as
    /// a function item does not satisfy the higher-ranked bound the closure form needs, and
    /// wrapping it in `|it| it.playback_state()` at four call sites is worse than one method here.
    #[must_use]
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "taking `ActivePlayer::playback_state` as a function item does not satisfy \
                  `with_playing`'s higher-ranked bound; the closure is what compiles"
    )]
    pub fn playback_state(&self) -> Option<crate::protobuf::playback_state::Enum> {
        self.with_playing(|playing| playing.playback_state())
    }

    /// The active player's device-reported queue index; see
    /// [`crate::player_state::queue_index`].
    #[must_use]
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "as `MrpState::playback_state`: the function-item form does not satisfy the \
                  higher-ranked bound"
    )]
    pub fn location(&self) -> i32 {
        self.with_playing(|playing| playing.location())
    }

    /// The identifier of the item currently playing, which is also
    /// [`pyatv_core::models::Playing::hash`] (`__init__.py:250-252,283`).
    ///
    /// Still exposed separately because `artwork_id` reads it without building a whole snapshot
    /// (`__init__.py:600-610`).
    #[must_use]
    pub fn item_identifier(&self) -> Option<String> {
        self.with_playing(|playing| playing.item_identifier().map(str::to_owned))
    }

    /// The device's last `DeviceInfoMessage`.
    #[must_use]
    pub fn device_info(&self) -> Option<DeviceInfoMessage> {
        self.device_info.lock().ok()?.clone()
    }

    /// Whether push updates are flowing (`MrpPushUpdater.active`, `__init__.py:711-714`).
    #[must_use]
    pub fn push_active(&self) -> bool {
        self.listeners.push.lock().is_ok_and(|push| push.active)
    }

    /// Register the push-update listener, replacing whatever was there.
    ///
    /// The slot is weak: this does **not** keep `listener` alive, and dropping the caller's last
    /// `Arc` unsubscribes. That is upstream's contract (`player_state.py:229-235`) and the only
    /// one that lets a caller stop receiving updates without a matching removal call.
    pub fn set_push_listener(&self, listener: &Arc<dyn PlaybackListener>) {
        if let Ok(mut push) = self.listeners.push.lock() {
            push.listener = Some(Arc::downgrade(listener));
        }
    }

    /// Start or stop forwarding player-state changes to the registered listener.
    pub fn set_push_active(&self, active: bool) {
        if let Ok(mut push) = self.listeners.push.lock() {
            push.active = active;
        }
    }

    /// Queue the current snapshot for the listener, whether or not anything changed.
    ///
    /// `MrpPushUpdater.start` schedules exactly one of these immediately rather than waiting for a
    /// device-originated change (`__init__.py:716-727`). The snapshot is taken **here**, on the
    /// caller's thread, so the listener sees the state as it was when the change happened rather
    /// than whatever it has become by the time the notifier gets to it.
    pub fn post_update(&self) {
        if !self.push_active() {
            return;
        }

        self.post(Notification::Playing(Box::new(self.playing())));
    }

    /// Queue a push-channel failure for the listener.
    ///
    /// `MrpPushUpdater.state_updated`'s exception branch (`__init__.py:736-743`).
    pub fn post_error(&self, error: pyatv_core::Error) {
        self.post(Notification::PlaybackError(error));
    }

    /// Apply one inbound message.
    ///
    /// Message types nothing here observes are ignored, exactly as upstream's dispatcher ignores
    /// anything nobody registered for.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Decode`] if a message this state does handle carries a payload that does
    /// not parse.
    pub fn handle(&self, message: &MrpMessage) -> Result<()> {
        match message.message_type_enum() {
            Some(Type::DeviceInfoMessage | Type::DeviceInfoUpdateMessage) => {
                self.handle_device_info(message)
            }
            Some(Type::VolumeControlAvailabilityMessage) => {
                self.handle_volume_availability(message)
            }
            Some(Type::VolumeControlCapabilitiesDidChangeMessage) => {
                self.handle_volume_capabilities(message)
            }
            Some(Type::VolumeDidChangeMessage) => self.handle_volume_changed(message),
            Some(Type::SetStateMessage) => self.handle_set_state(message),
            Some(Type::UpdateContentItemMessage) => self.handle_content_item_update(message),
            Some(Type::SetNowPlayingClientMessage) => self.handle_set_now_playing_client(message),
            Some(Type::SetNowPlayingPlayerMessage) => self.handle_set_now_playing_player(message),
            Some(Type::UpdateClientMessage) => self.handle_update_client(message),
            Some(Type::RemoveClientMessage) => self.handle_remove_client(message),
            Some(Type::RemovePlayerMessage) => self.handle_remove_player(message),
            Some(Type::SetDefaultSupportedCommandsMessage) => self.handle_default_commands(message),
            _ => Ok(()),
        }
    }

    fn handle_set_state(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::SET_STATE_MESSAGE)?;
        let path = inner.player_path.clone().unwrap_or_default();

        self.mutate(|players| {
            let player = players.player_mut(&path);
            let identifier = player.identifier.clone();
            player.handle_set_state(&inner);
            OwnedChange::player(identifier)
        });
        Ok(())
    }

    fn handle_content_item_update(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::UPDATE_CONTENT_ITEM_MESSAGE)?;
        let path = inner.player_path.clone().unwrap_or_default();

        self.mutate(|players| {
            let player = players.player_mut(&path);
            let identifier = player.identifier.clone();
            player.handle_content_item_update(&inner.content_items);
            OwnedChange::player(identifier)
        });
        Ok(())
    }

    fn handle_set_now_playing_client(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::SET_NOW_PLAYING_CLIENT_MESSAGE)?;
        let client = inner.client.unwrap_or_default();

        self.mutate(|players| {
            players.set_now_playing_client(&client);
            // Scoped to nothing upstream, so it always propagates (`player_state.py:255-260`).
            OwnedChange::always()
        });
        Ok(())
    }

    fn handle_set_now_playing_player(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::SET_NOW_PLAYING_PLAYER_MESSAGE)?;
        let path = inner.player_path.unwrap_or_default();

        self.mutate(|players| OwnedChange::client(players.set_now_playing_player(&path)));
        Ok(())
    }

    fn handle_update_client(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::UPDATE_CLIENT_MESSAGE)?;
        let client = inner.client.unwrap_or_default();

        self.mutate(|players| OwnedChange::client(players.update_client(&client)));
        Ok(())
    }

    fn handle_remove_client(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::REMOVE_CLIENT_MESSAGE)?;
        let client = inner.client.unwrap_or_default();

        self.mutate(|players| {
            if players.remove_client(&client) {
                OwnedChange::always()
            } else {
                OwnedChange::silent()
            }
        });
        Ok(())
    }

    fn handle_remove_player(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::REMOVE_PLAYER_MESSAGE)?;
        let path = inner.player_path.unwrap_or_default();

        self.mutate(|players| {
            players
                .remove_player(&path)
                .map_or_else(OwnedChange::silent, OwnedChange::client)
        });
        Ok(())
    }

    fn handle_default_commands(&self, message: &MrpMessage) -> Result<()> {
        let inner = message.inner(&extensions::SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE)?;
        let path = inner.player_path.unwrap_or_default();
        let commands = inner.supported_commands.unwrap_or_default();

        self.mutate(|players| {
            players.set_default_supported_commands(&path, &commands);
            // Scoped to nothing upstream, so it always propagates (`player_state.py:303-312`).
            OwnedChange::always()
        });
        Ok(())
    }

    /// Mutate the player model, then push an update if the change was in scope.
    ///
    /// The push happens **after** the lock is released, so a listener that reads the state back
    /// cannot deadlock.
    fn mutate(&self, apply: impl FnOnce(&mut PlayerStateManager) -> OwnedChange) {
        let notify = {
            let Ok(mut players) = self.players.lock() else {
                return;
            };
            let changed = apply(&mut players);
            !changed.silent
                && players.should_notify(Changed {
                    client: changed.client.as_deref(),
                    player: changed.player.as_deref(),
                })
        };

        if notify {
            self.post_update();
        }
    }
}

/// A [`Changed`] whose identifiers are owned, so it can outlive the borrow that produced it.
#[derive(Debug, Default)]
struct OwnedChange {
    client: Option<String>,
    player: Option<String>,
    /// Set when the caller determined there is nothing to notify about at all — upstream's
    /// early `return` before `_state_updated` is ever called.
    silent: bool,
}

impl OwnedChange {
    /// A change scoped to one player.
    fn player(identifier: String) -> Self {
        Self {
            player: Some(identifier),
            ..Self::default()
        }
    }

    /// A change scoped to one client.
    fn client(identifier: String) -> Self {
        Self {
            client: Some(identifier),
            ..Self::default()
        }
    }

    /// A change upstream could not scope, which therefore always propagates.
    fn always() -> Self {
        Self::default()
    }

    /// A change that must not propagate.
    fn silent() -> Self {
        Self {
            silent: true,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests;
