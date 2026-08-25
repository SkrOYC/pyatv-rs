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

pub mod power;
pub mod volume;

use std::sync::{Arc, Mutex};

use pyatv_core::consts::PowerState;
use pyatv_core::interface::{PlaybackListener, PowerListener};
use pyatv_core::models::{App, Playing};
use tokio::sync::{Notify, watch};

use crate::Result;
use crate::message::MrpMessage;
use crate::player_state::{ActivePlayer, Changed, PlayerStateManager};
use crate::playing::build_playing;
use crate::protobuf::{DeviceInfoMessage, extensions, protocol_message::Type};
use crate::state::volume::VolumeState;

/// Registered push-update listeners, and whether updates are flowing.
#[derive(Debug, Default)]
struct PushState {
    listeners: Vec<Arc<dyn PlaybackListener>>,
    active: bool,
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
    push: Mutex<PushState>,
    power_listener: Mutex<Option<Arc<dyn PowerListener>>>,
}

impl Default for MrpState {
    fn default() -> Self {
        Self::new()
    }
}

impl MrpState {
    /// A state that has heard nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            players: Mutex::new(PlayerStateManager::new()),
            device_info: Mutex::new(None),
            volume: Mutex::new(VolumeState::default()),
            volume_changed: Notify::new(),
            output_devices_changed: Notify::new(),
            power: watch::Sender::new(PowerState::Unknown),
            push: Mutex::new(PushState::default()),
            power_listener: Mutex::new(None),
        }
    }

    /// Register the listener notified when the device reports a new power state.
    pub fn set_power_listener(&self, listener: Option<Arc<dyn PowerListener>>) {
        if let Ok(mut slot) = self.power_listener.lock() {
            *slot = listener;
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

    /// Index of the playing item within the active player's queue.
    #[must_use]
    #[allow(
        clippy::redundant_closure_for_method_calls,
        reason = "as `MrpState::playback_state`: the function-item form does not satisfy the \
                  higher-ranked bound"
    )]
    pub fn location(&self) -> usize {
        self.with_playing(|playing| playing.location())
    }

    /// The identifier of the item currently playing, which is upstream's `Playing.hash`.
    ///
    /// Exposed separately because [`pyatv_core::models::Playing`] has no `hash` field.
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
        self.push.lock().is_ok_and(|push| push.active)
    }

    /// Register a push-update listener.
    pub fn add_push_listener(&self, listener: Arc<dyn PlaybackListener>) {
        if let Ok(mut push) = self.push.lock() {
            push.listeners.push(listener);
        }
    }

    /// Start or stop forwarding player-state changes to the registered listeners.
    pub fn set_push_active(&self, active: bool) {
        if let Ok(mut push) = self.push.lock() {
            push.active = active;
        }
    }

    /// Push the current snapshot to every listener, whether or not anything changed.
    ///
    /// `MrpPushUpdater.start` schedules exactly one of these immediately rather than waiting for a
    /// device-originated change (`__init__.py:716-727`).
    pub fn post_update(&self) {
        if !self.push_active() {
            return;
        }

        let playing = self.playing();
        let listeners = self
            .push
            .lock()
            .map(|push| push.listeners.clone())
            .unwrap_or_default();

        for listener in listeners {
            listener.playstatus_update(&playing);
        }
    }

    /// Report a push-channel failure to every listener.
    ///
    /// `MrpPushUpdater.state_updated`'s exception branch (`__init__.py:736-743`).
    pub fn post_error(&self, error: &pyatv_core::Error) {
        let listeners = self
            .push
            .lock()
            .map(|push| push.listeners.clone())
            .unwrap_or_default();

        for listener in listeners {
            listener.playstatus_error(error);
        }
    }

    /// Apply one inbound message.
    ///
    /// Message types nothing here observes are ignored, exactly as upstream's dispatcher ignores
    /// anything nobody registered for.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] if a message this state does handle carries a payload that does
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
