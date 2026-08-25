//! Now-playing bookkeeping: clients, players, and the merge rules that keep them current.
//!
//! Port of `pyatv/protocols/mrp/player_state.py`. The model is three levels deep — a
//! [`PlayerStateManager`] owns [`Client`]s keyed by bundle identifier, each of which owns
//! [`PlayerState`]s keyed by player identifier — and every device push updates one node of it.
//!
//! # Two merges that are not replacements
//!
//! * `SET_STATE_MESSAGE` updates only the fields the message actually carries
//!   (`player_state.py:100-111`). A partial `SetStateMessage` is a legitimate incremental update;
//!   treating it as a full-state replacement wipes state the device still considers current.
//! * `UPDATE_CONTENT_ITEM_MESSAGE` protobuf-merges the incoming metadata into the matching item
//!   (`player_state.py:113-124`). Upstream's own comment flags that this **appends** repeated
//!   fields rather than replacing them and is "likely not what is expected". This port replicates
//!   it — see [`PlayerState::handle_content_item_update`] for why.
//!
//! # No parent pointers
//!
//! Upstream's `PlayerState` holds a reference to its `Client` so `command_info` can fall back to
//! the client's defaults. That cycle is not worth reproducing in Rust: [`ActivePlayer`] resolves
//! the player and the client's defaults together, and every read goes through it.

use std::collections::BTreeMap;

use prost::Message as _;

use crate::protobuf::{
    Command, CommandInfo, ContentItem, ContentItemMetadata, NowPlayingClient, NowPlayingPlayer,
    PlayerPath, SetStateMessage, SupportedCommands, playback_state,
};

/// The player identifier a client falls back to when it has not named an active one.
///
/// `DEFAULT_PLAYER_ID` (`player_state.py:14`).
pub const DEFAULT_PLAYER_ID: &str = "MediaRemote-DefaultPlayer";

/// What one media player on the device is doing.
#[derive(Debug, Clone, Default)]
pub struct PlayerState {
    /// Player identifier; empty when the device did not name one.
    pub identifier: String,
    /// Human-readable name, sticky across updates that omit it.
    pub display_name: Option<String>,
    /// Raw `PlaybackState`, before the re-derivation in [`PlayerState::playback_state`].
    raw_playback_state: Option<i32>,
    /// Commands this player reported, before falling back to the client's defaults.
    pub supported_commands: Vec<CommandInfo>,
    /// The playback queue.
    pub items: Vec<ContentItem>,
    /// Index into [`PlayerState::items`] of the item actually playing.
    pub location: usize,
}

impl PlayerState {
    /// Build from a `NowPlayingPlayer`.
    #[must_use]
    pub fn new(player: &NowPlayingPlayer) -> Self {
        let mut state = Self {
            identifier: player.identifier.clone().unwrap_or_default(),
            ..Self::default()
        };
        state.update(player);
        state
    }

    /// Whether the device gave this player a usable identifier (`player_state.py:32-35`).
    #[must_use]
    pub fn is_valid(&self) -> bool {
        !self.identifier.is_empty()
    }

    /// Refresh the display name, keeping the old one when the update omits it.
    ///
    /// `self.display_name = player.displayName or self.display_name` (`player_state.py:37-39`) —
    /// an empty string counts as "omitted", which is what proto2 reports for an unset field.
    pub fn update(&mut self, player: &NowPlayingPlayer) {
        if let Some(name) = player.display_name.as_deref().filter(|it| !it.is_empty()) {
            self.display_name = Some(name.to_owned());
        }
    }

    /// Metadata of the item at [`PlayerState::location`], if the queue reaches that far.
    #[must_use]
    pub fn metadata(&self) -> Option<&ContentItemMetadata> {
        self.items.get(self.location)?.metadata.as_ref()
    }

    /// Identifier of the item at [`PlayerState::location`] (`player_state.py:76-81`).
    #[must_use]
    pub fn item_identifier(&self) -> Option<&str> {
        self.items.get(self.location)?.identifier.as_deref()
    }

    /// Playback state with upstream's two re-derivations applied (`player_state.py:41-70`).
    ///
    /// 1. `Paused` with nothing in the queue means *idle*, not paused, so it reports `None`.
    /// 2. `Playing` is disambiguated by `playbackRate`: rate 0 or 1 stays `Playing`, anything else
    ///    is `Seeking`. Note the dead branch upstream — the `rate == 0` case checks whether the
    ///    state is `Playing`, which it always is by then — reproduced here as the same outcome
    ///    without the unreachable arm.
    #[must_use]
    pub fn playback_state(&self) -> Option<playback_state::Enum> {
        let raw = playback_state::Enum::try_from(self.raw_playback_state?).ok()?;

        if raw == playback_state::Enum::Paused {
            return self.metadata().map(|_| playback_state::Enum::Paused);
        }
        if raw != playback_state::Enum::Playing {
            return Some(raw);
        }

        let Some(rate) = self.metadata().and_then(|it| it.playback_rate) else {
            return Some(raw);
        };
        if is_close(rate, 0.0) || is_close(rate, 1.0) {
            Some(playback_state::Enum::Playing)
        } else {
            Some(playback_state::Enum::Seeking)
        }
    }

    /// Apply a `SET_STATE_MESSAGE`, updating only the fields it carries.
    pub fn handle_set_state(&mut self, message: &SetStateMessage) {
        if let Some(state) = message.playback_state {
            self.raw_playback_state = Some(state);
        }
        if let Some(SupportedCommands { supported_commands }) = message.supported_commands.as_ref()
        {
            self.supported_commands.clone_from(supported_commands);
        }
        if let Some(queue) = message.playback_queue.as_ref() {
            self.items.clone_from(&queue.content_items);
            self.location = usize::try_from(queue.location.unwrap_or_default()).unwrap_or_default();
        }
    }

    /// Apply an `UPDATE_CONTENT_ITEM_MESSAGE` by protobuf-merging matched items.
    ///
    /// The merge is done by re-encoding the incoming metadata and calling `prost`'s
    /// [`prost::Message::merge`], which implements the same semantics as Python's `MergeFrom`:
    /// present scalars overwrite, repeated fields **append**. Upstream flags the appending as
    /// probably wrong (`player_state.py:118-121`) and has shipped it unchanged; this port keeps
    /// it, because "the same observable state as pyatv" is the contract, and a divergence here
    /// would show up as a metadata difference nobody could trace back to a deliberate decision.
    pub fn handle_content_item_update(&mut self, updates: &[ContentItem]) {
        for update in updates {
            let Some(metadata) = update.metadata.as_ref() else {
                continue;
            };
            for existing in &mut self.items {
                if existing.identifier == update.identifier {
                    let encoded = metadata.encode_to_vec();
                    let target = existing.metadata.get_or_insert_with(Default::default);
                    // Infallible: the buffer was produced by `prost` a line ago.
                    if let Err(error) = target.merge(encoded.as_slice()) {
                        tracing::warn!(%error, "could not merge a content item update");
                    }
                }
            }
        }
    }
}

/// One MRP media player client, i.e. an app.
#[derive(Debug, Clone, Default)]
pub struct Client {
    /// Bundle identifier, the key this client is filed under.
    pub bundle_identifier: String,
    /// Display name, sticky across updates that omit it.
    pub display_name: Option<String>,
    /// Commands the client declared as defaults for players that do not report their own.
    pub supported_commands: Vec<CommandInfo>,
    active_player: Option<String>,
    players: BTreeMap<String, PlayerState>,
}

impl Client {
    /// Build from a `NowPlayingClient`.
    #[must_use]
    pub fn new(client: &NowPlayingClient) -> Self {
        let mut state = Self {
            bundle_identifier: client.bundle_identifier.clone().unwrap_or_default(),
            ..Self::default()
        };
        state.update(client);
        state
    }

    /// Refresh the display name, keeping the old one when the update omits it.
    pub fn update(&mut self, client: &NowPlayingClient) {
        if let Some(name) = client.display_name.as_deref().filter(|it| !it.is_empty()) {
            self.display_name = Some(name.to_owned());
        }
    }

    /// The identifier of the player upstream's `active_player` property would resolve to.
    ///
    /// `player_state.py:143-150`: the explicitly-active player, else [`DEFAULT_PLAYER_ID`] if this
    /// client has one, else nothing — in which case callers see an empty [`ActivePlayer`].
    #[must_use]
    pub fn active_player_id(&self) -> Option<&str> {
        match self.active_player.as_deref() {
            Some(identifier) => Some(identifier),
            None => self
                .players
                .contains_key(DEFAULT_PLAYER_ID)
                .then_some(DEFAULT_PLAYER_ID),
        }
    }

    /// The active player and this client's default commands, resolved together.
    #[must_use]
    pub fn active_player(&self) -> ActivePlayer<'_> {
        ActivePlayer {
            player: self.active_player_id().and_then(|id| self.players.get(id)),
            defaults: &self.supported_commands,
        }
    }

    /// Get or create the state for a player (`player_state.py:157-161`).
    pub fn player_mut(&mut self, player: &NowPlayingPlayer) -> &mut PlayerState {
        let identifier = player.identifier.clone().unwrap_or_default();
        self.players
            .entry(identifier)
            .or_insert_with(|| PlayerState::new(player))
    }

    /// Every player this client has reported, for diagnostics and tests.
    #[must_use]
    pub fn players(&self) -> &BTreeMap<String, PlayerState> {
        &self.players
    }
}

/// The active player resolved against its client's defaults.
///
/// Never `None`: upstream's `PlayerStateManager.playing` always yields *some* `PlayerState`, just
/// possibly an empty throwaway one (`player_state.py:242-247`), and every derived value has a
/// defined answer for the empty case.
#[derive(Debug, Clone, Copy, Default)]
pub struct ActivePlayer<'a> {
    player: Option<&'a PlayerState>,
    defaults: &'a [CommandInfo],
}

impl<'a> ActivePlayer<'a> {
    /// The underlying player, if one is active at all.
    #[must_use]
    pub const fn player(self) -> Option<&'a PlayerState> {
        self.player
    }

    /// The active player's identifier, or the empty string when there is none.
    #[must_use]
    pub fn identifier(self) -> &'a str {
        self.player.map_or("", |it| it.identifier.as_str())
    }

    /// Index of the playing item within the queue.
    #[must_use]
    pub fn location(self) -> usize {
        self.player.map_or(0, |it| it.location)
    }

    /// Metadata of the item currently playing.
    #[must_use]
    pub fn metadata(self) -> Option<&'a ContentItemMetadata> {
        self.player?.metadata()
    }

    /// Identifier of the item currently playing.
    #[must_use]
    pub fn item_identifier(self) -> Option<&'a str> {
        self.player?.item_identifier()
    }

    /// Playback state, with upstream's re-derivations applied.
    #[must_use]
    pub fn playback_state(self) -> Option<playback_state::Enum> {
        self.player?.playback_state()
    }

    /// Command info for `command`, the player's own entry preferred over the client's default.
    ///
    /// `command_info` (`player_state.py:93-98`) chains the two lists in that order. This two-level
    /// fallback is how a feature the current player never mentioned can still report as available
    /// because the client declared it in `SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE`.
    #[must_use]
    pub fn command_info(self, command: Command) -> Option<&'a CommandInfo> {
        let own = self
            .player
            .map_or(&[][..], |it| it.supported_commands.as_slice());
        own.iter()
            .chain(self.defaults.iter())
            .find(|info| info.command == Some(command as i32))
    }
}

/// Which node a state change touched, so [`PlayerStateManager`] can decide whether to notify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Changed<'a> {
    /// Bundle identifier of the client that changed, when the caller could name one.
    pub client: Option<&'a str>,
    /// Identifier of the player that changed, when the caller could name one.
    pub player: Option<&'a str>,
}

/// Every media player the device has told us about.
#[derive(Debug, Clone, Default)]
pub struct PlayerStateManager {
    clients: BTreeMap<String, Client>,
    active_client: Option<String>,
}

impl PlayerStateManager {
    /// An empty manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The currently active client, if the device has named one.
    #[must_use]
    pub fn client(&self) -> Option<&Client> {
        self.clients.get(self.active_client.as_deref()?)
    }

    /// The active client's active player (`player_state.py:242-247`).
    #[must_use]
    pub fn playing(&self) -> ActivePlayer<'_> {
        self.client().map(Client::active_player).unwrap_or_default()
    }

    /// Get or create a client (`player_state.py:211-216`).
    pub fn client_mut(&mut self, client: &NowPlayingClient) -> &mut Client {
        let bundle = client.bundle_identifier.clone().unwrap_or_default();
        self.clients
            .entry(bundle)
            .or_insert_with(|| Client::new(client))
    }

    /// Get or create the player a `PlayerPath` names, creating the client too if needed.
    pub fn player_mut(&mut self, path: &PlayerPath) -> &mut PlayerState {
        let client = path.client.clone().unwrap_or_default();
        let player = path.player.clone().unwrap_or_default();
        self.client_mut(&client).player_mut(&player)
    }

    /// Whether a change to `changed` should be pushed to listeners.
    ///
    /// `_state_updated` (`player_state.py:320-327`), reproduced including its quirk: when the
    /// caller names neither node the change always propagates, **and** a `None` client compares
    /// equal to "no active client", so a scoped change on a device with no active client also
    /// propagates. Both fall out of Python's `==` on `None`; neither is obviously intended, and
    /// both are observable as extra push updates, so they are kept rather than tidied.
    #[must_use]
    pub fn should_notify(&self, changed: Changed<'_>) -> bool {
        let is_active_client = changed.client == self.active_client.as_deref();
        let is_active_player =
            changed.player.is_some() && changed.player == Some(self.playing().identifier());
        let is_always = changed.client.is_none() && changed.player.is_none();

        is_active_client || is_active_player || is_always
    }

    /// `SET_NOW_PLAYING_CLIENT_MESSAGE` (`player_state.py:262-268`).
    pub fn set_now_playing_client(&mut self, client: &NowPlayingClient) {
        let bundle = self.client_mut(client).bundle_identifier.clone();
        self.active_client = Some(bundle);
    }

    /// `SET_NOW_PLAYING_PLAYER_MESSAGE` (`player_state.py:270-276`).
    pub fn set_now_playing_player(&mut self, path: &PlayerPath) -> String {
        let player = path.player.clone().unwrap_or_default();
        let client = self.client_mut(&path.client.clone().unwrap_or_default());
        let identifier = client.player_mut(&player).identifier.clone();
        client.active_player = Some(identifier);
        client.bundle_identifier.clone()
    }

    /// `SET_DEFAULT_SUPPORTED_COMMANDS_MESSAGE` — a full replacement, not a merge
    /// (`player_state.py:163-165`).
    pub fn set_default_supported_commands(
        &mut self,
        path: &PlayerPath,
        commands: &SupportedCommands,
    ) {
        let client = self.client_mut(&path.client.clone().unwrap_or_default());
        client
            .supported_commands
            .clone_from(&commands.supported_commands);
    }

    /// `UPDATE_CLIENT_MESSAGE` (`player_state.py:314-318`).
    pub fn update_client(&mut self, client: &NowPlayingClient) -> String {
        let target = self.client_mut(client);
        target.update(client);
        target.bundle_identifier.clone()
    }

    /// `REMOVE_CLIENT_MESSAGE` (`player_state.py:278-288`).
    ///
    /// Returns whether the removed client was the active one, which is the only case upstream
    /// notifies for.
    pub fn remove_client(&mut self, client: &NowPlayingClient) -> bool {
        let bundle = client.bundle_identifier.clone().unwrap_or_default();
        if self.clients.remove(&bundle).is_none() {
            return false;
        }
        if self.active_client.as_deref() == Some(bundle.as_str()) {
            self.active_client = None;
            return true;
        }
        false
    }

    /// `REMOVE_PLAYER_MESSAGE` (`player_state.py:290-301`).
    ///
    /// Returns the bundle identifier to notify for, when the removed player was that client's
    /// active one.
    pub fn remove_player(&mut self, path: &PlayerPath) -> Option<String> {
        let identifier = path.player.as_ref()?.identifier.clone().unwrap_or_default();
        if identifier.is_empty() {
            return None;
        }

        let client = self.client_mut(&path.client.clone().unwrap_or_default());
        client.players.remove(&identifier);

        if client.active_player_id() == Some(identifier.as_str())
            || client.active_player.as_deref() == Some(identifier.as_str())
        {
            client.active_player = None;
            return Some(client.bundle_identifier.clone());
        }
        None
    }

    /// Every known client, for diagnostics and tests.
    #[must_use]
    pub fn clients(&self) -> &BTreeMap<String, Client> {
        &self.clients
    }
}

/// Python's `math.isclose` with its default tolerances (`rel_tol=1e-09`, `abs_tol=0.0`).
///
/// Spelled out rather than approximated with an epsilon comparison because the `rate == 0.0` case
/// depends on the exact semantics: with `abs_tol=0.0`, only a literal zero is "close to" zero.
fn is_close(a: f32, b: f32) -> bool {
    const REL_TOL: f64 = 1e-9;
    let (a, b) = (f64::from(a), f64::from(b));
    (a - b).abs() <= REL_TOL * a.abs().max(b.abs())
}

#[cfg(test)]
mod tests;
