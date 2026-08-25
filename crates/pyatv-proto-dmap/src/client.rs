//! `BaseDmapAppleTV`: the shared low-level client every DMAP interface sits on.
//!
//! Port of `pyatv/protocols/dmap/__init__.py:193-243`. It owns the [`DaapRequester`] and the
//! mutable session state — the play-status revision and the most recent response — that
//! [`crate::facade`]'s five interfaces read.

use std::sync::{Arc, Mutex, PoisonError};

use pyatv_core::models::Playing;

use crate::Result;
use crate::daap::DaapRequester;
use crate::parser::{self, DmapEntry};
use crate::playing::build_playing_instance;
use crate::tags::{string_tag, uint8_tag};

/// `_PSU_CMD` (`__init__.py:61`), with `{0}` spelled out.
pub const PSU_CMD: &str = "ctrl-int/1/playstatusupdate?[AUTH]&revision-number=";

/// `_ARTWORK_CMD` (`__init__.py:62`).
pub const ARTWORK_CMD: &str = "ctrl-int/1/nowplayingartwork";

/// `_CTRL_PROMPT_CMD` (`__init__.py:63`).
pub const CTRL_PROMPT_CMD: &str = "ctrl-int/1/controlpromptentry?[AUTH]&prompt-id=0";

/// The mutable state one connection accumulates.
#[derive(Debug, Default, Clone)]
pub struct ClientState {
    /// `playstatus_revision`: the `cmsr` from the last response, used to long-poll for the next.
    pub revision: u64,
    /// `latest_playstatus`: the raw parse tree, which [`crate::facade::features`] queries per field.
    pub latest_playstatus: Option<Vec<DmapEntry>>,
    /// `latest_playing`: the same response as a [`Playing`].
    pub latest_playing: Option<Playing>,
    /// `latest_hash`: `latest_playing.hash`, which `artwork_id` returns.
    pub latest_hash: Option<String>,
}

/// Talks DAAP to one device and remembers what it last said.
#[derive(Debug)]
pub struct BaseDmapAppleTV {
    daap: Arc<DaapRequester>,
    state: Mutex<ClientState>,
}

impl BaseDmapAppleTV {
    /// Wrap a requester.
    #[must_use]
    pub fn new(daap: Arc<DaapRequester>) -> Self {
        Self {
            daap,
            state: Mutex::new(ClientState::default()),
        }
    }

    /// The underlying requester, for the connect path's initial `login`.
    #[must_use]
    pub fn requester(&self) -> &Arc<DaapRequester> {
        &self.daap
    }

    /// A snapshot of the session state.
    #[must_use]
    pub fn state(&self) -> ClientState {
        self.locked().clone()
    }

    /// Force the next [`Self::playstatus`] with `use_revision` to ask from revision zero.
    ///
    /// `self._atv.playstatus_revision = 0`, which the push updater does on every `start` and again
    /// after any error that is not a hard connection loss (`__init__.py:476-478,519-522`). Zero is
    /// what makes the device answer immediately instead of holding the request open.
    pub fn reset_revision(&self) {
        self.locked().revision = 0;
    }

    /// `playstatus` (`__init__.py:204-218`).
    ///
    /// With `use_revision` set, the request carries the last `cmsr` and the device **holds the
    /// connection open** until playback state changes — that long poll is DMAP's entire push
    /// mechanism, and it is why this client applies no read timeout (see [`crate::http`]).
    ///
    /// # Errors
    ///
    /// Anything [`DaapRequester::get_daap`] or [`build_playing_instance`] can return.
    pub async fn playstatus(&self, use_revision: bool) -> Result<Playing> {
        let revision = if use_revision {
            self.locked().revision
        } else {
            0
        };
        let response = self.daap.get_daap(&format!("{PSU_CMD}{revision}")).await?;

        let playing = build_playing_instance(&response)?;

        let mut state = self.locked();
        // **Divergence:** upstream assigns `parser.first(resp, "cmst", "cmsr")` straight through,
        // so a response without a `cmsr` sets the revision to `None` and the *next* request goes
        // out as `revision-number=None`, which no device can parse. Treating a missing revision as
        // zero is the same thing pyatv's own error path does deliberately: ask for current state.
        state.revision = parser::first_uint(&response, &["cmst", "cmsr"]).unwrap_or(0);
        state.latest_hash.clone_from(&playing.hash);
        state.latest_playing = Some(playing.clone());
        state.latest_playstatus = Some(response);

        Ok(playing)
    }

    /// `artwork` (`__init__.py:220-226`): the raw image bytes, or `None` when there are none.
    ///
    /// Absent dimensions are sent as `0`, which is how the device is asked for its default size.
    /// The response is *not* DMAP — it is a PNG — so it is fetched with `daap_data=False` and never
    /// goes near the parser. An empty body means "no artwork", not an error.
    ///
    /// # Errors
    ///
    /// Anything [`DaapRequester::get`] can return.
    pub async fn artwork(
        &self,
        width: Option<u32>,
        height: Option<u32>,
    ) -> Result<Option<Vec<u8>>> {
        let command = format!(
            "{ARTWORK_CMD}?mw={}&mh={}&[AUTH]",
            width.unwrap_or(0),
            height.unwrap_or(0)
        );
        let body = self.daap.get(&command).await?;
        Ok(if body.is_empty() { None } else { Some(body) })
    }

    /// `ctrl_int_cmd` (`__init__.py:228-230`): the one-word transport and volume commands.
    ///
    /// # Errors
    ///
    /// Anything [`DaapRequester::post`] can return, including `Error::NotSupported` when the
    /// device answers 500 because the command makes no sense in its current state.
    pub async fn ctrl_int_cmd(&self, command: &str) -> Result<()> {
        self.daap
            .post(&format!("ctrl-int/1/{command}?[AUTH]&prompt-id=0"), None)
            .await
            .map(|_| ())
    }

    /// `controlprompt_cmd` (`__init__.py:232-235`): `cmbe` carries the command word, `cmcc` is
    /// `0x00`.
    ///
    /// Note the tag order — `cmbe` then `cmcc` — which is the *opposite* of what the D-pad gesture
    /// in [`crate::facade::remote`] sends. Both orders are upstream's and both are wire-visible.
    ///
    /// # Errors
    ///
    /// See [`Self::ctrl_int_cmd`].
    pub async fn controlprompt_cmd(&self, command: &str) -> Result<()> {
        let data = [string_tag("cmbe", command), uint8_tag("cmcc", 0)].concat();
        self.controlprompt_data(&data).await
    }

    /// `controlprompt_data` (`__init__.py:237-239`): the same endpoint with a caller-built body.
    ///
    /// # Errors
    ///
    /// See [`Self::ctrl_int_cmd`].
    pub async fn controlprompt_data(&self, data: &[u8]) -> Result<()> {
        self.daap
            .post(CTRL_PROMPT_CMD, Some(data))
            .await
            .map(|_| ())
    }

    /// `set_property` (`__init__.py:241-243`): `dacp.playingtime`, `dacp.shufflestate` or
    /// `dacp.repeatstate`.
    ///
    /// The property goes in the query string *before* `[AUTH]`, so the resulting URL reads
    /// `setproperty?dacp.playingtime=45000&session-id=...`.
    ///
    /// # Errors
    ///
    /// See [`Self::ctrl_int_cmd`].
    pub async fn set_property(&self, property: &str, value: i64) -> Result<()> {
        self.daap
            .post(
                &format!("ctrl-int/1/setproperty?{property}={value}&[AUTH]"),
                None,
            )
            .await
            .map(|_| ())
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, ClientState> {
        // A poisoned lock means a previous caller panicked mid-update. The state it left is a
        // stale snapshot, not a safety problem, and refusing to serve playback state because of it
        // would turn one panic into a permanently dead connection.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::{ARTWORK_CMD, CTRL_PROMPT_CMD, PSU_CMD};

    /// The command templates, spelled out as upstream writes them (`__init__.py:61-63`).
    #[test]
    fn the_command_templates_match_upstream() {
        assert_eq!(
            format!("{PSU_CMD}0"),
            "ctrl-int/1/playstatusupdate?[AUTH]&revision-number=0"
        );
        assert_eq!(
            format!("{ARTWORK_CMD}?mw=0&mh=0&[AUTH]"),
            "ctrl-int/1/nowplayingartwork?mw=0&mh=0&[AUTH]"
        );
        assert_eq!(
            CTRL_PROMPT_CMD,
            "ctrl-int/1/controlpromptentry?[AUTH]&prompt-id=0"
        );
    }
}
