//! The fake device's mutable state, and the use-case DSL tests drive it with.
//!
//! Mirrors `FakeDmapState` and `FakeDmapUseCases` (`tests/fake_device/dmap.py:60-107,332-448`).

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use pyatv_core::consts::{RepeatState, ShuffleState};

/// The session id upstream's fixture hands out (`test_dmap_functional.py:29`).
pub const SESSION_ID: u32 = 55_555;

/// The Home Sharing GUID upstream's fixture logs in with (`test_dmap_functional.py:27`).
pub const HSGID: &str = "12345678-6789-1111-2222-012345678911";

/// The pairing GUID upstream's fixture logs in with (`test_dmap_functional.py:28`).
pub const PAIRING_GUID: &str = "0x0000000000000001";

/// `cmmk` for music (`dmap.py:418-432`), which maps to [`MediaType::Music`].
///
/// [`MediaType::Music`]: pyatv_core::consts::MediaType::Music
pub const MEDIA_KIND_MUSIC: u32 = 2;

/// `cmmk` for video (`dmap.py:383-405`), which maps to [`MediaType::Video`].
///
/// [`MediaType::Video`]: pyatv_core::consts::MediaType::Video
pub const MEDIA_KIND_VIDEO: u32 = 3;

/// What `playstatusupdate` should answer with.
///
/// `PlayingResponse` (`tests/fake_device/dmap.py:37-57`). Every field is optional and an absent one
/// means the corresponding tag is simply not emitted, which is how a real device signals "I have
/// nothing to say about this".
#[derive(Debug, Clone, Default)]
pub struct PlayingResponse {
    /// Revision this response is valid for. A request asking for a different one gets a 500.
    pub revision: u32,
    /// `caps` via the paused/playing shortcut.
    pub paused: Option<bool>,
    /// `caps` from a playback rate, dispatched the way upstream's `math.isclose` chain does.
    pub playback_rate: Option<f64>,
    /// `caps` as a raw play-state integer.
    pub playstatus: Option<u32>,
    /// `cann`.
    pub title: Option<String>,
    /// `cana`.
    pub artist: Option<String>,
    /// `canl`.
    pub album: Option<String>,
    /// `cang`.
    pub genre: Option<String>,
    /// `cast`, in seconds; emitted as milliseconds.
    pub total_time: Option<u32>,
    /// Position in seconds; emitted as `cant`, the time *remaining*.
    pub position: Option<u32>,
    /// `cmmk`.
    pub media_kind: Option<u32>,
    /// `carp`.
    pub repeat: Option<RepeatState>,
    /// `cash`.
    pub shuffle: Option<ShuffleState>,
    /// Close the connection mid-request instead of answering, to simulate a hard drop.
    pub force_close: bool,
    /// Body of the artwork response.
    pub artwork: Option<Vec<u8>>,
    /// Status of the artwork response.
    pub artwork_status: Option<u16>,
}

/// Everything the fake device remembers.
#[derive(Debug)]
pub struct FakeDmapState {
    /// The Home Sharing id a login may present.
    pub hsgid: String,
    /// The pairing GUID a login may present.
    pub pairing_guid: String,
    /// What the next login hands out, and with what status.
    pub login_response: (u32, u16),
    /// The session id currently considered valid, or `None` before any login.
    pub session: Option<u32>,
    /// What `playstatusupdate` answers with.
    pub playing: PlayingResponse,
    /// `cavc`. `None` suppresses the tag entirely.
    pub volume_controls: Option<bool>,
    /// The last button the device saw, already translated from a gesture where applicable.
    pub last_button_pressed: Option<String>,
    /// How many control-prompt or playback POSTs have arrived, which is how a seven-step drag is
    /// recognised.
    pub buttons_press_count: u32,
    /// `mw` from the last artwork request.
    pub last_artwork_width: Option<u32>,
    /// `mh` from the last artwork request.
    pub last_artwork_height: Option<u32>,
    /// Every `setproperty` seen, as `(property, value)`.
    pub properties_set: Vec<(String, String)>,
    /// Every request path the device answered, in order.
    pub requests: Vec<String>,
    /// Client mistakes: a missing header, a bad credential, or a stale session id.
    ///
    /// Collected rather than asserted, because an assertion inside the server task would be an
    /// invisible panic. Tests assert this is empty.
    pub protocol_errors: Vec<String>,
}

impl Default for FakeDmapState {
    fn default() -> Self {
        Self {
            hsgid: HSGID.to_owned(),
            pairing_guid: PAIRING_GUID.to_owned(),
            login_response: (SESSION_ID, 200),
            session: None,
            playing: PlayingResponse::default(),
            // Upstream's fixture starts at `False`, so `cavc` is emitted as zero rather than
            // omitted (`tests/fake_device/dmap.py:71`).
            volume_controls: Some(false),
            last_button_pressed: None,
            buttons_press_count: 0,
            last_artwork_width: None,
            last_artwork_height: None,
            properties_set: Vec::new(),
            requests: Vec::new(),
            protocol_errors: Vec::new(),
        }
    }
}

/// A handle onto a running fake device's state.
#[derive(Debug, Clone)]
pub struct FakeDmapUseCases {
    state: Arc<Mutex<FakeDmapState>>,
}

impl FakeDmapUseCases {
    /// Wrap shared state.
    pub fn new(state: Arc<Mutex<FakeDmapState>>) -> Self {
        Self { state }
    }

    /// Read or write the state directly.
    pub fn state(&self) -> MutexGuard<'_, FakeDmapState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Assert the client made no protocol mistakes, and say which if it did.
    ///
    /// This is `_verify_headers`/`_verify_auth_parameters` (`tests/fake_device/dmap.py:302-329`)
    /// turned from an assertion inside the server into one a test makes deliberately.
    pub fn assert_no_protocol_errors(&self) {
        let errors = self.state().protocol_errors.clone();
        assert!(errors.is_empty(), "client protocol errors: {errors:?}");
    }

    /// `change_volume_control` (`dmap.py:342-344`).
    pub fn change_volume_control(&self, available: Option<bool>) {
        self.state().volume_controls = available;
    }

    /// `force_relogin` (`dmap.py:346-348`), plus the session invalidation upstream omits.
    ///
    /// See the module documentation on [`super`]: invalidating the current session here is what
    /// makes the client actually notice it has been logged out.
    pub fn force_relogin(&self, session: u32) {
        let mut state = self.state();
        state.login_response = (session, 200);
        state.session = None;
    }

    /// `make_login_fail` (`dmap.py:350-352`): the next login answers 503.
    pub fn make_login_fail(&self) {
        self.state().login_response = (0, 503);
    }

    /// `change_artwork` (`dmap.py:354-359`).
    pub fn change_artwork(&self, artwork: &[u8]) {
        let mut state = self.state();
        state.playing.artwork = Some(artwork.to_vec());
        state.playing.artwork_status = Some(200);
    }

    /// `artwork_no_permission` (`dmap.py:361-367`): artwork answers 403, as if logged out.
    pub fn artwork_no_permission(&self) {
        let mut state = self.state();
        state.playing.artwork = None;
        state.playing.artwork_status = Some(403);
    }

    /// `nothing_playing` (`dmap.py:369-371`).
    pub fn nothing_playing(&self) {
        self.state().playing = PlayingResponse::default();
    }

    /// `server_closes_connection` (`dmap.py:373-375`).
    pub fn server_closes_connection(&self) {
        self.state().playing = PlayingResponse {
            force_close: true,
            ..PlayingResponse::default()
        };
    }

    /// `media_is_loading` (`dmap.py:434-436`).
    pub fn media_is_loading(&self) {
        self.state().playing = PlayingResponse {
            playstatus: Some(1),
            ..PlayingResponse::default()
        };
    }

    /// `example_video()` with no overrides (`dmap.py:377-381`).
    ///
    /// Upstream takes `**kwargs` and merges; here the caller writes
    /// `video_playing(PlayingResponse { revision: 1, ..PlayingResponse::example_video() })`, which
    /// is the same thing with the merge done by the compiler.
    pub fn example_video(&self) {
        self.video_playing(PlayingResponse::example_video());
    }

    /// `video_playing` (`dmap.py:383-405`): media kind 3, plus whatever the caller set.
    pub fn video_playing(&self, playing: PlayingResponse) {
        self.state().playing = PlayingResponse {
            media_kind: Some(MEDIA_KIND_VIDEO),
            ..playing
        };
    }

    /// `example_music()` with no overrides (`dmap.py:407-416`).
    pub fn example_music(&self) {
        self.music_playing(PlayingResponse::example_music());
    }

    /// `music_playing` (`dmap.py:418-432`): media kind 2, plus whatever the caller set.
    pub fn music_playing(&self, playing: PlayingResponse) {
        self.state().playing = PlayingResponse {
            media_kind: Some(MEDIA_KIND_MUSIC),
            ..playing
        };
    }

    /// The last button the device saw, gestures already translated.
    pub fn last_button_pressed(&self) -> Option<String> {
        self.state().last_button_pressed.clone()
    }

    /// Every `setproperty` the device saw.
    pub fn properties_set(&self) -> Vec<(String, String)> {
        self.state().properties_set.clone()
    }

    /// Every request path the device answered.
    pub fn requests(&self) -> Vec<String> {
        self.state().requests.clone()
    }
}

impl PlayingResponse {
    /// The video upstream's `example_video` describes: paused, `"dummy"`, 123 seconds long and 3
    /// seconds in (`dmap.py:377-381`).
    ///
    /// Media kind is deliberately left unset here and stamped on by
    /// [`FakeDmapUseCases::video_playing`], so a caller cannot accidentally override it with
    /// struct-update syntax the way `**kwargs` lets them upstream.
    #[must_use]
    pub fn example_video() -> Self {
        Self {
            title: Some("dummy".to_owned()),
            paused: Some(true),
            total_time: Some(123),
            position: Some(3),
            ..Self::default()
        }
    }

    /// The track upstream's `example_music` describes (`dmap.py:407-416`).
    #[must_use]
    pub fn example_music() -> Self {
        Self {
            paused: Some(true),
            title: Some("music".to_owned()),
            artist: Some("artist".to_owned()),
            album: Some("album".to_owned()),
            genre: Some("genre".to_owned()),
            total_time: Some(49),
            position: Some(22),
            ..Self::default()
        }
    }

    /// The `caps` value this response implies, if any.
    ///
    /// `handle_playstatus`'s three-way priority (`dmap.py:228-242`): a playback rate wins over the
    /// paused flag, which wins over a raw play state. The rate dispatch is upstream's
    /// `math.isclose` chain — zero is paused, one is playing, anything else positive is
    /// fast-forward and anything negative is rewind.
    #[must_use]
    pub fn play_state(&self) -> Option<u32> {
        if let Some(rate) = self.playback_rate {
            return Some(if rate.abs() < f64::EPSILON {
                3
            } else if (rate - 1.0).abs() < f64::EPSILON {
                4
            } else if rate > 0.0 {
                6
            } else {
                5
            });
        }
        if let Some(paused) = self.paused {
            return Some(if paused { 3 } else { 4 });
        }
        self.playstatus
    }
}

#[cfg(test)]
mod tests {
    use super::PlayingResponse;

    /// The playback-rate dispatch, which decides `caps` before the paused flag is even consulted.
    #[test]
    fn a_playback_rate_wins_over_the_paused_flag() {
        for (rate, expected) in [(0.0, 3), (1.0, 4), (2.0, 6), (-1.0, 5)] {
            let playing = PlayingResponse {
                playback_rate: Some(rate),
                paused: Some(true),
                playstatus: Some(99),
                ..PlayingResponse::default()
            };
            assert_eq!(playing.play_state(), Some(expected), "rate={rate}");
        }
    }

    #[test]
    fn the_paused_flag_wins_over_a_raw_play_state() {
        assert_eq!(
            PlayingResponse {
                paused: Some(false),
                playstatus: Some(99),
                ..PlayingResponse::default()
            }
            .play_state(),
            Some(4)
        );
        assert_eq!(
            PlayingResponse {
                playstatus: Some(1),
                ..PlayingResponse::default()
            }
            .play_state(),
            Some(1)
        );
        assert_eq!(PlayingResponse::default().play_state(), None);
    }
}
