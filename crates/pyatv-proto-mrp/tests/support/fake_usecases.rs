//! The use-case helpers a test drives the fake device with.
//!
//! Port of `FakeMrpUseCases` (`tests/fake_device/mrp.py:653-829`). Upstream's are keyword-argument
//! bags on top of `PlayingState`; here each one takes the arguments its pyatv counterpart requires
//! positionally and an extra [`PlayingState`] delta where upstream would take `**kwargs`.

use pyatv_proto_mrp::protobuf::playback_state;

use super::fake_messages as build;
use super::fake_state::{APP_NAME, FakeDeviceState, PLAYER_IDENTIFIER, PlayingState};

impl FakeDeviceState {
    /// `video_playing` (`mrp.py:729-751`).
    pub fn video_playing(&self, paused: bool, title: &str, total_time: f64, position: f64) {
        let (playback_state, playback_rate) = PlayingState::paused(paused);
        self.set_player_state(
            PLAYER_IDENTIFIER,
            PlayingState {
                playback_state,
                playback_rate,
                title: Some(title.to_owned()),
                total_time: Some(total_time),
                position: Some(position),
                media_type: Some(build::VIDEO),
                app_name: Some(APP_NAME.to_owned()),
                ..PlayingState::default()
            },
        );
        self.set_active_player(Some(PLAYER_IDENTIFIER));
    }

    /// `example_video` (`mrp.py:721-727`): paused, `"dummy"`, 3 of 123 seconds.
    pub fn example_video(&self) {
        self.video_playing(true, "dummy", 123.0, 3.0);
    }

    /// `example_video` with extra fields merged into the state before it is announced.
    pub fn example_video_with(&self, extra: &PlayingState) {
        let (playback_state, playback_rate) = PlayingState::paused(true);
        let mut state = PlayingState {
            playback_state,
            playback_rate,
            title: Some("dummy".to_owned()),
            total_time: Some(123.0),
            position: Some(3.0),
            media_type: Some(build::VIDEO),
            app_name: Some(APP_NAME.to_owned()),
            ..PlayingState::default()
        };
        state.merge(extra);
        self.set_player_state(PLAYER_IDENTIFIER, state);
        self.set_active_player(Some(PLAYER_IDENTIFIER));
    }

    /// `music_playing` (`mrp.py:764-781`).
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per field of upstream's kwargs-only music_playing()"
    )]
    pub fn music_playing(
        &self,
        paused: bool,
        artist: &str,
        album: &str,
        title: &str,
        genre: &str,
        total_time: f64,
        position: f64,
    ) {
        let (playback_state, playback_rate) = PlayingState::paused(paused);
        self.set_player_state(
            PLAYER_IDENTIFIER,
            PlayingState {
                playback_state,
                playback_rate,
                artist: Some(artist.to_owned()),
                album: Some(album.to_owned()),
                title: Some(title.to_owned()),
                genre: Some(genre.to_owned()),
                total_time: Some(total_time),
                position: Some(position),
                media_type: Some(build::MUSIC),
                ..PlayingState::default()
            },
        );
        self.set_active_player(Some(PLAYER_IDENTIFIER));
    }

    /// `example_music` (`mrp.py:753-762`).
    pub fn example_music(&self) {
        self.music_playing(true, "artist", "album", "music", "genre", 49.0, 22.0);
    }

    /// `tv_playing` (`mrp.py:792-815`).
    #[allow(
        clippy::too_many_arguments,
        reason = "one argument per field of upstream's kwargs-only tv_playing()"
    )]
    pub fn tv_playing(
        &self,
        paused: bool,
        series_name: &str,
        total_time: f64,
        position: f64,
        season_number: i32,
        episode_number: i32,
        extra: &PlayingState,
    ) {
        let (playback_state, playback_rate) = PlayingState::paused(paused);
        let mut state = PlayingState {
            playback_state,
            playback_rate,
            series_name: Some(series_name.to_owned()),
            total_time: Some(total_time),
            position: Some(position),
            season_number: Some(season_number),
            episode_number: Some(episode_number),
            media_type: Some(build::VIDEO),
            ..PlayingState::default()
        };
        state.merge(extra);
        self.set_player_state(PLAYER_IDENTIFIER, state);
        self.set_active_player(Some(PLAYER_IDENTIFIER));
    }

    /// `nothing_playing` (`mrp.py:717-719`).
    pub fn nothing_playing(&self) {
        self.set_active_player(None);
    }

    /// `media_is_loading` (`mrp.py:817-821`).
    pub fn media_is_loading(&self) {
        self.set_player_state(
            PLAYER_IDENTIFIER,
            PlayingState {
                playback_state: Some(playback_state::Enum::Interrupted),
                ..PlayingState::default()
            },
        );
        self.set_active_player(Some(PLAYER_IDENTIFIER));
    }

    /// `change_state` (`mrp.py:703-711`): merge and re-announce with a `SET_STATE_MESSAGE`.
    pub fn change_state(&self, change: &PlayingState) {
        {
            let mut inner = self.lock();
            if let Some(state) = inner.states.get_mut(PLAYER_IDENTIFIER) {
                state.merge(change);
            }
        }
        self.update_state(PLAYER_IDENTIFIER);
    }

    /// `change_metadata` (`mrp.py:691-701`): merge and announce with an `UPDATE_CONTENT_ITEM`.
    pub fn change_metadata(&self, change: &PlayingState) {
        self.item_update(change, PLAYER_IDENTIFIER);
    }

    /// `change_artwork` (`mrp.py:677-689`).
    pub fn change_artwork(&self, artwork: &[u8], mimetype: &str, identifier: &str) {
        self.change_state(&PlayingState {
            artwork: Some(artwork.to_vec()),
            artwork_mimetype: Some(mimetype.to_owned()),
            artwork_identifier: Some(identifier.to_owned()),
            ..PlayingState::default()
        });
    }
}
