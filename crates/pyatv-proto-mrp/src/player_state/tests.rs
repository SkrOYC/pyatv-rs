//! Unit tests for the player-state store and its merge rules.

use super::{Changed, Client, DEFAULT_PLAYER_ID, PlayerState, PlayerStateManager, is_close};
use crate::protobuf::{
    Command, CommandInfo, ContentItem, ContentItemMetadata, NowPlayingClient, NowPlayingPlayer,
    PlaybackQueue, PlayerPath, SetStateMessage, playback_state,
};

fn player_path(bundle: &str, player: &str) -> PlayerPath {
    PlayerPath {
        client: Some(NowPlayingClient {
            bundle_identifier: Some(bundle.to_owned()),
            ..NowPlayingClient::default()
        }),
        player: Some(NowPlayingPlayer {
            identifier: Some(player.to_owned()),
            ..NowPlayingPlayer::default()
        }),
        origin: None,
    }
}

fn queue(title: &str) -> PlaybackQueue {
    PlaybackQueue {
        location: Some(0),
        content_items: vec![ContentItem {
            identifier: Some("item".to_owned()),
            metadata: Some(ContentItemMetadata {
                title: Some(title.to_owned()),
                ..ContentItemMetadata::default()
            }),
            ..ContentItem::default()
        }],
        ..PlaybackQueue::default()
    }
}

#[test]
fn a_partial_set_state_leaves_untouched_fields_alone() {
    let mut state = PlayerState::default();
    state.handle_set_state(&SetStateMessage {
        playback_state: Some(playback_state::Enum::Playing as i32),
        playback_queue: Some(queue("First")),
        ..SetStateMessage::default()
    });

    // A later message carries only the state; the queue must survive.
    state.handle_set_state(&SetStateMessage {
        playback_state: Some(playback_state::Enum::Stopped as i32),
        ..SetStateMessage::default()
    });

    assert_eq!(state.playback_state(), Some(playback_state::Enum::Stopped));
    assert_eq!(
        state.metadata().and_then(|it| it.title.as_deref()),
        Some("First")
    );
}

#[test]
fn paused_with_an_empty_queue_is_idle_not_paused() {
    let mut state = PlayerState::default();
    state.handle_set_state(&SetStateMessage {
        playback_state: Some(playback_state::Enum::Paused as i32),
        ..SetStateMessage::default()
    });
    assert_eq!(state.playback_state(), None);

    state.handle_set_state(&SetStateMessage {
        playback_queue: Some(queue("Something")),
        ..SetStateMessage::default()
    });
    assert_eq!(state.playback_state(), Some(playback_state::Enum::Paused));
}

#[test]
fn a_playback_rate_that_is_neither_zero_nor_one_means_seeking() {
    let mut state = PlayerState::default();
    let mut with_rate = |rate: f32| {
        let mut queue = queue("Track");
        queue.content_items[0]
            .metadata
            .as_mut()
            .unwrap()
            .playback_rate = Some(rate);
        state.handle_set_state(&SetStateMessage {
            playback_state: Some(playback_state::Enum::Playing as i32),
            playback_queue: Some(queue),
            ..SetStateMessage::default()
        });
        state.playback_state()
    };

    assert_eq!(with_rate(1.0), Some(playback_state::Enum::Playing));
    assert_eq!(with_rate(0.0), Some(playback_state::Enum::Playing));
    assert_eq!(with_rate(2.0), Some(playback_state::Enum::Seeking));
}

#[test]
fn a_content_item_update_merges_rather_than_replaces() {
    let mut state = PlayerState::default();
    state.handle_set_state(&SetStateMessage {
        playback_queue: Some(queue("Original")),
        ..SetStateMessage::default()
    });

    state.handle_content_item_update(&[ContentItem {
        identifier: Some("item".to_owned()),
        metadata: Some(ContentItemMetadata {
            album_name: Some("Album".to_owned()),
            ..ContentItemMetadata::default()
        }),
        ..ContentItem::default()
    }]);

    let metadata = state.metadata().unwrap();
    assert_eq!(metadata.title.as_deref(), Some("Original"));
    assert_eq!(metadata.album_name.as_deref(), Some("Album"));
}

#[test]
fn command_info_falls_back_to_the_clients_defaults() {
    let mut client = Client::new(&NowPlayingClient {
        bundle_identifier: Some("app".to_owned()),
        ..NowPlayingClient::default()
    });
    client.supported_commands = vec![CommandInfo {
        command: Some(Command::Play as i32),
        enabled: Some(true),
        ..CommandInfo::default()
    }];
    client.player_mut(&NowPlayingPlayer {
        identifier: Some(DEFAULT_PLAYER_ID.to_owned()),
        ..NowPlayingPlayer::default()
    });

    let active = client.active_player();
    assert!(active.command_info(Command::Play).is_some());
    assert!(active.command_info(Command::Pause).is_none());
}

#[test]
fn an_empty_manager_still_answers_every_question() {
    let manager = PlayerStateManager::new();
    let playing = manager.playing();

    assert_eq!(playing.identifier(), "");
    assert!(playing.metadata().is_none());
    assert!(playing.playback_state().is_none());
    assert!(manager.client().is_none());
}

#[test]
fn only_the_active_players_changes_are_pushed() {
    let mut manager = PlayerStateManager::new();
    manager.player_mut(&player_path("app", DEFAULT_PLAYER_ID));
    manager.player_mut(&player_path("other", DEFAULT_PLAYER_ID));
    manager.set_now_playing_client(&NowPlayingClient {
        bundle_identifier: Some("app".to_owned()),
        ..NowPlayingClient::default()
    });

    assert!(manager.should_notify(Changed {
        client: Some("app"),
        player: None
    }));
    assert!(!manager.should_notify(Changed {
        client: Some("other"),
        player: None
    }));
    assert!(manager.should_notify(Changed {
        client: None,
        player: None
    }));
}

#[test]
fn removing_the_active_client_clears_it() {
    let mut manager = PlayerStateManager::new();
    let client = NowPlayingClient {
        bundle_identifier: Some("app".to_owned()),
        ..NowPlayingClient::default()
    };
    manager.set_now_playing_client(&client);
    assert!(manager.client().is_some());

    assert!(manager.remove_client(&client));
    assert!(manager.client().is_none());
}

/// `abs_tol` is zero upstream, so only a literal zero is "close to" zero.
#[test]
fn is_close_matches_pythons_defaults() {
    assert!(is_close(0.0, 0.0));
    assert!(!is_close(1e-30, 0.0));
    assert!(is_close(1.0, 1.0));
    assert!(!is_close(1.5, 1.0));
}
