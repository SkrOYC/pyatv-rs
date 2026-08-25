//! Unit tests for the outbound message factories.

use super::{
    OutputDeviceChange, client_updates_config, command, crypto_pairing, device_information,
    modify_output_context, repeat, seek_to_position, send_hid_event, set_connection_state,
    set_volume, shuffle,
};
use pyatv_core::consts::{RepeatState, ShuffleState};
use pyatv_core::storage::InfoSettings;

use crate::protobuf::{Command, extensions};

#[test]
fn every_message_carries_a_fresh_unique_identifier() {
    let first = set_connection_state().unwrap();
    let second = set_connection_state().unwrap();

    assert!(first.unique_identifier().is_some());
    assert_ne!(first.unique_identifier(), second.unique_identifier());
}

#[test]
fn device_information_sets_all_fifteen_fields() {
    let message = device_information(&InfoSettings::default(), "PAIRING-ID", false).unwrap();
    let inner = message.inner(&extensions::DEVICE_INFO_MESSAGE).unwrap();

    assert_eq!(inner.unique_identifier.as_deref(), Some("PAIRING-ID"));
    assert_eq!(inner.localized_model_name.as_deref(), Some("iPhone"));
    assert_eq!(inner.last_supported_message_type, Some(108));
    assert_eq!(inner.shared_queue_version, Some(2));
    assert_eq!(inner.logical_device_count, Some(1));
    assert_eq!(inner.allows_pairing, Some(true));
    assert_eq!(inner.supports_acl, Some(true));
    assert_eq!(inner.supports_shared_queue, Some(true));
    assert_eq!(inner.supports_extended_motion, Some(true));
    assert_eq!(inner.supports_system_pairing, Some(true));
    assert_eq!(inner.protocol_version, Some(1));
}

/// The update variant is a different `type` sharing extension 20 (pyatv `REUSED_MESSAGES`).
#[test]
fn the_update_variant_reuses_the_same_extension() {
    let message = device_information(&InfoSettings::default(), "ID", true).unwrap();
    assert!(
        message
            .extension(&extensions::DEVICE_INFO_MESSAGE)
            .unwrap()
            .is_some()
    );
}

#[test]
fn crypto_pairing_state_is_two_only_while_setting_up() {
    let setup = crypto_pairing(b"tlv", true).unwrap();
    let verify = crypto_pairing(b"tlv", false).unwrap();

    assert_eq!(
        setup
            .inner(&extensions::CRYPTO_PAIRING_MESSAGE)
            .unwrap()
            .state,
        Some(2)
    );
    assert_eq!(
        verify
            .inner(&extensions::CRYPTO_PAIRING_MESSAGE)
            .unwrap()
            .state,
        Some(0)
    );
}

#[test]
fn client_updates_config_leaves_now_playing_pushes_off() {
    let inner = client_updates_config()
        .unwrap()
        .inner(&extensions::CLIENT_UPDATES_CONFIG_MESSAGE)
        .unwrap();

    assert_eq!(inner.now_playing_updates, Some(false));
    assert_eq!(inner.artwork_updates, Some(true));
    assert_eq!(inner.volume_updates, Some(true));
    assert_eq!(inner.keyboard_updates, Some(true));
    assert_eq!(inner.output_device_updates, Some(true));
}

#[test]
fn a_plain_command_carries_no_options_submessage() {
    let inner = command(Command::Play)
        .unwrap()
        .inner(&extensions::SEND_COMMAND_MESSAGE)
        .unwrap();

    assert_eq!(inner.command, Some(Command::Play as i32));
    assert!(inner.options.is_none());
    assert!(inner.player_path.is_none());
}

#[test]
fn repeat_and_shuffle_zero_send_options_but_seek_does_not() {
    let repeat_options = repeat(RepeatState::Track)
        .unwrap()
        .inner(&extensions::SEND_COMMAND_MESSAGE)
        .unwrap()
        .options
        .unwrap();
    assert_eq!(repeat_options.send_options, Some(0));
    assert_eq!(repeat_options.repeat_mode, Some(2));

    let shuffle_options = shuffle(ShuffleState::Songs)
        .unwrap()
        .inner(&extensions::SEND_COMMAND_MESSAGE)
        .unwrap()
        .options
        .unwrap();
    assert_eq!(shuffle_options.send_options, Some(0));
    assert_eq!(shuffle_options.shuffle_mode, Some(3));

    let seek_options = seek_to_position(90.0)
        .unwrap()
        .inner(&extensions::SEND_COMMAND_MESSAGE)
        .unwrap()
        .options
        .unwrap();
    assert!(seek_options.send_options.is_none());
    assert!((seek_options.playback_position.unwrap() - 90.0).abs() < f64::EPSILON);
}

#[test]
fn hid_event_data_is_sixty_bytes() {
    let inner = send_hid_event(1, 0x8B, true)
        .unwrap()
        .inner(&extensions::SEND_HID_EVENT_MESSAGE)
        .unwrap();

    assert_eq!(inner.hid_event_data.unwrap().len(), 60);
}

#[test]
fn volume_travels_as_a_fraction() {
    let inner = set_volume("UID", 0.42)
        .unwrap()
        .inner(&extensions::SET_VOLUME_MESSAGE)
        .unwrap();

    assert_eq!(inner.output_device_uid.as_deref(), Some("UID"));
    assert!((inner.volume.unwrap() - 0.42).abs() < f32::EPSILON);
}

/// Both the plain and the `clusterAware` field must be written, or the device half-applies it.
#[test]
fn output_device_changes_write_both_parallel_fields() {
    let uids = vec!["A".to_owned(), "B".to_owned()];
    for change in [
        OutputDeviceChange::Add,
        OutputDeviceChange::Remove,
        OutputDeviceChange::Set,
    ] {
        let inner = modify_output_context(change, &uids)
            .unwrap()
            .inner(&extensions::MODIFY_OUTPUT_CONTEXT_REQUEST_MESSAGE)
            .unwrap();

        let (plain, cluster) = match change {
            OutputDeviceChange::Add => (inner.adding_devices, inner.cluster_aware_adding_devices),
            OutputDeviceChange::Remove => {
                (inner.removing_devices, inner.cluster_aware_removing_devices)
            }
            OutputDeviceChange::Set => (inner.setting_devices, inner.cluster_aware_setting_devices),
        };

        assert_eq!(plain, uids);
        assert_eq!(cluster, uids);
        assert_eq!(inner.r#type, Some(1));
    }
}
