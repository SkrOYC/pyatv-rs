//! One accepted connection to the fake MRP device.
//!
//! Port of `FakeMrpService`'s framing and handlers (`tests/fake_device/mrp.py:379-650`) plus the
//! `MrpServerAuth` mixin it inherits (`pyatv/protocols/mrp/server_auth.py`).
//!
//! The framing is transcribed from `mrp.py:407-459` rather than reused from
//! [`crate::transport::direct`], for the same reason upstream's fake re-derives it: a
//! fixture that shares an implementation with the code under test cannot catch a bug in it.

use std::sync::Arc;

use crate::MrpMessage;
use crate::protobuf::{Command, extensions, protocol_message, send_error};
use crate::variant;
use bytes::{Bytes, BytesMut};
use pyatv_core::consts::InputAction;
use pyatv_pairing::chacha::Chacha20Cipher;
use pyatv_pairing::hkdf_derive::transport::MRP;
use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::{Tlv8, TlvValue};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, broadcast};

use super::fake_messages as build;
use super::fake_state::{DEVICE_UID, FakeDeviceState, HOLD_THRESHOLD, PlayingState, VOLUME_STEP};

/// `ProtocolMessage.Type`.
type Type = protocol_message::Type;

/// `_KEY_LOOKUP` (`mrp.py:25-42`): `(usagePage, usage)` to pyatv's name for the button.
const KEY_LOOKUP: &[((u16, u16), &str)] = &[
    ((1, 0x8C), "up"),
    ((1, 0x8D), "down"),
    ((1, 0x8B), "left"),
    ((1, 0x8A), "right"),
    ((12, 0xB7), "stop"),
    ((12, 0xB5), "next"),
    ((12, 0xB6), "previous"),
    ((1, 0x89), "select"),
    ((1, 0x86), "menu"),
    ((12, 0x60), "top_menu"),
    ((12, 0x40), "home"),
    ((1, 0x82), "suspend"),
    ((1, 0x83), "wakeup"),
    ((12, 0xE9), "volumeup"),
    ((12, 0xEA), "volumedown"),
];

/// `_COMMAND_LOOKUP` (`mrp.py:44-51`): the commands that map onto a button name.
const COMMAND_LOOKUP: &[(Command, &str)] = &[
    (Command::Play, "play"),
    (Command::TogglePlayPause, "playpause"),
    (Command::Pause, "pause"),
    (Command::Stop, "stop"),
    (Command::NextTrack, "nextitem"),
    (Command::PreviousTrack, "previtem"),
];

/// One accepted connection.
#[derive(Debug)]
pub struct Connection {
    stream: TcpStream,
    buffer: BytesMut,
    cipher: Option<Chacha20Cipher>,
    state: Arc<FakeDeviceState>,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    pushes: broadcast::Receiver<MrpMessage>,
    /// Which HAP state machine this connection's `CRYPTO_PAIRING_MESSAGE`s belong to.
    verifying: bool,
}

impl Connection {
    /// Wrap an accepted socket, subscribing it to the device's push stream.
    pub fn new(
        stream: TcpStream,
        state: Arc<FakeDeviceState>,
        accessory: Arc<Mutex<ReferenceAccessory>>,
    ) -> Self {
        let pushes = state.subscribe();
        Self {
            stream,
            buffer: BytesMut::new(),
            cipher: None,
            state,
            accessory,
            pushes,
            verifying: false,
        }
    }

    /// Interleave client requests with device pushes until the client goes away.
    pub async fn serve(mut self) {
        let mut chunk = [0u8; 8192];
        loop {
            while let Some(frame) = self.take_frame() {
                let Ok(message) = MrpMessage::decode(frame) else {
                    return;
                };
                self.handle(&message).await;
            }

            tokio::select! {
                read = self.stream.read(&mut chunk) => match read {
                    Ok(0) | Err(_) => return,
                    Ok(count) => self.buffer.extend_from_slice(&chunk[..count]),
                },
                push = self.pushes.recv() => match push {
                    Ok(message) => self.send(&message).await,
                    Err(broadcast::error::RecvError::Closed) => return,
                    // A lagging fixture would mean the test outran the socket; drop and carry on.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                },
            }
        }
    }

    /// Pull one whole frame off the buffer, decrypting it if a session key is installed.
    ///
    /// `data_received` (`mrp.py:444-459`).
    fn take_frame(&mut self) -> Option<Bytes> {
        let (length, consumed) = variant::read(&self.buffer).ok()?;
        let length = usize::try_from(length).ok()?;
        if self.buffer.len() < consumed + length {
            return None;
        }

        let frame = self.buffer.split_to(consumed + length).split_off(consumed);
        match self.cipher.as_mut() {
            Some(cipher) => Some(Bytes::from(
                cipher
                    .decrypt(&frame, None)
                    .expect("the client's frame must decrypt"),
            )),
            None => Some(frame.freeze()),
        }
    }

    /// `send_to_client` (`mrp.py:407-417`): seal, length-prefix, write.
    async fn send(&mut self, message: &MrpMessage) {
        let body = match self.cipher.as_mut() {
            Some(cipher) => cipher
                .encrypt(message.bytes(), None)
                .expect("sealing must succeed"),
            None => message.bytes().to_vec(),
        };

        let mut frame = variant::write(body.len() as u64);
        frame.extend_from_slice(&body);
        let _ = self.stream.write_all(&frame).await;
    }

    /// `data_received`'s `getattr(self, "handle_" + name)` dispatch (`mrp.py:461-469`).
    async fn handle(&mut self, message: &MrpMessage) {
        let identifier = message.identifier().map(str::to_owned);
        match message.message_type_enum() {
            Some(Type::DeviceInfoMessage) => self.handle_device_info(identifier.as_deref()).await,
            Some(Type::CryptoPairingMessage) => self.handle_crypto_pairing(message).await,
            Some(Type::SetConnectionStateMessage) => self.handle_set_connection_state(message),
            Some(Type::ClientUpdatesConfigMessage) => {
                self.handle_client_updates_config(identifier.as_deref())
                    .await;
            }
            Some(Type::GetKeyboardSessionMessage) => {
                if let Some(identifier) = identifier {
                    self.send(&build::keyboard(&identifier)).await;
                }
            }
            Some(Type::SendHidEventMessage) => {
                self.handle_send_hid_event(message, identifier.as_deref())
                    .await;
            }
            Some(Type::SendCommandMessage) => {
                self.handle_send_command(message, identifier.as_deref())
                    .await;
            }
            Some(Type::PlaybackQueueRequestMessage) => {
                if let Some(identifier) = identifier {
                    self.handle_playback_queue_request(&identifier).await;
                }
            }
            Some(Type::WakeDeviceMessage) => self.handle_wake_device(identifier.as_deref()).await,
            Some(Type::GenericMessage) => self.handle_generic(identifier.as_deref()).await,
            Some(Type::SetVolumeMessage) => {
                self.handle_set_volume(message, identifier.as_deref()).await;
            }
            Some(Type::ModifyOutputContextRequestMessage) => {
                self.handle_modify_output_context(message);
            }
            _ => {}
        }
    }

    /// An envelope of `message_type` correlated to a request, sent only when there is one.
    async fn reply(&mut self, message_type: Type, identifier: Option<&str>) {
        if let Some(identifier) = identifier {
            self.send(&build::bare(message_type, Some(identifier)))
                .await;
        }
    }

    /// `handle_device_info` (`mrp.py:471-472`).
    async fn handle_device_info(&mut self, identifier: Option<&str>) {
        let message = self.state.with(|inner| {
            build::device_info(
                inner.powered_on,
                inner.cluster_id.as_deref(),
                &inner.output_devices,
                identifier,
                false,
            )
        });
        self.send(&message).await;
    }

    /// `MrpServerAuth.handle_crypto_pairing` (`server_auth.py:100-113`), routed to the accessory.
    ///
    /// Which state machine runs is decided on `SeqNo == 1` and then sticks for the rest of the
    /// exchange: a `PublicKey` TLV there means pair-verify, a `Method` TLV means pair-setup.
    /// The MRP-level `CryptoPairingMessage.state` field plays no part in it.
    async fn handle_crypto_pairing(&mut self, message: &MrpMessage) {
        let Ok(inner) = message.inner(&extensions::CRYPTO_PAIRING_MESSAGE) else {
            return;
        };
        let payload = inner.pairing_data.unwrap_or_default();
        let Ok(tlv) = Tlv8::decode(&payload) else {
            return;
        };
        let sequence = tlv
            .get(TlvValue::SeqNo)
            .and_then(|value| value.first())
            .copied()
            .unwrap_or_default();

        if sequence == 1 {
            if tlv.get(TlvValue::PublicKey).is_some() {
                self.verifying = true;
            } else if tlv.get(TlvValue::Method).is_some() {
                self.verifying = false;
            }
        }

        let mut accessory = self.accessory.lock().await;
        let response = if self.verifying {
            accessory.handle_pair_verify(&payload)
        } else {
            accessory.handle_pair_setup(&payload)
        };
        let Ok(response) = response else { return };

        // Derive before releasing the accessory but install only after the plaintext M4 has gone
        // out: the device encrypts everything *after* the last verify message
        // (`server_auth.py:181-190`).
        let keys = if self.verifying && sequence == 3 {
            accessory
                .encryption_keys(MRP.salt, MRP.read_info, MRP.write_info)
                .ok()
        } else {
            None
        };
        drop(accessory);

        let reply = crate::messages::crypto_pairing(&response, false)
            .expect("the fixture's CRYPTO_PAIRING_MESSAGE must serialise");
        self.send(&reply).await;

        if let Some(keys) = keys {
            self.cipher = Some(Chacha20Cipher::with_padded_counter(
                &keys.output_key,
                &keys.input_key,
            ));
            self.state.update(|inner| inner.has_authenticated = true);
        }
    }

    /// `handle_set_connection_state` (`mrp.py:474-477`).
    fn handle_set_connection_state(&self, message: &MrpMessage) {
        let Ok(inner) = message.inner(&extensions::SET_CONNECTION_STATE_MESSAGE) else {
            return;
        };
        self.state
            .update(|state| state.connection_state = inner.state);
    }

    /// `handle_client_updates_config` (`mrp.py:478-487`): replay every known state, then ack.
    async fn handle_client_updates_config(&mut self, identifier: Option<&str>) {
        let (states, active) = self.state.with(|inner| {
            (
                inner
                    .states
                    .iter()
                    .map(|(key, state)| build::set_state(state, key))
                    .collect::<Vec<_>>(),
                inner.active_player.clone(),
            )
        });
        for state in states {
            self.send(&state).await;
        }
        if let Some(active) = active {
            self.send(&build::set_now_playing_client(Some(&active)))
                .await;
        }
        self.reply(Type::UnknownMessage, identifier).await;
    }

    /// `handle_send_hid_event` (`mrp.py:496-548`).
    ///
    /// The button and the press state are read straight out of `hidEventData[43:49]` as three
    /// big-endian `u16`s, which is the only part of that 60-byte blob anyone has decoded.
    async fn handle_send_hid_event(&mut self, message: &MrpMessage, identifier: Option<&str>) {
        let Ok(inner) = message.inner(&extensions::SEND_HID_EVENT_MESSAGE) else {
            return;
        };
        let data = inner.hid_event_data.unwrap_or_default();
        let Some(slice) = data.get(43..49) else {
            return;
        };
        let read = |at: usize| u16::from_be_bytes([slice[at], slice[at + 1]]);
        let (usage_page, usage, down) = (read(0), read(2), read(4));

        if down == 1 {
            self.state.update(|state| {
                state
                    .outstanding
                    .insert((usage_page, usage), std::time::Instant::now());
            });
            self.reply(Type::UnknownMessage, identifier).await;
            return;
        }
        if down != 0 {
            return;
        }

        let Some(held) = self
            .state
            .update(|state| state.outstanding.remove(&(usage_page, usage)))
        else {
            return;
        };
        let Some(key) = KEY_LOOKUP
            .iter()
            .find(|((page, code), _)| *page == usage_page && *code == usage)
            .map(|(_, name)| *name)
        else {
            panic!("unsupported key: usage_page={usage_page}, usage={usage}");
        };

        let mut announce_power_off = false;
        self.state.update(|state| {
            if key == "select" && state.last_button_pressed.as_deref() == Some("home") {
                state.powered_on = false;
                announce_power_off = true;
            }

            state.last_button_action = Some(if held.elapsed() > HOLD_THRESHOLD {
                InputAction::Hold
            } else if state.last_button_pressed.as_deref() == Some(key) {
                InputAction::DoubleTap
            } else {
                InputAction::SingleTap
            });
            state.last_button_pressed = Some(key.to_owned());
        });
        if announce_power_off {
            self.state.announce_device_info();
        }

        self.reply(Type::UnknownMessage, identifier).await;

        // The relative volume keys move the level and announce it (`mrp.py:532-544`).
        let volume = self.state.with(|state| state.volume);
        match key {
            "volumeup" => self
                .state
                .set_volume((volume + VOLUME_STEP).min(1.0), DEVICE_UID),
            "volumedown" => self
                .state
                .set_volume((volume - VOLUME_STEP).max(0.0), DEVICE_UID),
            _ => {}
        }
    }

    /// `handle_send_command` (`mrp.py:550-596`).
    async fn handle_send_command(&mut self, message: &MrpMessage, identifier: Option<&str>) {
        let Ok(inner) = message.inner(&extensions::SEND_COMMAND_MESSAGE) else {
            return;
        };
        let Some(raw) = inner.command else { return };
        self.state.update(|state| state.commands.push(raw));

        let options = inner.options.unwrap_or_default();
        let button = COMMAND_LOOKUP
            .iter()
            .find(|(command, _)| *command as i32 == raw)
            .map(|(_, name)| (*name).to_owned());

        let mut change = PlayingState::default();
        if let Some(button) = button {
            self.state
                .update(|state| state.last_button_pressed = Some(button));
        } else if raw == Command::ChangeRepeatMode as i32 {
            change.repeat = Some(build::repeat_state_of(options.repeat_mode));
        } else if raw == Command::ChangeShuffleMode as i32 {
            change.shuffle = Some(build::shuffle_state_of(options.shuffle_mode));
        } else if raw == Command::SeekToPlaybackPosition as i32 {
            change.position = options.playback_position;
        } else if raw == Command::SkipForward as i32 || raw == Command::SkipBackward as i32 {
            let interval = f64::from(options.skip_interval.unwrap_or_default()).trunc();
            let signed = if raw == Command::SkipForward as i32 {
                interval
            } else {
                -interval
            };
            let current = self.state.with(|state| {
                state
                    .states
                    .get(super::fake_state::PLAYER_IDENTIFIER)
                    .and_then(|it| it.position)
                    .unwrap_or_default()
            });
            change.position = Some(current + signed);
        } else {
            // `NoCommandHandlers`, which is what a real device answers for a command it does not
            // implement (`mrp.py:584-593`).
            if let Some(identifier) = identifier {
                self.send(&build::command_result(
                    identifier,
                    Some(send_error::Enum::NoCommandHandlers as i32),
                ))
                .await;
            }
            return;
        }

        if change != PlayingState::default() {
            self.state.change_state(&change);
        }
        self.state.update(|state| state.last_button_action = None);
        if let Some(identifier) = identifier {
            self.send(&build::command_result(identifier, None)).await;
        }
    }

    /// `handle_playback_queue_request` (`mrp.py:598-613`): artwork rides back in a `SET_STATE`.
    async fn handle_playback_queue_request(&mut self, identifier: &str) {
        let state = self.state.with(|inner| {
            inner
                .active_player
                .as_ref()
                .and_then(|active| inner.states.get(active).cloned())
                .unwrap_or_default()
        });
        self.send(&build::artwork(identifier, &state)).await;
    }

    /// `handle_wake_device` (`mrp.py:615-618`).
    async fn handle_wake_device(&mut self, identifier: Option<&str>) {
        if let Some(identifier) = identifier {
            self.send(&build::command_result(identifier, None)).await;
        }
        self.state.update(|state| state.powered_on = true);
        self.state.announce_device_info();
    }

    /// `handle_generic` (`mrp.py:620-630`): the heartbeat.
    async fn handle_generic(&mut self, identifier: Option<&str>) {
        self.state.update(|state| state.heartbeat_count += 1);
        self.reply(Type::UnknownMessage, identifier).await;
    }

    /// `handle_set_volume` (`mrp.py:632-639`).
    async fn handle_set_volume(&mut self, message: &MrpMessage, identifier: Option<&str>) {
        let Ok(inner) = message.inner(&extensions::SET_VOLUME_MESSAGE) else {
            return;
        };
        self.state.set_volume(
            inner.volume.unwrap_or_default(),
            &inner.output_device_uid.unwrap_or_default(),
        );
        self.reply(Type::UnknownMessage, identifier).await;
    }

    /// `handle_modify_output_context_request` (`mrp.py:641-650`).
    fn handle_modify_output_context(&self, message: &MrpMessage) {
        let Ok(inner) = message.inner(&extensions::MODIFY_OUTPUT_CONTEXT_REQUEST_MESSAGE) else {
            return;
        };
        if !inner.adding_devices.is_empty() {
            self.state.add_output_devices(&inner.adding_devices);
        }
        if !inner.removing_devices.is_empty() {
            self.state.remove_output_devices(&inner.removing_devices);
        }
        if !inner.setting_devices.is_empty() {
            self.state.set_output_devices(&inner.setting_devices);
        }
    }
}
