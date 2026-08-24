//! A hermetic Companion device, speaking real frames over a real TCP socket.
//!
//! Port of `tests/fake_device/companion.py::FakeCompanionService` (`companion.py:227-344,414-521`)
//! and the `CompanionServerAuth` state machine it inherits
//! (`pyatv/protocols/companion/server_auth.py:74-229`). The crypto is
//! [`pyatv_pairing::server::ReferenceAccessory`] with pyatv's fixed key material; this file adds
//! only the Companion framing and the handful of `_i` handlers bring-up needs.
//!
//! Framing is re-derived here rather than reusing [`pyatv_proto_companion::codec`], exactly as
//! upstream's fake device re-derives it rather than importing `connection.py`: a fixture that
//! shares an implementation with the code under test cannot catch a bug in it. The arithmetic
//! below is transcribed from `companion.py:256-306` directly.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use pyatv_opack::{Value, opack};
use pyatv_pairing::chacha::{AUTH_TAG_LENGTH, Chacha20Cipher};
use pyatv_pairing::hkdf_derive::transport::COMPANION;
use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::tlv8::Tlv8;
use pyatv_proto_companion::FrameType;

use super::fake_state::{DeviceState, Reply};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// The undocumented extra TLV pyatv's reference server puts in its pair-setup M2
/// (`server_auth.py:150`) and its client ignores.
///
/// `docs/research/companion-port-spec.md` §4.2 could only guess that this mimics real hardware.
/// **A live capture against an Apple TV 4K on 2026-08-24 settles it**: the device's own M2 carried
/// exactly four TLVs — `SeqNo` (1 byte), `Salt` (16), `PublicKey` (384) and this tag `0x1B` with a
/// single byte. Its meaning is still unknown, but it is genuinely on the wire, so the fixture emits
/// it and the client is proven to tolerate an unrecognised tag rather than merely assumed to.
const MYSTERY_TAG: u8 = 27;

/// A running fake device. Dropping it stops the accept loop.
#[derive(Debug)]
pub struct FakeCompanionDevice {
    address: SocketAddr,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    state: Arc<Mutex<DeviceState>>,
    task: tokio::task::JoinHandle<()>,
    /// Every accepted connection, so a test can drop them out from under the client.
    connections: Arc<std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Drop for FakeCompanionDevice {
    fn drop(&mut self) {
        self.task.abort();
        self.kill_connections();
    }
}

impl FakeCompanionDevice {
    /// Bind to an ephemeral loopback port and start serving.
    ///
    /// `pin` is what the device would be showing on screen.
    pub async fn start(pin: u32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let address = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let accessory = Arc::new(Mutex::new(ReferenceAccessory::with_pin(pin)));
        let state = Arc::new(Mutex::new(DeviceState::default()));
        let connections = Arc::new(std::sync::Mutex::new(Vec::new()));
        let served_accessory = Arc::clone(&accessory);
        let served_state = Arc::clone(&state);
        let served_connections = Arc::clone(&connections);

        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let accessory = Arc::clone(&served_accessory);
                let state = Arc::clone(&served_state);
                let handle = tokio::spawn(async move {
                    Connection::new(stream, accessory, state).serve().await;
                });
                if let Ok(mut open) = served_connections.lock() {
                    open.push(handle);
                }
            }
        });

        Self {
            address,
            accessory,
            state,
            task,
            connections,
        }
    }

    /// Yank every live connection, as a device losing power or Wi-Fi would.
    ///
    /// Aborting the task drops its `TcpStream`, which closes the socket; the client sees the read
    /// return zero bytes. This is the only way to reach the `connection_lost` path — a graceful
    /// `close()` takes the other branch.
    pub fn kill_connections(&self) {
        let Ok(mut open) = self.connections.lock() else {
            return;
        };
        for handle in open.drain(..) {
            handle.abort();
        }
    }

    /// Where a controller should connect.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The accessory's crypto state, for asserting on what it accepted.
    pub fn accessory(&self) -> Arc<Mutex<ReferenceAccessory>> {
        Arc::clone(&self.accessory)
    }

    /// What the device observed at the Companion layer.
    pub fn state(&self) -> Arc<Mutex<DeviceState>> {
        Arc::clone(&self.state)
    }
}

/// One accepted connection.
struct Connection {
    stream: TcpStream,
    buffer: BytesMut,
    cipher: Option<Chacha20Cipher>,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    state: Arc<Mutex<DeviceState>>,
    /// Keys derived during pair-verify, installed only after M4 has been sent in the clear.
    pending_keys: Option<([u8; 32], [u8; 32])>,
}

impl Connection {
    fn new(
        stream: TcpStream,
        accessory: Arc<Mutex<ReferenceAccessory>>,
        state: Arc<Mutex<DeviceState>>,
    ) -> Self {
        Self {
            stream,
            buffer: BytesMut::new(),
            cipher: None,
            accessory,
            state,
            pending_keys: None,
        }
    }

    /// Read frames until the client goes away.
    async fn serve(mut self) {
        loop {
            while let Some((frame_type, payload)) = self.take_frame() {
                let Ok((value, _)) = pyatv_opack::unpack(&payload) else {
                    return;
                };
                if !self.handle(frame_type, &value).await {
                    return;
                }
            }

            self.buffer.reserve(4096);
            match self.stream.read_buf(&mut self.buffer).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }

    /// Pull one whole frame off the buffer, decrypting it if a session key is installed.
    ///
    /// `payload_length = 4 + int.from_bytes(buffer[1:4], "big")` (`companion.py:272-284`).
    fn take_frame(&mut self) -> Option<(FrameType, Vec<u8>)> {
        if self.buffer.len() < 4 {
            return None;
        }
        let declared = usize::from(self.buffer[1]) << 16
            | usize::from(self.buffer[2]) << 8
            | usize::from(self.buffer[3]);
        let total = 4 + declared;
        if self.buffer.len() < total {
            return None;
        }

        let frame_type = FrameType::from_byte(self.buffer[0])?;
        let frame = self.buffer.split_to(total);
        let header = &frame[..4];
        let body = &frame[4..];

        let payload = match self.cipher.as_mut() {
            Some(cipher) if !body.is_empty() => cipher
                .decrypt(body, Some(header))
                .expect("the client's frame must decrypt"),
            _ => body.to_vec(),
        };
        Some((frame_type, payload))
    }

    /// Frame and write one OPACK value back to the client (`send_to_client`,
    /// `companion.py:256-269`).
    async fn send(&mut self, frame_type: FrameType, value: &Value) {
        let packed = pyatv_opack::pack(value).expect("the response must pack");

        let declared = if self.cipher.is_some() && !packed.is_empty() {
            packed.len() + AUTH_TAG_LENGTH
        } else {
            packed.len()
        };
        let length = u32::try_from(declared)
            .expect("a test payload fits three bytes")
            .to_be_bytes();
        let header = [frame_type as u8, length[1], length[2], length[3]];

        let body = match self.cipher.as_mut() {
            Some(cipher) if !packed.is_empty() => cipher
                .encrypt(&packed, Some(&header))
                .expect("sealing must succeed"),
            _ => packed.to_vec(),
        };

        let mut frame = Vec::with_capacity(4 + body.len());
        frame.extend_from_slice(&header);
        frame.extend_from_slice(&body);
        let _ = self.stream.write_all(&frame).await;
    }

    /// Dispatch one frame. Returns `false` to drop the connection.
    async fn handle(&mut self, frame_type: FrameType, value: &Value) -> bool {
        if frame_type.is_auth() {
            return self.handle_auth(frame_type, value).await;
        }

        // `if not self.chacha: raise Exception("client has not authenticated")`
        // (`companion.py:295-296`).
        if self.cipher.is_none() {
            return false;
        }
        self.state.lock().await.saw_encrypted_traffic = true;
        self.handle_command(value).await;
        true
    }

    /// Route a pairing frame to the reference accessory and frame its answer.
    async fn handle_auth(&mut self, frame_type: FrameType, value: &Value) -> bool {
        let Some(pairing_data) = value.get("_pd").and_then(Value::as_bytes) else {
            return false;
        };

        let setup = matches!(frame_type, FrameType::PsStart | FrameType::PsNext);
        let mut accessory = self.accessory.lock().await;

        let response = if setup {
            accessory.handle_pair_setup(pairing_data)
        } else {
            accessory.handle_pair_verify(pairing_data)
        };
        let Ok(response) = response else {
            return false;
        };

        let paired_now = setup && !accessory.pairings().is_empty();
        // Derive on the verify side before releasing the accessory, but install only after the
        // plaintext M4 has gone out (`server_auth.py:138-142`).
        let keys = if setup {
            None
        } else {
            accessory
                .encryption_keys(COMPANION.salt, COMPANION.read_info, COMPANION.write_info)
                .ok()
                .map(|keys| (keys.output_key, keys.input_key))
        };
        drop(accessory);

        let is_m2_setup = matches!(frame_type, FrameType::PsStart);
        let response = if is_m2_setup {
            with_mystery_tag(&response)
        } else {
            response
        };

        // `_pwTy` rides along on the M2 pair-setup response only (`server_auth.py:153`). A real
        // Apple TV 4K sends `{_pd}` alone here — no `_pwTy` and no `_x` — so keeping upstream's
        // extra key is the *stricter* fixture: a client that depended on it would pass this test
        // and fail against hardware, and one that ignores it (as this port does) passes both.
        let envelope = if is_m2_setup {
            opack! { "_pd" => response, "_pwTy" => 1u64 }
        } else {
            opack! { "_pd" => response }
        };
        self.send(frame_type.response_type(), &envelope).await;

        if paired_now {
            self.state.lock().await.has_paired = true;
        }
        if let Some((output_key, input_key)) = keys {
            self.pending_keys = Some((output_key, input_key));
        }
        // M4 is the last verify message, and the device encrypts everything after it.
        if matches!(frame_type, FrameType::PvNext)
            && let Some((output_key, input_key)) = self.pending_keys.take()
        {
            self.cipher = Some(Chacha20Cipher::with_bare_counter(&output_key, &input_key));
        }

        true
    }

    /// Route one message to [`DeviceState`] and send whatever it asked for.
    ///
    /// The handlers themselves are pure; this only owns the socket. `data_received`'s dispatch
    /// (`companion.py:296-305`) plus the `send_response`/`send_error`/`send_event` trio it calls.
    async fn handle_command(&mut self, request: &Value) {
        let identifier = request
            .get("_i")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let content = request.get("_c").cloned().unwrap_or(opack! {});
        let is_event = request.get("_t").and_then(Value::as_u64) == Some(1);

        let replies = self
            .state
            .lock()
            .await
            .handle(&identifier, &content, is_event);

        for reply in replies {
            match reply {
                Reply::Response(content) => self.send_response(request, content).await,
                Reply::Error(message, code) => self.send_error(request, &message, code).await,
                Reply::Event(name, content) => self.send_event(name, &content).await,
                Reply::Nothing => {}
            }
        }
    }

    /// `send_event` (`companion.py:320-329`). Upstream stamps an arbitrary `_x` on outbound events
    /// and the client ignores it; the same constant is used here so the wire shape matches.
    async fn send_event(&mut self, identifier: &str, content: &Value) {
        let value = opack! {
            "_i" => identifier,
            "_x" => 1234u64,
            "_t" => 1u64,
            "_c" => content.clone(),
        };
        self.send(FrameType::EOpack, &value).await;
    }

    /// `send_response` (`companion.py:309-318`).
    async fn send_response(&mut self, request: &Value, content: Value) {
        let value = opack! {
            "_i" => request.get("_i").and_then(Value::as_str).unwrap_or_default(),
            "_x" => request.get("_x").and_then(Value::as_u64).unwrap_or_default(),
            "_t" => 3u64,
            "_c" => content,
        };
        self.send(FrameType::EOpack, &value).await;
    }

    /// `send_error` (`companion.py:331-344`).
    async fn send_error(&mut self, request: &Value, message: &str, code: u64) {
        let value = opack! {
            "_i" => request.get("_i").and_then(Value::as_str).unwrap_or_default(),
            "_x" => request.get("_x").and_then(Value::as_u64).unwrap_or_default(),
            "_t" => 3u64,
            "_ec" => code,
            "_ed" => "RPErrorDomain",
            "_em" => message,
        };
        self.send(FrameType::EOpack, &value).await;
    }
}

/// Append the undocumented tag-27 TLV a real device's M2 appears to carry.
fn with_mystery_tag(tlv: &[u8]) -> Vec<u8> {
    let Ok(decoded) = Tlv8::decode(tlv) else {
        return tlv.to_vec();
    };
    let mut rebuilt = Tlv8::new();
    for tag in decoded.tags().collect::<Vec<_>>() {
        if let Some(value) = decoded.get_raw(tag) {
            rebuilt = rebuilt.with_raw(tag, value.clone());
        }
    }
    rebuilt
        .with_raw(MYSTERY_TAG, bytes::Bytes::from_static(&[0x01]))
        .encode()
        .to_vec()
}
