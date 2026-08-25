//! A data-stream channel that forwards to a real MRP device instead of echoing.
//!
//! [`super::fake_channels::serve_data`] answers a controller with its own bytes, which proves the
//! framing round-trips but cannot exercise anything above it. This variant instead proxies the
//! channel onto a plain TCP socket, so a hermetic MRP device — `pyatv-proto-mrp`'s own fixture,
//! unchanged — can sit behind an AirPlay tunnel and answer a real `connect()`.
//!
//! # Why a byte pipe is enough
//!
//! The two framings are the *same bytes*. A tunnelled `params.data` field is
//! `varint(len) ‖ ProtocolMessage` (`pyatv/protocols/airplay/channels.py:143-151`) and a direct-TCP
//! MRP frame is `varint(len) ‖ ProtocolMessage` (`pyatv/protocols/mrp/connection.py:97-113`). The
//! only work this does beyond copying is re-delimiting: the AirPlay side is message-oriented, so
//! the device's byte stream has to be split back into whole frames before each is wrapped in an
//! envelope and framed with a `DataHeader`.
//!
//! Both directions are plaintext at the MRP layer, which is exactly right: the tunnel path
//! registers a credential-less service and never pair-verifies at that layer
//! (`pyatv/protocols/airplay/mrp_connection.py:33-35`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use crate::ap2::data_stream::{COMMAND_COMM, COMMAND_NONE, MESSAGE_TYPE_REPLY, MESSAGE_TYPE_SYNC};

use super::fake_airplay::FakeState;
use super::fake_channels::{
    encode_frame, envelope_data, read_variant, take_frame, unwrap_envelope, wrap_payload,
};

/// Accept one controller connection on the data port and pipe it to `device`.
///
/// Runs until either side goes away. Every inbound `sync` frame is acknowledged with a `rply`
/// carrying the same seqno before its payload is forwarded, which is the order upstream's own
/// channel uses (`channels.py:153-163`).
pub async fn serve_data_bridge(
    listener: TcpListener,
    keys: SessionKeys,
    state: Arc<FakeState>,
    device: SocketAddr,
) {
    let Ok((stream, _)) = listener.accept().await else {
        return;
    };
    state.data_connected.store(true, Ordering::SeqCst);

    let Ok(upstream) = TcpStream::connect(device).await else {
        return;
    };
    let (mut device_read, mut device_write) = upstream.into_split();

    let mut session = HapSession::new(&keys.output_key, &keys.input_key);
    let (mut read_half, mut write_half) = stream.into_split();

    let mut inbound = Vec::new();
    let mut from_device = Vec::new();
    let mut seqno = 0x2_0000_0000u64;
    let mut controller_chunk = [0u8; 4096];
    let mut device_chunk = [0u8; 4096];

    loop {
        // Both `read`s are cancel-safe, so losing the race consumes nothing.
        let outbound = tokio::select! {
            read = read_half.read(&mut controller_chunk) => {
                let Ok(count) = read else { return };
                if count == 0 {
                    return;
                }
                let Ok(plaintext) = session.decrypt(&controller_chunk[..count]) else {
                    return;
                };
                inbound.extend_from_slice(&plaintext);

                let Some(bytes) = forward_to_device(
                    &mut inbound, &state, &mut device_write,
                ).await else {
                    return;
                };
                bytes
            }
            read = device_read.read(&mut device_chunk) => {
                let Ok(count) = read else { return };
                if count == 0 {
                    return;
                }
                from_device.extend_from_slice(&device_chunk[..count]);
                forward_to_controller(&mut from_device, &mut seqno)
            }
        };

        if outbound.is_empty() {
            continue;
        }
        let Ok(framed) = session.encrypt(&outbound) else {
            return;
        };
        if write_half.write_all(&framed).await.is_err() {
            return;
        }
    }
}

/// Drain every complete controller frame, forwarding its payload and collecting the `rply`s owed.
///
/// `None` means the device socket died and the bridge should stop.
async fn forward_to_device(
    inbound: &mut Vec<u8>,
    state: &Arc<FakeState>,
    device: &mut tokio::net::tcp::OwnedWriteHalf,
) -> Option<Vec<u8>> {
    let mut replies = Vec::new();

    while let Some((header, payload)) = take_frame(inbound) {
        if header.message_type == MESSAGE_TYPE_REPLY {
            state.replies_seen.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        if header.message_type != MESSAGE_TYPE_SYNC {
            continue;
        }

        replies.extend_from_slice(&encode_frame(
            MESSAGE_TYPE_REPLY,
            COMMAND_NONE,
            header.seqno,
            &[],
        ));

        let Some(data) = envelope_data(&payload) else {
            continue;
        };
        state
            .mrp_received
            .lock()
            .await
            .extend(unwrap_envelope(&payload));
        // The blob is already `varint(len) ‖ message`, which is a direct-TCP MRP frame verbatim.
        device.write_all(&data).await.ok()?;
    }

    Some(replies)
}

/// Split the device's byte stream into whole frames and wrap each one for the controller.
fn forward_to_controller(from_device: &mut Vec<u8>, seqno: &mut u64) -> Vec<u8> {
    let mut out = Vec::new();

    while let Some(frame) = take_varint_frame(from_device) {
        *seqno += 1;
        out.extend_from_slice(&encode_frame(
            MESSAGE_TYPE_SYNC,
            COMMAND_COMM,
            *seqno,
            &wrap_payload(&frame),
        ));
    }

    out
}

/// Take one whole `varint(len) ‖ body` frame off the front of `buffer`, prefix included.
fn take_varint_frame(buffer: &mut Vec<u8>) -> Option<Vec<u8>> {
    let (length, consumed) = read_variant(buffer)?;
    let total = consumed + usize::try_from(length).ok()?;
    if buffer.len() < total {
        return None;
    }

    Some(buffer.drain(..total).collect())
}
