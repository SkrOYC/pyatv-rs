//! The event and data sockets of the fake AirPlay 2 receiver.
//!
//! Both are what `setup_channel` dials (`pyatv/auth/hap_channel.py:79-97`): the *receiver* listens,
//! the controller connects, and everything after the TCP handshake is HAP-framed with keys derived
//! from the same pair-verify shared secret.
//!
//! The framing here is deliberately hand-rolled rather than reusing the crate's own encoder. Only
//! [`crate::ap2::data_stream::DataHeader`] is shared, because it is the thing under
//! test; the property-list envelope and the varint length prefix are built independently, so a test
//! that passes is not just the implementation agreeing with itself.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::ap2::data_stream::{
    COMMAND_COMM, COMMAND_NONE, DataHeader, HEADER_LEN, MESSAGE_TYPE_REPLY, MESSAGE_TYPE_SYNC,
    PADDING,
};
use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

use super::fake_airplay::FakeState;

/// Accept one controller connection on the event port and answer as a receiver would.
///
/// If `probe` is set it is sent verbatim once the controller connects, which is how the reply path
/// of [`crate::ap2::EventChannel`] gets exercised. Whatever the controller answers is
/// recorded on the shared state.
pub async fn serve_event(
    listener: TcpListener,
    keys: SessionKeys,
    state: Arc<FakeState>,
    probe: Option<Vec<u8>>,
) {
    let Ok((stream, _)) = listener.accept().await else {
        return;
    };
    state.event_connected.store(true, Ordering::SeqCst);

    // Mirror of the controller's derivation: what it writes with, this side reads with.
    let mut session = HapSession::new(&keys.output_key, &keys.input_key);
    let (mut read_half, mut write_half) = stream.into_split();

    if let Some(probe) = probe {
        let Ok(framed) = session.encrypt(&probe) else {
            return;
        };
        if write_half.write_all(&framed).await.is_err() {
            return;
        }
    }

    let mut plaintext = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let Ok(read) = read_half.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        let Ok(decrypted) = session.decrypt(&chunk[..read]) else {
            return;
        };
        plaintext.extend_from_slice(&decrypted);

        while let Some(boundary) = find(&plaintext, b"\r\n\r\n") {
            let message = plaintext.drain(..boundary + 4).collect::<Vec<u8>>();
            state
                .event_replies
                .lock()
                .await
                .push(String::from_utf8_lossy(&message).into_owned());
        }
    }
}

/// Accept one controller connection on the data port and echo every MRP message back.
///
/// Per inbound `sync` frame the receiver does two things, in upstream's own order: acknowledge it
/// with a `rply` carrying the *same* seqno (`channels.py:153-163`), then send the payload straight
/// back inside a fresh `sync` frame of its own, which the controller must acknowledge in turn.
pub async fn serve_data(listener: TcpListener, keys: SessionKeys, state: Arc<FakeState>) {
    let Ok((stream, _)) = listener.accept().await else {
        return;
    };
    state.data_connected.store(true, Ordering::SeqCst);

    let mut session = HapSession::new(&keys.output_key, &keys.input_key);
    let (mut read_half, mut write_half) = stream.into_split();

    let mut plaintext = Vec::new();
    let mut server_seqno = 0x2_0000_0000u64;

    loop {
        let mut chunk = [0u8; 4096];
        let Ok(read) = read_half.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        let Ok(decrypted) = session.decrypt(&chunk[..read]) else {
            return;
        };
        plaintext.extend_from_slice(&decrypted);

        while let Some((header, payload)) = take_frame(&mut plaintext) {
            if header.message_type == MESSAGE_TYPE_REPLY {
                state.replies_seen.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            if header.message_type != MESSAGE_TYPE_SYNC {
                continue;
            }

            let messages = unwrap_envelope(&payload);
            state.mrp_received.lock().await.extend(messages.clone());

            let mut out = encode_frame(MESSAGE_TYPE_REPLY, COMMAND_NONE, header.seqno, &[]);
            for message in messages {
                server_seqno += 1;
                out.extend_from_slice(&encode_frame(
                    MESSAGE_TYPE_SYNC,
                    COMMAND_COMM,
                    server_seqno,
                    &wrap_envelope(&message),
                ));
            }

            let Ok(framed) = session.encrypt(&out) else {
                return;
            };
            if write_half.write_all(&framed).await.is_err() {
                return;
            }
        }
    }
}

/// Take one complete data frame off the front of `buffer`.
pub(super) fn take_frame(buffer: &mut Vec<u8>) -> Option<(DataHeader, Vec<u8>)> {
    if buffer.len() < HEADER_LEN {
        return None;
    }
    let header = DataHeader::decode(buffer).ok()?;
    let size = header.size as usize;
    if buffer.len() < size {
        return None;
    }

    let frame: Vec<u8> = buffer.drain(..size).collect();
    Some((header, frame[HEADER_LEN..].to_vec()))
}

/// Build a frame header plus payload, independently of the crate's encoder.
pub(super) fn encode_frame(
    message_type: [u8; 12],
    command: [u8; 4],
    seqno: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(
        &DataHeader {
            size: u32::try_from(HEADER_LEN + payload.len()).expect("a plausible frame size"),
            message_type,
            command,
            seqno,
            padding: PADDING,
        }
        .encode(),
    );
    out.extend_from_slice(payload);
    out
}

/// `{"params": {"data": <varint-prefixed message>}}`, built here rather than borrowed.
pub(super) fn wrap_envelope(message: &[u8]) -> Vec<u8> {
    let mut data = write_variant(message.len() as u64);
    data.extend_from_slice(message);
    wrap_payload(&data)
}

/// `{"params": {"data": <blob>}}` with the blob taken verbatim.
///
/// The bridge in [`super::fake_bridge`] forwards whole `data` fields rather than individual
/// messages, so it needs the envelope without the length prefixing [`wrap_envelope`] applies.
pub(super) fn wrap_payload(data: &[u8]) -> Vec<u8> {
    let data = data.to_vec();

    let mut params = plist::Dictionary::new();
    params.insert("data".to_owned(), plist::Value::Data(data));
    let mut body = plist::Dictionary::new();
    body.insert("params".to_owned(), plist::Value::Dictionary(params));

    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &plist::Value::Dictionary(body)).expect("encodes");
    out
}

/// Pull the raw `params.data` blob back out of an envelope.
pub(super) fn envelope_data(payload: &[u8]) -> Option<Vec<u8>> {
    let value = plist::from_bytes::<plist::Value>(payload).ok()?;

    value
        .as_dictionary()?
        .get("params")?
        .as_dictionary()?
        .get("data")?
        .as_data()
        .map(<[u8]>::to_vec)
}

/// Pull every message back out of an envelope, applying the same `0x08` heuristic upstream does.
pub(super) fn unwrap_envelope(payload: &[u8]) -> Vec<Vec<u8>> {
    let Some(data) = envelope_data(payload) else {
        return Vec::new();
    };

    let mut messages = Vec::new();
    let mut rest = &data[..];
    while !rest.is_empty() {
        if rest[0] == 0x08 {
            messages.push(rest.to_vec());
            break;
        }
        let Some((length, consumed)) = read_variant(rest) else {
            break;
        };
        let end = consumed + usize::try_from(length).unwrap_or(usize::MAX);
        let Some(message) = rest.get(consumed..end) else {
            break;
        };
        messages.push(message.to_vec());
        rest = &rest[end..];
    }
    messages
}

pub(super) fn write_variant(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let group = u8::try_from(value & 0x7F).expect("masked to seven bits");
        value >>= 7;
        if value == 0 {
            out.push(group);
            return out;
        }
        out.push(group | 0x80);
    }
}

pub(super) fn read_variant(input: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    for (index, byte) in input.iter().take(10).enumerate() {
        result |= u64::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            return Some((result, index + 1));
        }
    }
    None
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Bind a fresh loopback listener and report its port.
pub async fn bind_loopback() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback port must succeed in tests");
    let port = listener
        .local_addr()
        .expect("a bound listener must have an address")
        .port();
    (listener, port)
}

/// Connect to a listener the way a controller would, for scaffolding that needs a raw socket.
pub async fn dial(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("loopback connect must succeed in tests")
}
