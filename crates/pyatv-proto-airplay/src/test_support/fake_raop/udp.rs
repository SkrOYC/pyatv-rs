//! The three UDP sockets a RAOP receiver owns, and what they captured.
//!
//! Port of `FakeRaopService`'s `AudioReceiver`, `ControlReceiver` and `TimingClient`
//! (`tests/fake_device/raop.py:186-263`), with one addition: AirPlay 2 payloads are decrypted here,
//! because upstream's fixture has no AirPlay 2 path at all and simply stores whatever arrived.

use std::net::SocketAddr;
use std::sync::Arc;

use pyatv_pairing::chacha::Chacha20Cipher;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use crate::raop::packets::{
    AUDIO_HEADER_LEN, PAYLOAD_TYPE_AUDIO_FIRST, RtpHeader, SyncPacket, TimingPacket,
};

/// One audio packet as the receiver saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioFrame {
    /// RTP sequence number.
    pub seqno: u16,
    /// RTP timestamp.
    pub timestamp: u32,
    /// Whether the packet carried the `0xE0` first-packet marker.
    pub first: bool,
    /// The payload, decrypted if the stream was an AirPlay 2 one.
    pub payload: Vec<u8>,
}

/// Everything the UDP side observed.
#[derive(Debug, Default)]
pub struct UdpCapture {
    /// Audio packets, in arrival order.
    pub audio: Mutex<Vec<AudioFrame>>,
    /// Sync packets, in arrival order.
    pub sync: Mutex<Vec<SyncPacket>>,
    /// Timing requests the receiver sent and got answers to.
    pub timing_replies: Mutex<Vec<TimingPacket>>,
    /// Payloads that failed to decrypt, which should always be empty.
    pub undecryptable: Mutex<Vec<Vec<u8>>>,
}

/// A bound UDP socket and the port it landed on.
#[derive(Debug)]
pub struct BoundSocket {
    /// The socket, shared with whatever task is reading it.
    pub socket: Arc<UdpSocket>,
    /// Its loopback port.
    pub port: u16,
}

/// Bind an ephemeral loopback UDP port.
pub async fn bind() -> BoundSocket {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("binding a loopback UDP port must succeed in tests");
    let port = socket
        .local_addr()
        .expect("a bound socket must have an address")
        .port();

    BoundSocket {
        socket: Arc::new(socket),
        port,
    }
}

/// Read audio packets until the socket closes.
///
/// `AudioReceiver.datagram_received` (`raop.py:200-215`). `key` is the AirPlay 2 `shk` the
/// controller announced in its audio-stream `SETUP`; with `None` the payload is taken verbatim,
/// which is the AirPlay 1 case.
pub async fn serve_audio(socket: Arc<UdpSocket>, capture: Arc<UdpCapture>, key: Option<[u8; 32]>) {
    // A fresh cipher per stream, whose counter must advance in lockstep with the sender's — the
    // nonce is on the wire, but decrypting with the counter proves ordering as well as content.
    let mut cipher = key.map(|key| Chacha20Cipher::with_padded_counter(&key, &key));
    let mut buffer = vec![0u8; 2048];

    loop {
        let Ok(read) = socket.recv(&mut buffer).await else {
            return;
        };
        let packet = &buffer[..read];
        if packet.len() < AUDIO_HEADER_LEN {
            continue;
        }

        let Ok(header) = RtpHeader::decode(packet) else {
            continue;
        };
        let timestamp = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let aad = &packet[4..12];

        let payload = match cipher.as_mut() {
            None => packet[AUDIO_HEADER_LEN..].to_vec(),
            Some(cipher) => {
                // The trailer is the eight low bytes of the nonce the sender sealed with; the
                // ciphertext is everything between the header and it.
                if packet.len() < AUDIO_HEADER_LEN + 8 {
                    capture.undecryptable.lock().await.push(packet.to_vec());
                    continue;
                }
                let split = packet.len() - 8;
                let ciphertext = &packet[AUDIO_HEADER_LEN..split];
                let Ok(plaintext) = cipher.decrypt(ciphertext, Some(aad)) else {
                    capture.undecryptable.lock().await.push(packet.to_vec());
                    continue;
                };
                plaintext
            }
        };

        capture.audio.lock().await.push(AudioFrame {
            seqno: header.seqno,
            timestamp,
            first: header.packet_type == PAYLOAD_TYPE_AUDIO_FIRST,
            payload,
        });
    }
}

/// Read sync packets until the socket closes.
///
/// `ControlReceiver.datagram_received` (`raop.py:217-235`), minus the retransmission injection: a
/// fixture that drops packets on purpose belongs to a test that asks for it, and none does yet.
pub async fn serve_control(socket: Arc<UdpSocket>, capture: Arc<UdpCapture>) {
    let mut buffer = vec![0u8; 2048];

    loop {
        let Ok(read) = socket.recv(&mut buffer).await else {
            return;
        };
        if let Ok(packet) = SyncPacket::decode(&buffer[..read]) {
            capture.sync.lock().await.push(packet);
        }
    }
}

/// Ask the controller's timing server for the time, once a second, and record its replies.
///
/// `TimingClient` (`raop.py:237-263`), which is the one place the *receiver* is the client: the
/// controller binds the timing port and the receiver polls it.
pub async fn poll_timing(socket: Arc<UdpSocket>, capture: Arc<UdpCapture>, server: SocketAddr) {
    let request = TimingPacket {
        header: RtpHeader {
            proto: crate::raop::packets::PROTO_NORMAL,
            packet_type: 0xD2,
            seqno: crate::raop::packets::TIMING_RESPONSE_SEQNO,
        },
        padding: 0,
        reftime_sec: 0,
        reftime_frac: 0,
        recvtime_sec: 0,
        recvtime_frac: 0,
        sendtime_sec: 0x1234_5678,
        sendtime_frac: 0x9ABC_DEF0,
    }
    .encode();

    let mut buffer = vec![0u8; 2048];
    loop {
        if socket.send_to(&request, server).await.is_err() {
            return;
        }

        let Ok((read, _)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        if let Ok(packet) = TimingPacket::decode(&buffer[..read]) {
            capture.timing_replies.lock().await.push(packet);
        }

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}
