//! The controller's control socket: sync packets out, retransmission requests in.
//!
//! Port of `ControlClient` (`pyatv/protocols/raop/stream_client.py:63-175`).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::Result;
use crate::raop::context::SharedContext;
use crate::raop::fifo::{PACKET_BACKLOG_SIZE, PacketFifo};
use crate::raop::packets::{
    PAYLOAD_TYPE_RETRANSMIT_REQUEST, PROTO_MARKER, PROTO_NORMAL, RetransmitRequest, RtpHeader,
    SyncPacket, retransmit_response,
};
use crate::raop::timing;

use super::{DATAGRAM_LIMIT, bind, is_from_receiver};

/// How often a sync packet is pushed to the receiver.
///
/// `await asyncio.sleep(1.0)` with the source comment "Very low granularity here"
/// (`stream_client.py:130`).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// The control socket, its backlog and its two tasks.
#[derive(Debug)]
pub struct ControlClient {
    socket: Arc<UdpSocket>,
    port: u16,
    backlog: Arc<Mutex<PacketFifo>>,
    receive_task: JoinHandle<()>,
    sync_task: Option<JoinHandle<()>>,
}

impl Drop for ControlClient {
    fn drop(&mut self) {
        self.receive_task.abort();
        if let Some(sync) = self.sync_task.take() {
            sync.abort();
        }
    }
}

impl ControlClient {
    /// Bind the control socket and start listening for retransmission requests from `receiver`.
    ///
    /// The listener starts immediately; the sync task does not, because it needs the receiver's
    /// control port, which only the audio-stream `SETUP` reply carries.
    ///
    /// Datagrams from any address other than `receiver` are dropped — see
    /// [the module header](super) for why this is stricter than upstream.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket cannot be bound.
    pub async fn start(local: IpAddr, port: u16, receiver: IpAddr) -> Result<Self> {
        let socket = Arc::new(bind(local, port).await?);
        let port = socket.local_addr()?.port();
        let backlog = Arc::new(Mutex::new(PacketFifo::default()));

        let listening = Arc::clone(&socket);
        let listening_backlog = Arc::clone(&backlog);
        let receive_task = tokio::spawn(async move {
            receive_loop(listening, listening_backlog, receiver).await;
        });

        Ok(Self {
            socket,
            port,
            backlog,
            receive_task,
            sync_task: None,
        })
    }

    /// The local port the receiver should be told about.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Record a sent packet so it can be resent if the receiver asks.
    pub fn remember(&self, seqno: u16, packet: impl Into<Bytes>) {
        self.locked_backlog().insert(seqno, packet);
    }

    /// Drop the whole backlog.
    pub fn clear_backlog(&self) {
        self.locked_backlog().clear();
    }

    /// Start pushing sync packets to `destination` once a second.
    ///
    /// `ControlClient.start` (`stream_client.py:84-101`), called from `send_audio` immediately
    /// after the audio socket is created — that is, **before** `RECORD` and `FLUSH`, so sync
    /// packets are already flowing when playback formally begins.
    ///
    /// Calling it twice replaces the running task, where upstream raises `RuntimeError`.
    pub fn start_sync(&mut self, destination: SocketAddr, context: SharedContext) {
        if let Some(previous) = self.sync_task.take() {
            previous.abort();
        }

        let socket = Arc::clone(&self.socket);
        self.sync_task = Some(tokio::spawn(async move {
            sync_loop(socket, destination, context).await;
        }));
    }

    /// Stop the sync task without closing the socket.
    pub fn stop_sync(&mut self) {
        if let Some(sync) = self.sync_task.take() {
            sync.abort();
        }
    }

    /// The backlog lock, recovered from poisoning — every critical section is one map operation.
    fn locked_backlog(&self) -> std::sync::MutexGuard<'_, PacketFifo> {
        self.backlog
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Build one sync packet from the current context.
///
/// Split out so the field mapping can be asserted without a socket. `first` selects the marker-bit
/// `proto` byte the first packet of a stream carries (`stream_client.py:104-112`).
#[must_use]
pub fn sync_packet(context: &crate::raop::context::StreamContext, first: bool) -> SyncPacket {
    let current_time = timing::ts2ntp(context.head_ts, context.audio.sample_rate);
    let (last_sync_sec, last_sync_frac) = timing::ntp2parts(current_time);

    SyncPacket {
        proto: if first { PROTO_MARKER } else { PROTO_NORMAL },
        now_without_latency: context.rtptime_without_latency(),
        last_sync_sec,
        last_sync_frac,
        now: context.rtptime(),
    }
}

/// Push a sync packet every [`SYNC_INTERVAL`] until the task is aborted.
async fn sync_loop(socket: Arc<UdpSocket>, destination: SocketAddr, context: SharedContext) {
    tracing::debug!(%destination, "starting periodic sync task");
    let mut first = true;

    loop {
        let packet = sync_packet(&context.snapshot(), first).encode();
        first = false;

        if let Err(error) = socket.send_to(&packet, destination).await {
            tracing::debug!(%destination, %error, "sync packet failed");
        }

        tokio::time::sleep(SYNC_INTERVAL).await;
    }
}

/// The most packets one request will ever be answered with.
///
/// `lost_packets` is a wire-supplied `u16`, so a request can ask for 65535 packets. The backlog
/// only ever holds [`PACKET_BACKLOG_SIZE`] of them, so every iteration past that is guaranteed to
/// miss — the clamp turns 64535 pointless lookups into none. Upstream has no equivalent because
/// its `for i in range(request.lost_packets)` costs a dict miss per iteration and it never
/// considered the request hostile.
#[allow(
    clippy::cast_possible_truncation,
    reason = "PACKET_BACKLOG_SIZE is the literal 1000; `u32::try_from` is not const"
)]
const MAX_RETRANSMIT_RESPONSES: u32 = PACKET_BACKLOG_SIZE as u32;

/// Answer retransmission requests out of the backlog.
///
/// `ControlClient.datagram_received`/`_retransmit_lost_packets` (`stream_client.py:137-170`): the
/// request's type byte is matched with the marker bit masked off, and a sequence number that is no
/// longer in the backlog is skipped silently rather than reported.
///
/// # Divergences
///
/// - Datagrams from anything but the receiver are dropped; see [the module header](super).
/// - The walk is clamped to [`MAX_RETRANSMIT_RESPONSES`].
/// - The sequence number is advanced with [`u16::wrapping_add`], where upstream computes
///   `request.lost_seqno + i` in Python's unbounded integers and then looks that up. Past 65535
///   upstream therefore looks up 65536, 65537 … which can never be in a backlog keyed by 16-bit
///   sequence numbers, so a request that straddles the wrap silently loses its tail there and is
///   answered in full here. Wrapping is what the RTP sequence number actually does
///   (`stream_client.py:601`), so this is a fix rather than a divergence to preserve.
async fn receive_loop(socket: Arc<UdpSocket>, backlog: Arc<Mutex<PacketFifo>>, receiver: IpAddr) {
    let mut buffer = vec![0u8; DATAGRAM_LIMIT];

    while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
        if !is_from_receiver(from, receiver) {
            tracing::debug!(%from, %receiver, "ignoring control data from another host");
            continue;
        }

        let data = &buffer[..read];
        let Ok(header) = RtpHeader::decode(data) else {
            continue;
        };
        if header.masked_type() != PAYLOAD_TYPE_RETRANSMIT_REQUEST {
            tracing::debug!(%from, packet_type = header.packet_type, "unhandled control data");
            continue;
        }

        let Ok(request) = RetransmitRequest::decode(data) else {
            tracing::debug!(%from, read, "ignoring a malformed retransmit request");
            continue;
        };

        let wanted = u32::from(request.lost_packets).min(MAX_RETRANSMIT_RESPONSES);
        if u32::from(request.lost_packets) > wanted {
            tracing::debug!(
                %from,
                asked = request.lost_packets,
                answering = wanted,
                "clamping an oversized retransmit request to the backlog size"
            );
        }

        for offset in 0..wanted {
            #[allow(
                clippy::cast_possible_truncation,
                reason = "the loop is bounded by MAX_RETRANSMIT_RESPONSES, far below u16::MAX"
            )]
            let seqno = request.lost_seqno.wrapping_add(offset as u16);
            let cached = {
                let backlog = backlog
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                backlog.get(seqno)
            };

            let Some(cached) = cached else {
                tracing::debug!(seqno, "packet not in backlog");
                continue;
            };
            let Ok(response) = retransmit_response(&cached) else {
                continue;
            };
            if let Err(error) = socket.send_to(&response, from).await {
                tracing::debug!(%from, %error, "retransmission failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{ControlClient, MAX_RETRANSMIT_RESPONSES, SYNC_INTERVAL, sync_packet};
    use crate::raop::context::{SharedContext, StreamContext};
    use crate::raop::fifo::PACKET_BACKLOG_SIZE;
    use crate::raop::packets::{
        PAYLOAD_TYPE_SYNC, PROTO_MARKER, PROTO_NORMAL, RetransmitRequest, RtpHeader, SyncPacket,
    };
    use crate::raop::timing;

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn retransmit(lost_seqno: u16, lost_packets: u16) -> RetransmitRequest {
        RetransmitRequest {
            header: RtpHeader {
                proto: 0x80,
                packet_type: 0xD5,
                seqno: 0,
            },
            lost_seqno,
            lost_packets,
        }
    }

    #[test]
    fn the_sync_interval_is_one_second() {
        assert_eq!(SYNC_INTERVAL.as_secs(), 1);
    }

    #[test]
    fn the_retransmit_clamp_is_the_backlog_size() {
        assert_eq!(MAX_RETRANSMIT_RESPONSES as usize, PACKET_BACKLOG_SIZE);
    }

    /// The first packet sets the marker bit; every later one does not, and the sequence number is
    /// the fixed `7` in both.
    #[test]
    fn the_first_sync_packet_is_the_only_one_with_the_marker_bit() {
        let mut context = StreamContext::default();
        context.reset();

        assert_eq!(sync_packet(&context, true).proto, PROTO_MARKER);
        assert_eq!(sync_packet(&context, false).proto, PROTO_NORMAL);

        let encoded = sync_packet(&context, true).encode();
        assert_eq!(encoded[1], PAYLOAD_TYPE_SYNC);
        assert_eq!(&encoded[2..4], &[0x00, 0x07]);
    }

    /// The wall-clock half is derived from `head_ts`, so it advances as audio is sent.
    #[test]
    fn the_sync_timestamps_follow_the_head_clock() {
        let mut context = StreamContext::default();
        context.reset();

        let first = sync_packet(&context, true);
        context.advance(44_100);
        let second = sync_packet(&context, false);

        assert_eq!(second.now_without_latency, 44_100);
        assert_eq!(second.now, first.now + 44_100);
        assert_eq!(second.last_sync_sec, first.last_sync_sec + 1);
        assert_eq!(
            timing::ntp2parts(timing::ts2ntp(context.head_ts, 44_100)),
            (second.last_sync_sec, second.last_sync_frac)
        );
    }

    /// A request for a packet still in the backlog is answered with the cached bytes, prefixed.
    #[tokio::test]
    async fn a_retransmit_request_is_answered_from_the_backlog() {
        let control = ControlClient::start(loopback(), 0, loopback())
            .await
            .expect("binds");
        let cached = [0x80, 0x60, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF];
        control.remember(42, cached.to_vec());

        let receiver = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");
        receiver
            .send_to(&retransmit(42, 1).encode(), (loopback(), control.port()))
            .await
            .expect("sends");

        let mut buffer = [0u8; 64];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv(&mut buffer),
        )
        .await
        .expect("the client answers")
        .expect("reads");

        assert_eq!(&buffer[..4], &[0x80, 0xD6, 0x00, 0x2A]);
        assert_eq!(&buffer[4..read], &cached);
    }

    /// The same request from a host that is not the receiver gets nothing, so the control socket
    /// cannot be used to reflect a session's audio at a third party.
    #[tokio::test]
    async fn a_retransmit_request_from_another_host_is_ignored() {
        // The session streams to 10.0.0.9; the request will arrive from loopback instead.
        let control = ControlClient::start(loopback(), 0, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))
            .await
            .expect("binds");
        control.remember(42, vec![0x80, 0x60, 0x00, 0x2A]);

        let stranger = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");
        stranger
            .send_to(&retransmit(42, 1).encode(), (loopback(), control.port()))
            .await
            .expect("sends");

        let mut buffer = [0u8; 64];
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            stranger.recv(&mut buffer),
        )
        .await;

        assert!(outcome.is_err(), "the client must not answer a stranger");
    }

    /// A request for every sequence number there is is answered from the backlog only, and the
    /// walk stops at the backlog size rather than iterating 65535 times.
    #[tokio::test]
    async fn an_oversized_retransmit_request_is_clamped() {
        let control = ControlClient::start(loopback(), 0, loopback())
            .await
            .expect("binds");
        // Two packets, at the two ends of the clamped window. Sequence number 1200 is inside the
        // *unclamped* window and outside the clamped one, so it must never come back.
        control.remember(0, vec![0x80, 0x60, 0x00, 0x00]);
        control.remember(999, vec![0x80, 0x60, 0x03, 0xE7]);
        control.remember(1200, vec![0x80, 0x60, 0x04, 0xB0]);

        let receiver = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");
        receiver
            .send_to(
                &retransmit(0, u16::MAX).encode(),
                (loopback(), control.port()),
            )
            .await
            .expect("sends");

        let mut seen = Vec::new();
        let mut buffer = [0u8; 64];
        while let Ok(Ok(read)) = tokio::time::timeout(
            std::time::Duration::from_millis(400),
            receiver.recv(&mut buffer),
        )
        .await
        {
            seen.push(buffer[..read].to_vec());
        }

        assert_eq!(seen.len(), 2, "only the two in-window packets come back");
        assert_eq!(&seen[0][..4], &[0x80, 0xD6, 0x00, 0x00]);
        assert_eq!(&seen[1][..4], &[0x80, 0xD6, 0x03, 0xE7]);
    }

    /// The sync task really does push a packet as soon as it starts, before the first sleep.
    #[tokio::test]
    async fn the_sync_task_pushes_immediately() {
        let receiver = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");
        let destination = receiver.local_addr().expect("bound");

        let mut context = StreamContext::default();
        context.reset();
        let shared = SharedContext::new(context);

        let mut control = ControlClient::start(loopback(), 0, loopback())
            .await
            .expect("binds");
        control.start_sync(destination, shared);

        let mut buffer = [0u8; 64];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv(&mut buffer),
        )
        .await
        .expect("a sync packet arrives")
        .expect("reads");

        let packet = SyncPacket::decode(&buffer[..read]).expect("decodes");
        assert_eq!(packet.proto, PROTO_MARKER);
        assert_eq!(packet.now_without_latency, 0);
    }
}
