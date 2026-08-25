//! The three UDP sockets a RAOP session runs alongside its RTSP connection.
//!
//! Port of `TimingServer` (`pyatv/protocols/raop/protocols/__init__.py:102-146`), `ControlClient`
//! (`stream_client.py:63-175`) and the throwaway `AudioProtocol` endpoint `send_audio` creates
//! (`stream_client.py:178-201, 390-393`).
//!
//! The three are independent and point in different directions, which is the part worth stating
//! plainly:
//!
//! - **Timing** is receiver-initiated. The controller binds a socket, tells the receiver its port
//!   in `SETUP`, and answers whatever timing requests arrive. It never sends unprompted.
//! - **Control** is controller-initiated. The controller pushes a sync packet to the receiver's
//!   control port once a second, and separately listens on its own control socket for
//!   retransmission requests.
//! - **Audio** is write-only. Nothing ever arrives on it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::Result;
use crate::raop::context::SharedContext;
use crate::raop::fifo::PacketFifo;
use crate::raop::packets::{
    PAYLOAD_TYPE_RETRANSMIT_REQUEST, PROTO_MARKER, PROTO_NORMAL, RetransmitRequest, RtpHeader,
    SyncPacket, TimingPacket, retransmit_response,
};
use crate::raop::timing;

use std::sync::Mutex;
use std::time::Duration;

/// How often a sync packet is pushed to the receiver.
///
/// `await asyncio.sleep(1.0)` with the source comment "Very low granularity here"
/// (`stream_client.py:130`).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(1);

/// Largest datagram either receive loop will accept. A retransmission response carries a full
/// audio packet plus two headers, which is the biggest thing on any of these sockets.
const DATAGRAM_LIMIT: usize = 2048;

/// Bind a UDP socket on `local` at `port`, letting the OS choose when `port` is zero.
///
/// `settings.protocols.raop.control_port`/`timing_port` both default to `0`
/// (`stream_client.py:311-322`).
async fn bind(local: IpAddr, port: u16) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(SocketAddr::new(local, port)).await?)
}

/// The controller's timing server.
///
/// Answers every [`TimingPacket`] it receives and sends nothing else. Dropping it closes the
/// socket and stops the loop.
#[derive(Debug)]
pub struct TimingServer {
    port: u16,
    task: JoinHandle<()>,
}

impl Drop for TimingServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TimingServer {
    /// Bind and start answering.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket cannot be bound.
    pub async fn start(local: IpAddr, port: u16) -> Result<Self> {
        let socket = bind(local, port).await?;
        let port = socket.local_addr()?.port();

        let task = tokio::spawn(async move {
            let mut buffer = vec![0u8; DATAGRAM_LIMIT];
            while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
                let Ok(request) = TimingPacket::decode(&buffer[..read]) else {
                    tracing::debug!(%from, read, "ignoring a malformed timing packet");
                    continue;
                };

                let (now_sec, now_frac) = timing::ntp2parts(timing::ntp_now());
                let reply = request.respond(now_sec, now_frac).encode();
                if let Err(error) = socket.send_to(&reply, from).await {
                    tracing::debug!(%from, %error, "timing reply failed");
                }
            }
        });

        Ok(Self { port, task })
    }

    /// The local port the receiver should be told about.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// The controller's control socket: sync packets out, retransmission requests in.
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
    /// Bind the control socket and start listening for retransmission requests.
    ///
    /// The listener starts immediately; the sync task does not, because it needs the receiver's
    /// control port, which only the audio-stream `SETUP` reply carries.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket cannot be bound.
    pub async fn start(local: IpAddr, port: u16) -> Result<Self> {
        let socket = Arc::new(bind(local, port).await?);
        let port = socket.local_addr()?.port();
        let backlog = Arc::new(Mutex::new(PacketFifo::default()));

        let listening = Arc::clone(&socket);
        let listening_backlog = Arc::clone(&backlog);
        let receive_task = tokio::spawn(async move {
            receive_loop(listening, listening_backlog).await;
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
    pub fn remember(&self, seqno: u16, packet: Vec<u8>) {
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

/// Answer retransmission requests out of the backlog.
///
/// `ControlClient.datagram_received`/`_retransmit_lost_packets` (`stream_client.py:137-170`): the
/// request's type byte is matched with the marker bit masked off, and a sequence number that is no
/// longer in the backlog is skipped silently rather than reported.
async fn receive_loop(socket: Arc<UdpSocket>, backlog: Arc<Mutex<PacketFifo>>) {
    let mut buffer = vec![0u8; DATAGRAM_LIMIT];

    while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
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

        for offset in 0..request.lost_packets {
            let seqno = request.lost_seqno.wrapping_add(offset);
            let cached = {
                let backlog = backlog
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                backlog.get(seqno).map(<[u8]>::to_vec)
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

/// The write-only audio socket.
///
/// Upstream creates this with `remote_addr=` and then calls `transport.sendto(packet)` with no
/// address, i.e. it is a *connected* UDP socket (`stream_client.py:390-393`). Reproduced with
/// [`UdpSocket::connect`] so the same "send with no destination" call shape works.
#[derive(Debug)]
pub struct AudioSender {
    socket: UdpSocket,
}

impl AudioSender {
    /// Connect a socket to the receiver's audio port.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket cannot be bound or connected.
    pub async fn connect(local: IpAddr, destination: SocketAddr) -> Result<Self> {
        let socket = bind(local, 0).await?;
        socket.connect(destination).await?;
        Ok(Self { socket })
    }

    /// Send one packet.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the datagram could not be handed to the kernel.
    pub async fn send(&self, packet: &[u8]) -> Result<()> {
        self.socket.send(packet).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{AudioSender, ControlClient, SYNC_INTERVAL, TimingServer, sync_packet};
    use crate::raop::context::{SharedContext, StreamContext};
    use crate::raop::packets::{
        PAYLOAD_TYPE_SYNC, PROTO_MARKER, PROTO_NORMAL, RetransmitRequest, RtpHeader, SyncPacket,
        TimingPacket,
    };
    use crate::raop::timing;

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    #[test]
    fn the_sync_interval_is_one_second() {
        assert_eq!(SYNC_INTERVAL.as_secs(), 1);
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

    /// A real socket answers a real timing request with the fixed reply shape.
    #[tokio::test]
    async fn the_timing_server_answers_a_request() {
        let server = TimingServer::start(loopback(), 0).await.expect("binds");
        let client = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");

        let request = TimingPacket {
            header: RtpHeader {
                proto: 0x80,
                packet_type: 0x52,
                seqno: 0,
            },
            padding: 0,
            reftime_sec: 0,
            reftime_frac: 0,
            recvtime_sec: 0,
            recvtime_frac: 0,
            sendtime_sec: 111,
            sendtime_frac: 222,
        };
        client
            .send_to(&request.encode(), (loopback(), server.port()))
            .await
            .expect("sends");

        let mut buffer = [0u8; 64];
        let read =
            tokio::time::timeout(std::time::Duration::from_secs(2), client.recv(&mut buffer))
                .await
                .expect("the server answers")
                .expect("reads");

        let reply = TimingPacket::decode(&buffer[..read]).expect("decodes");
        assert_eq!(reply.header.packet_type, 0xD3);
        assert_eq!(reply.header.seqno, 7);
        assert_eq!((reply.reftime_sec, reply.reftime_frac), (111, 222));
        assert_eq!(reply.recvtime_sec, reply.sendtime_sec);
    }

    /// A request for a packet still in the backlog is answered with the cached bytes, prefixed.
    #[tokio::test]
    async fn a_retransmit_request_is_answered_from_the_backlog() {
        let control = ControlClient::start(loopback(), 0).await.expect("binds");
        let cached = [0x80, 0x60, 0x00, 0x2A, 0xDE, 0xAD, 0xBE, 0xEF];
        control.remember(42, cached.to_vec());

        let receiver = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");
        let request = RetransmitRequest {
            header: RtpHeader {
                proto: 0x80,
                packet_type: 0xD5,
                seqno: 0,
            },
            lost_seqno: 42,
            lost_packets: 1,
        };
        receiver
            .send_to(&request.encode(), (loopback(), control.port()))
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

        let mut control = ControlClient::start(loopback(), 0).await.expect("binds");
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

    /// The audio socket is connected, so a bare `send` reaches the receiver.
    #[tokio::test]
    async fn the_audio_socket_sends_without_an_address() {
        let receiver = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");
        let destination = receiver.local_addr().expect("bound");

        let sender = AudioSender::connect(loopback(), destination)
            .await
            .expect("connects");
        sender.send(b"hello").await.expect("sends");

        let mut buffer = [0u8; 16];
        let read = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            receiver.recv(&mut buffer),
        )
        .await
        .expect("arrives")
        .expect("reads");

        assert_eq!(&buffer[..read], b"hello");
    }
}
