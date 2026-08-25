//! The controller's timing server.
//!
//! Port of `TimingServer` (`pyatv/protocols/raop/protocols/__init__.py:102-146`).

use std::net::IpAddr;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use crate::Result;
use crate::raop::packets::TimingPacket;
use crate::raop::timing;

use super::{DATAGRAM_LIMIT, bind, is_from_receiver};

/// The controller's timing server.
///
/// Answers every [`TimingPacket`] the receiver sends and sends nothing else. Dropping it closes
/// the socket and stops the loop.
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
    /// Bind and start answering requests from `receiver`.
    ///
    /// Datagrams from any other address are dropped — see [the module header](super) for why this
    /// is stricter than upstream.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Io`] if the socket cannot be bound.
    pub async fn start(local: IpAddr, port: u16, receiver: IpAddr) -> Result<Self> {
        let socket = bind(local, port).await?;
        let port = socket.local_addr()?.port();

        let task = tokio::spawn(async move {
            receive_loop(socket, receiver).await;
        });

        Ok(Self { port, task })
    }

    /// The local port the receiver should be told about.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Answer timing requests until the task is aborted.
async fn receive_loop(socket: UdpSocket, receiver: IpAddr) {
    let mut buffer = vec![0u8; DATAGRAM_LIMIT];

    while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
        if !is_from_receiver(from, receiver) {
            tracing::debug!(%from, %receiver, "ignoring a timing request from another host");
            continue;
        }

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
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::TimingServer;
    use crate::raop::packets::{RtpHeader, TimingPacket};

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn request() -> TimingPacket {
        TimingPacket {
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
        }
    }

    /// A real socket answers a real timing request with the fixed reply shape.
    #[tokio::test]
    async fn the_timing_server_answers_a_request() {
        let server = TimingServer::start(loopback(), 0, loopback())
            .await
            .expect("binds");
        let client = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");

        client
            .send_to(&request().encode(), (loopback(), server.port()))
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

    /// A request from anything but the receiver is dropped rather than answered, so the timing
    /// socket cannot be used as a reflector.
    #[tokio::test]
    async fn a_request_from_another_host_is_ignored() {
        // The session streams to 10.0.0.9; the request will arrive from loopback instead.
        let server = TimingServer::start(loopback(), 0, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)))
            .await
            .expect("binds");
        let stranger = tokio::net::UdpSocket::bind((loopback(), 0))
            .await
            .expect("binds");

        stranger
            .send_to(&request().encode(), (loopback(), server.port()))
            .await
            .expect("sends");

        let mut buffer = [0u8; 64];
        let outcome = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            stranger.recv(&mut buffer),
        )
        .await;

        assert!(outcome.is_err(), "the server must not answer a stranger");
    }
}
