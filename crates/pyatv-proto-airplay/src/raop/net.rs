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
//!
//! # Divergence: both receive loops answer only the receiver
//!
//! Neither of these sockets is authenticated and neither datagram format carries anything a
//! forger would have to guess — the retransmit request is six bytes of which two are constant, and
//! a timing request is a fixed shape with no session token in it. Upstream replies to whatever
//! address the datagram came from (`stream_client.py:146-183`: `datagram_received(self, data,
//! addr)` hands `addr` straight to `sendto`), which turns a controller into a small reflector: an
//! off-path host can ask for a thousand cached audio packets and have them sent to itself, or
//! spray timing replies out of it.
//!
//! This port checks the source address against the receiver the session is actually streaming to
//! and drops anything else. It is deliberately stricter than upstream. The comparison is on the
//! **IP only**, not the port, because a receiver answers from an ephemeral source port that
//! nothing in `SETUP` announces — matching the port too would drop legitimate traffic. That still
//! leaves a same-host or on-path attacker able to elicit a reply, which no amount of address
//! checking fixes; it removes the trivially remote case, which is the one worth removing.

pub mod control;
pub mod timing_server;

use std::net::{IpAddr, SocketAddr};

use tokio::net::UdpSocket;

use crate::Result;

pub use control::{ControlClient, SYNC_INTERVAL, sync_packet};
pub use timing_server::TimingServer;

/// Largest datagram either receive loop will accept. A retransmission response carries a full
/// audio packet plus two headers, which is the biggest thing on any of these sockets.
pub(crate) const DATAGRAM_LIMIT: usize = 2048;

/// Bind a UDP socket on `local` at `port`, letting the OS choose when `port` is zero.
///
/// `settings.protocols.raop.control_port`/`timing_port` both default to `0`
/// (`stream_client.py:311-322`).
pub(crate) async fn bind(local: IpAddr, port: u16) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(SocketAddr::new(local, port)).await?)
}

/// Whether a datagram that arrived from `from` should be answered.
///
/// See this module's header: the IP has to be the receiver's, the source port is not checked.
pub(crate) fn is_from_receiver(from: SocketAddr, receiver: IpAddr) -> bool {
    from.ip() == receiver
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

    use super::{AudioSender, is_from_receiver};

    fn loopback() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    /// Any source port from the receiver's IP is accepted; any other IP is not.
    #[test]
    fn only_the_receivers_ip_is_accepted_whatever_its_port() {
        let receiver = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

        assert!(is_from_receiver(
            "10.0.0.9:6001".parse().expect("addr"),
            receiver
        ));
        assert!(is_from_receiver(
            "10.0.0.9:54321".parse().expect("addr"),
            receiver
        ));
        assert!(!is_from_receiver(
            "10.0.0.8:6001".parse().expect("addr"),
            receiver
        ));
        assert!(!is_from_receiver(
            "127.0.0.1:6001".parse().expect("addr"),
            receiver
        ));
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
