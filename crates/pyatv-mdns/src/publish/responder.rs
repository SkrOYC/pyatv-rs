//! [`Responder`]: a [`ServiceRegistration`] put on a socket.
//!
//! The transport half. Every wire decision lives in [`super::registration`]; this module only
//! decides which datagram goes where, and when.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::registration::{ANNOUNCE_COUNT, ANNOUNCE_INTERVAL, ServiceRegistration};
use crate::dns::DnsMessage;
use crate::mdns::socket::{join_group, mcast_socket, private_ipv4_addresses};
use crate::mdns::{MDNS_PORT, MULTICAST_GROUP};

/// Receive buffer size.
///
/// RFC 6762 §17 allows a multicast DNS message up to 9000 bytes on a link with a 9000-byte MTU, so
/// a smaller buffer would silently truncate a legitimate query.
const RECEIVE_BUFFER: usize = 9_000;

/// Publishes one service instance and answers queries about it.
///
/// Dropping a `Responder` stops it answering but sends no goodbye — a goodbye needs an `await`, and
/// `Drop` cannot have one. Call [`Responder::unregister`] for a clean withdrawal.
#[derive(Debug)]
pub struct Responder {
    inner: Arc<Inner>,
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Debug)]
struct Inner {
    socket: UdpSocket,
    destination: SocketAddr,
    registration: ServiceRegistration,
}

impl Responder {
    /// Publish on the real multicast group: bind `0.0.0.0:5353` and join `224.0.0.251`.
    ///
    /// The group is joined on every private IPv4 address the host has, for the same reason
    /// [`crate::mdns::multicast`] queries from all of them: a host with more than one interface
    /// otherwise answers on whichever one the kernel picked by default, which need not be the one
    /// the device is on.
    ///
    /// Announcements start immediately in the background, per RFC 6762 §8.3.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if port 5353 cannot be bound. `SO_REUSEPORT` is set
    /// where the platform has it, so coexisting with avahi-daemon or mDNSResponder normally works;
    /// where it does not, this is where that shows up.
    pub fn bind(registration: ServiceRegistration) -> io::Result<Self> {
        let socket = mcast_socket(None, MDNS_PORT)?;
        for address in private_ipv4_addresses() {
            join_group(&socket, address);
        }

        let destination = SocketAddr::V4(SocketAddrV4::new(MULTICAST_GROUP, MDNS_PORT));
        Ok(Self::with_socket(socket, destination, registration))
    }

    /// Publish on a socket the caller already has, sending multicast responses to `destination`.
    ///
    /// This is what makes the responder testable without touching the multicast group or needing
    /// privileges for port 5353: a test binds two loopback sockets, points this one's destination
    /// at the other, and reads the exact bytes that come back.
    #[must_use]
    pub fn with_socket(
        socket: UdpSocket,
        destination: SocketAddr,
        registration: ServiceRegistration,
    ) -> Self {
        let inner = Arc::new(Inner {
            socket,
            destination,
            registration,
        });

        let serving = tokio::spawn(serve(Arc::clone(&inner)));
        let announcing = tokio::spawn(announce(Arc::clone(&inner)));

        Self {
            inner,
            tasks: vec![serving, announcing],
        }
    }

    /// The service being published.
    #[must_use]
    pub fn registration(&self) -> &ServiceRegistration {
        &self.inner.registration
    }

    /// The address the responder's own socket is bound to.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the socket has no local address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.socket.local_addr()
    }

    /// Send one announcement now, rather than waiting for the background schedule.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the datagram could not be sent.
    pub async fn announce_now(&self) -> io::Result<()> {
        self.inner
            .send(
                &self.inner.registration.announcement(),
                self.inner.destination,
            )
            .await
    }

    /// Withdraw the service: multicast the goodbye records, then stop answering.
    ///
    /// RFC 6762 §10.1. A receiver that misses this still expires the records on their own TTL, so a
    /// failure to send is logged rather than propagated — but it is returned too, because a caller
    /// tearing down deliberately may want to know.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the goodbye could not be sent.
    pub async fn unregister(mut self) -> io::Result<()> {
        let goodbye = self.inner.registration.goodbye();
        let result = self.inner.send(&goodbye, self.inner.destination).await;
        self.stop();
        result
    }

    fn stop(&mut self) {
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Inner {
    async fn send(&self, message: &DnsMessage, to: SocketAddr) -> io::Result<()> {
        let bytes = message.pack();
        tracing::trace!(%to, bytes = bytes.len(), "sending mDNS response");
        self.socket.send_to(&bytes, to).await.map(|_| ())
    }

    /// Answer one received datagram, if it asks about this service.
    async fn handle(&self, datagram: &[u8], from: SocketAddr) {
        let query = match DnsMessage::unpack(datagram) {
            Ok(query) => query,
            Err(error) => {
                // Anyone on the link can send anything; a malformed datagram is not an error here.
                tracing::trace!(%from, %error, "ignoring an undecodable datagram");
                return;
            }
        };

        // RFC 6762 §6.7: a query from a port other than 5353 is a one-shot resolver, not an mDNS
        // implementation. It gets the query's own ID echoed, the question repeated, capped TTLs,
        // and the answer by unicast whether or not it set the QU bit.
        let legacy = from.port() != MDNS_PORT;
        let Some(response) = self.registration.respond(&query, legacy) else {
            return;
        };

        let unicast = legacy || self.registration.wants_unicast(&query);
        let to = if unicast { from } else { self.destination };

        if let Err(error) = self.send(&response, to).await {
            tracing::debug!(%to, %error, "could not send an mDNS response");
        }
    }
}

/// Read datagrams forever, answering the ones that concern this service.
async fn serve(inner: Arc<Inner>) {
    let mut buffer = vec![0u8; RECEIVE_BUFFER];
    loop {
        match inner.socket.recv_from(&mut buffer).await {
            Ok((length, from)) => inner.handle(&buffer[..length], from).await,
            Err(error) => {
                // A datagram socket read failing is usually transient (ICMP port-unreachable from
                // a previous send shows up here on some platforms), so this logs and continues
                // rather than ending the responder.
                tracing::debug!(%error, "mDNS responder receive failed");
                tokio::time::sleep(ANNOUNCE_INTERVAL).await;
            }
        }
    }
}

/// Send the startup announcements, RFC 6762 §8.3.
async fn announce(inner: Arc<Inner>) {
    let message = inner.registration.announcement();
    for round in 0..ANNOUNCE_COUNT {
        if round > 0 {
            tokio::time::sleep(ANNOUNCE_INTERVAL).await;
        }
        if let Err(error) = inner.send(&message, inner.destination).await {
            tracing::debug!(%error, round, "could not send an mDNS announcement");
        }
    }
}

/// The IPv4 addresses a responder should publish, excluding loopback.
///
/// pyatv's DMAP pairing handler defaults its address list to
/// `get_private_addresses(include_loopback=False)` (`pyatv/protocols/dmap/pairing.py:207`).
/// [`private_ipv4_addresses`] has no such parameter — it reproduces the `include_loopback=True`
/// call the scanner makes — so the filter lives here instead of changing that function's contract.
#[must_use]
pub fn publishable_addresses() -> Vec<Ipv4Addr> {
    private_ipv4_addresses()
        .into_iter()
        .filter(|address| !address.is_loopback())
        .collect()
}

#[cfg(test)]
mod tests;
