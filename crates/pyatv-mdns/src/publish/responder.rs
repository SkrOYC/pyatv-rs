//! [`Responder`]: a [`ServiceRegistration`] put on a socket.
//!
//! The transport half. Every wire decision lives in [`super::registration`]; this module only
//! decides which datagram goes where, and when.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

use super::registration::{ANNOUNCE_COUNT, ANNOUNCE_INTERVAL, ServiceRegistration};
use crate::dns::{DnsMessage, DnsResource, QueryType, RecordData};
use crate::mdns::socket::{mcast_responder_socket, private_ipv4_addresses};
use crate::mdns::{MDNS_PORT, MULTICAST_GROUP};

/// Receive buffer size.
///
/// RFC 6762 §17 allows a multicast DNS message up to 9000 bytes on a link with a 9000-byte MTU, so
/// a smaller buffer would silently truncate a legitimate query.
const RECEIVE_BUFFER: usize = 9_000;

/// How long a record must rest between multicasts, RFC 6762 §6.
///
/// "A Multicast DNS responder MUST NOT (except in the one special case of answering probe queries)
/// multicast a record on a given interface until at least one second has elapsed since the last
/// time that record was multicast on that particular interface." One responder here owns one
/// interface, so "on that particular interface" is "by this responder".
///
/// Without it, every querier on a busy link that asks the same question inside the same second gets
/// its own copy of the same four records multicast to everyone.
pub const MULTICAST_RATE_LIMIT: Duration = Duration::from_secs(1);

/// The fraction of a record's TTL inside which a multicast still counts as "recent", RFC 6762 §5.4.
///
/// A `QU` question is answered by unicast only when every record it asks for has been multicast
/// within `TTL / QU_RECENT_TTL_FRACTION`. Otherwise the answer goes to the group instead, so that
/// caches other than the querier's are refreshed too.
pub const QU_RECENT_TTL_FRACTION: u32 = 4;

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
    multicast_log: MulticastLog,
}

impl Responder {
    /// Publish on the real multicast group from one interface: bind `0.0.0.0:5353`, point
    /// `IP_MULTICAST_IF` at `address`, and join `224.0.0.251` on it.
    ///
    /// Transmission is pinned to one interface and reception is not, and the split is deliberate.
    ///
    /// `IP_MULTICAST_IF` is what makes the outbound half correct: a socket without it sends its
    /// multicasts out of whichever interface the kernel's routing table picks by default, which on
    /// a host with more than one is quite likely not the one the Apple TV is on — and the responder
    /// would then be announcing an `A` record for an address unreachable from where the
    /// announcement arrived.
    ///
    /// The **bind**, though, must stay on the wildcard. A socket bound to `address` never receives
    /// a datagram sent to the group on Linux, because `__udp_is_mcast_sock()` compares the socket's
    /// `inet_rcv_saddr` against the datagram's destination — `224.0.0.251` — and drops the socket
    /// from delivery when a non-zero `inet_rcv_saddr` differs from it. Binding `address:5353` here
    /// is what made an Apple TV's `_touch-remote._tcp.local` browse query invisible and DMAP
    /// pairing along with it. [`mcast_responder_socket`] documents the kernel predicate in full;
    /// read it before changing this line.
    ///
    /// One responder therefore publishes **one** address, and `registration` should carry that one
    /// and no other; a caller with several interfaces builds one responder per interface, which is
    /// what [`crate::publish`]'s only caller does. Those responders all share port 5353 through
    /// `SO_REUSEPORT` and all see the whole host's group traffic, so a query arriving on one link is
    /// answered out of every link — each with its own `A` record, which is what an mDNS responder on
    /// a multi-homed host is supposed to do anyway.
    ///
    /// Announcements start immediately in the background, per RFC 6762 §8.3.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if `0.0.0.0:5353` cannot be bound. `SO_REUSEPORT` is
    /// set where the platform has it, so coexisting with avahi-daemon or mDNSResponder normally
    /// works; where it does not, this is where that shows up.
    pub fn bind(address: Ipv4Addr, registration: ServiceRegistration) -> io::Result<Self> {
        let socket = mcast_responder_socket(address, MDNS_PORT)?;
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
            multicast_log: MulticastLog::default(),
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
            .multicast(&self.inner.registration.announcement())
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
        let result = self.inner.multicast(&goodbye).await;
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
    /// Send to one address, no rate limiting: this is the unicast and announcement path.
    async fn send(&self, message: &DnsMessage, to: SocketAddr) -> io::Result<()> {
        let bytes = message.pack();
        tracing::trace!(%to, bytes = bytes.len(), "sending mDNS response");
        self.socket.send_to(&bytes, to).await.map(|_| ())
    }

    /// Multicast a message and record when each of its records went out.
    ///
    /// The record keeps [`MulticastLog`] honest for the §6 rate limit and the §5.4 `QU` decision.
    /// Announcements and goodbyes go through here too — they are multicasts of the same records,
    /// and pretending otherwise would make the responder think a freshly announced record had
    /// never been on the wire.
    async fn multicast(&self, message: &DnsMessage) -> io::Result<()> {
        let result = self.send(message, self.destination).await;
        if result.is_ok() {
            self.multicast_log
                .record(message.answers.iter().chain(&message.resources));
        }
        result
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
        // no cache-flush bits, and the answer by unicast whether or not it set the QU bit.
        let legacy = from.port() != MDNS_PORT;
        let Some(mut response) = self.registration.respond(&query, legacy) else {
            return;
        };

        if legacy {
            // A legacy-unicast answer reaches one resolver's cache and nobody else's, so neither
            // the §6 rate limit nor the §5.4 recency rule applies, and it is not recorded as a
            // multicast because it was not one.
            if let Err(error) = self.send(&response, from).await {
                tracing::debug!(to = %from, %error, "could not send a legacy mDNS response");
            }
            return;
        }

        // RFC 6762 §5.4: the QU bit asks for a unicast reply, and is honoured — but only while the
        // records are still fresh in everyone else's cache. If any of them has not been multicast
        // within a quarter of its TTL, the answer is multicast instead, so that one querier's
        // question refreshes the whole link rather than only itself.
        if self.registration.wants_unicast(&query)
            && self.multicast_log.all_recent(&response.answers)
        {
            if let Err(error) = self.send(&response, from).await {
                tracing::debug!(to = %from, %error, "could not send a unicast mDNS response");
            }
            return;
        }

        // RFC 6762 §6: a record may not be multicast twice inside one second. Records that are
        // still resting are dropped from the response rather than the whole response being
        // withheld, since a query may ask about several and only some be rate-limited.
        self.multicast_log.drop_rate_limited(&mut response);
        if response.answers.is_empty() {
            tracing::trace!(%from, "every answer was multicast within the last second, staying quiet");
            return;
        }

        if let Err(error) = self.multicast(&response).await {
            tracing::debug!(to = %self.destination, %error, "could not send an mDNS response");
        }
    }
}

/// Identifies one record independently of its TTL and cache-flush bit.
///
/// A record is "the same record" across two responses when it names the same thing, of the same
/// type, with the same data — the TTL differs by design between a legacy-capped answer and a full
/// one, and the cache-flush bit differs between the two paths, so neither can be part of the key.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordKey {
    /// Lowercased and without a trailing root dot, since DNS names are case-insensitive.
    qname: String,
    qtype: QueryType,
    rd: RecordData,
}

impl RecordKey {
    fn of(record: &DnsResource) -> Self {
        Self {
            qname: record.qname.trim_end_matches('.').to_ascii_lowercase(),
            qtype: record.qtype,
            rd: record.rd.clone(),
        }
    }
}

/// When each record was last multicast, for the RFC 6762 §6 and §5.4 timing rules.
///
/// An association list rather than a map: [`RecordData`] is not `Hash` (a `TXT` payload decodes
/// into a case-insensitive map, which has no meaningful hash), and the list is bounded by the
/// record set the registration owns — four records for a DMAP pairing service — so a linear scan
/// is both faster than hashing and never needs eviction.
#[derive(Debug, Default)]
struct MulticastLog {
    sent: Mutex<Vec<(RecordKey, Instant)>>,
}

impl MulticastLog {
    fn locked(&self) -> std::sync::MutexGuard<'_, Vec<(RecordKey, Instant)>> {
        self.sent.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Note that every one of `records` has just gone out on the group.
    fn record<'a>(&self, records: impl Iterator<Item = &'a DnsResource>) {
        let now = Instant::now();
        let mut sent = self.locked();
        for record in records {
            let key = RecordKey::of(record);
            match sent.iter_mut().find(|(candidate, _)| *candidate == key) {
                Some((_, at)) => *at = now,
                None => sent.push((key, now)),
            }
        }
    }

    /// How long ago `record` was last multicast, or `None` if it never has been.
    fn since(&self, record: &DnsResource) -> Option<Duration> {
        let key = RecordKey::of(record);
        self.locked()
            .iter()
            .find(|(candidate, _)| *candidate == key)
            .map(|(_, at)| at.elapsed())
    }

    /// Whether every record has been multicast within a quarter of its own TTL, RFC 6762 §5.4.
    ///
    /// An empty set is vacuously recent, but [`Inner::handle`] never asks about one — a response
    /// with no answers is not sent at all.
    fn all_recent(&self, records: &[DnsResource]) -> bool {
        records.iter().all(|record| {
            let window = Duration::from_secs(u64::from(record.ttl / QU_RECENT_TTL_FRACTION));
            self.since(record).is_some_and(|elapsed| elapsed < window)
        })
    }

    /// Remove every record that was multicast less than [`MULTICAST_RATE_LIMIT`] ago, RFC 6762 §6.
    fn drop_rate_limited(&self, response: &mut DnsMessage) {
        let rested = |record: &DnsResource| {
            self.since(record)
                .is_none_or(|elapsed| elapsed >= MULTICAST_RATE_LIMIT)
        };
        response.answers.retain(&rested);
        response.resources.retain(&rested);
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
///
/// Deliberately not subject to [`MulticastLog::drop_rate_limited`]: §8.3 governs announcements and
/// says two to eight of them, one second apart, which is the §6 rule's own lower bound. Filtering
/// them against a timestamp that the previous announcement wrote a second ago would turn a clock
/// that ran a microsecond fast into a silently skipped announcement.
async fn announce(inner: Arc<Inner>) {
    let message = inner.registration.announcement();
    for round in 0..ANNOUNCE_COUNT {
        if round > 0 {
            tokio::time::sleep(ANNOUNCE_INTERVAL).await;
        }
        if let Err(error) = inner.multicast(&message).await {
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
    exclude_loopback(private_ipv4_addresses())
}

/// The filter [`publishable_addresses`] applies, separated from the enumeration so it can be tested
/// against a fixed list rather than against whatever interfaces the host running the tests has.
fn exclude_loopback(addresses: Vec<Ipv4Addr>) -> Vec<Ipv4Addr> {
    addresses
        .into_iter()
        .filter(|address| !address.is_loopback())
        .collect()
}

#[cfg(test)]
mod tests;
