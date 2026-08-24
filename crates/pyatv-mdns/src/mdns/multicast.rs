//! Multicast DNS-SD browse across every local interface.
//!
//! Ports `MulticastDnsSdClientProtocol`, `ReceiveDelegate` and `multicast()` from
//! `pyatv/core/mdns.py:273-484, 506-531`. See `docs/research/discovery-port-spec.md` §2.5–§2.7.
//!
//! The socket layout, the once-a-second resend cadence, the per-source correlation, the deep-sleep
//! detection and the targeted unicast follow-up are all upstream behaviour reproduced deliberately;
//! each is documented at the item that implements it.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use pyatv_core::{Error, Result};
use tokio::net::UdpSocket;
use tokio::task::JoinSet;

use super::parser::ServiceParser;
use super::socket::{join_group, mcast_socket, private_ipv4_addresses};
use super::{RESEND_INTERVAL, create_service_queries, pack_queries, resend_rounds, to_response};
use crate::dns::{DnsMessage, QueryType};
use crate::service::{DEVICE_INFO_SERVICE, Response, SLEEP_PROXY_SERVICE};

/// Largest datagram accepted from a responder. See [`super::unicast`].
const MAX_DATAGRAM: usize = 9_000;

/// Depth of the channel receiver tasks hand datagrams to the correlation loop over.
///
/// A busy link with a dozen Apple devices produces a burst of a few datagrams per query round; 64
/// absorbs that without the receive tasks ever blocking, and bounds memory if the loop stalls.
const CHANNEL_DEPTH: usize = 64;

/// Predicate that ends a scan early once a good-enough [`Response`] has been assembled.
///
/// The caller's chance to say "this is the device I was looking for, stop now" without waiting out
/// the full window — `pyatv/core/scan.py` uses it to stop as soon as every requested identifier has
/// answered. It is called with the *fully assembled* response for one source, so it can look at
/// service types, ports, properties and the model.
pub type EndCondition = Box<dyn Fn(&Response) -> bool + Send + Sync>;

/// Browse the multicast group for a set of DNS-SD service types.
///
/// Opens one wildcard listener plus one socket per local IPv4 interface, sends every message
/// [`create_service_queries`] builds to `address:port` from each of them once a second for
/// `ceil(timeout)` rounds, and correlates the answers into one [`Response`] per responding host.
///
/// Returns as soon as `end_condition` accepts a response — in which case the map holds exactly that
/// one host, matching upstream, which discards every other in-flight partial — or when `timeout`
/// elapses, whichever comes first. An elapsed window is a normal outcome, not a failure.
///
/// `address` is [`MULTICAST_GROUP`](super::MULTICAST_GROUP) and `port` is [`MDNS_PORT`](super::MDNS_PORT) in production;
/// both are parameters so the whole path can be pointed at a fake responder on loopback, which is
/// what pyatv's own functional tests do by monkeypatching.
///
/// # IPv4 only
///
/// The destination is an [`Ipv4Addr`], not an [`IpAddr`]: pyatv's discovery path has no IPv6
/// anywhere — no `AAAA` parsing, no `ff02::fb`, no IPv6 interface enumeration — and making that a
/// type-level fact stops half-support from creeping in. See [`super`].
///
/// # Errors
///
/// Returns [`Error::Io`] only if the wildcard listener cannot be bound, which usually means another
/// process holds `port` on a platform without `SO_REUSEPORT`. Per-interface sockets that fail are
/// logged at debug and skipped, matching upstream's `except Exception: ... (ignoring)`.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), pyatv_core::Error> {
/// use std::time::Duration;
/// use pyatv_mdns::mdns::{MDNS_PORT, MULTICAST_GROUP, multicast};
///
/// let services = vec!["_airplay._tcp.local".to_owned()];
/// let responses = multicast(
///     &services,
///     MULTICAST_GROUP,
///     MDNS_PORT,
///     Duration::from_secs(4),
///     // Stop as soon as any host answers with a real, reachable service.
///     Some(Box::new(|response| {
///         response.services.iter().any(|service| service.port != 0)
///     })),
/// )
/// .await?;
///
/// for (host, response) in &responses {
///     println!("{host}: {} services", response.services.len());
/// }
/// # Ok(())
/// # }
/// ```
pub async fn multicast(
    services: &[String],
    address: Ipv4Addr,
    port: u16,
    timeout: Duration,
    end_condition: Option<EndCondition>,
) -> Result<HashMap<IpAddr, Response>> {
    let queries = create_service_queries(services, QueryType::PTR);
    let datagrams = pack_queries(&queries);
    let destination = SocketAddr::new(IpAddr::V4(address), port);

    let senders = open_sockets(port)?;
    let (datagram_tx, mut datagram_rx) = tokio::sync::mpsc::channel(CHANNEL_DEPTH);
    let mut receivers = JoinSet::new();
    for sender in &senders {
        receivers.spawn(receive_loop(
            Arc::clone(&sender.socket),
            datagram_tx.clone(),
        ));
    }
    // The loop below must see the channel close if every receiver dies, so it holds no sender.
    drop(datagram_tx);

    let mut state = MulticastState::new(services, datagrams.len());
    let mut rounds_left = resend_rounds(timeout);
    let mut ticker = tokio::time::interval(RESEND_INTERVAL);

    let outcome = tokio::time::timeout(timeout, async {
        loop {
            tokio::select! {
                // `interval`'s first tick is immediate, so round zero goes out with no delay.
                _ = ticker.tick(), if rounds_left > 0 => {
                    rounds_left -= 1;
                    send_round(&senders, &datagrams, destination, state.pending_unicasts(), port)
                        .await;
                }
                received = datagram_rx.recv() => {
                    let Some((source, data)) = received else {
                        tracing::debug!("every multicast receiver stopped");
                        return;
                    };
                    if state.handle(source, &data, end_condition.as_deref()) == Handled::Finished {
                        tracing::debug!(%source, "end condition met, ending multicast scan");
                        return;
                    }
                }
            }
        }
    })
    .await;

    if outcome.is_err() {
        tracing::debug!(?timeout, "multicast scan window elapsed");
    }
    receivers.shutdown().await;

    Ok(state.into_responses())
}

/// One socket, plus whether it is allowed to transmit.
#[derive(Debug)]
struct Sender {
    socket: Arc<UdpSocket>,
    /// A socket bound to a loopback address never sends.
    ///
    /// From `ReceiveDelegate.sendto` (`pyatv/core/mdns.py:282-285`). Without this guard the same
    /// query goes out over loopback once per socket and every local responder answers each copy.
    /// The socket still receives, which is what makes a loopback-only test setup work.
    is_loopback: bool,
}

/// Open the wildcard listener and one socket per local IPv4 interface.
///
/// Ports `multicast()`'s socket setup (`pyatv/core/mdns.py:519-527`).
///
/// **Deviation:** upstream binds the wildcard listener to a hardcoded `5353` and monkeypatches
/// `net.mcast_socket` in its tests to reach a fake responder. `port` is threaded through instead,
/// which is identical in production and testable without patching. Upstream also joins the group
/// only on the per-interface sockets; joining on the wildcard listener as well makes reception
/// independent of how many per-interface sockets could be opened, and a duplicate join is a
/// suppressed no-op.
///
/// # Errors
///
/// [`Error::Io`] if the wildcard listener cannot be bound. Per-interface failures are logged and
/// skipped.
fn open_sockets(port: u16) -> Result<Vec<Sender>> {
    let wildcard = mcast_socket(None, port).map_err(Error::Io)?;
    let interfaces = private_ipv4_addresses();
    for interface in &interfaces {
        join_group(&wildcard, *interface);
    }

    let mut senders = vec![Sender {
        // 0.0.0.0 is not a loopback address, so the wildcard socket transmits.
        is_loopback: false,
        socket: Arc::new(wildcard),
    }];

    for interface in interfaces {
        // Port zero: the per-interface sockets are for transmitting and for catching the unicast
        // replies the QU bit asks for, so they take ephemeral ports and leave 5353 to the wildcard
        // listener. Upstream does the same by letting `mcast_socket`'s `port` default to 0.
        match mcast_socket(Some(interface), 0) {
            Ok(socket) => senders.push(Sender {
                is_loopback: interface.is_loopback(),
                socket: Arc::new(socket),
            }),
            Err(error) => {
                tracing::debug!(%interface, %error, "failed to add listener (ignoring)");
            }
        }
    }

    tracing::debug!(sockets = senders.len(), "opened multicast sockets");
    Ok(senders)
}

/// Forward every datagram from one socket to the correlation loop, tagged with its source.
async fn receive_loop(socket: Arc<UdpSocket>, sink: tokio::sync::mpsc::Sender<(IpAddr, Vec<u8>)>) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let (length, source) = match socket.recv_from(&mut buffer).await {
            Ok(received) => received,
            Err(error) => {
                // `MulticastDnsSdClientProtocol.error_received` logs and carries on.
                tracing::debug!(%error, "error during multicast DNS lookup");
                return;
            }
        };

        tracing::trace!(source = %source.ip(), bytes = length, "received multicast DNS response");
        if sink
            .send((source.ip(), buffer[..length].to_vec()))
            .await
            .is_err()
        {
            return;
        }
    }
}

/// Send one round: every query to the group, then any queued unicast follow-ups.
///
/// Ports `_resend_loop` and `_sendto` (`pyatv/core/mdns.py:385-414`). A send failure on one socket
/// is logged and does not stop the others — an interface can disappear mid-scan.
async fn send_round(
    senders: &[Sender],
    datagrams: &[Vec<u8>],
    destination: SocketAddr,
    unicasts: Vec<(IpAddr, Vec<Vec<u8>>)>,
    port: u16,
) {
    let follow_ups = unicasts.iter().flat_map(|(address, datagrams)| {
        let target = SocketAddr::new(*address, port);
        datagrams.iter().map(move |datagram| (target, datagram))
    });

    for (target, datagram) in datagrams
        .iter()
        .map(|datagram| (destination, datagram))
        .chain(follow_ups)
    {
        for sender in senders {
            if sender.is_loopback {
                continue;
            }
            match sender.socket.send_to(datagram, target).await {
                Ok(sent) => tracing::trace!(%target, bytes = sent, "sent multicast DNS request"),
                Err(error) => tracing::debug!(%target, %error, "failed to send DNS request"),
            }
        }
    }
}

/// What one datagram did to the accumulated state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Handled {
    /// Dropped before it changed anything: undecodable, empty, or about services not asked for.
    Ignored,
    /// Folded into this source's running state.
    Accumulated,
    /// Completed a response that `end_condition` accepted; the scan is over.
    Finished,
}

/// One responding host's accumulated state, from pyatv's `QueryResponse`.
#[derive(Debug, Default)]
struct QueryResponse {
    /// Datagrams accepted from this source, *not* questions answered. See [`MulticastState::handle`].
    count: usize,
    /// Sticky once set: a host that ever looked asleep stays flagged for the rest of the scan.
    deep_sleep: bool,
    parser: ServiceParser,
}

/// The sans-io half of the multicast scan: correlation, deep-sleep detection, early stop.
///
/// Split out from the socket plumbing so the interesting behaviour can be tested by feeding it
/// datagrams, with no network involved.
#[derive(Debug)]
struct MulticastState {
    /// Service types the caller asked about; anything else makes a datagram foreign.
    services: Vec<String>,
    /// How many query messages went out. A source that has answered at least this many datagrams
    /// is considered done.
    query_count: usize,
    responses: HashMap<IpAddr, QueryResponse>,
    /// Targeted follow-up queries queued for sleeping hosts, sent on the next resend round.
    unicasts: HashMap<IpAddr, Vec<Vec<u8>>>,
}

impl MulticastState {
    fn new(services: &[String], query_count: usize) -> Self {
        Self {
            services: services.to_vec(),
            query_count,
            responses: HashMap::new(),
            unicasts: HashMap::new(),
        }
    }

    /// Fold one datagram into the state.
    ///
    /// Ports `datagram_received` (`pyatv/core/mdns.py:417-472`) step for step:
    ///
    /// 1. The source gets a state entry **before** anything is decoded. A host that only ever sends
    ///    garbage therefore still appears in the result, with an empty [`Response`]. That is
    ///    upstream's `setdefault`-first ordering; downstream handles empty responses fine, and
    ///    changing it would hide hosts that a caller may want to know answered at all.
    /// 2. Decode failures are logged and dropped whole — no partial processing.
    /// 3. The datagram is previewed with a *throwaway* parser, so a rejected one leaves no trace.
    /// 4. If **any** service in it has a type that was not asked for, and is not
    ///    [`DEVICE_INFO_SERVICE`] or [`SLEEP_PROXY_SERVICE`], the **entire datagram** is discarded.
    ///    Not a per-service filter: one unwanted type anywhere drops everything alongside it.
    /// 5. Every service reporting port `0` means a sleep proxy answered for a sleeping host — the
    ///    proxy has PTR records but no live `SRV`/`A`/`TXT` to back them, so every service
    ///    degenerates to the placeholder shape [`ServiceParser`] synthesises.
    /// 6. A sleeping host gets a targeted `ANY` re-query queued for the next resend round, aimed at
    ///    its exact instance names. It is deliberately not sent immediately.
    /// 7. Otherwise, once this source has sent at least as many datagrams as there were query
    ///    messages, its response is assembled and offered to `end_condition`. Accepting collapses
    ///    the state to that one host and ends the scan.
    fn handle(
        &mut self,
        source: IpAddr,
        data: &[u8],
        end_condition: Option<&(dyn Fn(&Response) -> bool + Send + Sync)>,
    ) -> Handled {
        self.responses.entry(source).or_default();

        let Ok(message) = DnsMessage::unpack(data) else {
            tracing::debug!(%source, "failed to decode multicast DNS response");
            return Handled::Ignored;
        };

        let preview = super::parse_services(&message);
        if preview.is_empty() {
            return Handled::Ignored;
        }
        if let Some(foreign) = preview
            .iter()
            .find(|service| !self.is_interesting(&service.service_type))
        {
            tracing::trace!(
                %source,
                service = %foreign.service_type,
                "dropping response containing an unrequested service type"
            );
            return Handled::Ignored;
        }

        let is_sleep_proxy = preview.iter().all(|service| service.port == 0);
        let Some(entry) = self.responses.get_mut(&source) else {
            // Inserted above; this branch cannot be reached.
            return Handled::Ignored;
        };
        entry.count += 1;
        entry.deep_sleep |= is_sleep_proxy;
        entry.parser.add_message(&message);

        if is_sleep_proxy {
            let names: Vec<String> = preview
                .iter()
                .map(|service| format!("{}.{}", service.name, service.service_type))
                .collect();
            tracing::debug!(%source, ?names, "host appears to be asleep, queueing unicast re-query");
            self.unicasts.insert(
                source,
                pack_queries(&create_service_queries(&names, QueryType::ANY)),
            );
            return Handled::Accumulated;
        }

        if entry.count < self.query_count {
            return Handled::Accumulated;
        }

        let response = to_response(&entry.parser, entry.deep_sleep);
        let Some(end_condition) = end_condition else {
            return Handled::Accumulated;
        };
        if !end_condition(&response) {
            return Handled::Accumulated;
        }

        self.responses.retain(|address, _| *address == source);
        Handled::Finished
    }

    /// Whether a service type is one the caller asked about, or one of the two always-implicit ones.
    fn is_interesting(&self, service_type: &str) -> bool {
        service_type == DEVICE_INFO_SERVICE
            || service_type == SLEEP_PROXY_SERVICE
            || self.services.iter().any(|wanted| wanted == service_type)
    }

    /// Follow-up queries queued for sleeping hosts, for the next resend round.
    fn pending_unicasts(&self) -> Vec<(IpAddr, Vec<Vec<u8>>)> {
        self.unicasts
            .iter()
            .map(|(address, datagrams)| (*address, datagrams.clone()))
            .collect()
    }

    /// Materialise one [`Response`] per host, from `_to_response`.
    fn into_responses(self) -> HashMap<IpAddr, Response> {
        self.responses
            .into_iter()
            .map(|(address, entry)| (address, to_response(&entry.parser, entry.deep_sleep)))
            .collect()
    }
}

#[cfg(test)]
mod tests;
