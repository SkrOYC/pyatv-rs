//! Unicast DNS-SD against one known host.
//!
//! Ports `UnicastDnsSdClientProtocol` and `unicast()` from `pyatv/core/mdns.py:185-270, 487-503`.
//! See `docs/research/discovery-port-spec.md` §2.4 and §2.7.
//!
//! This is the path `atvremote --scan-hosts` takes, and the one that works where multicast does
//! not: Docker bridges, most VLAN configurations, and consumer mesh Wi-Fi that proxies or drops
//! link-local multicast. The questions are identical to the multicast ones — same QU bit, same
//! appended sleep-proxy question — only the destination differs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use pyatv_core::{Error, Result};
use tokio::net::UdpSocket;

use super::parser::ServiceParser;
use super::{RESEND_INTERVAL, create_service_queries, pack_queries, resend_rounds};
use crate::dns::{DnsMessage, QueryType};
use crate::service::Response;

/// Largest datagram accepted from a responder.
///
/// RFC 6762 section 17 allows an mDNS message up to 9000 bytes over Ethernet. pyatv inherits
/// asyncio's 64 KiB receive buffer and never bounds this; 9000 is the documented ceiling and keeps
/// one buffer per scan rather than one per datagram.
const MAX_DATAGRAM: usize = 9_000;

/// Ask one host directly for a set of DNS-SD service types.
///
/// Sends every message [`create_service_queries`] builds to `address:port`, repeating the whole set
/// once a second for `ceil(timeout)` rounds, and collects answers until either every message has
/// been answered at least once or `timeout` elapses. Whatever was parsed by then is returned; a
/// timeout is a normal outcome, not a failure.
///
/// `port` is [`MDNS_PORT`](super::MDNS_PORT) in production. It is a parameter only because pyatv's own tests point it
/// at an ephemeral port on a fake responder, and this port's tests do the same.
///
/// # Deep sleep
///
/// [`Response::deep_sleep`] is always `false` here. Deep-sleep detection is a multicast-only
/// concept upstream — it depends on correlating several datagrams from one source, which the
/// unicast path does not do (`pyatv/core/mdns.py:215-219`).
///
/// # Termination
///
/// pyatv counts *datagrams*, not answered questions: `received_responses == len(self.queries)`
/// ends the scan (`pyatv/core/mdns.py:250-254`). A responder that sends two datagrams for one
/// query therefore ends a two-message scan early. Reproduced, because the resend loop makes it
/// self-correcting in practice and because pyatv's timing tests depend on it.
///
/// # Errors
///
/// * [`Error::Io`] if the socket cannot be bound or connected — the only hard failure. A refused
///   or unreachable destination surfaces here on the first send.
/// * [`Error::Timeout`] is *not* returned: an elapsed window yields whatever was collected, since
///   a partial answer is still useful and pyatv behaves the same way.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), pyatv_core::Error> {
/// use std::time::Duration;
/// use pyatv_mdns::mdns::{MDNS_PORT, unicast};
///
/// let services = vec!["_airplay._tcp.local".to_owned()];
/// let response = unicast(
///     "10.0.0.10".parse().expect("literal address"),
///     &services,
///     MDNS_PORT,
///     Duration::from_secs(4),
/// )
/// .await?;
///
/// for service in &response.services {
///     println!("{} on port {}", service.service_type, service.port);
/// }
/// # Ok(())
/// # }
/// ```
pub async fn unicast(
    address: IpAddr,
    services: &[String],
    port: u16,
    timeout: Duration,
) -> Result<Response> {
    let queries = create_service_queries(services, QueryType::PTR);
    let datagrams = pack_queries(&queries);

    let socket = connected_socket(address, port).await?;
    let mut parser = ServiceParser::new();

    {
        let resend = resend_loop(&socket, &datagrams, resend_rounds(timeout), address);
        let collect = collect_responses(&socket, &mut parser, datagrams.len(), address);

        if tokio::time::timeout(timeout, async {
            tokio::select! {
                () = resend => {}
                () = collect => {}
            }
        })
        .await
        .is_err()
        {
            tracing::debug!(%address, ?timeout, "unicast scan window elapsed");
        }
    }

    Ok(parser.response(false))
}

/// Bind an ephemeral local socket of the same family and connect it to the target.
///
/// pyatv passes `remote_addr=` to `create_datagram_endpoint`, which connects the socket, so sends
/// need no destination and datagrams from anywhere else are dropped by the kernel. Same here.
async fn connected_socket(address: IpAddr, port: u16) -> Result<UdpSocket> {
    let local: SocketAddr = match address {
        IpAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        IpAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };

    let socket = UdpSocket::bind(local).await.map_err(Error::Io)?;
    socket
        .connect(SocketAddr::new(address, port))
        .await
        .map_err(Error::Io)?;
    Ok(socket)
}

/// Resend every query once a second for `rounds` rounds, then wait out the remaining window.
///
/// Ports `_resend_loop` (`pyatv/core/mdns.py:225-236`). The send happens *before* the sleep, so
/// round zero goes out immediately. `tests/core/test_mdns_functional.py:146-152` drops the first
/// two requests and still expects an answer within a three-second window, which only holds if the
/// cadence is one full round per second starting at zero.
///
/// After the rounds are spent this future parks forever rather than completing, so that the caller
/// keeps collecting for whatever is left of the scan window instead of tearing down early.
async fn resend_loop(socket: &UdpSocket, datagrams: &[Vec<u8>], rounds: u32, address: IpAddr) {
    for round in 0..rounds {
        for datagram in datagrams {
            match socket.send(datagram).await {
                Ok(sent) => tracing::trace!(
                    %address,
                    round,
                    bytes = sent,
                    "sent unicast DNS request"
                ),
                Err(error) => {
                    tracing::debug!(%address, %error, "unicast DNS request failed to send");
                }
            }
        }
        tokio::time::sleep(RESEND_INTERVAL).await;
    }

    std::future::pending::<()>().await;
}

/// Collect answers until as many datagrams have arrived as there were query messages.
///
/// Ports `datagram_received` (`pyatv/core/mdns.py:238-251`). A datagram that will not decode is
/// logged and dropped *without* counting toward the total — upstream lets the exception escape into
/// asyncio's handler, which has the same effect on the count and a worse effect on the logs.
async fn collect_responses(
    socket: &UdpSocket,
    parser: &mut ServiceParser,
    expected: usize,
    address: IpAddr,
) {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    let mut received = 0usize;

    loop {
        let length = match socket.recv(&mut buffer).await {
            Ok(length) => length,
            Err(error) => {
                // pyatv's `error_received` releases the semaphore and returns what it has.
                tracing::debug!(%address, %error, "error during unicast DNS lookup");
                return;
            }
        };

        tracing::trace!(
            %address,
            bytes = length,
            index = received + 1,
            total = expected,
            "received unicast DNS response"
        );

        match DnsMessage::unpack(&buffer[..length]) {
            Ok(message) => {
                parser.add_message(&message);
                received += 1;
            }
            Err(error) => {
                tracing::debug!(%address, %error, "failed to decode unicast DNS response");
                continue;
            }
        }

        if received >= expected {
            return;
        }
    }
}
