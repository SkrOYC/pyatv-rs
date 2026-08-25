//! pyatv's hand-rolled mDNS/DNS-SD *client*, ported from `pyatv/core/mdns.py`.
//!
//! This is the transport half of discovery: [`crate::dns`] turns bytes into [`DnsMessage`]s, and
//! this module decides which questions to ask, over which socket, how often to repeat them, and
//! how to fold the answers back into one [`Response`] per host.
//!
//! # Why not a general-purpose mDNS crate
//!
//! pyatv does not browse the way RFC 6763 suggests. It asks `PTR` questions with the QU bit set,
//! bundles a `_sleep-proxy._udp.local` question into every single datagram, blind-resends once a
//! second instead of following the RFC 6762 backoff, and treats "every service in this datagram has
//! port 0" as the signal that a host is asleep behind a Bonjour sleep proxy. Those are the
//! behaviours Apple devices are actually exercised against, so they are reproduced here rather than
//! corrected. See `docs/research/discovery-port-spec.md` §2.
//!
//! # Layout
//!
//! * [`query`] — [`create_service_queries`], the question sets pyatv puts on the wire.
//! * [`parser`] — [`ServiceParser`], the sans-io accumulator that turns records into services.
//! * [`mod@unicast`] — [`unicast()`], one socket aimed at one known host.
//! * [`mod@multicast`] — [`multicast()`], the group browse across every local interface.
//!
//! # IPv4 only
//!
//! pyatv's discovery path is IPv4 throughout: `QueryType` has no `AAAA` member, the parser reads
//! only `A` records, the multicast group is hardcoded to `224.0.0.251`, and interface enumeration
//! filters to IPv4. This port matches that. [`crate::dns`] *decodes* `AAAA` records, but nothing
//! here consumes them, and [`multicast()`] takes an [`Ipv4Addr`] rather than an
//! [`IpAddr`](std::net::IpAddr) to make that non-negotiable at the type level.
//!
//! # Logging
//!
//! pyatv defines a custom `TRAFFIC` log level five steps below `DEBUG` and logs every datagram at
//! it (`pyatv/core/mdns.py:32-36`). `tracing` has no such level, so datagram-granularity logging
//! lands on `trace` and lifecycle events on `debug`.

pub mod multicast;
pub mod parser;
pub mod query;
pub mod socket;
pub mod unicast;

pub use multicast::{EndCondition, multicast};
pub use parser::{ServiceParser, get_model, parse_services};
pub use query::{SERVICES_PER_MSG, create_service_queries};
pub use unicast::unicast;

use std::net::Ipv4Addr;
use std::time::Duration;

use crate::dns::DnsMessage;
use crate::service::Response;

/// The mDNS port, RFC 6762 section 2.
///
/// Unicast queries go to this port on the target host directly, bypassing the multicast group.
pub const MDNS_PORT: u16 = 5353;

/// The IPv4 link-local multicast group mDNS uses, RFC 6762 section 3.
///
/// `pyatv/core/mdns.py:501` uses this as `multicast()`'s default destination, and
/// `pyatv/support/net.py:48` hardcodes it as the `IP_ADD_MEMBERSHIP` group *regardless* of the
/// destination the caller asked for. See [`socket::mcast_socket`].
pub const MULTICAST_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// pyatv's default scan window, from `unicast()` and `multicast()`'s `timeout: int = 4`.
///
/// Both entry points also use it as the resend budget: queries are repeated once a second for
/// `ceil(timeout)` rounds. See [`resend_rounds`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);

/// How long to wait between resends, from `await asyncio.sleep(1)` in both resend loops.
pub const RESEND_INTERVAL: Duration = Duration::from_secs(1);

/// Number of resend rounds for a scan window, reproducing pyatv's `math.ceil(timeout)`.
///
/// pyatv types `timeout` as `int` but the tests pass floats (`timeout=0.5`), and `math.ceil` is
/// what actually decides the round count, so a sub-second window still gets exactly one round.
///
/// ```
/// use std::time::Duration;
/// use pyatv_mdns::mdns::resend_rounds;
///
/// assert_eq!(resend_rounds(Duration::from_secs(4)), 4);
/// assert_eq!(resend_rounds(Duration::from_millis(500)), 1);
/// assert_eq!(resend_rounds(Duration::ZERO), 0);
/// ```
#[must_use]
pub fn resend_rounds(timeout: Duration) -> u32 {
    let seconds = timeout.as_secs();
    let rounds = if timeout.subsec_nanos() > 0 {
        seconds.saturating_add(1)
    } else {
        seconds
    };
    u32::try_from(rounds).unwrap_or(u32::MAX)
}

/// Pack every query message once, so a resend loop does not re-encode on each round.
///
/// pyatv's `create_service_queries` returns `List[bytes]` for the same reason.
fn pack_queries(queries: &[DnsMessage]) -> Vec<Vec<u8>> {
    queries.iter().map(DnsMessage::pack).collect()
}

/// Build the [`Response`] pyatv's `_to_response` builds from an accumulated parser.
fn to_response(parser: &ServiceParser, deep_sleep: bool) -> Response {
    let services = parser.parse();
    let model = get_model(&services);
    Response {
        services,
        deep_sleep,
        model,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{MDNS_PORT, MULTICAST_GROUP, resend_rounds};

    /// `math.ceil(timeout)` decides how many resend rounds a scan gets.
    #[test]
    fn resend_rounds_round_up() {
        assert_eq!(resend_rounds(Duration::ZERO), 0);
        assert_eq!(resend_rounds(Duration::from_nanos(1)), 1);
        assert_eq!(resend_rounds(Duration::from_millis(999)), 1);
        assert_eq!(resend_rounds(Duration::from_secs(1)), 1);
        assert_eq!(resend_rounds(Duration::from_millis(1001)), 2);
        assert_eq!(resend_rounds(Duration::from_secs(4)), 4);
    }

    /// These two constants are wire-visible; guard them against edits.
    #[test]
    fn constants_match_pyatv() {
        assert_eq!(MDNS_PORT, 5353);
        assert_eq!(MULTICAST_GROUP.octets(), [224, 0, 0, 251]);
    }
}
