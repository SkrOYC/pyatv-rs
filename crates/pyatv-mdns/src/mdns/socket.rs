//! Multicast socket construction and local interface enumeration.
//!
//! Ports `mcast_socket` and `get_private_addresses` from `pyatv/support/net.py:25-77`. See
//! `docs/research/discovery-port-spec.md` §2.7.
//!
//! pyatv enumerates interfaces with the `ifaddr` package; this uses `if-addrs`, the closest Rust
//! equivalent. Socket options that `std` does not expose come from `socket2`, and the configured
//! socket is handed to tokio with [`tokio::net::UdpSocket::from_std`].

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

use super::MULTICAST_GROUP;

/// Multicast TTL pyatv sets, from `struct.pack("b", 10)` (`pyatv/support/net.py:30`).
///
/// Ten hops is far more than mDNS needs — RFC 6762 section 11 specifies 255 for link-local
/// multicast and routers are supposed to drop it at the link boundary regardless — but it is what
/// pyatv sends.
pub const MULTICAST_TTL: u32 = 10;

/// Build a multicast-capable UDP socket, configured the way `pyatv/support/net.py:25-53` does.
///
/// With `interface` set to `None` this is the wildcard listener bound to `0.0.0.0:port`. With an
/// interface address it is bound to that address, has `IP_MULTICAST_IF` pointed at it, and joins
/// the group on it.
///
/// # A per-interface bind cannot receive multicast on Linux
///
/// The `Some(interface)` form is for **transmitting**, and for receiving the *unicast* replies a
/// `QU` question attracts — which is all the scanner asks of it. It will not see datagrams sent to
/// the group; see [`mcast_responder_socket`] for why, and use that instead when the socket has to
/// receive group traffic.
///
/// Options, in pyatv's order: `SO_REUSEADDR`, `IP_MULTICAST_TTL` = [`MULTICAST_TTL`],
/// `IP_MULTICAST_LOOP` on, and `SO_REUSEPORT` where the platform has it. `SO_REUSEPORT` is what
/// lets this coexist with a system responder such as avahi-daemon or mDNSResponder already holding
/// port 5353; without it, binding fails outright on most hosts.
///
/// # Group membership is hardcoded
///
/// `IP_ADD_MEMBERSHIP` always joins [`MULTICAST_GROUP`], never whatever destination address
/// `multicast()` was called with — upstream does not thread its `address` argument down to the
/// socket layer, only to the `sendto` destination. Reproduced, because it is what makes pyatv's own
/// tests work: they redirect the *destination* to `127.0.0.1` while the membership stays on the
/// real group.
///
/// `IP_MULTICAST_IF` and `IP_ADD_MEMBERSHIP` are both best-effort, matching upstream's
/// `with suppress(OSError)`. A joined-twice group, an interface that has gone away between
/// enumeration and bind, and a container with no multicast routing all fail here and none of them
/// should abort a scan.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] if the socket cannot be created, if a mandatory option is
/// rejected, or if the bind fails — most often because another process holds the port and the
/// platform has no `SO_REUSEPORT`.
pub fn mcast_socket(interface: Option<Ipv4Addr>, port: u16) -> io::Result<UdpSocket> {
    build_socket(interface, interface.unwrap_or(Ipv4Addr::UNSPECIFIED), port)
}

/// Build a multicast socket that **receives** group traffic while still transmitting from one
/// interface: `IP_MULTICAST_IF` and `IP_ADD_MEMBERSHIP` on `interface`, but bound to the wildcard.
///
/// This is [`mcast_socket`] minus its one fatal property for a responder — the per-interface bind.
///
/// # Why the bind must be the wildcard on Linux
///
/// A socket bound to a unicast address never sees a multicast datagram on Linux. `net/ipv4/udp.c`'s
/// `__udp_is_mcast_sock()`, the predicate `__udp4_lib_mcast_deliver()` filters candidate sockets
/// with, rejects a socket when
///
/// ```text
/// inet->inet_rcv_saddr && inet->inet_rcv_saddr != loc_addr
/// ```
///
/// where `loc_addr` is the datagram's *destination* — the group address, `224.0.0.251` — and
/// `inet_rcv_saddr` is whatever the socket was bound to. Bind to `192.168.1.5` and the two never
/// match, so the group's datagrams are filtered out before delivery even though the interface
/// joined the group. Joining a group and receiving its traffic are separate things: the join tells
/// the kernel and the switch to accept the frames, the bind decides which sockets they reach.
///
/// This bit an earlier version of [`crate::publish::Responder`]: it bound `address:5353`, never saw
/// the `_touch-remote._tcp.local` browse query an Apple TV sends, and DMAP pairing was invisible.
/// Do not "tidy" this back into a per-interface bind.
///
/// The scanner's per-interface sockets in [`mod@super::multicast`] are *not* affected and deliberately
/// keep their per-interface bind: they exist to transmit and to catch the unicast replies the `QU`
/// bit asks for, both of which are unicast paths that `__udp_is_mcast_sock()` never touches. The
/// scanner's group reception is the wildcard listener's job.
///
/// # Consequence of the wildcard bind
///
/// Every responder on the host receives every interface's group traffic, so on a multi-homed host a
/// query arriving on one link is also answered out of the others. That is legitimate mDNS — each
/// interface answers with its own `A` record — and the alternative, `IP_PKTINFO` plus a per-datagram
/// arrival-interface check, buys nothing for a service that wants to be found on every link.
///
/// # Errors
///
/// As [`mcast_socket`]: the underlying [`io::Error`] if the socket cannot be created, if a mandatory
/// option is rejected, or if binding `0.0.0.0:port` fails.
pub fn mcast_responder_socket(interface: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    build_socket(Some(interface), Ipv4Addr::UNSPECIFIED, port)
}

/// The shared body of [`mcast_socket`] and [`mcast_responder_socket`]: `interface` drives
/// `IP_MULTICAST_IF` and the group join, `bind_to` drives the bind, and the two are independent.
fn build_socket(
    interface: Option<Ipv4Addr>,
    bind_to: Ipv4Addr,
    port: u16,
) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    socket.set_multicast_ttl_v4(MULTICAST_TTL)?;
    socket.set_multicast_loop_v4(true)?;
    // `set_reuse_port` is only compiled in where the platform has SO_REUSEPORT, which mirrors
    // pyatv's `hasattr(socket, "SO_REUSEPORT")` guard.
    #[cfg(all(unix, not(any(target_os = "solaris", target_os = "illumos"))))]
    socket.set_reuse_port(true)?;

    if let Some(interface) = interface {
        if let Err(error) = socket.set_multicast_if_v4(&interface) {
            tracing::debug!(%interface, %error, "IP_MULTICAST_IF rejected (ignoring)");
        }
        if let Err(error) = socket.join_multicast_v4(&MULTICAST_GROUP, &interface) {
            tracing::debug!(%interface, %error, "IP_ADD_MEMBERSHIP rejected (ignoring)");
        }
    }

    let bind_address = SocketAddrV4::new(bind_to, port);
    tracing::debug!(address = %bind_address, ?interface, "binding multicast socket");
    socket.bind(&SocketAddr::V4(bind_address).into())?;
    socket.set_nonblocking(true)?;

    UdpSocket::from_std(socket.into())
}

/// Join [`MULTICAST_GROUP`] on `interface`, best-effort.
///
/// Used to subscribe the wildcard listener to every interface. pyatv relies on its per-interface
/// sockets alone for this, which works only because those sockets also receive; joining on the
/// wildcard socket as well costs nothing and makes reception independent of how many per-interface
/// sockets could be opened.
pub fn join_group(socket: &UdpSocket, interface: Ipv4Addr) {
    // `tokio::net::UdpSocket` exposes `join_multicast_v4` directly, so no socket2 round trip.
    if let Err(error) = socket.join_multicast_v4(MULTICAST_GROUP, interface) {
        tracing::debug!(%interface, %error, "IP_ADD_MEMBERSHIP rejected (ignoring)");
    }
}

/// Local IPv4 addresses worth sending multicast queries from.
///
/// Ports `get_private_addresses` (`pyatv/support/net.py:66-77`), which keeps every IPv4 address for
/// which Python's `IPv4Address.is_private` holds. That predicate is wider than
/// [`Ipv4Addr::is_private`]: it also covers loopback (127/8), link-local (169.254/16) and
/// carrier-grade NAT (100.64/10), all of which real Apple TVs turn up on — link-local in particular
/// is what a device falls back to when DHCP fails.
///
/// Returns an empty vector rather than an error if the interface list cannot be read, so that a
/// scan degrades to the wildcard socket instead of failing.
#[must_use]
pub fn private_ipv4_addresses() -> Vec<Ipv4Addr> {
    let interfaces = match if_addrs::get_if_addrs() {
        Ok(interfaces) => interfaces,
        Err(error) => {
            tracing::debug!(%error, "could not enumerate interfaces");
            return Vec::new();
        }
    };

    interfaces
        .into_iter()
        .filter_map(|interface| match interface.addr {
            if_addrs::IfAddr::V4(address) => Some(address.ip),
            // pyatv's discovery path is IPv4 only; see the module documentation on [`super`].
            if_addrs::IfAddr::V6(_) => None,
        })
        .filter(|address| is_private(*address))
        .collect()
}

/// Python's `ipaddress.IPv4Address.is_private`, restricted to the ranges that can reach a device.
fn is_private(address: Ipv4Addr) -> bool {
    address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        // 100.64.0.0/10, RFC 6598 shared address space.
        || (address.octets()[0] == 100 && (64..128).contains(&address.octets()[1]))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::{is_private, mcast_responder_socket, mcast_socket, private_ipv4_addresses};

    #[test]
    fn the_private_predicate_matches_pythons() {
        for address in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
        ] {
            assert!(is_private(address), "{address} should be private");
        }

        for address in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(172, 32, 0, 1),
            Ipv4Addr::new(100, 128, 0, 1),
            Ipv4Addr::new(1, 1, 1, 1),
        ] {
            assert!(!is_private(address), "{address} should not be private");
        }
    }

    /// Loopback always exists, so enumeration must find at least that.
    #[test]
    fn loopback_is_always_enumerated() {
        let addresses = private_ipv4_addresses();
        assert!(
            addresses.contains(&Ipv4Addr::LOCALHOST),
            "expected 127.0.0.1 among {addresses:?}"
        );
    }

    /// Binding the wildcard listener on an ephemeral port exercises every socket option without
    /// needing port 5353 or a real interface.
    #[tokio::test]
    async fn a_wildcard_socket_binds_with_every_option_applied() {
        let socket = mcast_socket(None, 0).expect("wildcard socket binds on an ephemeral port");
        let bound = socket.local_addr().expect("a bound socket has an address");

        assert!(bound.is_ipv4());
        assert_ne!(bound.port(), 0);
        assert_eq!(socket.multicast_ttl_v4().ok(), Some(super::MULTICAST_TTL));
        assert_eq!(socket.multicast_loop_v4().ok(), Some(true));
    }

    /// The receive half of the responder's socket: bound to the wildcard even though it is given an
    /// interface, because Linux's `__udp_is_mcast_sock()` will not deliver group traffic to a socket
    /// whose `inet_rcv_saddr` is a unicast address. See [`mcast_responder_socket`].
    #[tokio::test]
    async fn a_responder_socket_binds_the_wildcard_not_its_interface() {
        let interface = Ipv4Addr::new(192, 0, 2, 10);
        let socket = mcast_responder_socket(interface, 0).expect("responder socket binds");
        let bound = socket.local_addr().expect("a bound socket has an address");

        assert_eq!(
            bound.ip(),
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            "a per-interface bind stops the kernel delivering multicast to this socket"
        );
        assert_ne!(bound.port(), 0);
        assert_eq!(socket.multicast_ttl_v4().ok(), Some(super::MULTICAST_TTL));
        assert_eq!(socket.multicast_loop_v4().ok(), Some(true));
    }

    /// The transmit-side sockets the scanner opens keep their per-interface bind: they only ever
    /// receive unicast replies, so the kernel predicate above does not apply to them.
    #[tokio::test]
    async fn a_scanner_interface_socket_still_binds_its_interface() {
        let socket = mcast_socket(Some(Ipv4Addr::LOCALHOST), 0).expect("interface socket binds");
        let bound = socket.local_addr().expect("a bound socket has an address");

        assert_eq!(bound.ip(), std::net::IpAddr::V4(Ipv4Addr::LOCALHOST));
    }
}
