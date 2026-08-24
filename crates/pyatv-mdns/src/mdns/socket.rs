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

    let bind_address = SocketAddrV4::new(interface.unwrap_or(Ipv4Addr::UNSPECIFIED), port);
    tracing::debug!(address = %bind_address, "binding multicast socket");
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

    use super::{is_private, mcast_socket, private_ipv4_addresses};

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
}
