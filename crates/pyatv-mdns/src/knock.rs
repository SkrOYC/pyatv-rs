//! TCP "knocking" to wake sleeping devices before a unicast scan.
//!
//! Ported from `pyatv/support/knock.py:1-79`; see `docs/research/discovery-port-spec.md` §6.
//!
//! An Apple TV or HomePod that dozes off hands its Bonjour registrations to a sleep proxy on the
//! link. The proxy answers mDNS on the device's behalf — which is why a sleeping device shows up
//! with `port == 0` and no `A` record — but answering does not wake it. What does wake it is a
//! device's own service ports being touched, so pyatv opens a TCP connection to each of a few fixed
//! ports and immediately closes it. That is the entire mechanism: the SYN is the point, not a
//! usable connection.
//!
//! `pyatv/core/scan.py`'s unicast scanner fires this concurrently with its DNS query rather than
//! waiting for it, which is what [`knocker`] is for.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use pyatv_core::{Error, Result};
use tokio::net::TcpStream;
use tokio::task::{JoinHandle, JoinSet};

/// Ports pyatv knocks on, from `KNOCK_PORTS` in `pyatv/core/scan.py`.
///
/// 3689 is DAAP, 7000 is AirPlay's conventional port, and 49152/32498 are the low ends of the
/// ephemeral ranges MRP and Companion typically land in. Fixed, always, for every unicast-scanned
/// host, regardless of which service types the scan is actually looking for — the real ports come
/// from `SRV` records and are not known yet at knock time.
pub const KNOCK_PORTS: [u16; 4] = [3689, 7000, 49152, 32498];

/// How long a successful connection is held open before being torn down.
///
/// `_SLEEP_AFTER_CONNECT = 0.1` (`pyatv/support/knock.py:20`): a brief window for the remote to
/// react to the connection before it disappears.
const SLEEP_AFTER_CONNECT: Duration = Duration::from_millis(100);

/// Headroom subtracted from the overall budget to get each port's own connect timeout.
///
/// `_KNOCK_TIMEOUT_BUFFER = _SLEEP_AFTER_CONNECT * 2` (`pyatv/support/knock.py:21`), leaving room
/// for the final wait-and-cancel pass to finish inside the caller's window.
const KNOCK_TIMEOUT_BUFFER: Duration = Duration::from_millis(200);

/// pyatv's default overall knock budget, from `knocker(..., timeout: int = 4)`.
pub const DEFAULT_KNOCK_TIMEOUT: Duration = Duration::from_secs(4);

/// `EHOSTDOWN`, which has no portable [`io::ErrorKind`].
///
/// pyatv aborts a knock on `EHOSTDOWN` or `EHOSTUNREACH` (`_ABORT_KNOCK_ERRNOS`). The latter maps
/// to [`io::ErrorKind::HostUnreachable`]; the former does not map to any `ErrorKind` at all, so the
/// raw errno is compared instead. On a platform where the value is unknown the constant is one no
/// errno can take, so nothing matches and every `OSError` is swallowed — which is the safe
/// direction: an extra futile knock costs one connect attempt, a wrongly-aborted scan costs the
/// device.
#[cfg(target_os = "linux")]
const EHOSTDOWN: i32 = 112;
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
))]
const EHOSTDOWN: i32 = 64;
#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "watchos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly"
)))]
const EHOSTDOWN: i32 = i32::MIN;

/// Knock on every port in `ports` on `address`, concurrently, once each.
///
/// Each port gets its own connect timeout of `timeout` minus `KNOCK_TIMEOUT_BUFFER`. Returns once
/// every knock has finished, or immediately once one reports that the *host* is unreachable.
///
/// # One knock per call
///
/// `knocker`'s docstring upstream claims "New port knocks are sent every two seconds, so a timeout
/// of 4 seconds will result in two knocks" (`pyatv/support/knock.py:76-77`). The implementation
/// contains no resend loop whatsoever: `knock()` fires exactly one attempt per port and returns.
/// This is a verified doc/code mismatch on the pinned commit (`discovery-port-spec.md` §6 and §9),
/// and pyatv's own test asserts the *code*'s behaviour — `test_continuous_knocking`
/// (`tests/support/test_knock.py:38-44`) knocks with `timeout=6` and asserts the server saw
/// exactly **one** connection. The code is what is ported here.
///
/// # Errors
///
/// Returns [`Error::Io`] only when a connection attempt fails with `EHOSTDOWN` or `EHOSTUNREACH`.
/// Those two mean the host is not on the network at all, so no port will ever answer and continuing
/// is pointless. Every other failure — connection refused, connection reset, timeout — is expected:
/// a closed port is the normal case and is silently ignored.
///
/// # Examples
///
/// ```no_run
/// # async fn example() -> Result<(), pyatv_core::Error> {
/// use pyatv_mdns::knock::{DEFAULT_KNOCK_TIMEOUT, KNOCK_PORTS, knock};
///
/// knock(
///     "10.0.0.10".parse().expect("literal address"),
///     &KNOCK_PORTS,
///     DEFAULT_KNOCK_TIMEOUT,
/// )
/// .await?;
/// # Ok(())
/// # }
/// ```
pub async fn knock(address: IpAddr, ports: &[u16], timeout: Duration) -> Result<()> {
    let per_port = timeout.saturating_sub(KNOCK_TIMEOUT_BUFFER);

    let mut knocks = JoinSet::new();
    for &port in ports {
        // pyatv yields to the event loop before scheduling each task, "to ensure we do not block".
        tokio::task::yield_now().await;
        tracing::debug!(%address, port, "knocking");
        knocks.spawn(knock_port(address, port, per_port));
    }

    // `asyncio.wait(..., return_when=FIRST_EXCEPTION)`: stop at the first real failure, cancel the
    // rest, and let every other outcome pass.
    while let Some(joined) = knocks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                knocks.shutdown().await;
                return Err(Error::Io(error));
            }
            Err(join_error) => {
                // Cancellation is expected during shutdown; a panic is a bug worth surfacing, and
                // pyatv likewise re-raises anything that is not an `OSError`.
                if join_error.is_panic() {
                    knocks.shutdown().await;
                    return Err(Error::Io(io::Error::other(format!(
                        "knock task panicked: {join_error}"
                    ))));
                }
            }
        }
    }

    Ok(())
}

/// Schedule [`knock`] and hand back a cancellable handle without awaiting it.
///
/// Ports `knocker` (`pyatv/support/knock.py:68-79`), which returns the scheduled future directly so
/// that `UnicastMdnsScanner._get_services` can race it against its DNS query instead of paying for
/// it serially. Dropping the handle detaches the knock; call [`JoinHandle::abort`] to cancel it.
///
/// The knock outcome is deliberately not folded into the scan's result: a failed knock only means
/// the device stays asleep, which the scan then reports as a device with no reachable services.
///
/// # Examples
///
/// ```no_run
/// # async fn example() {
/// use pyatv_mdns::knock::{DEFAULT_KNOCK_TIMEOUT, KNOCK_PORTS, knocker};
///
/// let address = "10.0.0.10".parse().expect("literal address");
/// let handle = knocker(address, KNOCK_PORTS.to_vec(), DEFAULT_KNOCK_TIMEOUT);
/// // ... run the DNS query concurrently, then reap the knock ...
/// let _ = handle.await;
/// # }
/// ```
#[must_use]
pub fn knocker(address: IpAddr, ports: Vec<u16>, timeout: Duration) -> JoinHandle<Result<()>> {
    tokio::spawn(async move { knock(address, &ports, timeout).await })
}

/// Open and immediately close one TCP connection.
///
/// Ports `_async_knock` (`pyatv/support/knock.py:24-43`). A connect timeout is swallowed — the port
/// simply did not answer in time, which is not a failure for knocking purposes. So is any other
/// `OSError` except the two that mean the host itself is gone.
async fn knock_port(address: IpAddr, port: u16, timeout: Duration) -> io::Result<()> {
    let target = SocketAddr::new(address, port);

    match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => {
            // Hold the connection open briefly, then drop it. The remote reacts to the connection,
            // not to how it ends.
            tokio::time::sleep(SLEEP_AFTER_CONNECT).await;
            drop(stream);
            tracing::trace!(%target, "knock connected");
            Ok(())
        }
        Ok(Err(error)) if is_host_unreachable(&error) => {
            tracing::debug!(%target, %error, "host is unreachable, aborting knock");
            Err(error)
        }
        Ok(Err(error)) => {
            tracing::trace!(%target, %error, "knock refused (expected)");
            Ok(())
        }
        Err(_elapsed) => {
            tracing::trace!(%target, ?timeout, "knock timed out (expected)");
            Ok(())
        }
    }
}

/// Whether an error means the host itself is not there, rather than one port being closed.
fn is_host_unreachable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::HostUnreachable || error.raw_os_error() == Some(EHOSTDOWN)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use tokio::net::TcpListener;

    use super::{
        DEFAULT_KNOCK_TIMEOUT, EHOSTDOWN, Error, KNOCK_PORTS, is_host_unreachable, knock, knocker,
    };

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// A listener that counts accepted connections, standing in for `tests/conftest.py`'s
    /// `knock_server` fixture.
    struct KnockServer {
        port: u16,
        count: Arc<AtomicUsize>,
    }

    async fn knock_server() -> io::Result<KnockServer> {
        let listener = TcpListener::bind(SocketAddr::new(LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let count = Arc::new(AtomicUsize::new(0));

        let accepted = Arc::clone(&count);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                accepted.fetch_add(1, Ordering::Relaxed);
                drop(stream);
            }
        });

        Ok(KnockServer { port, count })
    }

    async fn until_count(server: &KnockServer, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while server.count.load(Ordering::Relaxed) < expected {
            assert!(Instant::now() < deadline, "timed out waiting for a knock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// These exact ports are what makes a sleeping device answer; guard them against edits.
    #[test]
    fn knock_ports_match_pyatv() {
        assert_eq!(KNOCK_PORTS, [3689, 7000, 49152, 32498]);
    }

    /// `test_single_port_knock`.
    #[tokio::test]
    async fn a_single_port_is_knocked() {
        let server = knock_server().await.expect("test listener binds");
        knock(LOCALHOST, &[server.port], Duration::from_secs(1))
            .await
            .expect("knocking a listening port succeeds");
        until_count(&server, 1).await;
    }

    /// `test_multi_port_knock`: every port is knocked, concurrently.
    #[tokio::test]
    async fn every_port_is_knocked() {
        let first = knock_server().await.expect("test listener binds");
        let second = knock_server().await.expect("test listener binds");

        knock(
            LOCALHOST,
            &[first.port, second.port],
            Duration::from_secs(1),
        )
        .await
        .expect("knocking listening ports succeeds");

        until_count(&first, 1).await;
        until_count(&second, 1).await;
    }

    /// `test_continuous_knocking`: despite the docstring, one call knocks exactly once per port.
    #[tokio::test]
    async fn a_knock_is_sent_once_not_repeatedly() {
        let server = knock_server().await.expect("test listener binds");

        knocker(LOCALHOST, vec![server.port], Duration::from_secs(3))
            .await
            .expect("the knock task runs to completion")
            .expect("knocking a listening port succeeds");

        // Give any (nonexistent) resend loop a full cadence to prove itself.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert_eq!(server.count.load(Ordering::Relaxed), 1);
    }

    /// `test_knock_does_not_raise`: a closed port is the normal case.
    #[tokio::test]
    async fn knocking_a_closed_port_is_not_an_error() {
        // Bind and immediately drop a listener to get a port nothing is listening on.
        let listener = TcpListener::bind(SocketAddr::new(LOCALHOST, 0))
            .await
            .expect("test listener binds");
        let port = listener.local_addr().expect("bound listener").port();
        drop(listener);

        knock(LOCALHOST, &[port], Duration::from_millis(500))
            .await
            .expect("a refused connection is swallowed");
    }

    /// Knocking no ports at all is a no-op rather than an error.
    #[tokio::test]
    async fn knocking_no_ports_succeeds() {
        knock(LOCALHOST, &[], DEFAULT_KNOCK_TIMEOUT)
            .await
            .expect("an empty port list is a no-op");
    }

    /// `test_knock_times_out`: a link-local address never answers, and that is not an error.
    ///
    /// Linux lets the SYN time out, which is the silence this test is about. macOS (as on the CI
    /// runners) has no route for `169.254/16` without a link-local interface and fails the
    /// connect immediately with `EHOSTUNREACH`, which is the *other* documented outcome — the
    /// host-level abort covered by `only_host_level_failures_abort`. Either is acceptable here;
    /// anything else (a refused connection surfacing, a panic) is not.
    #[tokio::test]
    async fn a_timed_out_knock_is_not_an_error() {
        let link_local = IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1));
        match knock(link_local, &[1], Duration::from_millis(300)).await {
            Ok(()) => {}
            Err(Error::Io(error)) => assert!(
                is_host_unreachable(&error),
                "only a host-level failure may surface, got {error}"
            ),
            Err(other) => panic!("unexpected error kind: {other}"),
        }
    }

    /// `EHOSTUNREACH` and `EHOSTDOWN` abort; a refused connection does not.
    #[test]
    fn only_host_level_failures_abort() {
        assert!(is_host_unreachable(&io::Error::from(
            io::ErrorKind::HostUnreachable
        )));
        assert!(is_host_unreachable(&io::Error::from_raw_os_error(
            EHOSTDOWN
        )));

        assert!(!is_host_unreachable(&io::Error::from(
            io::ErrorKind::ConnectionRefused
        )));
        assert!(!is_host_unreachable(&io::Error::from(
            io::ErrorKind::TimedOut
        )));
        assert!(!is_host_unreachable(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
    }
}
