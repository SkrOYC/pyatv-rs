//! The `GET /pair` server the Apple TV calls back into.
//!
//! Port of `DmapPairingHandler`'s web half (`pyatv/protocols/dmap/pairing.py:231-233,258-269`,
//! `:310-327`). One route, one method, an ephemeral port, and a reply that is either a DMAP
//! container or a bare HTTP 500.

use std::io;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use super::code::{RESPONSE_DEVICE_TYPE, verify};
use crate::tags::{container_tag, string_tag, uint64_tag};

/// The mDNS service type an Apple TV browses for when its "Add Remote" screen is open.
pub const REMOTE_SERVICE_TYPE: &str = "_touch-remote._tcp.local";

/// The `DvTy` TXT value: pyatv advertises itself as an iPod running the Remote app
/// (`pairing.py:291`). Not the same as [`RESPONSE_DEVICE_TYPE`]; see its documentation.
pub const DEVICE_TYPE: &str = "iPod";

/// The `RemV` TXT value, a hardcoded remote-protocol version (`pairing.py:290`).
pub const REMOTE_VERSION: &str = "10000";

/// The `RemN` TXT value (`pairing.py:292`).
pub const REMOTE_NAME: &str = "Remote";

/// The `txtvers` TXT value (`pairing.py:293`).
pub const TXT_VERSION: &str = "1";

/// The route the device calls back on.
pub const PAIR_PATH: &str = "/pair";

/// How much of a request head to buffer before giving up on it.
const MAX_REQUEST: usize = 8 * 1024;

/// What the request handler needs, shared with [`super::DmapPairingHandler`].
#[derive(Debug)]
pub struct PairingState {
    /// Uppercase hex, no `0x`.
    pairing_guid: String,
    /// The name shown as `DvNm` and returned as `cmnm`.
    name: String,
    /// `None` until [`super::DmapPairingHandler::pin`] is called, which means "accept any code".
    pin: Mutex<Option<u32>>,
    has_paired: AtomicBool,
}

impl PairingState {
    /// State for one pairing session.
    #[must_use]
    pub fn new(pairing_guid: String, name: String) -> Self {
        Self {
            pairing_guid,
            name,
            pin: Mutex::new(None),
            has_paired: AtomicBool::new(false),
        }
    }

    /// The GUID this session will persist on success.
    #[must_use]
    pub fn pairing_guid(&self) -> &str {
        &self.pairing_guid
    }

    /// The name published as `DvNm` and returned as `cmnm`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the PIN the user is being asked to type on the device (`pin`, `pairing.py:278-281`).
    pub fn set_pin(&self, pin: u32) {
        // Never logged: it is the pairing secret for the duration of this exchange.
        *self.pin.lock().unwrap_or_else(PoisonError::into_inner) = Some(pin);
    }

    /// Whether the device has called back with a matching code.
    #[must_use]
    pub fn has_paired(&self) -> bool {
        self.has_paired.load(Ordering::SeqCst)
    }

    /// Handle one `GET /pair` request, returning the response bytes to write.
    ///
    /// `handle_request` (`pairing.py:310-327`). On a match: HTTP 200 with a `cmpa` container of
    /// `cmpg` (the GUID as a **number**, not as its hex string), `cmnm` (this client's name, the
    /// same value published as `DvNm`) and `cmty` (the literal `iPhone`). On a mismatch: a bare
    /// HTTP 500 with no body at all — `test_failed_pairing` asserts the absence of the container,
    /// not just the status.
    #[must_use]
    pub fn respond(&self, request: &Request) -> Vec<u8> {
        if request.path != PAIR_PATH {
            return http_response(404, &[]);
        }

        let (Some(code), Some(service_name)) =
            (request.query("pairingcode"), request.query("servicename"))
        else {
            // Upstream indexes both parameters unconditionally, so a missing one is a `KeyError`
            // and aiohttp turns that into a 500. Same status, deliberately.
            tracing::debug!("pairing request without pairingcode or servicename");
            return http_response(500, &[]);
        };

        // `servicename` is read, logged, and never used for anything else — not validated against
        // the published instance name, not matched, purely informational (`pairing.py:314-316`).
        tracing::info!(service_name, "got a pairing request");

        let pin = *self.pin.lock().unwrap_or_else(PoisonError::into_inner);
        if !verify(&self.pairing_guid, pin, code) {
            tracing::debug!("pairing code did not match");
            return http_response(500, &[]);
        }

        let Ok(guid) = u64::from_str_radix(&self.pairing_guid, 16) else {
            // Unreachable through this crate's own constructors, which only ever build a GUID from
            // hex digits; a caller-supplied one that is not a number cannot be answered with.
            tracing::warn!(guid = %self.pairing_guid, "pairing GUID is not a 64-bit hex number");
            return http_response(500, &[]);
        };

        let body = container_tag(
            "cmpa",
            &[
                uint64_tag("cmpg", guid),
                string_tag("cmnm", &self.name),
                string_tag("cmty", RESPONSE_DEVICE_TYPE),
            ]
            .concat(),
        );

        self.has_paired.store(true, Ordering::SeqCst);
        http_response(200, &body)
    }
}

/// The parts of a request this server looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Path with the query string removed, e.g. `/pair`.
    pub path: String,
    /// Query parameters in wire order, still percent-encoded.
    pub query: Vec<(String, String)>,
}

impl Request {
    /// Parse a request line such as `GET /pair?pairingcode=abc&servicename=test HTTP/1.1`.
    ///
    /// Only `GET` is routed, which is upstream's single `web.get("/pair", ...)` route
    /// (`pairing.py:232`); any other method falls through to the 404 in [`PairingState::respond`]
    /// because its path will not match.
    #[must_use]
    pub fn parse(line: &str) -> Option<Self> {
        let mut parts = line.split(' ');
        let method = parts.next()?;
        let target = parts.next()?;
        if method != "GET" {
            return None;
        }

        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        Some(Self {
            path: path.to_owned(),
            query: query
                .split('&')
                .filter(|pair| !pair.is_empty())
                .map(|pair| {
                    let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                    (key.to_owned(), value.to_owned())
                })
                .collect(),
        })
    }

    /// The first value for `key`, if present.
    #[must_use]
    pub fn query(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
    }
}

/// Build an HTTP/1.1 response.
///
/// `Connection: close` because the device makes exactly one request and pyatv's `aiohttp` server
/// gains nothing from keeping the socket around either.
#[must_use]
fn http_response(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// The pairing web server, listening on an OS-assigned port.
#[derive(Debug)]
pub struct PairingServer {
    port: u16,
    task: JoinHandle<()>,
}

impl PairingServer {
    /// Bind `0.0.0.0:0` and start serving.
    ///
    /// `unused_port()` then `web.TCPSite(self.runner, "0.0.0.0", port)` (`pairing.py:260-264`),
    /// collapsed into one bind: asking the OS for a free port and then binding it separately is a
    /// race upstream lives with and this does not need to.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] if the listener cannot bind.
    pub async fn bind(state: Arc<PairingState>) -> io::Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        let port = listener.local_addr()?.port();
        tracing::debug!(port, "started the DMAP pairing web server");

        Ok(Self {
            port,
            task: tokio::spawn(serve(listener, state)),
        })
    }

    /// The port the device should be pointed at, which goes into the published SRV record.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for PairingServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Accept connections forever, answering each one and closing it.
async fn serve(listener: TcpListener, state: Arc<PairingState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = Arc::clone(&state);
                // One task per connection: a device that opens a socket and says nothing must not
                // block the next one, and the pairing window is short enough that an abandoned
                // task is bounded by the server's own lifetime.
                tokio::spawn(async move {
                    if let Err(error) = handle(stream, &state).await {
                        tracing::debug!(%peer, %error, "pairing request failed");
                    }
                });
            }
            Err(error) => {
                tracing::debug!(%error, "pairing listener accept failed");
                return;
            }
        }
    }
}

/// Read one request head, answer it, and close.
async fn handle(mut stream: TcpStream, state: &PairingState) -> io::Result<()> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 1024];

    let head_end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(());
        }
        buffer.extend_from_slice(&chunk[..read]);

        if let Some(end) = buffer.windows(4).position(|window| window == b"\r\n\r\n") {
            break end;
        }
        if buffer.len() > MAX_REQUEST {
            stream.write_all(&http_response(500, &[])).await?;
            return stream.shutdown().await;
        }
    };

    let line = String::from_utf8_lossy(&buffer[..head_end]);
    let response = Request::parse(line.lines().next().unwrap_or_default()).map_or_else(
        || http_response(404, &[]),
        |request| state.respond(&request),
    );

    stream.write_all(&response).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests;
