//! A minimal HTTP/1.1 client over one TCP connection.
//!
//! Port of `HttpConnection` (`pyatv/support/http.py:326-499`) restricted to what pairing needs:
//! `POST` with an optional body, one response per request, keep-alive, and an optional byte-stream
//! processor pair so that [`pyatv_pairing::session::HapSession`] can be spliced in after
//! pair-verify.
//!
//! Two details are reproduced exactly because a device notices them:
//!
//! - **Header order.** `_format_message` (`pyatv/support/http.py:50-80`) emits the start line, then
//!   a default `User-Agent` only if the caller did not supply one, then `Content-Length` only if
//!   the body is non-empty, and only then the caller's headers in their own insertion order. The
//!   caller's `Content-Type` therefore lands *after* `Content-Length`, not before it. See
//!   [`HttpConnection::post`].
//! - **`Content-Length`-only framing.** Both directions. See [`crate::codec::parse_frame`].
//!
//! This does not use `Framed`: the [`pyatv_pairing::session::HapSession`] wrapper operates on raw
//! socket reads and writes, below HTTP parsing, exactly as pyatv's `receive_processor`/
//! `send_processor` do (`pyatv/support/http.py:344-349,387,457`).

use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::codec::{CONTENT_LENGTH, Frame, HTTP_1_1, Request, Response, encode_frame, parse_frame};
use crate::{Error, Result};

/// How long to wait for a device to answer one request.
///
/// pyatv uses ten seconds for a request (`pyatv/support/http.py:446`) but twenty-five to reach a
/// device at all, because a sleeping Apple TV can take that long to wake up when a service is
/// requested from it (`pyatv/support/http.py:36-39`). Both are kept.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait for the TCP connection itself (`pyatv/support/http.py:39`).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(25);

/// The user agent used when a caller supplies none (`pyatv/support/http.py:33`).
///
/// Upstream sends `pyatv/{version}`; this port names itself, since a device that special-cases the
/// string would be responding to a claim about a codebase this is not. No pairing request reaches
/// this default: every one of them sets [`crate::auth::PAIRING_USER_AGENT`] explicitly.
pub const DEFAULT_USER_AGENT: &str = concat!("pyatv-rs/", env!("CARGO_PKG_VERSION"));

/// Read chunk size. Pairing messages are a few hundred bytes; RTSP bodies are a few kilobytes.
const READ_CHUNK: usize = 8 * 1024;

/// One HTTP/1.1 connection to a device, reused for every request.
#[derive(Debug)]
pub struct HttpConnection {
    stream: TcpStream,
    buffer: BytesMut,
    /// Set once pair-verify has completed and the control channel is encrypted.
    session: Option<HapSession>,
    remote: SocketAddr,
}

impl HttpConnection {
    /// Open a connection to `address`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket could not be opened, or a timed-out
    /// [`std::io::ErrorKind::TimedOut`] error after [`CONNECT_TIMEOUT`].
    pub async fn connect(address: SocketAddr) -> Result<Self> {
        tracing::debug!(%address, "opening AirPlay HTTP connection");

        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out connecting to {address}"),
                )
            })??;

        // Pairing is a strict request/response ping-pong of small messages; waiting for more data
        // to coalesce only adds latency.
        stream.set_nodelay(true)?;

        Ok(Self {
            stream,
            buffer: BytesMut::new(),
            session: None,
            remote: address,
        })
    }

    /// The address this connection was opened to.
    #[must_use]
    pub fn remote_address(&self) -> SocketAddr {
        self.remote
    }

    /// Whether transport encryption has been enabled.
    #[must_use]
    pub fn is_encrypted(&self) -> bool {
        self.session.is_some()
    }

    /// Splice a [`HapSession`] into the byte stream, encrypting everything from here on.
    ///
    /// Equivalent to `verify_connection`'s two assignments
    /// (`pyatv/protocols/airplay/auth/__init__.py:114-115`). Called once, after pair-verify.
    pub fn enable_encryption(&mut self, session: HapSession) {
        tracing::debug!(remote = %self.remote, "enabling AirPlay control channel encryption");
        self.session = Some(session);
    }

    /// Send a `POST` and await its response.
    ///
    /// `headers` are emitted in the given order, after the `Content-Length` this method inserts for
    /// a non-empty `body` — that relative order is upstream's and is part of the byte sequence a
    /// device sees.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] on `401`/`403`, [`Error::Status`] on any other
    /// non-`2xx`, [`Error::Malformed`] if the reply cannot be parsed and [`Error::Io`] if the
    /// connection fails or the device does not answer within [`REQUEST_TIMEOUT`].
    pub async fn post(
        &mut self,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response> {
        let request = build_request(path, headers, body);
        let response = self.send_and_receive(request).await?;

        if matches!(response.status, 401 | 403) {
            return Err(Error::NotAuthenticated {
                status: response.status,
            });
        }
        if !response.is_success() {
            return Err(Error::Status {
                status: response.status,
                reason: response.reason,
            });
        }

        Ok(response)
    }

    /// Write one request and read frames until the matching response arrives.
    async fn send_and_receive(&mut self, request: Request) -> Result<Response> {
        let method = request.method.clone();
        let uri = request.uri.clone();

        let mut wire = BytesMut::new();
        encode_frame(&Frame::Request(request), &mut wire);
        tracing::debug!(
            remote = %self.remote,
            %method,
            %uri,
            bytes = wire.len(),
            "sending request"
        );
        tracing::trace!(remote = %self.remote, head = %head_of(&wire), "request head");

        let outbound = match self.session.as_mut() {
            Some(session) => BytesMut::from(&session.encrypt(&wire)?[..]),
            None => wire,
        };
        self.stream.write_all(&outbound).await?;
        self.stream.flush().await?;

        tokio::time::timeout(REQUEST_TIMEOUT, self.read_response())
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("no response to {method} {uri} from {}", self.remote),
                )
            })?
    }

    /// Read until a response frame completes, dispatching anything else that arrives first.
    async fn read_response(&mut self) -> Result<Response> {
        loop {
            while let Some((frame, consumed)) = parse_frame(&self.buffer)? {
                tracing::trace!(
                    remote = %self.remote,
                    head = %head_of(&self.buffer[..consumed]),
                    "response head"
                );
                let _ = self.buffer.split_to(consumed);
                match frame {
                    Frame::Response(response) => {
                        tracing::debug!(
                            remote = %self.remote,
                            status = response.status,
                            reason = %response.reason,
                            body = response.body.len(),
                            "received response"
                        );
                        return Ok(response);
                    }
                    // The receiver opens reverse requests on this socket once streaming starts
                    // (`pyatv/support/http.py:399-404` logs the mirror case). Pairing never sees
                    // one, so dropping it is safe here.
                    // TODO(step-2): hand these to the RTSP layer's inbound dispatcher instead of
                    // discarding them, which `RtspSession::request` will need.
                    Frame::Request(request) => tracing::debug!(
                        remote = %self.remote,
                        method = %request.method,
                        uri = %request.uri,
                        "ignoring reverse request from receiver"
                    ),
                }
            }

            let mut chunk = [0u8; READ_CHUNK];
            let read = self.stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("{} closed the connection", self.remote),
                )
                .into());
            }

            match self.session.as_mut() {
                Some(session) => self
                    .buffer
                    .extend_from_slice(&session.decrypt(&chunk[..read])?),
                None => self.buffer.extend_from_slice(&chunk[..read]),
            }
        }
    }

    /// Shut the connection down.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket could not be shut down cleanly.
    pub async fn close(&mut self) -> Result<()> {
        tracing::debug!(remote = %self.remote, "closing AirPlay HTTP connection");
        self.stream.shutdown().await?;
        Ok(())
    }
}

/// Render a message's header block for logging, with the CRLFs made visible.
///
/// Only the head: bodies carry SRP proofs, encrypted TLVs and, on the legacy path, the PIN-derived
/// material, none of which belongs in a log. `\r\n` is escaped so one exchange stays one log line.
fn head_of(message: &[u8]) -> String {
    let end = message
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map_or(message.len(), |boundary| boundary + 4);

    String::from_utf8_lossy(&message[..end])
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// Build the request pyatv's `_format_message` would produce for a `POST`.
///
/// The three conditional insertions, in upstream's order
/// (`pyatv/support/http.py:64-74`):
///
/// 1. `User-Agent`, only when the caller did not supply one.
/// 2. `Content-Type`, only from the dedicated parameter — which `post` never passes, so it never
///    appears here; callers put their own `Content-Type` in `headers` instead, where it lands after
///    `Content-Length`.
/// 3. `Content-Length`, only when the body is non-empty. Python's truthiness test means a
///    zero-length body produces no header at all, not `Content-Length: 0`.
fn build_request(path: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
    let mut wire_headers: Vec<(String, String)> = Vec::with_capacity(headers.len() + 2);

    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
    {
        wire_headers.push(("User-Agent".to_owned(), DEFAULT_USER_AGENT.to_owned()));
    }
    if !body.is_empty() {
        wire_headers.push((CONTENT_LENGTH.to_owned(), body.len().to_string()));
    }
    wire_headers.extend(
        headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );

    Request {
        method: "POST".to_owned(),
        uri: path.to_owned(),
        protocol: HTTP_1_1.to_owned(),
        headers: wire_headers,
        body: bytes::Bytes::copy_from_slice(body),
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::build_request;
    use crate::codec::{Frame, encode_frame};

    fn rendered(path: &str, headers: &[(&str, &str)], body: &[u8]) -> String {
        let mut out = BytesMut::new();
        encode_frame(
            &Frame::Request(build_request(path, headers, body)),
            &mut out,
        );
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The exact bytes `AirPlayHapPairSetupProcedure.start_pairing` puts on the wire for its first
    /// request (`pyatv/protocols/airplay/auth/hap.py:20-25,52`): no `Content-Length`, because the
    /// body is empty, and the four headers in the order the `_AIRPLAY_HEADERS` dict declares them.
    #[test]
    fn pin_start_request_matches_pyatv_byte_for_byte() {
        let wire = rendered(
            "/pair-pin-start",
            &[
                ("User-Agent", "AirPlay/320.20"),
                ("Connection", "keep-alive"),
                ("X-Apple-HKP", "3"),
                ("Content-Type", "application/octet-stream"),
            ],
            b"",
        );

        assert_eq!(
            wire,
            "POST /pair-pin-start HTTP/1.1\r\n\
             User-Agent: AirPlay/320.20\r\n\
             Connection: keep-alive\r\n\
             X-Apple-HKP: 3\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        );
    }

    /// `Content-Length` is inserted *before* the caller's headers, so the caller's `Content-Type`
    /// follows it. Getting this backwards is the easy mistake, since every other HTTP client emits
    /// `Content-Type` first.
    #[test]
    fn content_length_precedes_the_callers_headers() {
        let wire = rendered(
            "/pair-setup",
            &[
                ("User-Agent", "AirPlay/320.20"),
                ("Connection", "keep-alive"),
                ("X-Apple-HKP", "3"),
                ("Content-Type", "application/octet-stream"),
            ],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        );

        assert_eq!(
            wire,
            "POST /pair-setup HTTP/1.1\r\n\
             Content-Length: 6\r\n\
             User-Agent: AirPlay/320.20\r\n\
             Connection: keep-alive\r\n\
             X-Apple-HKP: 3\r\n\
             Content-Type: application/octet-stream\r\n\r\n\
             \x00\x01\x02\x03\x04\x05"
        );
    }

    /// A caller that supplies no `User-Agent` gets the default, in first position.
    #[test]
    fn a_default_user_agent_is_added_when_absent() {
        let wire = rendered("/anything", &[("Connection", "keep-alive")], b"");
        assert!(wire.starts_with("POST /anything HTTP/1.1\r\nUser-Agent: pyatv-rs/"));
    }
}
