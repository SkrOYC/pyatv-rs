//! A minimal HTTP/1.1 client over one TCP connection.
//!
//! Port of `HttpConnection` (`pyatv/support/http.py:326-499`): one request at a time, keep-alive,
//! and an optional byte-stream processor pair so that [`pyatv_pairing::session::HapSession`] can be
//! spliced in after pair-verify. [`HttpConnection::post`] is what pairing uses;
//! [`HttpConnection::send`] is the general form the RTSP verbs need.
//!
//! Two details are reproduced exactly because a device notices them:
//!
//! - **Header order**, which [`RequestSpec`] and its tests pin down.
//! - **`Content-Length`-only framing.** Both directions. See [`crate::codec::parse_frame`].
//!
//! This does not use `Framed`: the [`pyatv_pairing::session::HapSession`] wrapper operates on raw
//! socket reads and writes, below HTTP parsing, exactly as pyatv's `receive_processor`/
//! `send_processor` do (`pyatv/support/http.py:344-349,387,457`).

mod request;

use std::net::SocketAddr;
use std::time::Duration;

use bytes::BytesMut;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub use request::RequestSpec;

use request::build_request;

use crate::codec::{Frame, Request, Response, encode_frame, parse_frame};
use crate::{Error, Result};

/// How long to wait for a device to answer one request.
///
/// pyatv uses ten seconds for a request (`HttpConnection.send_and_receive`'s `timeout: int = 10`,
/// `pyatv/support/http.py:446`) but twenty-five to reach a device at all, because a sleeping Apple
/// TV can take that long to wake up when a service is requested from it
/// (`pyatv/support/http.py:36-39`). Both are kept.
///
/// # Not the four seconds in `rtsp.py:316`
///
/// `RtspSession.exchange` looks like it bounds an RTSP request at four seconds, and it does not.
/// Read in order (`pyatv/support/rtsp.py:290-320`): it `await`s `send_and_receive` — that is the
/// ten seconds, and it is where a device that never answers is caught — then files the response
/// under the `CSeq` it came back with and **sets that `CSeq`'s event**, and only then waits four
/// seconds for the event belonging to the `CSeq` it asked about. In the ordinary case those are
/// the same number, so the event is already set and the wait returns immediately. The four seconds
/// only elapse when a response arrives carrying a *different* `CSeq` — reordering across
/// concurrent in-flight requests, which this port's one-request-at-a-time
/// [`HttpConnection::send`] cannot produce at all.
///
/// So the faithful bound for "device did not answer" is ten, not four; adopting four would make
/// this client give up on requests pyatv would still be waiting for, on exactly the sleepy devices
/// the long connect timeout above exists for.
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

    /// The local address of this socket, which the RTSP session URI is built from.
    ///
    /// `HttpConnection.local_ip` (`pyatv/support/http.py:352-355`) reads the same value off the
    /// transport, and `RtspSession.uri` (`pyatv/support/rtsp.py:92-95`) interpolates it into
    /// `rtsp://{local_ip}/{session_id}`. A receiver sees that string, so it has to be this
    /// connection's own source address rather than any other interface's.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the socket has no local address.
    pub fn local_address(&self) -> Result<SocketAddr> {
        Ok(self.stream.local_addr()?)
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
        self.send(&RequestSpec {
            method: "POST",
            uri: path,
            headers,
            body,
            ..RequestSpec::default()
        })
        .await
    }

    /// Send one arbitrary message and await its response.
    ///
    /// The general form [`HttpConnection::post`] is a special case of, and the one the RTSP verbs
    /// need: they are not `POST`, they travel as `RTSP/1.0`, and they carry a `User-Agent` that
    /// has to precede `Content-Length` rather than follow it (see [`RequestSpec::user_agent`]).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotAuthenticated`] on `401`/`403` and [`Error::Status`] on any other
    /// non-`2xx`, unless [`RequestSpec::allow_error`] is set, in which case the response is
    /// returned whatever its status. Also [`Error::Malformed`] if the reply cannot be parsed and
    /// [`Error::Io`] if the connection fails or the device does not answer within
    /// [`REQUEST_TIMEOUT`].
    pub async fn send(&mut self, spec: &RequestSpec<'_>) -> Result<Response> {
        let response = self.send_and_receive(build_request(spec)).await?;

        if spec.allow_error {
            return Ok(response);
        }
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
