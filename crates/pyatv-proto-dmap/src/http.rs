//! A small HTTP/1.1 client, for DAAP and nothing else.
//!
//! # Why this exists rather than reusing something
//!
//! Three candidates were considered before writing it.
//!
//! **`pyatv-proto-airplay`'s `HttpConnection`** is the closest fit and was rejected on two counts.
//! Structurally, `pyatv-proto-dmap` depending on `pyatv-proto-airplay` breaks the workspace's
//! dependency rule — protocol crates depend on `pyatv-core`, never on each other — and the umbrella
//! crate is the only place protocols are allowed to meet. Substantively, that client is not
//! general: it parses RTSP verbs and `RTSP/1.0` status lines alongside HTTP ones, threads a
//! `HapSession` through raw socket reads to splice in encryption below the HTTP layer, and
//! documents `Content-Length`-only framing as a deliberate simplification because AirPlay genuinely
//! never sends anything else. None of that is DMAP, and the last part is the problem — see below.
//!
//! **Moving that codec into `pyatv-core`** would have fixed the direction but not the substance:
//! what would move is an RTSP-aware, HAP-aware codec whose two callers want different things from
//! it, and `pyatv-core` is the crate that is supposed to have no protocol knowledge at all.
//!
//! **A real HTTP client crate** (`hyper`, `reqwest`) would work — `docs/research/rust-crates.md`
//! §62 rejected them for AirPlay on the grounds that they hide raw framing, which is not an
//! objection that applies to DAAP. It is a large dependency for one legacy protocol that needs
//! `GET` and `POST` over one connection, so the ~200 lines below won.
//!
//! # Framing, and the `Accept-Encoding: gzip` question
//!
//! pyatv's DMAP client goes through `aiohttp` (`pyatv/support/http.py:251-323`), a fully conformant
//! HTTP/1.1 implementation, and sends `Accept-Encoding: gzip` on every request (`daap.py:19`).
//! `docs/research/dmap-port-spec.md` §6.2 flags the consequence: pyatv would transparently handle a
//! chunked or gzip-encoded answer, and nobody has captured a gen 1-3 Apple TV to find out whether
//! one ever arrives.
//!
//! Two ways to close that gap without a device to measure against. Dropping the header changes a
//! request byte pattern that demonstrably works, in exchange for an assumption about what devices
//! do; implementing the two codings costs about eighty lines and assumes nothing. This client
//! therefore sends pyatv's header set byte for byte and handles `Content-Length`, `chunked`, and
//! `Content-Encoding: gzip` on the way back. If a capture ever proves the codings never occur, the
//! code is dead and harmless; if one occurs, it works.
//!
//! # One connection per request
//!
//! pyatv reuses an `aiohttp` session. This opens a connection, sends `Connection: close`, and
//! closes it. DAAP has no protocol state on the connection — the session lives in the `session-id`
//! query parameter — so nothing observable depends on reuse, and the alternative would mean
//! managing a keep-alive pool around `playstatusupdate`, a request that legitimately holds a socket
//! open for minutes at a time.

pub mod response;

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub use response::{ChunkedDecoder, Framing, Head, MAX_BODY_LEN, MAX_CHUNKED_RAW_LEN, is_success};

use crate::{Error, Result};

/// How long to wait for the TCP handshake.
///
/// **Not** pyatv's. `daap.py:28` declares `DEFAULT_TIMEOUT = 10.0` and then never applies it:
/// every call site passes `timeout=None` explicitly (`DaapRequester.get`/`post` default it to
/// `None`, `daap.py:106,117`) and the push updater passes `0`, both of which `aiohttp` reads as
/// "no timeout". So DMAP requests are unbounded upstream, and [`HttpRequest::timeout`] keeps that.
/// Bounding the *connect* is different: a request that has not reached a device yet cannot be a
/// long poll, and hanging forever on a `SYN` to an unplugged Apple TV serves nobody.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How much to read at a time. DAAP bodies are a few hundred bytes; artwork is a few hundred KiB.
const READ_CHUNK: usize = 16 * 1024;

/// The two verbs DAAP uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`, used for `login`, `playstatusupdate` and `nowplayingartwork`.
    Get,
    /// `POST`, used for every command.
    Post,
}

impl Method {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// One request to send.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    /// `GET` or `POST`.
    pub method: Method,
    /// Path and query, without a leading slash — DAAP command templates are relative
    /// (`ctrl-int/1/play?...`) and the slash is added when the request line is built.
    pub path: &'a str,
    /// Headers to send verbatim, in order. `Host`, `Connection` and, for a `POST`,
    /// `Content-Length` are added on top.
    pub headers: &'a [(&'a str, &'a str)],
    /// Request body. `POST` with `None` sends `Content-Length: 0`.
    pub body: Option<&'a [u8]>,
    /// Overall deadline, or `None` for no deadline — which is what DAAP uses, see
    /// [`CONNECT_TIMEOUT`].
    pub timeout: Option<Duration>,
}

/// What a device answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code. `_do` branches on this and only this (`daap.py:130-152`).
    pub status: u16,
    /// The decoded body: de-chunked and de-gzipped, ready to hand to the DMAP parser.
    pub body: Vec<u8>,
}

/// Sends requests to one device.
#[derive(Debug, Clone)]
pub struct HttpClient {
    peer: SocketAddr,
    host: String,
}

impl HttpClient {
    /// A client for the device at `peer`.
    ///
    /// `peer` is the config's address plus the service's SRV port — never a hardcoded 3689.
    #[must_use]
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            host: peer.to_string(),
            peer,
        }
    }

    /// The address requests are sent to.
    #[must_use]
    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    /// Send one request and read the whole response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] if the connection cannot be opened or drops mid-response — which is
    /// what a device closing the socket to signal an error looks like, and what
    /// `server_closes_connection` exercises — or [`Error::Http`] if the request cannot be
    /// represented on the wire (see this type's private `encode`), or if the response cannot be
    /// framed or
    /// decoded.
    pub async fn send(&self, request: &HttpRequest<'_>) -> Result<HttpResponse> {
        match request.timeout {
            None => self.exchange(request).await,
            Some(limit) => tokio::time::timeout(limit, self.exchange(request))
                .await
                .map_err(|_| {
                    Error::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("{} {} timed out", request.method.as_str(), request.path),
                    ))
                })?,
        }
    }

    async fn exchange(&self, request: &HttpRequest<'_>) -> Result<HttpResponse> {
        // Encoded before the socket is opened: a request that cannot be represented is refused
        // without a connection ever being made to report it with.
        let bytes = self.encode(request)?;

        let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(self.peer))
            .await
            .map_err(|_| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out connecting to {}", self.peer),
                ))
            })??;
        // Requests are small and strictly one at a time; waiting for more data to coalesce would
        // only add latency.
        stream.set_nodelay(true)?;

        stream.write_all(&bytes).await?;
        stream.flush().await?;

        self.read_response(&mut stream).await
    }

    /// Build the request bytes.
    ///
    /// # Why this validates
    ///
    /// The request target is assembled from a command template and a *stored credential*
    /// ([`crate::daap::url::mkurl`]), and that credential is whatever was on disk or came back
    /// from a pairing exchange. It is only ever prefix-matched — `re.match` upstream, and
    /// [`crate::daap::url::classify`] here, both deliberately accept trailing junk — so a
    /// credential such as `"0x0000000000000001\r\nX-Injected: 1"` classifies as a pairing GUID and
    /// is interpolated straight into the request line. Written out unchecked, that CRLF ends the
    /// request line early and everything after it becomes attacker-chosen headers, or a second
    /// request entirely.
    ///
    /// So the bytes are checked here rather than at the credential parser, where narrowing the
    /// match would be a behavioural divergence from upstream for no security gain: a device would
    /// reject such a login anyway, and any *other* caller-supplied path or header has the same
    /// problem. RFC 9112 §3.2 makes a request target a sequence of visible ASCII, RFC 9110 §5.1
    /// makes a field name a token, and §5.5 forbids controls in a field value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] if the path contains a byte outside `0x21..=0x7E`, if a header name
    /// is not a token, or if a header value contains a control byte.
    fn encode(&self, request: &HttpRequest<'_>) -> Result<Vec<u8>> {
        check_request_target(request.path)?;

        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(
            format!("{} /{} HTTP/1.1\r\n", request.method.as_str(), request.path).as_bytes(),
        );
        // HTTP/1.1 requires Host (RFC 9112 §3.2). pyatv does not build it by hand either; aiohttp
        // adds it from the URL, which is this same host:port.
        out.extend_from_slice(format!("Host: {}\r\n", self.host).as_bytes());

        for (name, value) in request.headers {
            check_header(name, value)?;
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }

        if request.method == Method::Post {
            let length = request.body.map_or(0, <[u8]>::len);
            out.extend_from_slice(format!("Content-Length: {length}\r\n").as_bytes());
        }
        out.extend_from_slice(b"Connection: close\r\n\r\n");

        if let Some(body) = request.body {
            out.extend_from_slice(body);
        }
        Ok(out)
    }

    /// Read a head, then whatever framing it declares.
    async fn read_response(&self, stream: &mut TcpStream) -> Result<HttpResponse> {
        let mut buffer = Vec::new();
        let (head, head_len) = loop {
            if let Some(parsed) = response::parse_head(&buffer)? {
                break parsed;
            }
            if read_more(stream, &mut buffer).await? == 0 {
                return Err(closed("before the response head was complete"));
            }
        };

        let body = match head.framing()? {
            Framing::Length(length) => {
                // Refused on the declared length, before a byte of it is read: the point of the
                // cap is not to allocate what is about to be rejected.
                if length > MAX_BODY_LEN {
                    return Err(response::body_too_large(length));
                }
                while buffer.len() - head_len < length {
                    if read_more(stream, &mut buffer).await? == 0 {
                        return Err(closed(&format!(
                            "after {} of {length} body bytes",
                            buffer.len() - head_len
                        )));
                    }
                }
                buffer[head_len..head_len + length].to_vec()
            }
            Framing::Chunked => {
                // The decoder is kept across reads so a body arriving in many pieces is decoded
                // once rather than re-scanned from byte zero every time; it enforces
                // `MAX_BODY_LEN` on the decoded data as it goes.
                //
                // That cap alone does not bound this loop, though, because the decoded body and the
                // raw buffer are not the same quantity: chunk framing, and anything the decoder is
                // still waiting to complete, sit in `buffer` without ever reaching `body`. The
                // decoder bounds each individual incomplete region it can be strung along by (a
                // chunk-size line, the trailer section); `MAX_CHUNKED_RAW_LEN` bounds the sum, and
                // with it the memory this loop can be made to hold.
                let mut decoder = ChunkedDecoder::new();
                loop {
                    if decoder.feed(&buffer[head_len..])?.is_some() {
                        break decoder.into_body();
                    }
                    let raw = buffer.len() - head_len;
                    if raw > MAX_CHUNKED_RAW_LEN {
                        return Err(response::framing_too_large(
                            "chunked response",
                            raw,
                            MAX_CHUNKED_RAW_LEN,
                        ));
                    }
                    if read_more(stream, &mut buffer).await? == 0 {
                        return Err(closed("inside a chunked body"));
                    }
                }
            }
            Framing::ToEof => {
                // Nothing declares how long this is, so the only bound is the cap.
                while read_more(stream, &mut buffer).await? != 0 {
                    if buffer.len() - head_len > MAX_BODY_LEN {
                        return Err(response::body_too_large(buffer.len() - head_len));
                    }
                }
                buffer[head_len..].to_vec()
            }
        };

        let body = head.decode_body(body)?;
        tracing::trace!(status = head.status, bytes = body.len(), "DAAP response");
        Ok(HttpResponse {
            status: head.status,
            body,
        })
    }
}

/// The device hung up mid-response.
///
/// Deliberately [`Error::Io`] rather than [`Error::Http`]: this is a transport failure, not a
/// malformed message, and [`crate::facade::updates`] tells the two apart to decide whether a push
/// loop should report a lost connection and stop or reset its revision and carry on. It is also
/// exactly what pyatv's fake device does to simulate a drop (`force_close`,
/// `tests/fake_device/dmap.py:219-220`), which is what `test_connection_lost` is built on.
fn closed(where_: &str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        format!("connection closed {where_}"),
    ))
}

/// Whether a byte may appear in a request target.
///
/// RFC 9112 §3.2: the target is `origin-form`, made of `pchar`/`/`/`?` — all of which are visible
/// ASCII. Anything below `0x21` (which is every control byte, plus the space that would end the
/// target) or above `0x7E` cannot be there, and a URL that needs one must percent-encode it.
fn is_target_byte(byte: u8) -> bool {
    (0x21..=0x7E).contains(&byte)
}

/// Whether a byte may appear in a header field name.
///
/// RFC 9110 §5.6.2 `tchar`, which is what a field name is a sequence of.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Refuse a request target that would not survive being written into a request line.
fn check_request_target(path: &str) -> Result<()> {
    match path.bytes().find(|byte| !is_target_byte(*byte)) {
        None => Ok(()),
        Some(byte) => Err(Error::Http(format!(
            "request path contains {byte:#04X}, which cannot appear in a request target: {path:?}"
        ))),
    }
}

/// Refuse a header field that would not survive being written into a head.
///
/// Field values are checked against every control byte rather than only `CR` and `LF`. A bare `CR`
/// or a `NUL` is not a header terminator here but is one to some intermediary, and DAAP's seven
/// headers contain nothing but printable ASCII, so there is no legitimate value to lose.
fn check_header(name: &str, value: &str) -> Result<()> {
    if name.is_empty() || !name.bytes().all(is_token_byte) {
        return Err(Error::Http(format!("header name is not a token: {name:?}")));
    }
    if value.bytes().any(|byte| byte < 0x20 || byte == 0x7F) {
        return Err(Error::Http(format!(
            "header {name} carries a control byte in its value: {value:?}"
        )));
    }
    Ok(())
}

/// Append one read's worth of bytes, returning how many arrived. Zero means end of stream.
async fn read_more(stream: &mut TcpStream, buffer: &mut Vec<u8>) -> Result<usize> {
    let start = buffer.len();
    buffer.resize(start + READ_CHUNK, 0);
    let read = stream.read(&mut buffer[start..]).await?;
    buffer.truncate(start + read);
    Ok(read)
}

#[cfg(test)]
mod tests;
