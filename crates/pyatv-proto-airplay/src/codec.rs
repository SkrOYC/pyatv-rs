//! The bidirectional RTSP/HTTP codec.
//!
//! One `Framed<TcpStream, AirPlayCodec>` serves both directions of an AirPlay connection: the
//! controller's own requests and their responses, and the requests the receiver sends back over the
//! same socket. See this crate's module documentation and `docs/research/rust-crates.md` §5 for why
//! no existing HTTP crate fits.
//!
//! Bodies stay opaque [`bytes::Bytes`] at this layer. Decoding `application/x-apple-binary-plist`
//! is [`crate::rtsp`]'s job, one layer up.

use bytes::Bytes;

/// The header carrying the body length. No chunked transfer encoding is used or accepted.
pub const CONTENT_LENGTH: &str = "Content-Length";

/// Content type for the binary plist bodies AirPlay uses throughout.
pub const BPLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

/// The user agent pyatv presents.
pub const USER_AGENT: &str = "AirPlay/550.10";

/// A request travelling in either direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Method, which may be an RTSP verb rather than an HTTP one.
    pub method: String,
    /// Request target.
    pub uri: String,
    /// Protocol token, `RTSP/1.0` or `HTTP/1.1` depending on device generation.
    pub protocol: String,
    /// Headers in wire order, with names as sent.
    pub headers: Vec<(String, String)>,
    /// Body bytes, undecoded.
    pub body: Bytes,
}

/// A response travelling in either direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// Protocol token.
    pub protocol: String,
    /// Status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: String,
    /// Headers in wire order.
    pub headers: Vec<(String, String)>,
    /// Body bytes, undecoded.
    pub body: Bytes,
}

/// One decoded message, from either role.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// The peer sent a request.
    Request(Request),
    /// The peer sent a response.
    Response(Response),
}

/// Encodes and decodes AirPlay's RTSP-flavoured messages.
///
/// Stateless: every frame is self-delimiting given its `Content-Length`.
#[derive(Debug, Default, Clone, Copy)]
pub struct AirPlayCodec;

// TODO(step-1): implement `tokio_util::codec::Decoder` and `Encoder<Frame>` for AirPlayCodec:
//
//   1. Scan for the \r\n\r\n header/body boundary; return Ok(None) if it is not there yet.
//   2. Parse the first line permissively, trying response shape (protocol status reason) then
//      request shape (method uri protocol). pyatv's parser does exactly this because the grammar
//      genuinely is the same read from either direction.
//   3. Read Content-Length and return Ok(None) until that many body bytes have arrived.
//   4. Emit Frame::Request or Frame::Response, body as opaque Bytes.
//
// Steps 1-3 should be plain functions over &[u8] with no tokio involvement, so they can be tested
// against captured byte slices; the Decoder impl is then a thin wrapper. See
// docs/research/rust-crates.md §5.
