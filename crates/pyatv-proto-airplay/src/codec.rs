//! The bidirectional RTSP/HTTP codec.
//!
//! One `Framed<TcpStream, AirPlayCodec>` serves both directions of an AirPlay connection: the
//! controller's own requests and their responses, and the requests the receiver sends back over the
//! same socket. See this crate's module documentation and `docs/research/rust-crates.md` §5 for why
//! no existing HTTP crate fits.
//!
//! Bodies stay opaque [`bytes::Bytes`] at this layer. Decoding `application/x-apple-binary-plist`
//! is [`crate::rtsp`]'s job, one layer up.
//!
//! The parsing itself lives in [`parse`] as plain functions over `&[u8]`, so it can be tested
//! against captured byte slices with no runtime involved; the [`tokio_util::codec`] impls at the
//! bottom of this file are thin wrappers over them. [`crate::http::HttpConnection`] uses the plain
//! functions directly rather than `Framed`, because the post-pair-verify
//! [`pyatv_pairing::session::HapSession`] framing has to be applied to the raw byte stream before
//! any HTTP parsing happens — the same `receive_processor`/`send_processor` split pyatv uses
//! (`pyatv/support/http.py:344-349,385-390`).

mod parse;

#[cfg(test)]
mod tests;

use bytes::{BufMut, Bytes, BytesMut};

pub use parse::parse_frame;

use crate::Error;

/// The header carrying the body length. No chunked transfer encoding is used or accepted.
pub const CONTENT_LENGTH: &str = "Content-Length";

/// The header naming a body's format.
pub const CONTENT_TYPE: &str = "Content-Type";

/// Content type for the binary plist bodies AirPlay uses throughout.
pub const BPLIST_CONTENT_TYPE: &str = "application/x-apple-binary-plist";

/// Content type for the raw TLV8 and device-auth bodies pairing uses
/// (`pyatv/protocols/airplay/auth/hap.py:24`).
pub const OCTET_STREAM_CONTENT_TYPE: &str = "application/octet-stream";

/// The user agent pyatv presents on the RTSP and playback connections
/// (`pyatv/support/rtsp.py:22`, `pyatv/protocols/airplay/player.py:17`).
///
/// Pairing uses a different, older one — see [`crate::auth::PAIRING_USER_AGENT`].
pub const USER_AGENT: &str = "AirPlay/550.10";

/// The protocol token pyatv sends on the pairing connection
/// (`pyatv/support/http.py:440`, the `protocol` default of `send_and_receive`).
pub const HTTP_1_1: &str = "HTTP/1.1";

/// The protocol token every RTSP verb travels under, including the ones whose method is an
/// ordinary HTTP one (`pyatv/support/rtsp.py:262`, the `protocol` default of `exchange`). `GET
/// /info` and `POST /feedback` are sent as `RTSP/1.0` too, despite their HTTP-shaped method and
/// path.
pub const RTSP_1_0: &str = "RTSP/1.0";

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

impl Response {
    /// Look up a header by any casing of its name.
    ///
    /// Upstream keeps these in a `CaseInsensitiveDict` (`pyatv/support/http.py:120`) and reads them
    /// back with whatever spelling the caller happens to use, so lookups here have to ignore case
    /// too.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether the status is in the `2xx` success range, as `send_and_receive` tests it
    /// (`pyatv/support/http.py:492`).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
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

/// Serialise a frame onto `out`.
///
/// Headers are emitted in the order they appear in the frame, and nothing is added: no
/// `Content-Length`, no `User-Agent`, no `Server`. That is deliberate. pyatv's `_format_message`
/// (`pyatv/support/http.py:50-80`) inserts those in one specific position relative to the
/// caller-supplied header map, and reproducing that ordering byte-for-byte is
/// [`crate::http::HttpConnection`]'s job, where the full header list is known.
pub fn encode_frame(frame: &Frame, out: &mut BytesMut) {
    let (start_line, headers, body) = match frame {
        Frame::Request(request) => (
            format!("{} {} {}", request.method, request.uri, request.protocol),
            &request.headers,
            &request.body,
        ),
        Frame::Response(response) => (
            format!(
                "{} {} {}",
                response.protocol, response.status, response.reason
            ),
            &response.headers,
            &response.body,
        ),
    };

    out.reserve(start_line.len() + body.len() + 4);
    out.put_slice(start_line.as_bytes());
    for (name, value) in headers {
        out.put_slice(b"\r\n");
        out.put_slice(name.as_bytes());
        out.put_slice(b": ");
        out.put_slice(value.as_bytes());
    }
    out.put_slice(b"\r\n\r\n");
    out.put_slice(body);
}

impl tokio_util::codec::Decoder for AirPlayCodec {
    type Item = Frame;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Frame>, Error> {
        let Some((frame, consumed)) = parse_frame(src)? else {
            return Ok(None);
        };
        let _ = src.split_to(consumed);
        Ok(Some(frame))
    }
}

impl tokio_util::codec::Encoder<Frame> for AirPlayCodec {
    type Error = Error;

    fn encode(&mut self, item: Frame, dst: &mut BytesMut) -> Result<(), Error> {
        encode_frame(&item, dst);
        Ok(())
    }
}
