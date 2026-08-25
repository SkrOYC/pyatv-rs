//! Sans-io message parsing.
//!
//! A direct port of `_parse_http_message`, `parse_response` and `parse_request`
//! (`pyatv/support/http.py:105-218`). Three properties of that parser are load-bearing and are kept
//! exactly:
//!
//! - **Framing is `Content-Length` only.** A missing header means a zero-length body; chunked
//!   transfer encoding is neither produced nor accepted anywhere in pyatv's AirPlay stack.
//! - **A short buffer is not an error.** Upstream returns `None` plus the untouched buffer so the
//!   caller can wait for more bytes; here that is `Ok(None)`.
//! - **The start line is read permissively from either role.** pyatv tries the response shape and
//!   then the request shape on the same connection, because an AirPlay receiver sends requests back
//!   over the socket the controller opened.

use bytes::Bytes;

use crate::codec::{Frame, Request, Response};
use crate::{Error, Result};

/// End of the header block.
const HEADER_TERMINATOR: &[u8] = b"\r\n\r\n";

/// The largest `Content-Length` this parser will wait for.
///
/// 8 MiB. Nothing AirPlay sends comes close: a binary plist reply is kilobytes, an MRP protobuf
/// frame is smaller still, and the biggest body in the whole stack is a piece of cover artwork —
/// which this crate *sends* rather than receives, and which no receiver returns. A header is a
/// promise from the peer about how many bytes are coming; without a ceiling, a single unread
/// `Content-Length: 4294967295` makes the connection's read buffer grow to four gigabytes while
/// the parser politely waits for a body that will never arrive. pyatv has the same exposure
/// (`pyatv/support/http.py:122-131` reads the value straight into a slice bound) and this port
/// deliberately does not.
pub const MAX_BODY_LEN: usize = 8 * 1024 * 1024;

/// Parse one message from the front of `input`.
///
/// Returns the frame and how many bytes of `input` it consumed, or `Ok(None)` if `input` does not
/// yet hold a complete message.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the header block is not UTF-8, if the start line matches neither
/// the request nor the response shape, if `Content-Length` is not a number, or if it names a body
/// larger than [`MAX_BODY_LEN`].
pub fn parse_frame(input: &[u8]) -> Result<Option<(Frame, usize)>> {
    let Some(boundary) = find_subslice(input, HEADER_TERMINATOR) else {
        return Ok(None);
    };
    let body_start = boundary + HEADER_TERMINATOR.len();

    let header_block = std::str::from_utf8(&input[..boundary])
        .map_err(|error| Error::Malformed(format!("header block is not UTF-8: {error}")))?;

    let mut lines = header_block.split("\r\n");
    let start_line = lines
        .next()
        .ok_or_else(|| Error::Malformed("message has no start line".to_owned()))?;

    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header)
        .collect::<Result<Vec<_>>>()?;

    let content_length = content_length(&headers)?;
    // `body_start + content_length` overflows for a `Content-Length` near `usize::MAX`, which a
    // peer can simply state. The cap in `content_length` already refuses that, but the addition is
    // checked anyway so the two guards do not depend on each other.
    let body_end = body_start
        .checked_add(content_length)
        .ok_or_else(|| Error::Malformed("Content-Length overflows the buffer".to_owned()))?;
    let Some(body) = input.get(body_start..body_end) else {
        return Ok(None);
    };
    let body = Bytes::copy_from_slice(body);

    let frame = match parse_start_line(start_line)? {
        StartLine::Response {
            protocol,
            status,
            reason,
        } => Frame::Response(Response {
            protocol,
            status,
            reason,
            headers,
            body,
        }),
        StartLine::Request {
            method,
            uri,
            protocol,
        } => Frame::Request(Request {
            method,
            uri,
            protocol,
            headers,
            body,
        }),
    };

    Ok(Some((frame, body_end)))
}

/// The two shapes a start line can take.
enum StartLine {
    /// `HTTP/1.1 200 OK`, or `RTSP/1.0 200 OK`.
    Response {
        protocol: String,
        status: u16,
        reason: String,
    },
    /// `POST /pair-setup HTTP/1.1`, or `SETUP rtsp://… RTSP/1.0`.
    Request {
        method: String,
        uri: String,
        protocol: String,
    },
}

/// Classify and split a start line.
///
/// pyatv distinguishes the two with regexes tried in order (`pyatv/support/http.py:178,209`); the
/// discriminant those encode is that a response starts with a `<name>/<version>` token followed by
/// a numeric status. Checking for exactly that is equivalent and avoids a regex dependency for two
/// fixed grammars.
fn parse_start_line(line: &str) -> Result<StartLine> {
    let mut parts = line.splitn(3, ' ');
    let (Some(first), Some(second)) = (parts.next(), parts.next()) else {
        return Err(Error::Malformed(format!("bad start line: {line}")));
    };
    let rest = parts.next().unwrap_or("");

    if first.contains('/') && !second.is_empty() && second.bytes().all(|byte| byte.is_ascii_digit())
    {
        let status = second
            .parse()
            .map_err(|_| Error::Malformed(format!("status code out of range: {second}")))?;
        return Ok(StartLine::Response {
            protocol: first.to_owned(),
            status,
            reason: rest.to_owned(),
        });
    }

    if rest.is_empty() {
        return Err(Error::Malformed(format!("bad start line: {line}")));
    }

    Ok(StartLine::Request {
        method: first.to_owned(),
        uri: second.to_owned(),
        protocol: rest.to_owned(),
    })
}

/// Split one `Name: value` header line.
///
/// Upstream splits on `": "` with `maxsplit=1` (`pyatv/support/http.py:105-107`), so a value may
/// itself contain colons. A missing separator raises there; it is an error here too.
fn parse_header(line: &str) -> Result<(String, String)> {
    line.split_once(':')
        .map(|(name, value)| (name.trim().to_owned(), value.trim_start().to_owned()))
        .ok_or_else(|| Error::Malformed(format!("header line has no colon: {line}")))
}

/// Read `Content-Length`, defaulting to zero when absent (`pyatv/support/http.py:122`).
///
/// A value larger than [`MAX_BODY_LEN`] is an error rather than a body to wait for; see that
/// constant for why. A value that does not fit a `usize` at all takes the same path, since
/// `parse::<usize>` refuses it.
fn content_length(headers: &[(String, String)]) -> Result<usize> {
    let Some((_, value)) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(super::CONTENT_LENGTH))
    else {
        return Ok(0);
    };

    let length: usize = value
        .trim()
        .parse()
        .map_err(|_| Error::Malformed(format!("bad Content-Length: {value}")))?;

    if length > MAX_BODY_LEN {
        return Err(Error::Malformed(format!(
            "Content-Length {length} exceeds the {MAX_BODY_LEN} byte limit"
        )));
    }

    Ok(length)
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
