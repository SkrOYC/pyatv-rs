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

/// Parse one message from the front of `input`.
///
/// Returns the frame and how many bytes of `input` it consumed, or `Ok(None)` if `input` does not
/// yet hold a complete message.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the header block is not UTF-8, if the start line matches neither
/// the request nor the response shape, or if `Content-Length` is not a number.
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
    let Some(body) = input.get(body_start..body_start + content_length) else {
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

    Ok(Some((frame, body_start + content_length)))
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
fn content_length(headers: &[(String, String)]) -> Result<usize> {
    let Some((_, value)) = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(super::CONTENT_LENGTH))
    else {
        return Ok(0);
    };

    value
        .trim()
        .parse()
        .map_err(|_| Error::Malformed(format!("bad Content-Length: {value}")))
}

/// Index of the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
