//! Response head parsing, body framing, and content decoding.
//!
//! Sans-io: every function here takes bytes and returns bytes. [`super::HttpClient`] owns the
//! socket and decides when to read more.

use flate2::read::GzDecoder;
use std::io::Read;

use crate::{Error, Result};

/// Cap on how much of a response head will be buffered before giving up.
///
/// A DMAP device sends a handful of short headers. Anything past this is a peer that is never going
/// to finish, and reading it into memory unbounded would be the bug.
pub const MAX_HEAD_LEN: usize = 16 * 1024;

/// A parsed status line plus headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    /// The three-digit status code.
    pub status: u16,
    /// Header names and values, in the order they arrived. Names keep their original case;
    /// [`Head::header`] compares case-insensitively, as RFC 9110 §5.1 requires.
    pub headers: Vec<(String, String)>,
}

/// How the body's length is determined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `Content-Length: n`.
    Length(usize),
    /// `Transfer-Encoding: chunked`.
    Chunked,
    /// Neither: the body ends when the connection does (RFC 9112 §6.3, last resort).
    ToEof,
}

impl Head {
    /// A header's value, matched case-insensitively.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Whether the status is in the 2xx range, which is what `_do` treats as success
    /// (`daap.py:136-137`).
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// How to read the body that follows.
    ///
    /// `Transfer-Encoding` wins over `Content-Length` (RFC 9112 §6.1), and a message carrying both
    /// is a request smuggling vector, so it is refused rather than resolved.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] for an unparseable `Content-Length`, a transfer coding other than
    /// `chunked`, or both framing headers at once.
    pub fn framing(&self) -> Result<Framing> {
        let chunked = match self.header("Transfer-Encoding") {
            None => false,
            Some(coding) if coding.eq_ignore_ascii_case("chunked") => true,
            Some(coding) => {
                return Err(Error::Http(format!(
                    "unsupported transfer coding: {coding}"
                )));
            }
        };
        let length = self.header("Content-Length");

        match (chunked, length) {
            (true, Some(_)) => Err(Error::Http(
                "response carries both Transfer-Encoding and Content-Length".to_owned(),
            )),
            (true, None) => Ok(Framing::Chunked),
            (false, Some(value)) => value
                .trim()
                .parse::<usize>()
                .map(Framing::Length)
                .map_err(|_| Error::Http(format!("unparseable Content-Length: {value}"))),
            (false, None) => Ok(Framing::ToEof),
        }
    }

    /// Undo `Content-Encoding` on a fully read body.
    ///
    /// This exists because the request advertises `Accept-Encoding: gzip` — one of the seven
    /// headers pyatv sends on every DAAP request (`daap.py:17-25`) — which permits the device to
    /// compress its answer. pyatv never sees that happen because `aiohttp` decompresses
    /// transparently and its own code only ever looks at the result. Dropping the header instead
    /// would have been a wire-visible change to a request byte pattern this port has no device to
    /// re-verify against, so the header stays and the decompression is done here.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] for a content coding other than `gzip` or `identity`, or if a gzip
    /// body will not inflate.
    pub fn decode_body(&self, body: Vec<u8>) -> Result<Vec<u8>> {
        match self.header("Content-Encoding") {
            None => Ok(body),
            Some(coding) if coding.eq_ignore_ascii_case("identity") => Ok(body),
            Some(coding) if coding.eq_ignore_ascii_case("gzip") => {
                let mut decoded = Vec::new();
                GzDecoder::new(body.as_slice())
                    .read_to_end(&mut decoded)
                    .map_err(|error| Error::Http(format!("undecodable gzip body: {error}")))?;
                Ok(decoded)
            }
            Some(coding) => Err(Error::Http(format!("unsupported content coding: {coding}"))),
        }
    }
}

/// Parse a response head, or report that more bytes are needed.
///
/// Returns the head and how many bytes of `buffer` it consumed, so the caller knows where the body
/// starts.
///
/// # Errors
///
/// Returns [`Error::Http`] if the status line is not `HTTP/1.x <code> ...`, if a header line has no
/// colon, if any of it is not valid UTF-8, or if the head exceeds [`MAX_HEAD_LEN`].
pub fn parse_head(buffer: &[u8]) -> Result<Option<(Head, usize)>> {
    let Some(end) = find_head_end(buffer) else {
        if buffer.len() > MAX_HEAD_LEN {
            return Err(Error::Http(format!(
                "response head exceeds {MAX_HEAD_LEN} bytes"
            )));
        }
        return Ok(None);
    };

    let text = core::str::from_utf8(&buffer[..end])
        .map_err(|_| Error::Http("response head is not valid UTF-8".to_owned()))?;
    let mut lines = text.split("\r\n");

    let status_line = lines
        .next()
        .ok_or_else(|| Error::Http("empty response".to_owned()))?;
    let status = parse_status_line(status_line)?;

    let mut headers = Vec::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| Error::Http(format!("header line without a colon: {line}")))?;
        headers.push((name.trim().to_owned(), value.trim().to_owned()));
    }

    Ok(Some((Head { status, headers }, end)))
}

/// `HTTP/1.1 200 OK` — the version is checked only for the `HTTP/` prefix, since a device that
/// answers `HTTP/1.0` or `ICY/1.0` is still telling us a status we can act on.
fn parse_status_line(line: &str) -> Result<u16> {
    let mut parts = line.split(' ');
    let version = parts
        .next()
        .filter(|it| it.starts_with("HTTP/"))
        .ok_or_else(|| Error::Http(format!("not an HTTP status line: {line}")))?;
    let code = parts
        .next()
        .ok_or_else(|| Error::Http(format!("status line has no code: {line}")))?;

    code.parse::<u16>().map_err(|_| {
        Error::Http(format!(
            "unparseable status code in {version} response: {code}"
        ))
    })
}

/// The offset just past the blank line ending the head, if it has arrived.
fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

/// Decode a chunked body, or report that more bytes are needed.
///
/// Returns the decoded body and how many bytes of `data` the chunked framing occupied. Trailers
/// after the terminating zero-length chunk are consumed and discarded: nothing in DAAP sends them,
/// and a caller that ignored them would leave bytes on a connection it is about to close anyway.
///
/// # Errors
///
/// Returns [`Error::Http`] for a chunk size that is not hexadecimal, or a chunk not terminated by
/// `CRLF`.
pub fn decode_chunked(data: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    let mut body = Vec::new();
    let mut offset = 0usize;

    loop {
        let Some(line_end) = find_crlf(&data[offset..]) else {
            return Ok(None);
        };
        let header = core::str::from_utf8(&data[offset..offset + line_end])
            .map_err(|_| Error::Http("chunk size line is not valid UTF-8".to_owned()))?;
        // A chunk-size may carry `;ext=value` extensions (RFC 9112 §7.1.1); everything after the
        // first semicolon is ignored.
        let size_text = header.split(';').next().unwrap_or(header).trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| Error::Http(format!("unparseable chunk size: {size_text}")))?;
        offset += line_end + 2;

        if size == 0 {
            // Trailer section, ending with its own blank line.
            let Some(end) = find_head_end_after_chunks(&data[offset..]) else {
                return Ok(None);
            };
            return Ok(Some((body, offset + end)));
        }

        let Some(chunk) = data.get(offset..offset + size) else {
            return Ok(None);
        };
        if data.get(offset + size..offset + size + 2) != Some(b"\r\n".as_slice()) {
            if data.len() < offset + size + 2 {
                return Ok(None);
            }
            return Err(Error::Http("chunk is not CRLF-terminated".to_owned()));
        }

        body.extend_from_slice(chunk);
        offset += size + 2;
    }
}

/// The end of the trailer section following the terminating chunk.
///
/// The common case is no trailers at all, which on the wire is a bare `CRLF`.
fn find_head_end_after_chunks(data: &[u8]) -> Option<usize> {
    if data.starts_with(b"\r\n") {
        return Some(2);
    }
    find_head_end(data)
}

fn find_crlf(data: &[u8]) -> Option<usize> {
    data.windows(2).position(|window| window == b"\r\n")
}

#[cfg(test)]
mod tests;
