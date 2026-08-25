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

/// Cap on how large a decoded response body may be.
///
/// Every framing this client understands is unbounded on the wire: a `Content-Length` is a
/// device-supplied number, a chunked body is a device-supplied number of chunks, and a `ToEof` body
/// is however much the device feels like sending. Without a cap, a device — or anything that can
/// answer on its address — decides how much of this process's memory to consume.
///
/// Eight mebibytes is two orders of magnitude above the largest thing DAAP carries. A now-playing
/// response is a few hundred bytes and `nowplayingartwork` is a few hundred kibibytes even at
/// full resolution, so nothing legitimate comes near this and anything that does is not artwork.
pub const MAX_BODY_LEN: usize = 8 * 1024 * 1024;

/// How many bytes of chunk framing a chunked body may carry on top of [`MAX_BODY_LEN`].
///
/// [`MAX_BODY_LEN`] bounds the *decoded* body, which is not by itself a bound on memory: chunk
/// framing costs at least five bytes per chunk (`"1\r\n" + byte + "\r\n"` is the smallest a
/// one-byte chunk can be), so a peer that never sends a terminating chunk can make the raw read
/// buffer grow without the decoded body ever approaching its cap. This is the allowance for that
/// difference, and [`MAX_CHUNKED_RAW_LEN`] is what actually gets enforced.
///
/// A mebibyte is roughly 200 000 chunks, which no HTTP server produces for an eight-mebibyte body —
/// a `Vec`-backed writer flushes in kibibytes, not in bytes. It is generous on purpose: the job here
/// is to bound memory, not to second-guess a device's chunk sizes.
pub const MAX_CHUNK_FRAMING_LEN: usize = 1024 * 1024;

/// Cap on the *raw* bytes of a chunked body, framing included.
///
/// See [`MAX_CHUNK_FRAMING_LEN`]. Enforced by [`super::HttpClient`], which is the only place that
/// knows how many raw bytes it has buffered; [`ChunkedDecoder`] sees only what it is handed.
pub const MAX_CHUNKED_RAW_LEN: usize = MAX_BODY_LEN + MAX_CHUNK_FRAMING_LEN;

/// Cap on one chunk-size line, including any `;ext=value` parameters.
///
/// A chunk-size line is a hexadecimal number: sixteen digits covers `usize::MAX`, and the rest is
/// for extensions nothing in DAAP sends. A peer that opens a chunk-size line and never sends the
/// `CRLF` that ends it is otherwise an unbounded read, since [`ChunkedDecoder::feed`] has nothing to
/// measure until that `CRLF` arrives.
pub const MAX_CHUNK_LINE_LEN: usize = 4 * 1024;

/// Cap on the trailer section following the terminating zero-length chunk.
///
/// The same shape of hole one step further on: after `0\r\n` the decoder looks for the blank line
/// that ends the trailers, and a peer that sends trailer lines forever never produces one. Nothing
/// in DAAP sends trailers at all, so this is pure headroom.
pub const MAX_TRAILER_LEN: usize = 8 * 1024;

/// Whether a status code is one `_do` treats as success (`daap.py:136-137`).
///
/// A free function rather than only a method on [`Head`] because the retry state machine in
/// [`crate::daap`] branches on a bare status long after the head has been dropped, and two
/// independent spellings of "2xx" is one too many.
#[must_use]
pub fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// The error for a body that would not fit under [`MAX_BODY_LEN`].
pub(crate) fn body_too_large(bytes: usize) -> Error {
    Error::Http(format!(
        "response body of at least {bytes} bytes exceeds the {MAX_BODY_LEN}-byte cap"
    ))
}

/// The same error for the framing around a body rather than the body itself.
///
/// `what` names the region — "chunked response", "chunk size line", "chunk trailer section" — so a
/// log distinguishes a genuinely huge artwork response from a peer stringing the decoder along.
pub(crate) fn framing_too_large(what: &str, bytes: usize, cap: usize) -> Error {
    Error::Http(format!(
        "{what} of at least {bytes} bytes exceeds the {cap}-byte cap"
    ))
}

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
        is_success(self.status)
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

/// A chunked-body decoder that survives being handed a partial body.
///
/// The socket hands over whatever one `read` returned, which lands wherever it lands — halfway
/// through a chunk-size line as readily as on a chunk boundary. A decoder that started over from
/// byte zero on every read would re-scan and re-copy everything already decoded, making a body
/// delivered in *n* reads cost O(n²); this one remembers how far it got and resumes there.
///
/// `data` is expected to be the whole chunked region, from its first byte, growing between calls.
/// That is what [`super::HttpClient`] has — one buffer it appends to — so nothing has to be
/// shuffled forward to keep the decoder's offsets meaningful.
#[derive(Debug, Default)]
pub struct ChunkedDecoder {
    /// Chunk data decoded so far, with the framing removed.
    body: Vec<u8>,
    /// How many bytes of `data` have been fully consumed: always a chunk boundary.
    consumed: usize,
}

impl ChunkedDecoder {
    /// A decoder positioned at the start of a chunked body.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The body decoded so far.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The decoded body, once [`Self::feed`] has reported completion.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Decode as much of `data` as has arrived.
    ///
    /// Returns `Some(consumed)` — how many bytes of `data` the chunked framing occupied — once the
    /// terminating zero-length chunk and its trailer section have both arrived, and `None` while
    /// more bytes are needed. Trailers are consumed and discarded: nothing in DAAP sends them, and
    /// leaving them would strand bytes on a connection this client is about to close anyway.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`] for a chunk size that is not hexadecimal, a chunk not terminated by
    /// `CRLF`, a body that would exceed [`MAX_BODY_LEN`], a chunk-size line longer than
    /// [`MAX_CHUNK_LINE_LEN`], or a trailer section longer than [`MAX_TRAILER_LEN`].
    ///
    /// The last two exist because "more bytes are needed" and "this peer is never going to finish"
    /// look identical from inside the decoder: without them, a chunk-size line with no `CRLF` and an
    /// endless run of trailer lines both leave the caller reading forever into a growing buffer,
    /// while [`MAX_BODY_LEN`] — which only ever sees decoded chunk data — stays at zero.
    pub fn feed(&mut self, data: &[u8]) -> Result<Option<usize>> {
        loop {
            let offset = self.consumed;
            let Some(line_end) = find_crlf(&data[offset..]) else {
                let pending = data.len() - offset;
                if pending > MAX_CHUNK_LINE_LEN {
                    return Err(framing_too_large(
                        "chunk size line",
                        pending,
                        MAX_CHUNK_LINE_LEN,
                    ));
                }
                return Ok(None);
            };
            let header = core::str::from_utf8(&data[offset..offset + line_end])
                .map_err(|_| Error::Http("chunk size line is not valid UTF-8".to_owned()))?;
            // A chunk-size may carry `;ext=value` extensions (RFC 9112 §7.1.1); everything after
            // the first semicolon is ignored.
            let size_text = header.split(';').next().unwrap_or(header).trim();
            let size = usize::from_str_radix(size_text, 16)
                .map_err(|_| Error::Http(format!("unparseable chunk size: {size_text}")))?;
            let start = offset + line_end + 2;

            if size == 0 {
                // Trailer section, ending with its own blank line.
                let Some(end) = find_head_end_after_chunks(&data[start..]) else {
                    // `start` is inside `data`: `find_crlf` only reports a `CRLF` it has both
                    // bytes of, so `offset + line_end + 2` cannot be past the end.
                    let pending = data.len() - start;
                    if pending > MAX_TRAILER_LEN {
                        return Err(framing_too_large(
                            "chunk trailer section",
                            pending,
                            MAX_TRAILER_LEN,
                        ));
                    }
                    return Ok(None);
                };
                self.consumed = start + end;
                return Ok(Some(self.consumed));
            }

            // Checked before the chunk is read, so a device cannot make this buffer the bytes it
            // is about to be refused for.
            let total = self.body.len().saturating_add(size);
            if total > MAX_BODY_LEN {
                return Err(body_too_large(total));
            }

            let Some(chunk) = data.get(start..start + size) else {
                return Ok(None);
            };
            match data.get(start + size..start + size + 2) {
                None => return Ok(None),
                Some(separator) if separator == b"\r\n" => {}
                Some(_) => return Err(Error::Http("chunk is not CRLF-terminated".to_owned())),
            }

            self.body.extend_from_slice(chunk);
            self.consumed = start + size + 2;
        }
    }
}

/// Decode a complete chunked body in one go.
///
/// Returns the decoded body and how many bytes of `data` the chunked framing occupied, or `None` if
/// `data` does not yet hold a whole one. [`ChunkedDecoder`] is what the client uses; this is the
/// same thing for a caller that already has every byte.
///
/// # Errors
///
/// See [`ChunkedDecoder::feed`].
pub fn decode_chunked(data: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    let mut decoder = ChunkedDecoder::new();
    let consumed = decoder.feed(data)?;
    Ok(consumed.map(|consumed| (decoder.into_body(), consumed)))
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
