//! The fixture's own HTTP/1.1 plumbing: read a request, format a response.
//!
//! Upstream's fixture gets this from `aiohttp` (`tests/fake_device/dmap.py:7,141-148`). It is
//! written out here, and deliberately *not* shared with [`crate::http`]: a framing bug in the
//! client must not be cancelled out by the same bug in the device it is tested against.

use std::io;

use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// How much of a request head to buffer before giving up on it.
const MAX_HEAD: usize = 16 * 1024;

/// The parts of a request the device looks at.
#[derive(Debug, Clone, Default)]
pub struct Request {
    /// `GET` or `POST`.
    pub method: String,
    /// Request target with the query string removed, e.g. `/ctrl-int/1/playstatusupdate`.
    pub path: String,
    /// The full request target, query string included — what the device records.
    pub target: String,
    /// Query parameters in wire order.
    pub query: Vec<(String, String)>,
    /// Headers in wire order, names as sent.
    pub headers: Vec<(String, String)>,
    /// Request body, already read.
    pub body: Vec<u8>,
}

impl Request {
    /// Parse a request head: the request line and its headers, without the trailing blank line.
    #[must_use]
    pub fn parse_head(head: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split("\r\n");
        let mut parts = lines.next()?.split(' ');
        let method = parts.next()?.to_owned();
        let target = parts.next()?.to_owned();

        let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
        let query = query
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
                (key.to_owned(), value.to_owned())
            })
            .collect();

        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_owned(), value.trim().to_owned()))
            .collect();

        Some(Self {
            method,
            path: path.to_owned(),
            target: target.clone(),
            query,
            headers,
            body: Vec::new(),
        })
    }

    /// The first value for a query parameter.
    #[must_use]
    pub fn query(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(candidate, _)| candidate == key)
            .map(|(_, value)| value.as_str())
    }

    /// A query parameter parsed as a number.
    #[must_use]
    pub fn number(&self, key: &str) -> Option<i64> {
        self.query(key)?.parse().ok()
    }

    /// A header value, matched case-insensitively as HTTP requires.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// The last path segment, which is the command word for a playback button.
    #[must_use]
    pub fn last_segment(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or_default()
    }
}

/// Read a head and, if one is declared, a `Content-Length` body. `None` means the peer went away.
///
/// # Errors
///
/// Returns whatever the socket read failed with.
pub async fn read_request(stream: &mut TcpStream) -> io::Result<Option<Request>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    let head_end = loop {
        if let Some(end) = find_head_end(&buffer) {
            break end;
        }
        if buffer.len() > MAX_HEAD {
            return Ok(None);
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    };

    let Some(mut request) = Request::parse_head(&buffer[..head_end]) else {
        return Ok(None);
    };

    let length = request
        .header("content-length")
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let body_start = head_end + 4;
    while buffer.len() - body_start < length {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    request.body = buffer[body_start..body_start + length].to_vec();

    Ok(Some(request))
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

/// Format an HTTP/1.1 response. `Connection: close` because the client opens one per request.
#[must_use]
pub fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Unknown",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[cfg(test)]
mod tests {
    use super::{Request, response};

    #[test]
    fn a_request_line_splits_into_a_path_and_ordered_query_parameters() {
        let request = Request::parse_head(
            b"GET /ctrl-int/1/playstatusupdate?session-id=1&revision-number=0 HTTP/1.1\r\n\
              Accept: */*\r\nUser-Agent: Remote/1021",
        )
        .expect("the head must parse");

        assert_eq!(request.method, "GET");
        assert_eq!(request.path, "/ctrl-int/1/playstatusupdate");
        assert_eq!(request.last_segment(), "playstatusupdate");
        assert_eq!(request.query("session-id"), Some("1"));
        assert_eq!(request.number("revision-number"), Some(0));
        assert_eq!(request.query("missing"), None);
    }

    /// Header names are case-insensitive on the wire, so the lookup has to be too.
    #[test]
    fn headers_are_matched_without_regard_to_case() {
        let request = Request::parse_head(b"POST /x HTTP/1.1\r\nCONTENT-LENGTH: 12")
            .expect("the head must parse");
        assert_eq!(request.header("content-length"), Some("12"));
        assert_eq!(request.header("Content-Length"), Some("12"));
    }

    #[test]
    fn a_response_declares_its_length_and_closes() {
        assert_eq!(
            response(200, b"ab"),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nab".to_vec()
        );
        assert_eq!(
            response(500, &[]),
            b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .to_vec()
        );
    }
}
