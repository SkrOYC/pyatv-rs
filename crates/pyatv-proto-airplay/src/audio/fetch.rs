//! A minimal `http://` GET, for streaming a URL rather than a local file.
//!
//! Stands in for `InternetSource`/`PatchedIceCastClient`
//! (`pyatv/protocols/raop/audio_source.py:458-658`), which downloads on a background thread while
//! `miniaudio` decodes incrementally. This port downloads to memory first and decodes afterwards,
//! matching what `FileSource` does for local files rather than what `InternetSource` does for
//! remote ones — see [`super::open_source`] for why.
//!
//! # No TLS
//!
//! `https://` is refused with a clear error rather than silently downgraded. This workspace links
//! no TLS stack: nothing else in it needs one, and adding `rustls` and a certificate store to
//! fetch an audio file is a dependency decision for whoever wants it, not something to slip in
//! here. pyatv gets TLS free from `requests`.
//!
//! ICY metadata interleaving (`icy-metaint`) is not stripped, because this client does not send
//! `Icy-MetaData: 1` and a server therefore does not interleave any.
//!
//! # The request is `HTTP/1.0`
//!
//! The body here is framed by end-of-stream, not by `Content-Length`, because a `Connection: close`
//! download does not need to parse a length. That framing is only safe if the server cannot answer
//! with `Transfer-Encoding: chunked`, whose chunk-size lines would otherwise be decoded as audio.
//! Chunked encoding does not exist in HTTP/1.0 (RFC 9112 §7.1: a server must not apply it to a
//! 1.0 request), so asking in 1.0 is what makes end-of-stream framing correct rather than merely
//! usual. pyatv gets this from `requests`, which does parse chunked.

pub mod url;

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::{Error, Result};

pub use url::{HttpUrl, is_url, parse_url};

/// The largest body this will download.
///
/// A guard against a "URL" that turns out to be an endless stream: an hour of 320 kbit/s MP3 is
/// about 144 MB, so this allows a generous single track and refuses a live radio feed rather than
/// growing until the process dies. pyatv has no such limit because it decodes incrementally.
pub const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

/// The `User-Agent` presented when fetching a URL.
pub const USER_AGENT: &str = concat!("pyatv-rs/", env!("CARGO_PKG_VERSION"));

/// How many `3xx` responses are followed before giving up.
///
/// `requests.get` follows redirects by default, which is what `PatchedIceCastClient` relies on
/// (`audio_source.py:453-457,517`) — a plain `http://` link to a track very often lands on a `302`
/// to a CDN, and refusing to follow it fails the download with an HTML body rather than audio.
/// Five is a working ceiling rather than `requests`' own thirty: a legitimate audio URL needs one
/// or two hops, and a shorter chain bounds how long a redirect loop can spin.
pub const MAX_REDIRECTS: u32 = 5;

/// Download a URL into memory, following up to [`MAX_REDIRECTS`] redirects.
///
/// # Errors
///
/// Returns [`Error::Audio`] if the host cannot be resolved, the server answers a non-`2xx` that is
/// not a followable redirect, the redirect chain is longer than [`MAX_REDIRECTS`], the response
/// cannot be parsed, or the body exceeds [`MAX_DOWNLOAD_BYTES`]. Returns [`Error::Io`] if the
/// connection fails mid-transfer.
pub async fn download(url: &HttpUrl) -> Result<Vec<u8>> {
    let mut current = url.clone();

    for _ in 0..=MAX_REDIRECTS {
        let response = get_once(&current).await?;

        if (200..300).contains(&response.status) {
            return Ok(response.body);
        }

        let Some(location) = redirect_target(&response) else {
            return Err(Error::audio_source(format!(
                "the server answered {} for {}{}",
                response.status, current.host, current.path
            )));
        };
        let next = resolve_location(&current, &location)?;
        tracing::debug!(status = response.status, from = %current.path, to = %next.path, "following a redirect");
        current = next;
    }

    Err(Error::audio_source(format!(
        "{}{} redirected more than {MAX_REDIRECTS} times",
        url.host, url.path
    )))
}

/// One request/response round trip, with no redirect handling.
async fn get_once(url: &HttpUrl) -> Result<HttpResponse> {
    let address = resolve(url).await?;
    tracing::debug!(host = %url.host, %address, path = %url.path, "downloading audio");

    let mut stream = TcpStream::connect(address).await?;
    // `HTTP/1.0`, so the server cannot answer with chunked framing — see the module header.
    let request = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n",
        url.path,
        url.authority()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        if raw.len() + read > MAX_DOWNLOAD_BYTES {
            return Err(Error::audio_source(format!(
                "the audio at {} exceeds the {MAX_DOWNLOAD_BYTES} byte download limit",
                url.host
            )));
        }
        raw.extend_from_slice(&chunk[..read]);
    }

    split_response(raw)
}

/// The `Location` of a redirect, if this response is one.
fn redirect_target(response: &HttpResponse) -> Option<String> {
    // 301, 302, 303, 307 and 308. 304 and 305 are not redirects to follow.
    if !matches!(response.status, 301..=303 | 307 | 308) {
        return None;
    }

    response
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("location"))
        .map(|(_, value)| value.clone())
}

/// Turn a `Location` value into the next URL to fetch.
///
/// Absolute `http://` targets are re-parsed; anything beginning with `/` keeps the current host;
/// anything else is a relative reference resolved against the current directory.
fn resolve_location(current: &HttpUrl, location: &str) -> Result<HttpUrl> {
    if is_url(location) {
        // `parse_url` refuses `https://` with the no-TLS message, which is the right answer for a
        // redirect to one too.
        return parse_url(location);
    }
    if location.is_empty() {
        return Err(Error::audio_source(
            "the redirect names no location".to_owned(),
        ));
    }

    let path = if location.starts_with('/') {
        location.to_owned()
    } else {
        let base = current.path.rsplit_once('/').map_or("/", |(head, _)| head);
        format!("{base}/{location}")
    };

    Ok(HttpUrl {
        path,
        ..current.clone()
    })
}

/// Resolve a URL's host and port.
async fn resolve(url: &HttpUrl) -> Result<SocketAddr> {
    tokio::net::lookup_host((url.host.as_str(), url.port))
        .await?
        .next()
        .ok_or_else(|| Error::audio_source(format!("{} does not resolve", url.host)))
}

/// One parsed response: everything the download loop branches on.
#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Split a raw response into its status code, headers and body.
///
/// `Content-Length` is not consulted: the request asked for `Connection: close` under `HTTP/1.0`,
/// so everything after the header block and before end-of-stream is the body, and the server has
/// no chunked framing available to it.
///
/// Takes the buffer by value and hands the body back out of it with [`Vec::split_off`], so a
/// hundred-megabyte download is never copied a second time just to drop a few hundred bytes of
/// header off the front.
fn split_response(mut raw: Vec<u8>) -> Result<HttpResponse> {
    let boundary = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            Error::audio_source("the server sent no complete response header".to_owned())
        })?;

    let body = raw.split_off(boundary + 4);
    raw.truncate(boundary);

    let head = std::str::from_utf8(&raw)
        .map_err(|_| Error::audio_source("the response header is not text".to_owned()))?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| Error::audio_source("the response has no status code".to_owned()))?;

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        .collect();

    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddr};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::{HttpUrl, MAX_REDIRECTS, download, split_response};

    #[test]
    fn a_response_splits_at_the_header_boundary() {
        let response = split_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc".to_vec())
            .expect("splits");

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"abc");
        assert_eq!(
            response.headers,
            [("Content-Length".to_owned(), "3".to_owned())]
        );
    }

    #[test]
    fn a_truncated_response_is_an_error() {
        assert!(split_response(b"HTTP/1.1 200 OK\r\n".to_vec()).is_err());
        assert!(split_response(b"garbage\r\n\r\n".to_vec()).is_err());
    }

    /// Serve `replies` one per connection, then answer nothing more.
    ///
    /// Returns the address to point [`download`] at. Each reply is written verbatim and the socket
    /// is closed, which is what a `Connection: close` client expects.
    async fn serve(replies: Vec<Vec<u8>>) -> SocketAddr {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
        let address = listener.local_addr().expect("bound");

        tokio::spawn(async move {
            for reply in replies {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                // Drain the request so the client's write cannot block.
                let mut scratch = [0u8; 2048];
                let _ = stream.read(&mut scratch).await;
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            }
        });

        address
    }

    fn url(address: SocketAddr, path: &str) -> HttpUrl {
        HttpUrl {
            host: address.ip().to_string(),
            port: address.port(),
            path: path.to_owned(),
        }
    }

    /// A body is everything after the header block, verbatim.
    #[tokio::test]
    async fn a_body_is_downloaded_whole() {
        let address = serve(vec![
            b"HTTP/1.0 200 OK\r\nContent-Type: audio/mpeg\r\n\r\nID3\x00\x01\x02".to_vec(),
        ])
        .await;

        let body = download(&url(address, "/track.mp3"))
            .await
            .expect("downloads");

        assert_eq!(body, b"ID3\x00\x01\x02");
    }

    /// A server that answers `Transfer-Encoding: chunked` anyway would corrupt the body if the
    /// chunk framing were decoded as audio. The request is `HTTP/1.0` precisely so a compliant
    /// server never does this — and if a broken one does, the bytes come through untouched rather
    /// than being silently mis-framed, which a decode failure then reports honestly.
    #[tokio::test]
    async fn the_request_is_http_1_0_so_a_server_cannot_chunk() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("binds");
        let address = listener.local_addr().expect("bound");
        let seen = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accepts");
            let mut scratch = vec![0u8; 2048];
            let read = stream.read(&mut scratch).await.expect("reads");
            let request = String::from_utf8_lossy(&scratch[..read]).into_owned();
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nplain").await;
            let _ = stream.shutdown().await;
            request
        });

        let body = download(&url(address, "/a.mp3")).await.expect("downloads");
        let request = seen.await.expect("the server task finishes");

        assert!(
            request.starts_with("GET /a.mp3 HTTP/1.0\r\n"),
            "the request line must be HTTP/1.0: {request}"
        );
        assert!(request.contains("Connection: close\r\n"), "{request}");
        assert_eq!(body, b"plain");
    }

    /// A `302` is followed to its `Location`, which is what a CDN-fronted audio URL needs.
    #[tokio::test]
    async fn a_redirect_is_followed() {
        let address = serve(vec![
            b"HTTP/1.0 302 Found\r\nLocation: /real.mp3\r\n\r\n".to_vec(),
            b"HTTP/1.0 200 OK\r\n\r\naudio".to_vec(),
        ])
        .await;

        let body = download(&url(address, "/redirect"))
            .await
            .expect("downloads");

        assert_eq!(body, b"audio");
    }

    /// A loop is broken rather than followed forever, and the error says so.
    #[tokio::test]
    async fn a_redirect_loop_stops_at_the_limit() {
        let replies = std::iter::repeat_n(
            b"HTTP/1.0 302 Found\r\nLocation: /loop\r\n\r\n".to_vec(),
            MAX_REDIRECTS as usize + 2,
        )
        .collect();
        let address = serve(replies).await;

        let error = download(&url(address, "/loop"))
            .await
            .expect_err("gives up");

        assert!(
            error.to_string().contains("redirected more than"),
            "{error}"
        );
    }

    /// A non-redirect failure is reported as the status it is.
    #[tokio::test]
    async fn a_not_found_is_reported_as_a_status() {
        let address = serve(vec![b"HTTP/1.0 404 Not Found\r\n\r\nnope".to_vec()]).await;

        let error = download(&url(address, "/missing"))
            .await
            .expect_err("refused");

        assert!(error.to_string().contains("404"), "{error}");
    }

    /// The whole path end to end over a real IPv6 loopback socket, so the bracketed authority is
    /// exercised by a server rather than only by the parser.
    #[tokio::test]
    async fn an_ipv6_host_downloads() {
        let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).await else {
            // Some CI sandboxes have no IPv6 loopback at all; the parser tests still cover the
            // interesting part.
            return;
        };
        let port = listener.local_addr().expect("bound").port();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut scratch = [0u8; 2048];
            let _ = stream.read(&mut scratch).await;
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\n\r\nsix").await;
            let _ = stream.shutdown().await;
        });

        let body = download(&HttpUrl {
            host: "::1".to_owned(),
            port,
            path: "/a.mp3".to_owned(),
        })
        .await
        .expect("downloads");

        assert_eq!(body, b"six");
    }
}
