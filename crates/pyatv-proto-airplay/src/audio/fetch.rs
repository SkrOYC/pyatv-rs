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

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::{Error, Result};

/// The largest body this will download.
///
/// A guard against a "URL" that turns out to be an endless stream: an hour of 320 kbit/s MP3 is
/// about 144 MB, so this allows a generous single track and refuses a live radio feed rather than
/// growing until the process dies. pyatv has no such limit because it decodes incrementally.
pub const MAX_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024;

/// The `User-Agent` presented when fetching a URL.
pub const USER_AGENT: &str = concat!("pyatv-rs/", env!("CARGO_PKG_VERSION"));

/// A URL split into what a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    /// Host, without the port.
    pub host: String,
    /// Port, defaulted to 80.
    pub port: u16,
    /// Path and query, always beginning with `/`.
    pub path: String,
}

impl HttpUrl {
    /// The file extension of the path, if it has one, as a decode hint.
    #[must_use]
    pub fn extension(&self) -> Option<&str> {
        self.path
            .rsplit('/')
            .next()?
            .rsplit_once('.')
            .map(|(_, extension)| extension)
            .filter(|extension| !extension.is_empty() && extension.len() <= 5)
    }
}

/// Whether a source string is a URL rather than a path.
///
/// `re.match("^http(|s)://", source)` (`audio_source.py:733`).
#[must_use]
pub fn is_url(source: &str) -> bool {
    let lowered = source.to_ascii_lowercase();
    lowered.starts_with("http://") || lowered.starts_with("https://")
}

/// Split an `http://` URL.
///
/// # Errors
///
/// Returns [`Error::Audio`] for an `https://` URL, since no TLS stack is linked, and for anything
/// that is not a URL at all.
pub fn parse_url(url: &str) -> Result<HttpUrl> {
    if url.to_ascii_lowercase().starts_with("https://") {
        return Err(Error::Audio(
            "https:// audio sources need a TLS stack, which this build does not link; download \
             the file first or serve it over http://"
                .to_owned(),
        ));
    }

    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))
        .ok_or_else(|| Error::Audio(format!("{url} is not an http:// URL")))?;

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    // Credentials in the authority are not supported; pyatv does not handle them either.
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse()
                .map_err(|_| Error::Audio(format!("{url} has an unusable port")))?,
        ),
        None => (authority, 80),
    };

    if host.is_empty() {
        return Err(Error::Audio(format!("{url} has no host")));
    }

    Ok(HttpUrl {
        host: host.to_owned(),
        port,
        path,
    })
}

/// Download a URL into memory.
///
/// Follows no redirects: a `3xx` is reported as the status it is, so the caller sees why rather
/// than a decode failure on an HTML body.
///
/// # Errors
///
/// Returns [`Error::Audio`] if the host cannot be resolved, the server answers a non-`2xx`, the
/// response cannot be parsed, or the body exceeds [`MAX_DOWNLOAD_BYTES`]. Returns [`Error::Io`] if
/// the connection fails mid-transfer.
pub async fn download(url: &HttpUrl) -> Result<Vec<u8>> {
    let address = resolve(url).await?;
    tracing::debug!(host = %url.host, %address, path = %url.path, "downloading audio");

    let mut stream = TcpStream::connect(address).await?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: {USER_AGENT}\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n",
        url.path, url.host, url.port
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
            return Err(Error::Audio(format!(
                "the audio at {} exceeds the {MAX_DOWNLOAD_BYTES} byte download limit",
                url.host
            )));
        }
        raw.extend_from_slice(&chunk[..read]);
    }

    let (status, body) = split_response(&raw)?;
    if !(200..300).contains(&status) {
        return Err(Error::Audio(format!(
            "the server answered {status} for {}{}",
            url.host, url.path
        )));
    }

    Ok(body)
}

/// Resolve a URL's host and port.
async fn resolve(url: &HttpUrl) -> Result<SocketAddr> {
    tokio::net::lookup_host((url.host.as_str(), url.port))
        .await?
        .next()
        .ok_or_else(|| Error::Audio(format!("{} does not resolve", url.host)))
}

/// Split a raw response into its status code and body.
///
/// `Content-Length` is not consulted: the request asked for `Connection: close`, so everything
/// after the header block and before end-of-stream is the body. That also handles a server that
/// answers with chunked encoding by simply not claiming to — which is why the status is checked
/// first, so an unusual response fails as a status rather than as a corrupt decode.
fn split_response(raw: &[u8]) -> Result<(u16, Vec<u8>)> {
    let boundary = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| Error::Audio("the server sent no complete response header".to_owned()))?;

    let head = std::str::from_utf8(&raw[..boundary])
        .map_err(|_| Error::Audio("the response header is not text".to_owned()))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| Error::Audio("the response has no status code".to_owned()))?;

    Ok((status, raw[boundary + 4..].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::{is_url, parse_url, split_response};

    #[test]
    fn urls_are_told_apart_from_paths() {
        assert!(is_url("http://example.com/a.mp3"));
        assert!(is_url("https://example.com/a.mp3"));
        assert!(!is_url("/home/user/a.mp3"));
        assert!(!is_url("a.mp3"));
        assert!(!is_url("ftp://example.com/a.mp3"));
    }

    #[test]
    fn a_url_splits_into_host_port_and_path() {
        let url = parse_url("http://example.com:8080/music/track.mp3?x=1").expect("parses");

        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/music/track.mp3?x=1");
    }

    #[test]
    fn the_port_and_path_have_defaults() {
        let url = parse_url("http://example.com").expect("parses");

        assert_eq!(url.port, 80);
        assert_eq!(url.path, "/");
    }

    /// The extension is a decode hint, so a query string or a path with no dot yields nothing
    /// rather than nonsense.
    #[test]
    fn the_extension_is_only_taken_when_it_looks_like_one() {
        assert_eq!(
            parse_url("http://h/a.flac").expect("parses").extension(),
            Some("flac")
        );
        assert_eq!(parse_url("http://h/a").expect("parses").extension(), None);
        assert_eq!(parse_url("http://h/").expect("parses").extension(), None);
    }

    /// No TLS is linked, and saying so beats failing later on an unparseable body.
    #[test]
    fn https_is_refused_with_an_explanation() {
        let error = parse_url("https://example.com/a.mp3").expect_err("refused");

        assert!(error.to_string().contains("TLS"), "{error}");
    }

    #[test]
    fn a_non_url_is_refused() {
        assert!(parse_url("/tmp/a.mp3").is_err());
        assert!(parse_url("http://").is_err());
        assert!(parse_url("http://h:notaport/a").is_err());
    }

    #[test]
    fn a_response_splits_at_the_header_boundary() {
        let (status, body) =
            split_response(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc").expect("splits");

        assert_eq!(status, 200);
        assert_eq!(body, b"abc");
    }

    #[test]
    fn a_truncated_response_is_an_error() {
        assert!(split_response(b"HTTP/1.1 200 OK\r\n").is_err());
        assert!(split_response(b"garbage\r\n\r\n").is_err());
    }
}
