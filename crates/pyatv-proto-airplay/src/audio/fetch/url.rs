//! Splitting an `http://` URL into what a request needs.
//!
//! `re.match("^http(|s)://", source)` decides what is a URL at all
//! (`pyatv/protocols/raop/audio_source.py:733`); everything below it is this port's own parsing,
//! because pyatv hands the string straight to `requests` and never looks at its parts.
//!
//! Split out of [`super`] so the string handling — which is where an IPv6 literal or a stray colon
//! goes wrong — sits apart from the socket work.

use crate::{Error, Result};

/// A URL split into what a request needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpUrl {
    /// Host, without the port and without the brackets an IPv6 literal is written in.
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

    /// The `Host` header value, re-bracketing an IPv6 literal.
    ///
    /// RFC 9110 §7.2: the header carries the authority as written, so `::1` has to go back into
    /// its brackets or the server sees a header it cannot parse.
    #[must_use]
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
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
        return Err(Error::audio_format(
            "https:// audio sources need a TLS stack, which this build does not link; download \
             the file first or serve it over http://"
                .to_owned(),
        ));
    }

    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))
        .ok_or_else(|| Error::audio_source(format!("{url} is not an http:// URL")))?;

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_owned()),
    };
    let (host, port) = split_authority(authority)
        .ok_or_else(|| Error::audio_source(format!("{url} has an unusable authority")))?;

    if host.is_empty() {
        return Err(Error::audio_source(format!("{url} has no host")));
    }

    Ok(HttpUrl {
        host: host.to_owned(),
        port,
        path,
    })
}

/// Split `host:port` into its parts, defaulting the port to 80.
///
/// An IPv6 literal is written `[::1]` or `[::1]:8080` (RFC 3986 §3.2.2) and is full of colons, so
/// it has to be recognised by its brackets before any `:` split — `rsplit_once(':')` on `[::1]`
/// yields the host `[:` and the "port" `1]`. The brackets are stripped from the returned host,
/// because that is the form [`std::net::IpAddr`] and [`tokio::net::lookup_host`] both want.
///
/// Credentials in the authority are not supported; pyatv does not handle them either.
fn split_authority(authority: &str) -> Option<(&str, u16)> {
    let Some(rest) = authority.strip_prefix('[') else {
        return match authority.rsplit_once(':') {
            Some((host, port)) => Some((host, port.parse().ok()?)),
            None => Some((authority, 80)),
        };
    };

    let (host, after) = rest.split_once(']')?;
    match after {
        "" => Some((host, 80)),
        port => Some((host, port.strip_prefix(':')?.parse().ok()?)),
    }
}

#[cfg(test)]
mod tests {
    use super::{is_url, parse_url};

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

    /// An IPv6 literal is bracketed and full of colons, so it must not be split on the last one.
    #[test]
    fn an_ipv6_literal_authority_parses() {
        let bare = parse_url("http://[::1]/track.mp3").expect("parses");
        assert_eq!(bare.host, "::1");
        assert_eq!(bare.port, 80);
        assert_eq!(bare.path, "/track.mp3");
        assert_eq!(bare.authority(), "[::1]:80");

        let ported = parse_url("http://[2001:db8::5]:8080/a.flac").expect("parses");
        assert_eq!(ported.host, "2001:db8::5");
        assert_eq!(ported.port, 8080);
        assert_eq!(ported.path, "/a.flac");
        assert_eq!(ported.authority(), "[2001:db8::5]:8080");

        // A named host keeps its unbracketed authority.
        assert_eq!(
            parse_url("http://example.com:81/a")
                .expect("parses")
                .authority(),
            "example.com:81"
        );
    }

    #[test]
    fn a_malformed_bracketed_authority_is_refused() {
        assert!(parse_url("http://[::1/a").is_err());
        assert!(parse_url("http://[::1]x/a").is_err());
        assert!(parse_url("http://[::1]:notaport/a").is_err());
    }
}
