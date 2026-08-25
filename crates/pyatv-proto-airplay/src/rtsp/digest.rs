//! HTTP Digest authentication for password-protected RAOP receivers.
//!
//! Port of `get_digest_payload` and `DigestInfo` (`pyatv/support/rtsp.py:52-73`, `129-168`). This
//! is the old `qop`-less MD5 variant of RFC 2617: no `qop`, no `nc`, no `cnonce`, and the username
//! is the fixed literal `"pyatv"` rather than anything configurable.
//!
//! MD5 is used because the protocol says so, and for nothing else. It authenticates a device
//! password to an AirPort Express-era receiver over an already-plaintext RTSP connection; nothing
//! here depends on MD5's collision resistance, and substituting a stronger hash would simply fail
//! to authenticate.

use md5::{Digest as _, Md5};

/// The username every `Authorization` header carries.
///
/// `DigestInfo("pyatv", realm, password, nonce)` (`rtsp.py:159`) — a literal, not the device or
/// account name. Kept as upstream's value because the receiver folds it into `HA1` and a different
/// string produces a different, rejected response.
pub const DIGEST_USERNAME: &str = "pyatv";

/// The challenge a receiver issued, plus the password to answer it with.
///
/// Held for the lifetime of the connection once a `401` has been answered: upstream computes the
/// header fresh per request from the same stored nonce and never re-parses a later challenge
/// (`rtsp.py:275-279`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestInfo {
    /// Username, always [`DIGEST_USERNAME`].
    pub username: String,
    /// Realm from the challenge.
    pub realm: String,
    /// The device password.
    pub password: String,
    /// Nonce from the challenge.
    pub nonce: String,
}

impl DigestInfo {
    /// Build the challenge answer for a device password.
    #[must_use]
    pub fn new(realm: &str, password: &str, nonce: &str) -> Self {
        Self {
            username: DIGEST_USERNAME.to_owned(),
            realm: realm.to_owned(),
            password: password.to_owned(),
            nonce: nonce.to_owned(),
        }
    }

    /// The `Authorization` header value for one request.
    #[must_use]
    pub fn authorization(&self, method: &str, uri: &str) -> String {
        digest_response(
            method,
            uri,
            &self.username,
            &self.realm,
            &self.password,
            &self.nonce,
        )
    }
}

/// Parse a `WWW-Authenticate` challenge into its realm and nonce.
///
/// Upstream splits the header on literal `"` characters and takes fixed positions —
/// `_, realm, _, nonce, _ = www_authenticate.split('"')` (`rtsp.py:158`) — so it assumes the exact
/// shape `Digest realm="…", nonce="…"` with no `qop`, `opaque` or `domain`, in that order. That
/// positional assumption is reproduced here rather than replaced with a real parameter parser: a
/// receiver that sends anything else would break upstream too, and silently accepting a header
/// upstream rejects would hide a real interop difference.
#[must_use]
pub fn parse_challenge(www_authenticate: &str) -> Option<(String, String)> {
    let quoted: Vec<&str> = www_authenticate.split('"').collect();
    match quoted.as_slice() {
        [_, realm, _, nonce, _] => Some(((*realm).to_owned(), (*nonce).to_owned())),
        _ => None,
    }
}

/// Answer an RTSP `401` Digest challenge.
///
/// `get_digest_payload` (`pyatv/support/rtsp.py:65-73`) verbatim: `HA1 = MD5(user:realm:pwd)`,
/// `HA2 = MD5(method:uri)`, `response = MD5(HA1:nonce:HA2)`, all lowercase hex.
#[must_use]
pub fn digest_response(
    method: &str,
    uri: &str,
    username: &str,
    realm: &str,
    password: &str,
    nonce: &str,
) -> String {
    let ha1 = md5_hex(&format!("{username}:{realm}:{password}"));
    let ha2 = md5_hex(&format!("{method}:{uri}"));
    let response = md5_hex(&format!("{ha1}:{nonce}:{ha2}"));

    format!(
        "Digest username=\"{username}\", realm=\"{realm}\", nonce=\"{nonce}\", uri=\"{uri}\", \
         response=\"{response}\""
    )
}

/// `md5(...).hexdigest()`.
fn md5_hex(input: &str) -> String {
    use std::fmt::Write as _;

    Md5::digest(input.as_bytes())
        .iter()
        .fold(String::with_capacity(32), |mut out, byte| {
            // Writing into a `String` is infallible; the `Result` exists only for the trait.
            let _ = write!(out, "{byte:02x}");
            out
        })
}

#[cfg(test)]
mod tests {
    use super::{DigestInfo, digest_response, md5_hex, parse_challenge};

    /// `md5(b"").hexdigest()`, the standard vector.
    #[test]
    fn the_hash_is_lowercase_hex() {
        assert_eq!(md5_hex(""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    }

    /// The whole header, computed the way the fake receiver recomputes it
    /// (`tests/fake_device/raop.py:107-118`).
    #[test]
    fn the_authorization_header_matches_the_receivers_own_computation() {
        let header = digest_response(
            "ANNOUNCE",
            "rtsp://10.0.0.2/1234",
            "pyatv",
            "raop",
            "secret",
            "abc123",
        );

        let ha1 = md5_hex("pyatv:raop:secret");
        let ha2 = md5_hex("ANNOUNCE:rtsp://10.0.0.2/1234");
        let expected = md5_hex(&format!("{ha1}:abc123:{ha2}"));

        assert_eq!(
            header,
            format!(
                "Digest username=\"pyatv\", realm=\"raop\", nonce=\"abc123\", \
                 uri=\"rtsp://10.0.0.2/1234\", response=\"{expected}\""
            )
        );
    }

    /// The header is recomputed per request, because `HA2` folds in the method and URI.
    #[test]
    fn a_different_verb_produces_a_different_response() {
        let info = DigestInfo::new("raop", "secret", "abc123");

        assert_ne!(
            info.authorization("ANNOUNCE", "rtsp://10.0.0.2/1"),
            info.authorization("SETUP", "rtsp://10.0.0.2/1")
        );
    }

    /// The exact challenge shape the fake receiver sends (`tests/fake_device/raop.py:96-104`).
    #[test]
    fn the_challenge_splits_into_realm_and_nonce() {
        assert_eq!(
            parse_challenge("Digest realm=\"raop\", nonce=\"deadbeef\""),
            Some(("raop".to_owned(), "deadbeef".to_owned()))
        );
    }

    /// A challenge with a third quoted parameter does not match upstream's positional split, and
    /// is refused rather than misread.
    #[test]
    fn a_challenge_with_extra_parameters_is_refused() {
        assert_eq!(
            parse_challenge("Digest realm=\"raop\", nonce=\"n\", qop=\"auth\""),
            None
        );
        assert_eq!(parse_challenge("Basic realm=raop"), None);
    }
}
