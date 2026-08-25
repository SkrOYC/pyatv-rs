//! The RTSP layer: methods, plist bodies, SDP bodies and Digest authentication.
//!
//! Port of `RtspSession` (`pyatv/support/rtsp.py:76-330`), sitting on
//! [`crate::http::HttpConnection`] rather than on [`crate::codec`]'s `Framed` wrapper, because the
//! post-pair-verify [`pyatv_pairing::session::HapSession`] framing sits *below* HTTP and a `Framed`
//! leaves no seam to insert it at. That is also how upstream layers the two: `RtspSession` holds an
//! `HttpConnection` and knows nothing about encryption.
//!
//! # What is implemented so far
//!
//! Enough to bring up an AirPlay 2 remote-control tunnel's control connection: [`RtspSession::info`]
//! and [`RtspSession::setup`], plus the `CSeq`/`DACP-ID`/`Active-Remote`/`Client-Instance` header
//! block every verb carries. `ANNOUNCE`, `RECORD`, `FLUSH`, `TEARDOWN`, `SET_PARAMETER` and the
//! Digest challenge belong to the RAOP path and are still stubs.
//!
//! # Divergence: no `CSeq` correlation table
//!
//! Upstream keys an `asyncio.Event` per outstanding `CSeq` and matches responses against it
//! (`rtsp.py:295-325`), because several requests can be in flight on one socket. This port sends
//! one request at a time and reads the next response, so it only *checks* the echoed `CSeq` and
//! logs a mismatch. Once the event and data channels are driven concurrently, the correlation table
//! has to come with them.

use std::net::SocketAddr;

use crate::codec::{BPLIST_CONTENT_TYPE, CONTENT_TYPE, RTSP_1_0, Response, USER_AGENT};
use crate::http::{HttpConnection, RequestSpec};
use crate::{Error, Result};

pub mod digest;

pub use digest::{DigestInfo, digest_response};

/// RTSP methods pyatv sends. Not a subset of the HTTP verbs, which is one reason a generic HTTP
/// client cannot be used here.
pub mod method {
    /// Advertise the stream's format via an SDP body.
    pub const ANNOUNCE: &str = "ANNOUNCE";
    /// Negotiate transport ports.
    pub const SETUP: &str = "SETUP";
    /// Begin streaming.
    pub const RECORD: &str = "RECORD";
    /// Discard buffered audio.
    pub const FLUSH: &str = "FLUSH";
    /// End the session.
    pub const TEARDOWN: &str = "TEARDOWN";
    /// Set a session parameter, e.g. volume or track metadata.
    pub const SET_PARAMETER: &str = "SET_PARAMETER";
    /// Read a session parameter.
    pub const GET_PARAMETER: &str = "GET_PARAMETER";
    /// Query supported methods.
    pub const OPTIONS: &str = "OPTIONS";
    /// Read the receiver's `/info` property list. An HTTP verb travelling under `RTSP/1.0`.
    pub const GET: &str = "GET";
    /// Post the `/feedback` keepalive. Also an HTTP verb travelling under `RTSP/1.0`
    /// (`pyatv/support/rtsp.py:246-248`).
    pub const POST: &str = "POST";
}

/// Frames per RTP packet, from pyatv's `rtsp.py`.
pub const FRAMES_PER_PACKET: u32 = 352;

/// Path the receiver's property list is read from (`pyatv/support/rtsp.py:100`).
pub const INFO_PATH: &str = "/info";

/// Path the two-second keepalive is posted to (`pyatv/support/rtsp.py:246-248`).
pub const FEEDBACK_PATH: &str = "/feedback";

/// Encode a property list as the binary plist AirPlay bodies use.
///
/// `plistlib.dumps(body, fmt=FMT_BINARY)` (`pyatv/support/rtsp.py:287-289`).
///
/// # Errors
///
/// Returns [`Error::Plist`] if the value cannot be serialised.
pub fn encode_plist(value: &plist::Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value).map_err(|error| Error::Plist(error.to_string()))?;
    Ok(out)
}

/// Decode a binary property list body.
///
/// `decode_bplist_from_body` (`pyatv/support/http.py:221-232`).
///
/// # Errors
///
/// Returns [`Error::Plist`] if `body` is not a property list.
pub fn decode_plist(body: &[u8]) -> Result<plist::Value> {
    plist::from_bytes(body).map_err(|error| Error::Plist(error.to_string()))
}

/// An RTSP session over one connection.
///
/// The three identifiers are drawn once per session and repeated on every request. They are
/// AirPlay-1-lineage DACP values with no role in the remote-control tunnel, but a receiver sees
/// them on every exchange, so they are sent exactly as upstream shapes them
/// (`pyatv/support/rtsp.py:86-89`).
#[derive(Debug)]
pub struct RtspSession {
    session_id: u32,
    dacp_id: String,
    active_remote: u32,
    /// Incremented on every request; the device echoes it back.
    cseq: u32,
    /// Set once a password-protected receiver has been challenged, and then applied to every
    /// subsequent request on this connection (`pyatv/support/rtsp.py:275-279`).
    digest: Option<DigestInfo>,
}

/// The parameters of one RTSP exchange.
///
/// The argument list of `RtspSession.exchange` (`pyatv/support/rtsp.py:254-262`) as a struct, so
/// the RAOP verbs — which need a `Content-Type` that is not a property list, extra headers, and in
/// one case an `HTTP/1.1` protocol token — can reach the same code path the tunnel's `SETUP` uses.
/// Construct with `..Exchange::default()` and override only what differs.
#[derive(Debug, Clone, Copy)]
pub struct Exchange<'a> {
    /// The verb.
    pub method: &'a str,
    /// Request target. `None` uses the `rtsp://…` session URI.
    pub uri: Option<&'a str>,
    /// `Content-Type`, emitted before `Content-Length` — upstream's `content_type` parameter.
    pub content_type: Option<&'a str>,
    /// Extra headers, appended after the four every request carries.
    pub headers: &'a [(&'a str, &'a str)],
    /// Body bytes.
    pub body: &'a [u8],
    /// Return the response whatever its status.
    pub allow_error: bool,
    /// Protocol token. `RTSP/1.0` for everything except `/auth-setup`, which upstream sends as
    /// `HTTP/1.1` (`pyatv/support/rtsp.py:112-123`).
    pub protocol: &'a str,
}

impl Default for Exchange<'_> {
    fn default() -> Self {
        Self {
            method: method::POST,
            uri: None,
            content_type: None,
            headers: &[],
            body: &[],
            allow_error: false,
            protocol: RTSP_1_0,
        }
    }
}

impl RtspSession {
    /// A fresh session with randomly drawn identifiers.
    ///
    /// `session_id = randrange(2**32)`, `dacp_id = f"{randrange(2**64):X}"`,
    /// `active_remote = randrange(2**32)` (`pyatv/support/rtsp.py:86-89`). Note the uppercase,
    /// unpadded hex of `dacp_id`: a draw below `0x1000_0000_0000_0000` really does render shorter
    /// than sixteen digits, and that is what upstream puts on the wire.
    #[must_use]
    pub fn new() -> Self {
        Self::with_identifiers(rand::random(), rand::random(), rand::random())
    }

    /// A session with the identifiers fixed, so a test can assert on the exact bytes.
    #[must_use]
    pub fn with_identifiers(session_id: u32, dacp_id: u64, active_remote: u32) -> Self {
        Self {
            session_id,
            dacp_id: format!("{dacp_id:X}"),
            active_remote,
            cseq: 0,
            digest: None,
        }
    }

    /// The random 32-bit session identifier.
    ///
    /// Doubles as the RTP `ssrc` and as the AirPlay 2 audio stream's `streamConnectionID`; the
    /// three are literally the same number, not independently drawn
    /// (`stream_client.py:586`, `airplayv2.py:143`).
    #[must_use]
    pub fn session_id(&self) -> u32 {
        self.session_id
    }

    /// Start answering a password challenge on every subsequent request.
    ///
    /// `self.digest_info = info` (`pyatv/support/rtsp.py:159-160`), set once from the `401` that
    /// answered the first `ANNOUNCE` and never refreshed afterwards.
    pub fn set_digest(&mut self, digest: DigestInfo) {
        self.digest = Some(digest);
    }

    /// Whether a password challenge has been answered on this connection.
    #[must_use]
    pub fn has_digest(&self) -> bool {
        self.digest.is_some()
    }

    /// The `rtsp://{local_ip}/{session_id}` URI the session verbs target.
    ///
    /// `RtspSession.uri` (`pyatv/support/rtsp.py:91-95`). The port of `local` is deliberately not
    /// included; upstream interpolates a bare IP.
    #[must_use]
    pub fn uri(&self, local: SocketAddr) -> String {
        format!("rtsp://{}/{}", local.ip(), self.session_id)
    }

    /// The `CSeq` the next request will carry.
    #[must_use]
    pub fn next_cseq(&self) -> u32 {
        self.cseq
    }

    /// Send one RTSP request and await its response.
    ///
    /// `uri` of `None` targets the session URI; a bare path such as `/info` is passed through as
    /// given. A `body` is always sent as a binary property list with
    /// `Content-Type: application/x-apple-binary-plist`, which is the only body shape the remote
    /// control tunnel uses (`pyatv/support/rtsp.py:284-289`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] for a non-success status unless `allow_error` is set,
    /// [`Error::Plist`] if `body` cannot be serialised, and [`Error::Io`] on a transport failure.
    pub async fn exchange(
        &mut self,
        http: &mut HttpConnection,
        method: &str,
        uri: Option<&str>,
        body: Option<&plist::Value>,
        allow_error: bool,
    ) -> Result<Response> {
        // `isinstance(body, dict)` selects the binary plist body and its content type
        // (`pyatv/support/rtsp.py:284-289`); the header lands *after* `Content-Length`, which is
        // where upstream's `hdrs` dict puts it.
        let encoded = body.map(encode_plist).transpose()?;
        let headers: &[(&str, &str)] = match encoded {
            Some(_) => &[(CONTENT_TYPE, BPLIST_CONTENT_TYPE)],
            None => &[],
        };

        self.send(
            http,
            &Exchange {
                method,
                uri,
                headers,
                body: encoded.as_deref().unwrap_or_default(),
                allow_error,
                ..Exchange::default()
            },
        )
        .await
    }

    /// Send one arbitrary RTSP exchange and await its response.
    ///
    /// The general form [`RtspSession::exchange`] is a special case of. Every request carries the
    /// same four identifiers plus, once a challenge has been answered, an `Authorization` header
    /// recomputed for this verb and URI (`pyatv/support/rtsp.py:264-279`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] for a non-success status unless
    /// [`Exchange::allow_error`] is set, and [`Error::Io`] on a transport failure.
    pub async fn send(
        &mut self,
        http: &mut HttpConnection,
        exchange: &Exchange<'_>,
    ) -> Result<Response> {
        let cseq = self.cseq;
        self.cseq += 1;

        let session_uri = match exchange.uri {
            Some(_) => String::new(),
            None => self.uri(http.local_address()?),
        };
        let target = exchange.uri.unwrap_or(&session_uri);

        let cseq_value = cseq.to_string();
        let active_remote = self.active_remote.to_string();
        let authorization = self
            .digest
            .as_ref()
            .map(|digest| digest.authorization(exchange.method, target));

        let mut headers = vec![
            ("CSeq", cseq_value.as_str()),
            ("DACP-ID", self.dacp_id.as_str()),
            ("Active-Remote", active_remote.as_str()),
            ("Client-Instance", self.dacp_id.as_str()),
        ];
        if let Some(authorization) = authorization.as_deref() {
            headers.push(("Authorization", authorization));
        }
        headers.extend_from_slice(exchange.headers);

        let response = http
            .send(&RequestSpec {
                method: exchange.method,
                uri: target,
                protocol: exchange.protocol,
                user_agent: Some(USER_AGENT),
                content_type: exchange.content_type,
                headers: &headers,
                body: exchange.body,
                allow_error: exchange.allow_error,
            })
            .await?;

        match response.header("CSeq") {
            Some(echoed) if echoed == cseq_value => {}
            echoed => tracing::warn!(
                sent = cseq,
                echoed = echoed.unwrap_or("<absent>"),
                "RTSP response carried an unexpected CSeq"
            ),
        }

        Ok(response)
    }

    /// Read the receiver's `/info` property list.
    ///
    /// `RtspSession.info` (`pyatv/support/rtsp.py:99-108`): sent with `allow_error`, and a
    /// non-`200` means "this device has no `/info`" rather than a failure, so it comes back as an
    /// empty dictionary. Read-only, and the least intrusive request there is — nothing about the
    /// device's playback state changes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Plist`] if a `200` response's body is not a property list, or
    /// [`Error::Io`] on a transport failure.
    pub async fn info(&mut self, http: &mut HttpConnection) -> Result<plist::Value> {
        let response = self
            .exchange(http, method::GET, Some(INFO_PATH), None, true)
            .await?;

        if !response.is_success() {
            tracing::debug!(status = response.status, "device does not support /info");
            return Ok(plist::Value::Dictionary(plist::Dictionary::new()));
        }

        decode_plist(&response.body)
    }

    /// Send `SETUP` with a property list body and return the decoded reply.
    ///
    /// `RtspSession.setup` (`pyatv/support/rtsp.py:169-175`). Both remote-control channels are
    /// negotiated through this one verb; what differs is only the body
    /// (`pyatv/protocols/airplay/ap2_session.py:110-113`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the device refuses the request, and [`Error::Plist`] if either
    /// body fails to encode or decode.
    pub async fn setup(
        &mut self,
        http: &mut HttpConnection,
        body: &plist::Value,
    ) -> Result<plist::Value> {
        let response = self
            .exchange(http, method::SETUP, None, Some(body), false)
            .await?;

        decode_plist(&response.body)
    }

    /// Send a bodyless `RECORD` against the session URI.
    ///
    /// `RtspSession.record` (`pyatv/support/rtsp.py:178-184`), called with neither headers nor a
    /// body by `AP2Session.setup_remote_control` (`ap2_session.py:81`). A receiver that answered
    /// the event-channel `SETUP` with `skipRecord: true` does not want this at all — see
    /// [`crate::ap2::EventChannelSetup::skip_record`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] if the device refuses the request and [`Error::Io`] on a transport
    /// failure.
    pub async fn record(&mut self, http: &mut HttpConnection) -> Result<Response> {
        self.exchange(http, method::RECORD, None, None, false).await
    }

    /// Send the two-second keepalive.
    ///
    /// `RtspSession.feedback` (`pyatv/support/rtsp.py:246-248`): a bare `POST` to the literal path
    /// `/feedback`, still travelling as `RTSP/1.0` with the whole `CSeq`/DACP header block. It is
    /// not a `SET_PARAMETER`-family verb and it does not target the `rtsp://…` session URI, both of
    /// which the name invites getting wrong.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Status`] for a non-success status unless `allow_error` is set, and
    /// [`Error::Io`] on a transport failure.
    pub async fn feedback(
        &mut self,
        http: &mut HttpConnection,
        allow_error: bool,
    ) -> Result<Response> {
        self.exchange(http, method::POST, Some(FEEDBACK_PATH), None, allow_error)
            .await
    }
}

impl Default for RtspSession {
    fn default() -> Self {
        Self::new()
    }
}

/// The parameters an `ANNOUNCE` SDP body is built from.
///
/// Only these three are substituted into pyatv's `ANNOUNCE_PAYLOAD` template; the codec, payload
/// type and frames
/// per packet are literals in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceFormat {
    /// Bits per channel, i.e. `8 * bytes_per_channel`.
    pub bits_per_channel: u32,
    /// Channel count.
    pub channels: u32,
    /// Sample rate in Hz.
    pub sample_rate: u32,
}

/// Build the SDP body for an `ANNOUNCE` request.
///
/// `ANNOUNCE_PAYLOAD` (`pyatv/support/rtsp.py:25-35`), reproduced line for line including the
/// trailing CRLF on the last line. Note that the codec named in `rtpmap` is `L16` — raw 16-bit
/// linear PCM — even though the `fmtp` line follows ALAC's conventional field layout, and that the
/// `96 L16/44100/2` and `352` tokens are hardcoded upstream rather than templated on
/// [`AnnounceFormat`]: only `bits_per_channel`, `channels` and `sample_rate` are substituted,
/// which is why a receiver asking for something other than 44100/2 gets an internally inconsistent
/// body. That inconsistency is upstream's and is reproduced (`docs/research/rust-crates.md` §7,
/// `airplay-playurl-raop-port-spec.md` §11).
#[must_use]
pub fn announce_sdp(
    session_id: u32,
    local_ip: &str,
    remote_ip: &str,
    format: AnnounceFormat,
) -> String {
    let AnnounceFormat {
        bits_per_channel,
        channels,
        sample_rate,
    } = format;

    format!(
        "v=0\r\n\
         o=iTunes {session_id} 0 IN IP4 {local_ip}\r\n\
         s=iTunes\r\n\
         c=IN IP4 {remote_ip}\r\n\
         t=0 0\r\n\
         m=audio 0 RTP/AVP 96\r\n\
         a=rtpmap:96 L16/44100/2\r\n\
         a=fmtp:96 {FRAMES_PER_PACKET} 0 {bits_per_channel} 40 10 14 {channels} 255 0 0 \
         {sample_rate}\r\n"
    )
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::{RtspSession, decode_plist, encode_plist};

    fn local() -> SocketAddr {
        "10.0.0.2:54321".parse().expect("valid socket address")
    }

    /// `f"rtsp://{self.connection.local_ip}/{self.session_id}"` — the local *IP*, with no port
    /// (`pyatv/support/rtsp.py:91-95`).
    #[test]
    fn the_session_uri_carries_the_local_ip_without_its_port() {
        let session = RtspSession::with_identifiers(3_735_928_559, 0x0102_0304_0506_0708, 42);
        assert_eq!(session.uri(local()), "rtsp://10.0.0.2/3735928559");
    }

    /// `f"{randrange(2**64):X}"` is uppercase and unpadded, so a small draw renders short.
    #[test]
    fn the_dacp_identifier_is_uppercase_unpadded_hex() {
        assert_eq!(
            RtspSession::with_identifiers(0, 0xdead_beef, 0).dacp_id,
            "DEADBEEF"
        );
        assert_eq!(
            RtspSession::with_identifiers(0, u64::MAX, 0).dacp_id,
            "FFFFFFFFFFFFFFFF"
        );
    }

    /// `CSeq` starts at zero and advances by one per request (`pyatv/support/rtsp.py:86,255-256`).
    #[test]
    fn cseq_starts_at_zero() {
        assert_eq!(RtspSession::new().next_cseq(), 0);
    }

    /// Two sessions must not collide on the identifiers a receiver uses to tell clients apart.
    #[test]
    fn sessions_draw_distinct_identifiers() {
        let first = RtspSession::new();
        let second = RtspSession::new();
        assert!(
            first.session_id != second.session_id
                || first.dacp_id != second.dacp_id
                || first.active_remote != second.active_remote
        );
    }

    /// Bodies go out as `bplist00`, not XML — the receiver rejects the XML form.
    #[test]
    fn plist_bodies_round_trip_as_binary() {
        let mut dictionary = plist::Dictionary::new();
        dictionary.insert(
            "isRemoteControlOnly".to_owned(),
            plist::Value::Boolean(true),
        );
        let value = plist::Value::Dictionary(dictionary);

        let encoded = encode_plist(&value).expect("encodes");
        assert!(encoded.starts_with(b"bplist00"));
        assert_eq!(decode_plist(&encoded).expect("decodes"), value);
    }

    /// A body that is not a property list is a decode error, not a panic.
    #[test]
    fn a_non_plist_body_is_an_error() {
        assert!(decode_plist(b"not a plist").is_err());
    }
}
