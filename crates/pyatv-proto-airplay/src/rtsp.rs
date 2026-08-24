//! The RTSP layer: methods, SDP bodies and Digest authentication.
//!
//! Sits directly on [`crate::codec`]. See `docs/research/airplay-raop-dmap.md` for the request
//! sequences and `docs/research/rust-crates.md` §5 for the framing decisions.
//!
//! # What is already built
//!
//! [`crate::codec`] parses and encodes both roles and implements `tokio_util::codec::Decoder` and
//! `Encoder`, so `Framed<TcpStream, AirPlayCodec>` works today. [`crate::http::HttpConnection`]
//! drives the same parser over a raw socket instead, because the post-pair-verify
//! [`pyatv_pairing::session::HapSession`] framing sits *below* HTTP and a `Framed` leaves no seam
//! to insert it at. An RTSP session can either grow on top of `HttpConnection` — adding `CSeq`,
//! `Session` and the non-`POST` verbs, and consuming the reverse requests it currently logs and
//! drops — or use `Framed` and forgo encryption. The first is what pyatv does.

use crate::Result;
use crate::codec::Response;

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
}

/// Frames per RTP packet, from pyatv's `rtsp.py`.
pub const FRAMES_PER_PACKET: u32 = 352;

/// An RTSP session over one connection.
#[derive(Debug)]
pub struct RtspSession {
    session_id: Option<String>,
    /// Incremented on every request; the device echoes it back.
    cseq: u32,
}

impl RtspSession {
    /// A fresh session with no identifier yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session_id: None,
            cseq: 0,
        }
    }

    /// The session identifier the device assigned, once `SETUP` has completed.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Send a request and await its response.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::Status`] for a non-success status, or
    /// [`crate::Error::PasswordRequired`] on a `401` carrying a Digest challenge that no password
    /// can answer.
    // TODO(step-1): build the request, add CSeq/Session/User-Agent headers, write it through the
    // Framed codec, then read frames until the matching response arrives — inbound requests from
    // the receiver must be dispatched, not discarded, since they share the socket.
    pub async fn request(&mut self, method: &str, uri: &str, body: &[u8]) -> Result<Response> {
        let _ = (method, uri, body, self.cseq);
        todo!("RtspSession::request")
    }
}

impl Default for RtspSession {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the SDP body for an `ANNOUNCE` request.
///
/// pyatv hand-builds this as a string template. Note the codec named in `rtpmap` is `L16` — raw
/// 16-bit linear PCM — even though the `fmtp` line follows ALAC's conventional field layout. See
/// `docs/research/rust-crates.md` §7.
// TODO(step-1): reproduce pyatv's ANNOUNCE_PAYLOAD template exactly, including the v=/o=/s=/c=/t=/
// m=/a=rtpmap/a=fmtp line order.
#[must_use]
pub fn announce_sdp(session_id: u32, local_addr: &str, remote_addr: &str) -> String {
    let _ = (session_id, local_addr, remote_addr);
    todo!("rtsp::announce_sdp")
}

/// Answer an RTSP `401` Digest challenge.
///
/// pyatv computes this by hand with MD5 rather than through an HTTP auth middleware.
// TODO(step-1): MD5 Digest per RFC 2617. Adding an MD5 dependency for this is unavoidable; it is
// used only for the challenge response, never for anything security-bearing.
#[must_use]
pub fn digest_response(
    username: &str,
    password: &str,
    realm: &str,
    nonce: &str,
    uri: &str,
) -> String {
    let _ = (username, password, realm, nonce, uri);
    todo!("rtsp::digest_response")
}
