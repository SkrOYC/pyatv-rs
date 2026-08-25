//! The RAOP half of the RTSP verb set.
//!
//! Port of the `RtspSession` methods `AirPlayV1`/`AirPlayV2`/`StreamClient` drive but the
//! remote-control tunnel never touches: `announce`, `auth_setup`, `flush`, `teardown`,
//! `set_parameter`, `set_metadata` and `set_artwork` (`pyatv/support/rtsp.py:110-252`). They live
//! here rather than on [`crate::rtsp::RtspSession`] itself for the same reason upstream's own
//! comment gives for `announce` — "this method is only used by AirPlay 1 and is very specific …
//! should probably move to the AirPlay 1 specific RAOP implementation" (`rtsp.py:125-128`).
//!
//! Everything is expressed as free functions over `(&mut RtspSession, &mut HttpConnection)` so no
//! second session type has to exist; [`crate::rtsp::Exchange`] carries the content types and extra
//! headers these verbs need and the base session does not.

use crate::codec::OCTET_STREAM_CONTENT_TYPE;
use crate::http::HttpConnection;
use crate::rtsp::{AnnounceFormat, DigestInfo, Exchange, RtspSession, announce_sdp, method};
use crate::{Error, Result};

use super::metadata::TrackMetadata;

/// Content type of the `ANNOUNCE` body.
pub const SDP_CONTENT_TYPE: &str = "application/sdp";

/// Content type of the `volume` and `progress` `SET_PARAMETER` bodies.
pub const TEXT_PARAMETERS_CONTENT_TYPE: &str = "text/parameters";

/// Content type of the DAAP metadata `SET_PARAMETER` body.
pub const DMAP_CONTENT_TYPE: &str = "application/x-dmap-tagged";

/// Content type artwork is always sent with, whatever the bytes actually are
/// (`pyatv/support/rtsp.py:228-244` sniffs nothing).
pub const ARTWORK_CONTENT_TYPE: &str = "image/jpeg";

/// Path the `MFiSAP` dummy handshake is posted to.
pub const AUTH_SETUP_PATH: &str = "/auth-setup";

/// The leading byte of the `/auth-setup` body: "proceed unencrypted"
/// (`AUTH_SETUP_UNENCRYPTED`, `pyatv/support/rtsp.py:38`).
pub const AUTH_SETUP_UNENCRYPTED: u8 = 0x01;

/// The fixed Curve25519 public key `/auth-setup` sends.
///
/// A static value pyatv borrows verbatim from owntone-server's `raop.c:276`
/// (`pyatv/support/rtsp.py:40-49`). Nothing about the reply is ever verified or used: the whole
/// exchange exists only because some receivers refuse to stream until `/auth-setup` has been
/// called at all (pyatv issue #1134). It is therefore not a key in any meaningful sense and
/// carries no secret.
pub const CURVE25519_PUB_KEY: [u8; 32] = [
    0x59, 0x02, 0xed, 0xe9, 0x0d, 0x4e, 0xf2, 0xbd, 0x4c, 0xb6, 0x8a, 0x63, 0x30, 0x03, 0x82, 0x07,
    0xa9, 0x4d, 0xbd, 0x50, 0xd8, 0xaa, 0x46, 0x5b, 0x5d, 0x8c, 0x01, 0x2a, 0x0c, 0x7e, 0x1d, 0x4e,
];

/// Send `POST /auth-setup`.
///
/// `RtspSession.auth_setup` (`pyatv/support/rtsp.py:110-123`). The one call site in upstream's
/// RTSP layer that overrides the protocol token to `HTTP/1.1`, so the request line reads
/// `POST /auth-setup HTTP/1.1` rather than `… RTSP/1.0`.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the body, or [`Error::Io`] on a transport
/// failure.
pub async fn auth_setup(rtsp: &mut RtspSession, http: &mut HttpConnection) -> Result<()> {
    let mut body = Vec::with_capacity(1 + CURVE25519_PUB_KEY.len());
    body.push(AUTH_SETUP_UNENCRYPTED);
    body.extend_from_slice(&CURVE25519_PUB_KEY);

    rtsp.send(
        http,
        &Exchange {
            method: method::POST,
            uri: Some(AUTH_SETUP_PATH),
            content_type: Some(OCTET_STREAM_CONTENT_TYPE),
            body: &body,
            protocol: crate::codec::HTTP_1_1,
            ..Exchange::default()
        },
    )
    .await?;

    Ok(())
}

/// Send `ANNOUNCE`, answering a password challenge if one comes back.
///
/// `RtspSession.announce` (`pyatv/support/rtsp.py:129-168`): the first attempt is sent with
/// `allow_error` **only when a password is configured**, and a `401` carrying a `WWW-Authenticate`
/// then arms [`RtspSession::set_digest`] and repeats the request once. A receiver that challenges
/// a client with no password configured produces a plain [`Error::NotAuthenticated`] instead,
/// because upstream never enters the retry branch in that case.
///
/// # Errors
///
/// Returns [`Error::PasswordRequired`] if the challenge cannot be parsed the way upstream parses
/// it, [`Error::NotAuthenticated`] if the receiver rejects the password, and [`Error::Io`] on a
/// transport failure.
pub async fn announce(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    format: AnnounceFormat,
    password: Option<&str>,
) -> Result<()> {
    let body = announce_sdp(
        rtsp.session_id(),
        &http.local_address()?.ip().to_string(),
        &http.remote_address().ip().to_string(),
        format,
    );

    let request = |allow_error| Exchange {
        method: method::ANNOUNCE,
        content_type: Some(SDP_CONTENT_TYPE),
        body: body.as_bytes(),
        allow_error,
        ..Exchange::default()
    };

    let Some(password) = password else {
        rtsp.send(http, &request(false)).await?;
        return Ok(());
    };

    let response = rtsp.send(http, &request(true)).await?;
    if response.status != 401 {
        return Ok(());
    }

    let challenge = response
        .header("WWW-Authenticate")
        .and_then(crate::rtsp::digest::parse_challenge)
        .ok_or(Error::PasswordRequired)?;

    tracing::debug!(realm = %challenge.0, "answering an RTSP digest challenge");
    rtsp.set_digest(DigestInfo::new(&challenge.0, password, &challenge.1));
    rtsp.send(http, &request(false)).await?;

    Ok(())
}

/// Send `SETUP` with a `Transport` header, and return the header the receiver answered with.
///
/// The AirPlay-1 shape of `SETUP` (`airplayv1.py:61-79`): a header, not a property list body. The
/// reply's `Transport` and `Session` headers are returned raw for
/// [`super::protocol_v1::parse_transport`] to pick apart.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the request, [`Error::Malformed`] if the
/// reply carries no `Transport` header, and [`Error::Io`] on a transport failure.
pub async fn setup_transport(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    transport: &str,
) -> Result<(String, Option<String>)> {
    let response = rtsp
        .send(
            http,
            &Exchange {
                method: method::SETUP,
                headers: &[("Transport", transport)],
                ..Exchange::default()
            },
        )
        .await?;

    let transport = response
        .header("Transport")
        .ok_or_else(|| Error::Malformed("SETUP reply carries no Transport header".to_owned()))?
        .to_owned();
    let session = response.header("Session").map(str::to_owned);

    Ok((transport, session))
}

/// Send `FLUSH` with the header block that resets the receiver's buffer.
///
/// `self.rtsp.flush(headers={"Range": "npt=0-", "Session": …, "RTP-Info": …})`
/// (`stream_client.py:439-448`), sent immediately after `RECORD` and before the first audio
/// packet.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the request and [`Error::Io`] on a transport
/// failure.
pub async fn flush(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    session: u32,
    seqno: u16,
    rtptime: u32,
) -> Result<()> {
    let session = session.to_string();
    let rtp_info = format!("seq={seqno};rtptime={rtptime}");

    rtsp.send(
        http,
        &Exchange {
            method: method::FLUSH,
            headers: &[
                ("Range", "npt=0-"),
                ("Session", session.as_str()),
                ("RTP-Info", rtp_info.as_str()),
            ],
            ..Exchange::default()
        },
    )
    .await?;

    Ok(())
}

/// Send `TEARDOWN`.
///
/// `RtspSession.teardown` (`pyatv/support/rtsp.py:250-252`): one `Session` header, no body.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the request and [`Error::Io`] on a transport
/// failure.
pub async fn teardown(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    session: u32,
) -> Result<()> {
    let session = session.to_string();

    rtsp.send(
        http,
        &Exchange {
            method: method::TEARDOWN,
            headers: &[("Session", session.as_str())],
            ..Exchange::default()
        },
    )
    .await?;

    Ok(())
}

/// Send `SET_PARAMETER` with a `text/parameters` body.
///
/// `RtspSession.set_parameter` (`pyatv/support/rtsp.py:194-200`): the body is literally
/// `"{parameter}: {value}"` with no trailing newline, and no `Session`/`RTP-Info` headers.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the parameter — which a receiver that will
/// not take a volume before streaming has started really does, with `500` — and [`Error::Io`] on a
/// transport failure.
pub async fn set_parameter(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    parameter: &str,
    value: &str,
) -> Result<()> {
    let body = format!("{parameter}: {value}");

    rtsp.send(
        http,
        &Exchange {
            method: method::SET_PARAMETER,
            content_type: Some(TEXT_PARAMETERS_CONTENT_TYPE),
            body: body.as_bytes(),
            ..Exchange::default()
        },
    )
    .await?;

    Ok(())
}

/// The `Session` and `RTP-Info` headers the metadata and artwork verbs both carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpInfo {
    /// `context.rtsp_session` — zero on the AirPlay 2 path, which never learns one.
    pub session: u32,
    /// `context.rtpseq` at the moment the verb is sent, i.e. before any packet has gone out.
    pub seqno: u16,
    /// `context.rtptime` at the same moment.
    pub rtptime: u32,
}

impl RtpInfo {
    /// Render the two header values.
    fn headers(self) -> (String, String) {
        (
            self.session.to_string(),
            format!("seq={};rtptime={}", self.seqno, self.rtptime),
        )
    }
}

/// Send the DAAP track metadata.
///
/// `RtspSession.set_metadata` (`pyatv/support/rtsp.py:202-226`). The payload order is fixed and is
/// **title, album, artist** — album before artist — and each field is omitted entirely when it is
/// empty rather than sent as a zero-length tag.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the body and [`Error::Io`] on a transport
/// failure.
pub async fn set_metadata(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    info: RtpInfo,
    metadata: &TrackMetadata,
) -> Result<()> {
    let (session, rtp_info) = info.headers();

    rtsp.send(
        http,
        &Exchange {
            method: method::SET_PARAMETER,
            content_type: Some(DMAP_CONTENT_TYPE),
            headers: &[
                ("Session", session.as_str()),
                ("RTP-Info", rtp_info.as_str()),
            ],
            body: &metadata.to_daap(),
            ..Exchange::default()
        },
    )
    .await?;

    Ok(())
}

/// Send cover artwork.
///
/// `RtspSession.set_artwork` (`pyatv/support/rtsp.py:228-244`): the bytes go out as-is under a
/// hardcoded `image/jpeg`, with no format sniffing or validation.
///
/// # Errors
///
/// Returns [`Error::Status`] if the receiver refuses the body and [`Error::Io`] on a transport
/// failure.
pub async fn set_artwork(
    rtsp: &mut RtspSession,
    http: &mut HttpConnection,
    info: RtpInfo,
    artwork: &[u8],
) -> Result<()> {
    let (session, rtp_info) = info.headers();

    rtsp.send(
        http,
        &Exchange {
            method: method::SET_PARAMETER,
            content_type: Some(ARTWORK_CONTENT_TYPE),
            headers: &[
                ("Session", session.as_str()),
                ("RTP-Info", rtp_info.as_str()),
            ],
            body: artwork,
            ..Exchange::default()
        },
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{AUTH_SETUP_UNENCRYPTED, CURVE25519_PUB_KEY, RtpInfo};
    use crate::rtsp::{AnnounceFormat, announce_sdp};

    /// The template verbatim, including the hardcoded `L16/44100/2` and `352`
    /// (`pyatv/support/rtsp.py:25-35`).
    #[test]
    fn the_announce_body_matches_pyatvs_template() {
        let sdp = announce_sdp(
            1_234_567_890,
            "10.0.0.2",
            "10.0.0.9",
            AnnounceFormat {
                bits_per_channel: 16,
                channels: 2,
                sample_rate: 44_100,
            },
        );

        assert_eq!(
            sdp,
            "v=0\r\n\
             o=iTunes 1234567890 0 IN IP4 10.0.0.2\r\n\
             s=iTunes\r\n\
             c=IN IP4 10.0.0.9\r\n\
             t=0 0\r\n\
             m=audio 0 RTP/AVP 96\r\n\
             a=rtpmap:96 L16/44100/2\r\n\
             a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n"
        );
    }

    /// Only three tokens are substituted; the `rtpmap` line is untouched even at 48 kHz. That is
    /// upstream's behaviour, not an oversight in this port.
    #[test]
    fn the_rtpmap_line_is_not_templated_on_the_sample_rate() {
        let sdp = announce_sdp(
            1,
            "10.0.0.2",
            "10.0.0.9",
            AnnounceFormat {
                bits_per_channel: 24,
                channels: 1,
                sample_rate: 48_000,
            },
        );

        assert!(sdp.contains("a=rtpmap:96 L16/44100/2\r\n"));
        assert!(sdp.contains("a=fmtp:96 352 0 24 40 10 14 1 255 0 0 48000\r\n"));
    }

    /// The fake receiver accepts exactly `1 + 32` bytes (`tests/fake_device/raop.py:531`).
    #[test]
    fn the_auth_setup_body_is_thirty_three_bytes() {
        assert_eq!(1 + CURVE25519_PUB_KEY.len(), 33);
        assert_eq!(AUTH_SETUP_UNENCRYPTED, 0x01);
        assert_eq!(CURVE25519_PUB_KEY[0], 0x59);
        assert_eq!(CURVE25519_PUB_KEY[31], 0x4E);
    }

    #[test]
    fn the_rtp_info_header_is_a_semicolon_pair() {
        let (session, rtp_info) = RtpInfo {
            session: 1,
            seqno: 40_000,
            rtptime: 66_150,
        }
        .headers();

        assert_eq!(session, "1");
        assert_eq!(rtp_info, "seq=40000;rtptime=66150");
    }
}
