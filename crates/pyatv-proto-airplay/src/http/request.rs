//! Outgoing message construction: `RequestSpec` and the exact header order it produces.
//!
//! Split out of [`super`] because reproducing `_format_message`
//! (`pyatv/support/http.py:49-80`) is its own responsibility with its own byte-level tests, and
//! because pyatv offers three different ways to spell a header that all land in different places
//! on the wire.

use crate::codec::{CONTENT_LENGTH, CONTENT_TYPE, HTTP_1_1, Request};

use super::DEFAULT_USER_AGENT;

/// The parameters of one outgoing message.
///
/// A field-for-field mirror of `_format_message`/`send_and_receive`
/// (`pyatv/support/http.py:49-80,430-499`), because their argument list is what decides the header
/// order a device sees. Construct with `..RequestSpec::default()` and override only what differs:
/// the default is the bodyless `POST /` over `HTTP/1.1` that pairing sends.
#[derive(Debug, Clone, Copy)]
pub struct RequestSpec<'a> {
    /// Request method, which may be an RTSP verb.
    pub method: &'a str,
    /// Request target: a path, or the `rtsp://…` session URI for the RTSP verbs.
    pub uri: &'a str,
    /// Protocol token. `HTTP/1.1` for pairing, `RTSP/1.0` for the RTSP verbs.
    pub protocol: &'a str,
    /// User agent, emitted **before** `Content-Length` and ignored when `headers` already carries
    /// one — in which case it lands wherever `headers` puts it, which is after `Content-Length`.
    /// pyatv uses both spellings: pairing puts it in its header dict, RTSP passes it as this
    /// parameter, and the resulting byte order differs between the two.
    ///
    /// `None` selects [`DEFAULT_USER_AGENT`], as upstream's parameter default does.
    pub user_agent: Option<&'a str>,
    /// Content type emitted **before** `Content-Length`. A content type belonging after it goes in
    /// `headers` instead.
    pub content_type: Option<&'a str>,
    /// Headers in the order they should appear, after the three conditional insertions above.
    pub headers: &'a [(&'a str, &'a str)],
    /// Body bytes. Empty means no body and no `Content-Length` header at all.
    pub body: &'a [u8],
    /// Return the response whatever its status, rather than mapping a non-`2xx` onto an error.
    /// `allow_error` (`pyatv/support/http.py:437`); `GET /info` is sent this way because a device
    /// that does not implement the route answers `404` and pyatv treats that as "no info", not as
    /// a failure (`pyatv/support/rtsp.py:101-108`).
    pub allow_error: bool,
}

impl Default for RequestSpec<'_> {
    fn default() -> Self {
        Self {
            method: "POST",
            uri: "/",
            protocol: HTTP_1_1,
            user_agent: None,
            content_type: None,
            headers: &[],
            body: &[],
            allow_error: false,
        }
    }
}

/// Build the request pyatv's `_format_message` would produce for `spec`.
///
/// The three conditional insertions, in upstream's order
/// (`pyatv/support/http.py:64-74`):
///
/// 1. `User-Agent`, only when the caller did not supply one in `headers`.
/// 2. `Content-Type`, only from [`RequestSpec::content_type`]. A `Content-Type` placed in
///    `headers` instead lands *after* `Content-Length`; upstream has both spellings and the
///    difference is visible on the wire, so both are kept.
/// 3. `Content-Length`, only when the body is non-empty. Python's truthiness test means a
///    zero-length body produces no header at all, not `Content-Length: 0`.
pub(super) fn build_request(spec: &RequestSpec<'_>) -> Request {
    let mut wire_headers: Vec<(String, String)> = Vec::with_capacity(spec.headers.len() + 3);

    if !spec
        .headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("User-Agent"))
    {
        let user_agent = spec.user_agent.unwrap_or(DEFAULT_USER_AGENT);
        wire_headers.push(("User-Agent".to_owned(), user_agent.to_owned()));
    }
    if let Some(content_type) = spec.content_type {
        wire_headers.push((CONTENT_TYPE.to_owned(), content_type.to_owned()));
    }
    if !spec.body.is_empty() {
        wire_headers.push((CONTENT_LENGTH.to_owned(), spec.body.len().to_string()));
    }
    wire_headers.extend(
        spec.headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned())),
    );

    Request {
        method: spec.method.to_owned(),
        uri: spec.uri.to_owned(),
        protocol: spec.protocol.to_owned(),
        headers: wire_headers,
        body: bytes::Bytes::copy_from_slice(spec.body),
    }
}

#[cfg(test)]
mod tests {
    use bytes::BytesMut;

    use super::{RequestSpec, build_request};
    use crate::codec::{Frame, encode_frame};

    fn render(spec: &RequestSpec<'_>) -> String {
        let mut out = BytesMut::new();
        encode_frame(&Frame::Request(build_request(spec)), &mut out);
        String::from_utf8_lossy(&out).into_owned()
    }

    fn rendered(path: &str, headers: &[(&str, &str)], body: &[u8]) -> String {
        render(&RequestSpec {
            uri: path,
            headers,
            body,
            ..RequestSpec::default()
        })
    }

    /// The exact bytes `AirPlayHapPairSetupProcedure.start_pairing` puts on the wire for its first
    /// request (`pyatv/protocols/airplay/auth/hap.py:20-25,52`): no `Content-Length`, because the
    /// body is empty, and the four headers in the order the `_AIRPLAY_HEADERS` dict declares them.
    #[test]
    fn pin_start_request_matches_pyatv_byte_for_byte() {
        let wire = rendered(
            "/pair-pin-start",
            &[
                ("User-Agent", "AirPlay/320.20"),
                ("Connection", "keep-alive"),
                ("X-Apple-HKP", "3"),
                ("Content-Type", "application/octet-stream"),
            ],
            b"",
        );

        assert_eq!(
            wire,
            "POST /pair-pin-start HTTP/1.1\r\n\
             User-Agent: AirPlay/320.20\r\n\
             Connection: keep-alive\r\n\
             X-Apple-HKP: 3\r\n\
             Content-Type: application/octet-stream\r\n\r\n"
        );
    }

    /// `Content-Length` is inserted *before* the caller's headers, so the caller's `Content-Type`
    /// follows it. Getting this backwards is the easy mistake, since every other HTTP client emits
    /// `Content-Type` first.
    #[test]
    fn content_length_precedes_the_callers_headers() {
        let wire = rendered(
            "/pair-setup",
            &[
                ("User-Agent", "AirPlay/320.20"),
                ("Connection", "keep-alive"),
                ("X-Apple-HKP", "3"),
                ("Content-Type", "application/octet-stream"),
            ],
            &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05],
        );

        assert_eq!(
            wire,
            "POST /pair-setup HTTP/1.1\r\n\
             Content-Length: 6\r\n\
             User-Agent: AirPlay/320.20\r\n\
             Connection: keep-alive\r\n\
             X-Apple-HKP: 3\r\n\
             Content-Type: application/octet-stream\r\n\r\n\
             \x00\x01\x02\x03\x04\x05"
        );
    }

    /// A caller that supplies no `User-Agent` gets the default, in first position.
    #[test]
    fn a_default_user_agent_is_added_when_absent() {
        let wire = rendered("/anything", &[("Connection", "keep-alive")], b"");
        assert!(wire.starts_with("POST /anything HTTP/1.1\r\nUser-Agent: pyatv-rs/"));
    }

    /// The RTSP spelling: the user agent arrives as a parameter rather than in the header map, so
    /// it precedes `Content-Length` instead of following it — the mirror image of
    /// `content_length_precedes_the_callers_headers`, and the reason both spellings exist.
    #[test]
    fn a_user_agent_parameter_precedes_content_length() {
        let wire = render(&RequestSpec {
            method: "SETUP",
            uri: "rtsp://10.0.0.2/1234",
            protocol: crate::codec::RTSP_1_0,
            user_agent: Some(crate::codec::USER_AGENT),
            headers: &[
                ("CSeq", "0"),
                ("Content-Type", crate::codec::BPLIST_CONTENT_TYPE),
            ],
            body: b"body",
            ..RequestSpec::default()
        });

        assert_eq!(
            wire,
            "SETUP rtsp://10.0.0.2/1234 RTSP/1.0\r\n\
             User-Agent: AirPlay/550.10\r\n\
             Content-Length: 4\r\n\
             CSeq: 0\r\n\
             Content-Type: application/x-apple-binary-plist\r\n\r\n\
             body"
        );
    }

    /// The `content_type` parameter is upstream's third spelling and lands between the user agent
    /// and `Content-Length` (`pyatv/support/http.py:69-72`), which is where `/auth-setup` and the
    /// `ANNOUNCE`/`SET_PARAMETER` verbs put theirs.
    #[test]
    fn a_content_type_parameter_precedes_content_length() {
        let wire = render(&RequestSpec {
            uri: "/auth-setup",
            content_type: crate::codec::OCTET_STREAM_CONTENT_TYPE.into(),
            body: b"\x01",
            ..RequestSpec::default()
        });

        assert!(
            wire.contains(
                "Content-Type: application/octet-stream\r\nContent-Length: 1\r\n\r\n\u{1}"
            )
        );
    }
}
