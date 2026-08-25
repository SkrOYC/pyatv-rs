//! Codec unit tests: exact request bytes out, permissive frames in.

use bytes::BytesMut;

use super::{Frame, MAX_BODY_LEN, Request, Response, encode_frame, parse_frame};

fn request(method: &str, uri: &str, headers: &[(&str, &str)], body: &[u8]) -> Request {
    Request {
        method: method.to_owned(),
        uri: uri.to_owned(),
        protocol: "HTTP/1.1".to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect(),
        body: bytes::Bytes::copy_from_slice(body),
    }
}

fn encoded(frame: &Frame) -> Vec<u8> {
    let mut out = BytesMut::new();
    encode_frame(frame, &mut out);
    out.to_vec()
}

#[test]
fn a_request_encodes_headers_in_the_order_given() {
    let wire = encoded(&Frame::Request(request(
        "POST",
        "/pair-verify",
        &[
            ("Content-Length", "4"),
            ("User-Agent", "AirPlay/320.20"),
            ("X-Apple-HKP", "3"),
        ],
        b"\x01\x02\x03\x04",
    )));

    assert_eq!(
        wire,
        b"POST /pair-verify HTTP/1.1\r\n\
          Content-Length: 4\r\n\
          User-Agent: AirPlay/320.20\r\n\
          X-Apple-HKP: 3\r\n\r\n\
          \x01\x02\x03\x04"
            .to_vec()
    );
}

#[test]
fn an_empty_body_still_terminates_the_header_block() {
    let wire = encoded(&Frame::Request(request(
        "POST",
        "/pair-pin-start",
        &[],
        b"",
    )));
    assert_eq!(wire, b"POST /pair-pin-start HTTP/1.1\r\n\r\n".to_vec());
}

#[test]
fn a_response_round_trips_through_encode_and_parse() {
    let original = Response {
        protocol: "HTTP/1.1".to_owned(),
        status: 200,
        reason: "OK".to_owned(),
        headers: vec![
            ("Content-Length".to_owned(), "3".to_owned()),
            (
                "Content-Type".to_owned(),
                "application/octet-stream".to_owned(),
            ),
        ],
        body: bytes::Bytes::from_static(b"abc"),
    };

    let wire = encoded(&Frame::Response(original.clone()));
    let (frame, consumed) = parse_frame(&wire).unwrap().unwrap();

    assert_eq!(consumed, wire.len());
    assert_eq!(frame, Frame::Response(original));
}

#[test]
fn a_response_is_parsed_and_its_length_reported() {
    let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nCSeq: 1\r\n\r\nhello";
    let (frame, consumed) = parse_frame(wire).unwrap().unwrap();

    assert_eq!(consumed, wire.len());
    let Frame::Response(response) = frame else {
        panic!("expected a response");
    };
    assert_eq!(response.protocol, "HTTP/1.1");
    assert_eq!(response.status, 200);
    assert_eq!(response.reason, "OK");
    assert_eq!(response.body, bytes::Bytes::from_static(b"hello"));
    assert_eq!(response.header("cseq"), Some("1"));
    assert_eq!(response.header("Content-Length"), Some("5"));
    assert!(response.is_success());
}

/// The receiver talks back over the controller's own socket, so the same parser has to accept a
/// request. `RTSP/1.0` in the protocol slot must not be mistaken for a response.
#[test]
fn a_reverse_request_is_recognised_as_a_request() {
    let wire = b"POST /feedback RTSP/1.0\r\nContent-Length: 0\r\n\r\n";
    let (frame, consumed) = parse_frame(wire).unwrap().unwrap();

    assert_eq!(consumed, wire.len());
    let Frame::Request(request) = frame else {
        panic!("expected a request");
    };
    assert_eq!(request.method, "POST");
    assert_eq!(request.uri, "/feedback");
    assert_eq!(request.protocol, "RTSP/1.0");
    assert!(request.body.is_empty());
}

/// pyatv's parser treats a missing `Content-Length` as a zero-length body rather than as
/// "read until close" (`pyatv/support/http.py:122`).
#[test]
fn a_missing_content_length_means_an_empty_body() {
    let wire = b"HTTP/1.1 200 OK\r\nCSeq: 1\r\n\r\n";
    let (frame, consumed) = parse_frame(wire).unwrap().unwrap();

    assert_eq!(consumed, wire.len());
    let Frame::Response(response) = frame else {
        panic!("expected a response");
    };
    assert!(response.body.is_empty());
}

/// Keep-alive: two responses arriving in one read must both be recoverable, and the first parse
/// must report exactly its own length so the caller can advance past it.
#[test]
fn two_pipelined_responses_are_split_at_the_right_offset() {
    let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nokHTTP/1.1 204 No Content\r\n\r\n";
    let (first, consumed) = parse_frame(wire).unwrap().unwrap();

    let Frame::Response(first) = first else {
        panic!("expected a response");
    };
    assert_eq!(first.body, bytes::Bytes::from_static(b"ok"));

    let (second, second_consumed) = parse_frame(&wire[consumed..]).unwrap().unwrap();
    let Frame::Response(second) = second else {
        panic!("expected a response");
    };
    assert_eq!(second.status, 204);
    assert_eq!(consumed + second_consumed, wire.len());
}

/// A partial message is not an error, it is "come back with more bytes". Feeding the same response
/// one byte at a time must yield `None` on every prefix and the frame on the last byte.
#[test]
fn a_body_split_across_reads_yields_none_until_complete() {
    let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n12345678";

    for length in 0..wire.len() {
        assert!(
            parse_frame(&wire[..length]).unwrap().is_none(),
            "prefix of {length} bytes should not parse yet"
        );
    }

    let (frame, consumed) = parse_frame(wire).unwrap().unwrap();
    assert_eq!(consumed, wire.len());
    let Frame::Response(response) = frame else {
        panic!("expected a response");
    };
    assert_eq!(response.body, bytes::Bytes::from_static(b"12345678"));
}

/// The header block can arrive complete while the body has not; that is still `None`.
#[test]
fn complete_headers_with_a_short_body_yield_none() {
    let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\nshort";
    assert!(parse_frame(wire).unwrap().is_none());
}

#[test]
fn a_start_line_matching_neither_shape_is_an_error() {
    assert!(parse_frame(b"garbage\r\n\r\n").is_err());
}

#[test]
fn a_non_numeric_content_length_is_an_error() {
    assert!(parse_frame(b"HTTP/1.1 200 OK\r\nContent-Length: soon\r\n\r\n").is_err());
}

/// `u64::MAX` as a `Content-Length` would overflow `body_start + content_length` on a 64-bit
/// target and does not fit a `usize` at all; either way it is an error rather than a panic or a
/// wrapped, far-too-small body slice.
#[test]
fn a_content_length_that_cannot_fit_a_usize_is_an_error() {
    let error = parse_frame(b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551615\r\n\r\n")
        .expect_err("refused");

    assert!(error.to_string().contains("Content-Length"), "{error}");
}

/// A body one byte past the cap is refused; the cap itself is accepted, so the guard cannot be
/// off by one in the direction that breaks a legitimate message.
#[test]
fn a_content_length_over_the_cap_is_an_error() {
    let over = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        MAX_BODY_LEN + 1
    );
    let error = parse_frame(over.as_bytes()).expect_err("refused");
    assert!(error.to_string().contains("exceeds"), "{error}");

    // At the cap the message is merely incomplete — the parser waits for the body rather than
    // refusing it.
    let at = format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_BODY_LEN}\r\n\r\n");
    assert!(parse_frame(at.as_bytes()).expect("valid").is_none());
}
