//! Head-parsing, framing and content-decoding known-answers.

use std::io::Write;

use super::{ChunkedDecoder, Framing, Head, MAX_BODY_LEN, decode_chunked, is_success, parse_head};

fn head_of(raw: &[u8]) -> Head {
    parse_head(raw).expect("well formed").expect("complete").0
}

#[test]
fn a_head_parses_into_a_status_and_headers() {
    let (head, consumed) = parse_head(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
        .expect("well formed")
        .expect("complete");

    assert_eq!(head.status, 200);
    assert!(head.is_success());
    assert_eq!(head.header("content-length"), Some("4"));
    assert_eq!(
        consumed,
        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n".len()
    );
}

/// RFC 9110 §5.1: field names are case-insensitive, and a device may capitalise them any way.
#[test]
fn header_lookup_ignores_case() {
    let head = head_of(b"HTTP/1.1 200 OK\r\nCONTENT-length: 7\r\n\r\n");
    assert_eq!(head.header("Content-Length"), Some("7"));
    assert_eq!(head.header("content-LENGTH"), Some("7"));
    assert!(head.header("Content-Type").is_none());
}

/// An incomplete head is not an error; the caller reads more and asks again.
#[test]
fn an_incomplete_head_asks_for_more() {
    assert!(
        parse_head(b"HTTP/1.1 200 OK\r\nContent-Len")
            .expect("not malformed, just short")
            .is_none()
    );
}

#[test]
fn a_malformed_head_is_rejected() {
    for bad in [
        b"NOT-HTTP 200 OK\r\n\r\n".as_slice(),
        b"HTTP/1.1 abc OK\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nno-colon-here\r\n\r\n".as_slice(),
    ] {
        assert!(parse_head(bad).is_err(), "{bad:?} should be rejected");
    }
}

/// The three framings, plus the two ways a device can be ambiguous about them.
#[test]
fn framing_follows_the_headers() {
    assert_eq!(
        head_of(b"HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n")
            .framing()
            .expect("valid"),
        Framing::Length(12)
    );
    assert_eq!(
        head_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .framing()
            .expect("valid"),
        Framing::Chunked
    );
    assert_eq!(
        head_of(b"HTTP/1.1 200 OK\r\n\r\n")
            .framing()
            .expect("valid"),
        Framing::ToEof
    );

    // Both at once is a smuggling vector, and an unknown coding cannot be framed at all.
    assert!(
        head_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n")
            .framing()
            .is_err()
    );
    assert!(
        head_of(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: deflate\r\n\r\n")
            .framing()
            .is_err()
    );
    assert!(
        head_of(b"HTTP/1.1 200 OK\r\nContent-Length: lots\r\n\r\n")
            .framing()
            .is_err()
    );
}

/// A 403 is what `artwork_no_permission` serves, and what drives the re-login path.
#[test]
fn non_2xx_statuses_are_not_successes() {
    for status in [403u16, 500, 503, 199, 300] {
        let raw = format!("HTTP/1.1 {status} Something\r\n\r\n");
        assert!(!head_of(raw.as_bytes()).is_success(), "{status}");
    }
}

#[test]
fn a_chunked_body_is_reassembled() {
    let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    let (body, consumed) = decode_chunked(raw).expect("well formed").expect("complete");

    assert_eq!(body, b"Wikipedia");
    assert_eq!(consumed, raw.len());
}

/// Chunk extensions are legal (RFC 9112 §7.1.1) and carry nothing DAAP needs.
#[test]
fn chunk_extensions_are_ignored() {
    let (body, _) = decode_chunked(b"4;name=value\r\nWiki\r\n0\r\n\r\n")
        .expect("well formed")
        .expect("complete");
    assert_eq!(body, b"Wiki");
}

/// Trailers after the terminating chunk are consumed, not left on the socket.
#[test]
fn trailers_are_consumed() {
    let raw = b"4\r\nWiki\r\n0\r\nExpires: never\r\n\r\n";
    let (body, consumed) = decode_chunked(raw).expect("well formed").expect("complete");

    assert_eq!(body, b"Wiki");
    assert_eq!(consumed, raw.len());
}

/// Every prefix of a valid chunked body must ask for more rather than erroring or truncating.
#[test]
fn a_partial_chunked_body_asks_for_more() {
    let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    for cut in 1..raw.len() {
        assert!(
            decode_chunked(&raw[..cut])
                .expect("a prefix is short, not malformed")
                .is_none(),
            "prefix of {cut} bytes"
        );
    }
}

#[test]
fn a_bad_chunk_size_is_rejected() {
    assert!(decode_chunked(b"zz\r\nWiki\r\n0\r\n\r\n").is_err());
}

/// The decoder resumes where it stopped rather than starting over, so a chunk it has already
/// consumed is not appended a second time when the rest of the body arrives.
///
/// Every split is exercised, which puts the boundary inside the chunk-size line, inside the chunk
/// data, and between a chunk and its terminating `CRLF` in turn.
#[test]
fn a_chunked_body_split_across_reads_decodes_each_chunk_once() {
    let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

    for split in 1..raw.len() {
        let mut decoder = ChunkedDecoder::new();
        assert!(
            decoder
                .feed(&raw[..split])
                .expect("a prefix is short, not malformed")
                .is_none(),
            "split at {split} should not be complete"
        );

        let consumed = decoder
            .feed(raw)
            .expect("well formed")
            .expect("the whole body is there now");
        assert_eq!(consumed, raw.len(), "split at {split}");
        assert_eq!(decoder.into_body(), b"Wikipedia", "split at {split}");
    }
}

/// The pathological case: one byte per read. Whatever the decoder does per call, the answer has to
/// be the same, and the caller may only be told it is complete once.
#[test]
fn a_chunked_body_fed_one_byte_at_a_time_decodes_once() {
    let raw = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nExpires: never\r\n\r\n";

    let mut decoder = ChunkedDecoder::new();
    let mut completions = 0usize;
    let mut consumed = None;
    for end in 1..=raw.len() {
        if let Some(total) = decoder.feed(&raw[..end]).expect("well formed") {
            completions += 1;
            consumed = Some(total);
        }
    }

    assert_eq!(completions, 1, "completion must be reported exactly once");
    assert_eq!(consumed, Some(raw.len()));
    assert_eq!(decoder.body(), b"Wikipedia");
    assert_eq!(decoder.into_body(), b"Wikipedia");
}

/// A chunked body is as unbounded as a `Content-Length` one, and is capped the same way — before
/// the chunk it is about to refuse is copied anywhere.
#[test]
fn a_chunked_body_over_the_cap_is_refused() {
    let oversized = format!("{:x}\r\n", MAX_BODY_LEN + 1);

    let error = ChunkedDecoder::new()
        .feed(oversized.as_bytes())
        .expect_err("an oversized chunk must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");

    // And in aggregate, across chunks each of which is individually fine.
    let chunk = vec![b'x'; 1024 * 1024];
    let mut data = Vec::new();
    for _ in 0..9 {
        data.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        data.extend_from_slice(&chunk);
        data.extend_from_slice(b"\r\n");
    }
    assert!(ChunkedDecoder::new().feed(&data).is_err());
}

/// A chunk-size line with no `CRLF` never becomes parseable, so the decoder can be strung along
/// forever unless it bounds the incomplete line itself. [`MAX_BODY_LEN`] cannot see this: not one
/// byte of it is chunk data.
#[test]
fn a_chunk_size_line_that_never_ends_is_refused() {
    let mut decoder = ChunkedDecoder::new();
    let mut data = Vec::new();

    // Well under the cap: still just an incomplete line.
    data.resize(super::MAX_CHUNK_LINE_LEN, b'a');
    assert!(
        decoder
            .feed(&data)
            .expect("still short, not malformed")
            .is_none(),
        "a line at exactly the cap is short, not refused"
    );

    data.push(b'a');
    let error = decoder
        .feed(&data)
        .expect_err("a chunk size line past the cap must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
    assert!(error.to_string().contains("chunk size line"), "{error}");
}

/// The same hole after the terminating chunk: trailer lines that never produce the blank line
/// ending the trailer section.
#[test]
fn a_trailer_section_that_never_ends_is_refused() {
    let mut decoder = ChunkedDecoder::new();
    let mut data = b"4\r\nWiki\r\n0\r\n".to_vec();
    let head_len = data.len();

    while data.len() - head_len <= super::MAX_TRAILER_LEN {
        data.extend_from_slice(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
        // Nothing here is a blank line, so the trailer section never ends.
        assert!(!data.ends_with(b"\r\n\r\n"));
    }

    let error = decoder
        .feed(&data)
        .expect_err("an endless trailer section must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
    assert!(error.to_string().contains("trailer"), "{error}");

    // The chunk before the terminator was still decoded normally on the way past.
    assert_eq!(decoder.body(), b"Wiki");
}

/// The free function and the method agree, which is what lets [`crate::daap`] branch on a bare
/// status after the head has been dropped.
#[test]
fn the_free_success_predicate_matches_the_method() {
    for status in [199u16, 200, 204, 299, 300, 403, 500, 503] {
        let raw = format!("HTTP/1.1 {status} Something\r\n\r\n");
        assert_eq!(head_of(raw.as_bytes()).is_success(), is_success(status));
    }
    assert!(is_success(200) && is_success(299));
    assert!(!is_success(199) && !is_success(300));
}

/// The reason `Accept-Encoding: gzip` can stay on the request.
#[test]
fn a_gzip_body_is_inflated() {
    let payload = b"cmst\x00\x00\x00\x00";
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(payload).expect("in-memory write");
    let compressed = encoder.finish().expect("gzip finishes");

    let head = head_of(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n");
    assert_eq!(head.decode_body(compressed).expect("inflates"), payload);
}

#[test]
fn an_unencoded_body_passes_through() {
    for raw_head in [
        b"HTTP/1.1 200 OK\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\n\r\n".as_slice(),
    ] {
        let head = head_of(raw_head);
        assert_eq!(
            head.decode_body(b"plain".to_vec()).expect("passes through"),
            b"plain"
        );
    }
}

#[test]
fn an_unknown_or_broken_content_coding_is_rejected() {
    assert!(
        head_of(b"HTTP/1.1 200 OK\r\nContent-Encoding: br\r\n\r\n")
            .decode_body(b"whatever".to_vec())
            .is_err()
    );
    assert!(
        head_of(b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n")
            .decode_body(b"not actually gzip".to_vec())
            .is_err()
    );
}
