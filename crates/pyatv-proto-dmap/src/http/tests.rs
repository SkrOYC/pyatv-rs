//! Client tests against a one-shot TCP server that answers with canned bytes.

use std::io::Write;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{HttpClient, HttpRequest, Method, response};

/// Serve `reply` to one connection and hand back the request bytes that arrived.
async fn serve_once(reply: Vec<u8>) -> (HttpClient, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback bind");
    let address = listener.local_addr().expect("bound");

    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("one connection");

        // Read until the request head is complete, then the declared body.
        let mut request = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let read = stream.read(&mut chunk).await.expect("read");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..read]);
            if let Some(head_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|start| start + 4)
            {
                let text = String::from_utf8_lossy(&request[..head_end]).to_lowercase();
                let expected = text
                    .split("content-length:")
                    .nth(1)
                    .and_then(|rest| rest.split("\r\n").next())
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if request.len() >= head_end + expected {
                    break;
                }
            }
        }

        stream.write_all(&reply).await.expect("write");
        stream.shutdown().await.expect("shutdown");
        request
    });

    (HttpClient::new(address), handle)
}

fn get<'a>(path: &'a str, headers: &'a [(&'a str, &'a str)]) -> HttpRequest<'a> {
    HttpRequest {
        method: Method::Get,
        path,
        headers,
        body: None,
        timeout: None,
    }
}

/// The request line, `Host`, the caller's headers in order, and no `Content-Length` on a `GET`.
#[tokio::test]
async fn a_get_is_written_the_way_a_device_expects() {
    let (client, server) =
        serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi".to_vec()).await;

    let response = client
        .send(&get(
            "login?pairing-guid=0x0000000000000001&hasFP=1",
            &[("Accept", "*/*"), ("User-Agent", "Remote/1021")],
        ))
        .await
        .expect("request succeeds");

    assert_eq!(response.status, 200);
    assert_eq!(response.body, b"hi");

    let raw = server.await.expect("server task");
    let text = String::from_utf8(raw).expect("ASCII request");
    assert!(
        text.starts_with(
            "GET /login?pairing-guid=0x0000000000000001&hasFP=1 HTTP/1.1\r\nHost: 127.0.0.1:"
        ),
        "{text}"
    );
    assert!(
        text.contains("\r\nAccept: */*\r\nUser-Agent: Remote/1021\r\n"),
        "{text}"
    );
    assert!(!text.to_lowercase().contains("content-length"), "{text}");
    assert!(text.ends_with("\r\nConnection: close\r\n\r\n"), "{text}");
}

/// A `POST` carries a `Content-Length` and the body, which is how command payloads travel.
#[tokio::test]
async fn a_post_sends_its_body_with_a_length() {
    let (client, server) =
        serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;

    let body = crate::tags::string_tag("cmbe", "select");
    let response = client
        .send(&HttpRequest {
            method: Method::Post,
            path: "ctrl-int/1/controlpromptentry?session-id=1&prompt-id=0",
            headers: &[("Content-Type", "application/x-www-form-urlencoded")],
            body: Some(&body),
            timeout: None,
        })
        .await
        .expect("request succeeds");

    assert_eq!(response.status, 200);
    assert!(response.body.is_empty());

    let raw = server.await.expect("server task");
    assert!(
        raw.starts_with(b"POST /ctrl-int/1/controlpromptentry?session-id=1&prompt-id=0 HTTP/1.1")
    );
    assert!(raw.ends_with(&body));
    assert!(String::from_utf8_lossy(&raw).contains(&format!("Content-Length: {}\r\n", body.len())));
}

/// A body-less `POST` still declares a zero length, or a server waits for bytes that never come.
#[tokio::test]
async fn a_post_without_a_body_declares_zero_length() {
    let (client, server) =
        serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;

    client
        .send(&HttpRequest {
            method: Method::Post,
            path: "ctrl-int/1/play?session-id=1&prompt-id=0",
            headers: &[],
            body: None,
            timeout: None,
        })
        .await
        .expect("request succeeds");

    let raw = String::from_utf8(server.await.expect("server task")).expect("ASCII");
    assert!(raw.contains("Content-Length: 0\r\n"), "{raw}");
}

/// The status is what `_do` branches on, and a body may come with it.
#[tokio::test]
async fn a_non_success_status_is_returned_rather_than_raised() {
    let (client, _server) =
        serve_once(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".to_vec()).await;

    let response = client.send(&get("whatever", &[])).await.expect("no error");
    assert_eq!(response.status, 403);
}

#[tokio::test]
async fn a_chunked_response_is_reassembled() {
    let (client, _server) = serve_once(
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n"
            .to_vec(),
    )
    .await;

    let response = client.send(&get("whatever", &[])).await.expect("succeeds");
    assert_eq!(response.body, b"Wikipedia");
}

/// The reason `Accept-Encoding: gzip` can stay on every request byte for byte.
#[tokio::test]
async fn a_gzip_response_is_inflated() {
    let payload = crate::tags::container_tag("cmst", &crate::tags::uint32_tag("caps", 4));
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&payload).expect("in-memory write");
    let compressed = encoder.finish().expect("gzip finishes");

    let mut reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
        compressed.len()
    )
    .into_bytes();
    reply.extend_from_slice(&compressed);

    let (client, _server) = serve_once(reply).await;
    let response = client.send(&get("whatever", &[])).await.expect("succeeds");
    assert_eq!(response.body, payload);
}

/// No framing headers at all: the body ends when the connection does (RFC 9112 §6.3).
#[tokio::test]
async fn a_body_can_be_delimited_by_the_connection_closing() {
    let (client, _server) = serve_once(b"HTTP/1.1 200 OK\r\n\r\nartwork-bytes".to_vec()).await;

    let response = client.send(&get("whatever", &[])).await.expect("succeeds");
    assert_eq!(response.body, b"artwork-bytes");
}

/// What `server_closes_connection` does to a real client: the socket dies mid-response.
#[tokio::test]
async fn a_truncated_response_is_an_error() {
    let (client, _server) =
        serve_once(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec()).await;

    assert!(client.send(&get("whatever", &[])).await.is_err());
}

/// A connection that closes before any head arrives cannot be interpreted as an empty response.
#[tokio::test]
async fn an_empty_response_is_an_error() {
    let (client, _server) = serve_once(Vec::new()).await;

    assert!(client.send(&get("whatever", &[])).await.is_err());
}

/// A deadline is optional and off for DAAP, but it has to work when a caller asks for one.
#[tokio::test]
async fn a_timeout_gives_up_rather_than_hanging() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback bind");
    let address = listener.local_addr().expect("bound");
    // Accept but never answer, which is what a long poll looks like from the outside.
    let _server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("one connection");
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        drop(stream);
    });

    let client = HttpClient::new(address);
    let error = client
        .send(&HttpRequest {
            method: Method::Get,
            path: "whatever",
            headers: &[],
            body: None,
            timeout: Some(std::time::Duration::from_millis(150)),
        })
        .await
        .expect_err("should time out");

    assert!(error.to_string().contains("timed out"), "{error}");
}

/// Nothing is dialled until a request is sent, so building a client cannot fail.
#[test]
fn the_peer_is_whatever_the_srv_record_said() {
    let client = HttpClient::new("192.0.2.10:3689".parse().expect("valid address"));
    assert_eq!(client.peer().port(), 3689);
}

// ---- Request splitting ----

/// A client aimed at TEST-NET-1, which nothing answers: any test using it asserts that the request
/// was refused *before* a socket was opened, because otherwise it would hang for `CONNECT_TIMEOUT`.
fn unreachable_client() -> HttpClient {
    HttpClient::new("192.0.2.10:3689".parse().expect("valid address"))
}

/// The credential from the review: `classify` accepts it as a pairing GUID because the match is
/// anchored only at the start, `mkurl` interpolates it, and unchecked it would end the request line
/// and let the rest of the string become headers of the attacker's choosing.
#[test]
fn a_credential_carrying_a_crlf_cannot_reach_the_wire() {
    const INJECTED: &str = "0x0000000000000001\r\nX-Injected: 1";

    // The credential parser still accepts it — that parity with `re.match` is deliberate.
    let url = crate::daap::url::mkurl(crate::daap::url::LOGIN_CMD, INJECTED, 0, false, true)
        .expect("a prefix match classifies");
    assert!(url.contains("\r\n"), "the URL really does carry the CRLF");

    let error = unreachable_client()
        .encode(&get(&url, &[]))
        .expect_err("a request line cannot carry a CRLF");
    assert!(
        error.to_string().contains("request path contains"),
        "{error}"
    );
}

/// Every byte HTTP forbids in a request target, not just the two that split a request.
#[test]
fn a_request_target_rejects_every_non_visible_byte() {
    let client = unreachable_client();

    for path in [
        "login?x=\r\nX: 1",
        "login?x=\ry",
        "login?x=\ny",
        "login?x=a b",
        "login?x=\0",
        "login?x=\u{7f}",
        "login?x=caf\u{e9}",
    ] {
        assert!(
            client.encode(&get(path, &[])).is_err(),
            "{path:?} should be refused"
        );
    }

    // Everything DAAP actually sends is visible ASCII and must still go through.
    for path in [
        "login?pairing-guid=0x0000000000000001&hasFP=1",
        "ctrl-int/1/playstatusupdate?session-id=55555&revision-number=0",
        "ctrl-int/1/setproperty?dacp.playingtime=45000&session-id=55555",
        "ctrl-int/1/nowplayingartwork?mw=123&mh=456&session-id=55555",
    ] {
        assert!(
            client.encode(&get(path, &[])).is_ok(),
            "{path:?} should be accepted"
        );
    }
}

/// A caller-supplied header is the same hole one field further down.
#[test]
fn a_header_cannot_split_the_request_either() {
    let client = unreachable_client();

    for (name, value) in [
        ("User-Agent", "Remote/1021\r\nX-Injected: 1"),
        ("User-Agent", "Remote/1021\r"),
        ("User-Agent", "Remote/1021\n"),
        ("User-Agent", "Remote\u{0}1021"),
        ("User-Agent\r\nX-Injected: 1", "Remote/1021"),
        ("User Agent", "Remote/1021"),
        ("User:Agent", "Remote/1021"),
        ("", "Remote/1021"),
    ] {
        assert!(
            client.encode(&get("login", &[(name, value)])).is_err(),
            "{name:?}: {value:?} should be refused"
        );
    }

    // The seven real DAAP headers must all still be encodable.
    let headers = crate::daap::DMAP_HEADERS;
    assert!(client.encode(&get("login", &headers)).is_ok());
}

// ---- Body cap ----

/// A device — or anything answering on its address — must not be able to name a body size that
/// this client will try to hold in memory.
#[tokio::test]
async fn a_content_length_over_the_cap_is_refused_before_any_body_is_read() {
    let declared = super::MAX_BODY_LEN + 1;
    let (client, _server) =
        serve_once(format!("HTTP/1.1 200 OK\r\nContent-Length: {declared}\r\n\r\n").into_bytes())
            .await;

    let error = client
        .send(&get("whatever", &[]))
        .await
        .expect_err("an oversized body must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
}

/// The same cap on a body that never declares a length at all.
#[tokio::test]
async fn a_body_delimited_by_eof_is_capped_too() {
    let mut reply = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
    reply.resize(reply.len() + super::MAX_BODY_LEN + 1024, b'x');

    let (client, _server) = serve_once(reply).await;
    let error = client
        .send(&get("whatever", &[]))
        .await
        .expect_err("an unbounded body must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
}

/// A chunked body reassembled across several reads, with the split landing inside a chunk rather
/// than on a boundary — the case a decoder that restarts from byte zero gets right by accident and
/// an incremental one has to get right on purpose.
#[tokio::test]
async fn a_chunked_body_split_mid_chunk_across_reads_is_reassembled() {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback bind");
    let address = listener.local_addr().expect("bound");

    let _server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("one connection");
        let mut discard = [0u8; 4096];
        let _ = stream.read(&mut discard).await;

        // Three writes, each cutting a chunk in half.
        for piece in [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chun".as_slice(),
            b"ked\r\n\r\n4\r\nWi".as_slice(),
            b"ki\r\n5\r\npe".as_slice(),
            b"dia\r\n0\r\n\r\n".as_slice(),
        ] {
            stream.write_all(piece).await.expect("write");
            stream.flush().await.expect("flush");
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        stream.shutdown().await.expect("shutdown");
    });

    let response = HttpClient::new(address)
        .send(&get("whatever", &[]))
        .await
        .expect("succeeds");
    assert_eq!(response.body, b"Wikipedia");
}

// ---- Chunked framing caps ----

/// Serve a chunked response head, then `prologue`, then `piece` over and over in small writes, until
/// the client gives up or `limit` bytes of `piece` have gone out.
///
/// Small writes on purpose: the client reassembles this one `read_more` at a time, exactly as it
/// does off a real socket, so what ends the loop is a cap and nothing else. `limit` is a backstop
/// that keeps a regression to a failed assertion rather than a hung test run — with the cap removed
/// the client reads until the server stops and then reports a *closed connection*, which is a
/// different error and fails the assertion on the message. Keep it a small multiple of the cap under
/// test: an uncapped decoder re-scans the whole incomplete region on every read, so a generous
/// backstop turns a regression into a quadratic crawl rather than a quick failure.
async fn serve_endless_chunked(prologue: Vec<u8>, piece: Vec<u8>, limit: usize) -> HttpClient {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("loopback bind");
    let address = listener.local_addr().expect("bound");

    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("one connection");
        let mut discard = [0u8; 4096];
        let _ = stream.read(&mut discard).await;

        let head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        if stream.write_all(head).await.is_err() || stream.write_all(&prologue).await.is_err() {
            return;
        }

        let mut sent = 0usize;
        while sent < limit {
            // A write failing means the client hung up, which is the outcome under test.
            if stream.write_all(&piece).await.is_err() {
                return;
            }
            sent += piece.len();
        }
        let _ = stream.shutdown().await;
    });

    HttpClient::new(address)
}

/// A chunk-size line that never gets its `CRLF` is an unbounded read: `MAX_BODY_LEN` bounds *decoded
/// chunk data*, and this input produces none of it, so nothing else stops the read buffer growing.
#[tokio::test]
async fn a_chunk_size_line_that_never_ends_does_not_grow_the_read_buffer_forever() {
    // Hex digits, so the line stays a plausible chunk size right up until it is refused.
    let client = serve_endless_chunked(
        Vec::new(),
        b"aaaaaaaaaaaaaaaa".to_vec(),
        16 * response::MAX_CHUNK_LINE_LEN,
    )
    .await;

    let error = client
        .send(&get("whatever", &[]))
        .await
        .expect_err("an unterminated chunk size line must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
    assert!(error.to_string().contains("chunk size line"), "{error}");
}

/// The same hole one step further on: the terminating `0\r\n` chunk arrives and is then followed by
/// trailer lines forever, so the blank line that would end the trailer section never comes.
#[tokio::test]
async fn a_trailer_section_that_never_ends_does_not_grow_the_read_buffer_forever() {
    // No two consecutive CRLFs ever appear after the terminator.
    let client = serve_endless_chunked(
        b"4\r\nWiki\r\n0\r\n".to_vec(),
        b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaa\r\n".to_vec(),
        16 * response::MAX_TRAILER_LEN,
    )
    .await;

    let error = client
        .send(&get("whatever", &[]))
        .await
        .expect_err("an endless trailer section must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
    assert!(error.to_string().contains("trailer"), "{error}");
}

/// Framing alone, spread over well-formed chunks, is enough to outrun `MAX_BODY_LEN`: one-byte
/// chunks cost six raw bytes each, so eight mebibytes of decoded body would need forty-eight of
/// buffer. `MAX_CHUNKED_RAW_LEN` is what bounds that, and it is checked here on a body whose decoded
/// size never comes close to its own cap.
#[tokio::test]
async fn chunk_framing_alone_cannot_outgrow_the_raw_cap() {
    // Written a block at a time rather than a chunk at a time: nine mebibytes in six-byte writes
    // would be a million syscalls, and what this test is about is the total, not the split.
    let block = b"1\r\nx\r\n".repeat(8 * 1024);
    let client = serve_endless_chunked(Vec::new(), block, 2 * super::MAX_CHUNKED_RAW_LEN).await;

    let error = client
        .send(&get("whatever", &[]))
        .await
        .expect_err("a chunked body over the raw cap must be refused");
    assert!(error.to_string().contains("exceeds"), "{error}");
    assert!(error.to_string().contains("chunked response"), "{error}");
}
