//! Client tests against a one-shot TCP server that answers with canned bytes.

use std::io::Write;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::{HttpClient, HttpRequest, Method};

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
