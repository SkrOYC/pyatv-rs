//! The `_do` retry/re-login state machine, driven by a scripted server.
//!
//! Each test hands the server a list of canned replies, one per connection — the client opens one
//! connection per request — and then asserts both the outcome and the exact sequence of request
//! lines that produced it. That sequence is the state machine.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::DaapRequester;
use crate::tags::{container_tag, uint32_tag};
use crate::{Error, parser};

const PAIRING_GUID: &str = "0x0000000000000001";
const SESSION_ID: u64 = 55_555;

/// A response with a body and a status.
fn reply(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} Whatever\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

/// A successful login handing back `session`.
fn login_ok(session: u32) -> Vec<u8> {
    reply(200, &container_tag("mlog", &uint32_tag("mlid", session)))
}

/// Serve `replies` in order, one per connection, recording each request's first line.
fn scripted(replies: Vec<Vec<u8>>) -> (DaapRequester, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("bound");
    let listener = TcpListener::from_std(listener).expect("into tokio");

    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&requests);

    tokio::spawn(async move {
        for reply in replies {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            let text = String::from_utf8_lossy(&buffer[..read]).into_owned();
            let line = text.lines().next().unwrap_or_default().to_owned();
            recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(line);

            let _ = stream.write_all(&reply).await;
            let _ = stream.shutdown().await;
        }
    });

    (DaapRequester::new(address, PAIRING_GUID), requests)
}

fn recorded(requests: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// `_assure_logged_in` (`daap.py:172-176`): the first command logs in before it is sent.
#[tokio::test]
async fn the_first_command_logs_in_first() {
    let (requester, requests) = scripted(vec![login_ok(55_555), reply(200, b"")]);

    requester
        .get("ctrl-int/1/playstatusupdate?[AUTH]&revision-number=0")
        .await
        .expect("succeeds");

    assert_eq!(
        recorded(&requests),
        vec![
            "GET /login?pairing-guid=0x0000000000000001&hasFP=1 HTTP/1.1".to_owned(),
            "GET /ctrl-int/1/playstatusupdate?session-id=55555&revision-number=0 HTTP/1.1"
                .to_owned(),
        ]
    );
    assert_eq!(requester.session_id(), SESSION_ID);
}

/// A second command reuses the session rather than logging in again.
#[tokio::test]
async fn a_later_command_reuses_the_session() {
    let (requester, requests) = scripted(vec![login_ok(55_555), reply(200, b""), reply(200, b"")]);

    requester.get("a?[AUTH]").await.expect("succeeds");
    requester.get("b?[AUTH]").await.expect("succeeds");

    assert_eq!(recorded(&requests).len(), 3, "one login, two commands");
}

/// `login` parses `mlog.mlid` out of the response (`daap.py:101`).
#[tokio::test]
async fn login_reads_the_session_id_out_of_the_response() {
    let (requester, _) = scripted(vec![login_ok(1_234)]);

    assert_eq!(requester.login().await.expect("succeeds"), 1_234);
    assert_eq!(requester.session_id(), 1_234);
}

/// A login that answers 2xx with no `mlid` leaves nothing to authenticate later requests with.
#[tokio::test]
async fn a_login_without_a_session_id_is_malformed() {
    let (requester, _) = scripted(vec![reply(200, b"")]);

    assert!(matches!(requester.login().await, Err(Error::Malformed(_))));
}

/// Exactly 500 is terminal on the first attempt: no re-login, no retry (`daap.py:139-141`).
#[tokio::test]
async fn an_http_500_is_terminal() {
    let (requester, requests) = scripted(vec![login_ok(55_555), reply(500, b"")]);

    assert!(matches!(
        requester.get("a?[AUTH]").await,
        Err(Error::NotSupported)
    ));
    assert_eq!(
        recorded(&requests).len(),
        2,
        "a 500 must not trigger a re-login or a retry"
    );
}

/// The behaviour pyatv issue #2 is about: a stale session is recovered from transparently.
///
/// `test_relogin_if_session_expired` (`tests/protocols/dmap/test_dmap_functional.py:106-116`)
/// describes exactly this sequence — 403, re-login with a new id, retry the *original* request —
/// and the caller sees only the eventual success.
#[tokio::test]
async fn a_non_2xx_relogs_in_and_retries_once() {
    let (requester, requests) = scripted(vec![
        login_ok(55_555),
        reply(403, b""),
        login_ok(1_234),
        reply(200, b"artwork"),
    ]);

    let body = requester
        .get("ctrl-int/1/nowplayingartwork?mw=0&mh=0&[AUTH]")
        .await
        .expect("the retry succeeds");

    assert_eq!(body, b"artwork");
    assert_eq!(
        recorded(&requests),
        vec![
            "GET /login?pairing-guid=0x0000000000000001&hasFP=1 HTTP/1.1".to_owned(),
            "GET /ctrl-int/1/nowplayingartwork?mw=0&mh=0&session-id=55555 HTTP/1.1".to_owned(),
            "GET /login?pairing-guid=0x0000000000000001&hasFP=1 HTTP/1.1".to_owned(),
            "GET /ctrl-int/1/nowplayingartwork?mw=0&mh=0&session-id=1234 HTTP/1.1".to_owned(),
        ],
        "the retry must carry the *new* session id"
    );
}

/// The retry budget is one, and upstream logs in a second time on the way out because the guard it
/// skips is `is_login`, not `retry` (`daap.py:143-152`).
#[tokio::test]
async fn the_retry_budget_is_exactly_one() {
    let (requester, requests) = scripted(vec![
        login_ok(55_555),
        reply(403, b""),
        login_ok(55_555),
        reply(403, b""),
        login_ok(55_555),
    ]);

    assert!(matches!(
        requester.get("a?[AUTH]").await,
        Err(Error::Authentication(403))
    ));
    assert_eq!(
        recorded(&requests).len(),
        5,
        "login, command, login, command, login"
    );
}

/// `test_connect_failed` (`test_dmap_functional.py:96-102`): the fixture makes login fail *twice*
/// "since the client will retry one time", and only then does the error surface.
#[tokio::test]
async fn a_failing_login_is_retried_exactly_once() {
    let (requester, requests) = scripted(vec![reply(503, b""), reply(503, b"")]);

    assert!(matches!(
        requester.login().await,
        Err(Error::Authentication(503))
    ));
    assert_eq!(
        recorded(&requests).len(),
        2,
        "a login retries itself, it does not recurse into a second login"
    );
}

/// A login that fails once and succeeds on the retry is not an error at all.
#[tokio::test]
async fn a_login_that_succeeds_on_the_retry_succeeds() {
    let (requester, requests) = scripted(vec![reply(503, b""), login_ok(9)]);

    assert_eq!(requester.login().await.expect("the retry succeeds"), 9);
    assert_eq!(recorded(&requests).len(), 2);
}

/// A 500 on the login is `NotSupportedError` too — the branch is checked before `is_login`.
#[tokio::test]
async fn an_http_500_on_login_is_also_terminal() {
    let (requester, requests) = scripted(vec![reply(500, b""), login_ok(1)]);

    assert!(matches!(requester.login().await, Err(Error::NotSupported)));
    assert_eq!(recorded(&requests).len(), 1);
}

/// The credential is only inspected when it is about to be sent (`daap.py:154-170`), so a bad one
/// fails on first use rather than at construction.
#[tokio::test]
async fn an_unusable_credential_fails_at_login() {
    let (_unused, _) = scripted(Vec::new());
    let requester = DaapRequester::new(
        "127.0.0.1:1".parse().expect("valid address"),
        "not-a-credential",
    );

    assert!(matches!(
        requester.login().await,
        Err(Error::InvalidCredentials(_))
    ));
    assert!(matches!(
        requester.get("a?[AUTH]").await,
        Err(Error::InvalidCredentials(_))
    ));
}

/// A `POST` sends its body and the extra `Content-Type` (`daap.py:123-125`).
#[tokio::test]
async fn a_post_carries_the_command_body() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("bound");
    let listener = TcpListener::from_std(listener).expect("into tokio");

    let captured = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&captured);
    tokio::spawn(async move {
        for reply_bytes in [login_ok(55_555), reply(200, b"")] {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(buffer[..read].to_vec());
            let _ = stream.write_all(&reply_bytes).await;
            let _ = stream.shutdown().await;
        }
    });

    let requester = DaapRequester::new(address, PAIRING_GUID);
    let body = crate::tags::string_tag("cmbe", "select");
    requester
        .post(
            "ctrl-int/1/controlpromptentry?[AUTH]&prompt-id=0",
            Some(&body),
        )
        .await
        .expect("succeeds");

    let raw = captured
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .last()
        .cloned()
        .expect("the POST was captured");
    let text = String::from_utf8_lossy(&raw).into_owned();

    assert!(
        text.starts_with(
            "POST /ctrl-int/1/controlpromptentry?session-id=55555&prompt-id=0 HTTP/1.1"
        ),
        "{text}"
    );
    assert!(
        text.contains("Content-Type: application/x-www-form-urlencoded\r\n"),
        "{text}"
    );
    assert!(
        raw.ends_with(&body),
        "the command payload should be the body"
    );
}

/// A DMAP-typed response comes back parsed.
#[tokio::test]
async fn a_daap_get_returns_a_parse_tree() {
    let playstatus = container_tag("cmst", &uint32_tag("caps", 4));
    let (requester, _) = scripted(vec![login_ok(55_555), reply(200, &playstatus)]);

    let parsed = requester
        .get_daap("ctrl-int/1/playstatusupdate?[AUTH]&revision-number=0")
        .await
        .expect("succeeds");

    assert_eq!(parser::first_uint(&parsed, &["cmst", "caps"]), Some(4));
}

/// Every request carries the seven headers `_verify_headers` asserts
/// (`tests/fake_device/dmap.py:302-305`), with `Content-Type` added only on a `POST`.
#[tokio::test]
async fn every_request_carries_the_dmap_header_set() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("loopback bind");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("bound");
    let listener = TcpListener::from_std(listener).expect("into tokio");

    let captured = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&captured);
    tokio::spawn(async move {
        for reply_bytes in [login_ok(55_555), reply(200, b"")] {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buffer = vec![0u8; 8192];
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            recorder
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(String::from_utf8_lossy(&buffer[..read]).into_owned());
            let _ = stream.write_all(&reply_bytes).await;
            let _ = stream.shutdown().await;
        }
    });

    let requester = DaapRequester::new(address, PAIRING_GUID);
    requester.get("a?[AUTH]").await.expect("succeeds");

    for request in captured
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
    {
        for (name, value) in super::DMAP_HEADERS {
            assert!(
                request.contains(&format!("{name}: {value}\r\n")),
                "{request}"
            );
        }
        assert!(
            !request.to_lowercase().contains("content-type"),
            "a GET sends no Content-Type: {request}"
        );
    }
}
