//! The `/pair` handler, both as pure request/response and over a real socket.

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::{PairingServer, PairingState, Request};
use crate::parser::{first_str, first_uint, parse};

const PAIRING_GUID: &str = "0000000000000001";
const PAIRING_CODE: &str = "690E6FF61E0D7C747654A42AED17047D";
const REMOTE_NAME: &str = "pyatv remote";
const PIN_CODE: u32 = 1234;

fn state() -> Arc<PairingState> {
    Arc::new(PairingState::new(
        PAIRING_GUID.to_owned(),
        REMOTE_NAME.to_owned(),
    ))
}

fn request(query: &str) -> Request {
    Request::parse(&format!("GET /pair?{query} HTTP/1.1")).expect("a GET request line")
}

/// Split a response into its status code and body.
fn split(response: &[u8]) -> (u16, Vec<u8>) {
    let head_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .expect("a complete head")
        + 4;
    let head = String::from_utf8_lossy(&response[..head_end]).into_owned();
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("a status code");
    (status, response[head_end..].to_vec())
}

#[test]
fn a_request_line_parses_into_a_path_and_query() {
    let parsed = request("pairingcode=abc&servicename=test");

    assert_eq!(parsed.path, "/pair");
    assert_eq!(parsed.query("pairingcode"), Some("abc"));
    assert_eq!(parsed.query("servicename"), Some("test"));
    assert!(parsed.query("nope").is_none());
}

/// Upstream registers one route and one method (`web.get("/pair", ...)`, `pairing.py:232`).
#[test]
fn only_get_is_routed() {
    assert!(Request::parse("POST /pair?pairingcode=x HTTP/1.1").is_none());
    assert!(Request::parse("nonsense").is_none());
    assert!(Request::parse("GET /pair HTTP/1.1").is_some());
}

/// `test_succesful_pairing` (`tests/protocols/dmap/test_dmap_pairing.py:435-450`): the reply is a
/// `cmpa` container carrying the GUID as a *number*, this client's name, and the literal `iPhone`.
#[test]
fn a_matching_code_is_answered_with_the_pairing_container() {
    let state = state();
    state.set_pin(PIN_CODE);

    let (status, body) = split(&state.respond(&request(&format!(
        "pairingcode={PAIRING_CODE}&servicename=test"
    ))));

    assert_eq!(status, 200);
    let parsed = parse(&body).expect("a DMAP body");
    assert_eq!(first_uint(&parsed, &["cmpa", "cmpg"]), Some(1));
    assert_eq!(first_str(&parsed, &["cmpa", "cmnm"]), Some(REMOTE_NAME));
    assert_eq!(first_str(&parsed, &["cmpa", "cmty"]), Some("iPhone"));
    assert!(state.has_paired());
}

/// `test_pair_custom_pairing_guid` (`test_dmap_pairing.py:485-500`): `cmpg` is the whole GUID as an
/// integer, not the low byte and not the hex string.
#[test]
fn the_guid_is_returned_as_a_sixty_four_bit_number() {
    let state = Arc::new(PairingState::new(
        "1234ABCDE56789FF".to_owned(),
        REMOTE_NAME.to_owned(),
    ));
    state.set_pin(5555);

    let (status, body) = split(&state.respond(&request(
        "pairingcode=58AD1D195B6DAA58AA2EA29DC25B81C3&servicename=test",
    )));

    assert_eq!(status, 200);
    let parsed = parse(&body).expect("a DMAP body");
    assert_eq!(
        first_uint(&parsed, &["cmpa", "cmpg"]),
        Some(0x1234_ABCD_E567_89FF)
    );
}

/// `test_failed_pairing` (`test_dmap_pairing.py:503-509`): a bare 500 with no container at all.
#[test]
fn a_wrong_code_is_a_bodyless_500() {
    let state = state();
    state.set_pin(PIN_CODE);

    let (status, body) = split(&state.respond(&request("pairingcode=wrong&servicename=test")));

    assert_eq!(status, 500);
    assert!(body.is_empty(), "there must be no cmpa container");
    assert!(!state.has_paired());
}

/// `test_succesful_pairing_with_any_pin` (`test_dmap_pairing.py:467-473`).
#[test]
fn any_code_is_accepted_before_a_pin_is_set() {
    let state = state();

    let (status, body) = split(&state.respond(&request(
        "pairingcode=invalid_pairing_code&servicename=test",
    )));

    assert_eq!(status, 200);
    assert!(!body.is_empty());
    assert!(state.has_paired());
}

/// `test_succesful_pairing_with_pin_leadering_zeros` (`test_dmap_pairing.py:476-482`).
#[test]
fn a_pin_with_leading_zeros_pairs() {
    let state = Arc::new(PairingState::new(
        "7D1324235F535AE7".to_owned(),
        REMOTE_NAME.to_owned(),
    ));
    state.set_pin(1);

    let (status, _) = split(&state.respond(&request(
        "pairingcode=A34C3361C7D57D61CA41F62A8042F069&servicename=test",
    )));

    assert_eq!(status, 200);
}

/// Both query parameters are indexed unconditionally upstream, so a missing one is a 500.
#[test]
fn a_request_missing_a_parameter_is_a_500() {
    let state = state();
    state.set_pin(PIN_CODE);

    for query in [
        format!("pairingcode={PAIRING_CODE}"),
        "servicename=test".to_owned(),
        String::new(),
    ] {
        let (status, _) = split(&state.respond(&request(&query)));
        assert_eq!(status, 500, "{query:?}");
        assert!(!state.has_paired());
    }
}

/// `servicename` is logged and otherwise ignored — not matched against the published instance.
#[test]
fn the_service_name_is_not_validated() {
    let state = state();
    state.set_pin(PIN_CODE);

    let (status, _) = split(&state.respond(&request(&format!(
        "pairingcode={PAIRING_CODE}&servicename=something-entirely-unrelated"
    ))));

    assert_eq!(status, 200);
}

/// Any other path is not this server's business.
#[test]
fn another_path_is_a_404() {
    let state = state();
    let parsed = Request::parse("GET /login?x=1 HTTP/1.1").expect("a GET request line");

    let (status, _) = split(&state.respond(&parsed));
    assert_eq!(status, 404);
}

/// End to end over a socket, which is what the Apple TV actually does.
#[tokio::test]
async fn the_server_answers_a_real_request() {
    let state = state();
    state.set_pin(PIN_CODE);
    let server = PairingServer::bind(Arc::clone(&state))
        .await
        .expect("binds an ephemeral port");

    let mut stream = TcpStream::connect(("127.0.0.1", server.port()))
        .await
        .expect("connects");
    stream
        .write_all(
            format!(
                "GET /pair?pairingcode={PAIRING_CODE}&servicename=test HTTP/1.1\r\n\
                 Host: 127.0.0.1\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("writes");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("reads");

    let (status, body) = split(&response);
    assert_eq!(status, 200);
    let parsed = parse(&body).expect("a DMAP body");
    assert_eq!(first_uint(&parsed, &["cmpa", "cmpg"]), Some(1));
    assert!(state.has_paired());
}

/// A second request on a new connection is served too: the accept loop keeps running.
#[tokio::test]
async fn the_server_serves_more_than_one_connection() {
    let state = state();
    let server = PairingServer::bind(Arc::clone(&state))
        .await
        .expect("binds");

    for _ in 0..2 {
        let mut stream = TcpStream::connect(("127.0.0.1", server.port()))
            .await
            .expect("connects");
        stream
            .write_all(b"GET /pair?pairingcode=x&servicename=t HTTP/1.1\r\n\r\n")
            .await
            .expect("writes");

        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.expect("reads");
        assert_eq!(split(&response).0, 200);
    }
}

/// Garbage on the socket gets an answer rather than hanging the accept loop.
#[tokio::test]
async fn a_junk_request_is_answered_and_closed() {
    let state = state();
    let server = PairingServer::bind(state).await.expect("binds");

    let mut stream = TcpStream::connect(("127.0.0.1", server.port()))
        .await
        .expect("connects");
    stream
        .write_all(b"this is not http\r\n\r\n")
        .await
        .expect("writes");

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.expect("reads");
    assert_eq!(split(&response).0, 404);
}
