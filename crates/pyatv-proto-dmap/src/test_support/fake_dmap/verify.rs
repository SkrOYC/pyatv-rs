//! What the fixture checks the *client* got right.
//!
//! Ports `_verify_headers` and `_verify_auth_parameters` (`tests/fake_device/dmap.py:299-329`),
//! with one change throughout: upstream asserts inside its request handler, where a failure is an
//! exception in a server coroutine that the test under way never sees. These collect into
//! [`FakeDmapState::protocol_errors`] instead, and a test asserts on that deliberately with
//! [`FakeDmapUseCases::assert_no_protocol_errors`].
//!
//! [`FakeDmapState::protocol_errors`]: crate::test_support::fake_state::FakeDmapState
//! [`FakeDmapUseCases::assert_no_protocol_errors`]:
//!     crate::test_support::fake_state::FakeDmapUseCases::assert_no_protocol_errors

use super::http::{Request, response as http_response};
use super::{EXPECTED_HEADERS, EXPECTED_POST_CONTENT_TYPE};
use crate::test_support::fake_state::FakeDmapState;

/// `_verify_headers` (`dmap.py:299-305`), collecting instead of asserting.
///
/// Stricter than upstream in two ways, both of which pin things that are wire-visible and that
/// upstream's dict-based check cannot see: the seven headers must arrive **in order**, and the
/// `Content-Type` must be present on a `POST` and absent on a `GET`.
pub(super) fn verify_headers(request: &Request, state: &mut FakeDmapState) {
    for (name, expected) in EXPECTED_HEADERS {
        match request.header(name) {
            Some(value) if value == expected => {}
            Some(value) => state.protocol_errors.push(format!(
                "{} {}: header {name} was {value:?}, expected {expected:?}",
                request.method, request.path
            )),
            None => state.protocol_errors.push(format!(
                "{} {}: header {name} is missing",
                request.method, request.path
            )),
        }
    }

    // `_DMAP_HEADERS` is an ordered dict upstream and this client writes it out in that order, so a
    // capture from either implementation should diff clean. Nothing on a device depends on it —
    // HTTP field order is not significant — but a silent reordering here is a silent divergence.
    let arrived: Vec<&str> = request
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| {
            EXPECTED_HEADERS
                .iter()
                .any(|(expected, _)| expected.eq_ignore_ascii_case(name))
        })
        .collect();
    let expected_order: Vec<&str> = EXPECTED_HEADERS.iter().map(|(name, _)| *name).collect();
    if arrived != expected_order {
        state.protocol_errors.push(format!(
            "{} {}: DAAP headers arrived as {arrived:?}, expected {expected_order:?}",
            request.method, request.path
        ));
    }

    match (request.method.as_str(), request.header("Content-Type")) {
        ("POST", Some(value)) if value == EXPECTED_POST_CONTENT_TYPE => {}
        ("POST", Some(value)) => state.protocol_errors.push(format!(
            "POST {}: Content-Type was {value:?}, expected {EXPECTED_POST_CONTENT_TYPE:?}",
            request.path
        )),
        ("POST", None) => state
            .protocol_errors
            .push(format!("POST {}: Content-Type is missing", request.path)),
        // `_DMAP_HEADERS` gains the Content-Type only on the `POST` copy, so a `GET` carrying one
        // means the client mutated the shared header list.
        (method, Some(value)) => state.protocol_errors.push(format!(
            "{method} {}: a request without a body must not carry Content-Type {value:?}",
            request.path
        )),
        (_, None) => {}
    }
}

/// Every `ctrl-int` command POST carries `prompt-id=0` (`__init__.py:63,228-230`).
///
/// `setproperty` is the exception — its template has no `prompt-id` — so this is called from the
/// button handlers rather than from the router.
pub(super) fn verify_prompt_id(request: &Request, state: &mut FakeDmapState) {
    if request.query("prompt-id") != Some("0") {
        state.protocol_errors.push(format!(
            "{} {} was sent with prompt-id={:?}, expected \"0\"",
            request.method,
            request.path,
            request.query("prompt-id")
        ));
    }
}

/// `_verify_auth_parameters(check_login_id=True)` (`dmap.py:315-324`).
pub(super) fn verify_login_id(request: &Request, state: &mut FakeDmapState) {
    let expected_hsgid = state.hsgid.clone();
    let expected_guid = state.pairing_guid.clone();

    match (request.query("hsgid"), request.query("pairing-guid")) {
        (Some(hsgid), _) if hsgid == expected_hsgid => {}
        (Some(hsgid), _) => state
            .protocol_errors
            .push(format!("hsgid {hsgid:?} does not match {expected_hsgid:?}")),
        (None, Some(guid)) if guid == expected_guid => {}
        (None, Some(guid)) => state.protocol_errors.push(format!(
            "pairing-guid {guid:?} does not match {expected_guid:?}"
        )),
        (None, None) => state
            .protocol_errors
            .push("neither hsgid nor pairing-guid was sent".to_owned()),
    }
}

/// `_verify_auth_parameters(check_session=True)` (`dmap.py:326-329`), answering rather than
/// asserting.
///
/// Returns the response to send when the session is wrong, or `None` to carry on. See the module
/// documentation on [`super`] for why this is a 403 and not a panic.
pub(super) fn verify_session(request: &Request, state: &mut FakeDmapState) -> Option<Vec<u8>> {
    match (request.number("session-id"), state.session) {
        (Some(sent), Some(current)) if sent == i64::from(current) => None,
        (Some(_), _) => Some(http_response(403, &[])),
        (None, _) => {
            state.protocol_errors.push(format!(
                "{} {} was sent without a session-id",
                request.method, request.path
            ));
            Some(http_response(403, &[]))
        }
    }
}
