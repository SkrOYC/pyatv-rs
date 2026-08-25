//! A fake DMAP Apple TV on a real TCP socket.
//!
//! Port of `FakeDmapService` (`tests/fake_device/dmap.py:110-329`). Upstream gets its HTTP server
//! from `aiohttp`; there is no equivalent dependency here and a DAAP request is a request line, a
//! handful of headers and at most a `Content-Length` body, so the ~90 lines of server below are
//! written out rather than pulled in.
//!
//! Nothing here shares code with [`crate::http`]: the fixture parses requests and formats responses
//! itself, so a framing bug in the client cannot be cancelled out by the same bug in the device.
//! The DMAP *body* codec is shared with [`crate::tags`] and [`crate::parser`], exactly as upstream
//! shares `tags`/`parser` with its own fixture — those have known-answer tests of their own
//! (`crate::parser::tests`), which is what makes the sharing safe.

pub mod http;

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

use self::http::{Request, read_request, response as http_response};
use super::fake_state::{FakeDmapState, FakeDmapUseCases};
use crate::parser;
use crate::tags::{container_tag, string_tag, uint8_tag, uint32_tag};

/// The headers every DAAP request must carry (`dmap.py:17-25`).
///
/// The same list as [`crate::daap::DMAP_HEADERS`], repeated rather than imported: this is the
/// device's independent statement of what it expects, and importing the client's constant would
/// make the assertion vacuous.
pub const EXPECTED_HEADERS: [(&str, &str); 7] = [
    ("Accept", "*/*"),
    ("Accept-Encoding", "gzip"),
    ("Client-DAAP-Version", "3.13"),
    ("Client-ATV-Sharing-Version", "1.2"),
    ("Client-iTunes-Sharing-Version", "3.15"),
    ("User-Agent", "Remote/1021"),
    ("Viewer-Only-Client", "1"),
];

/// The playback buttons that are their own endpoint (`dmap.py:127-139`).
pub const PLAYBACK_BUTTONS: [&str; 8] = [
    "play",
    "playpause",
    "pause",
    "stop",
    "nextitem",
    "previtem",
    "volumedown",
    "volumeup",
];

/// A running fake device. Dropping it stops the accept loop.
#[derive(Debug)]
pub struct FakeDmapDevice {
    address: SocketAddr,
    state: Arc<Mutex<FakeDmapState>>,
    task: JoinHandle<()>,
}

impl Drop for FakeDmapDevice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeDmapDevice {
    /// Bind an ephemeral loopback port and start serving, with default state.
    pub async fn start() -> Self {
        Self::start_with(FakeDmapState::default()).await
    }

    /// Bind an ephemeral loopback port and start serving the supplied state.
    pub async fn start_with(state: FakeDmapState) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let address = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let state = Arc::new(Mutex::new(state));
        let served = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&served);
                // One task per connection. The client opens a new one per request and
                // `playstatusupdate` can legitimately hold one for a long time, so serving them
                // sequentially would deadlock any test that polls while pressing a button.
                tokio::spawn(async move {
                    if let Err(error) = serve_connection(stream, &state).await {
                        tracing::debug!(%error, "fake DMAP connection ended");
                    }
                });
            }
        });

        Self {
            address,
            state,
            task,
        }
    }

    /// Where the client should be pointed.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The port the client should be pointed at.
    pub fn port(&self) -> u16 {
        self.address.port()
    }

    /// A handle for altering behaviour and inspecting what the client did.
    pub fn use_cases(&self) -> FakeDmapUseCases {
        FakeDmapUseCases::new(Arc::clone(&self.state))
    }
}

/// Read one request, answer it, close. `Ok(())` even for a request the device refused.
async fn serve_connection(mut stream: TcpStream, state: &Mutex<FakeDmapState>) -> io::Result<()> {
    let Some(request) = read_request(&mut stream).await? else {
        return Ok(());
    };

    let response = {
        let mut state = state.lock().unwrap_or_else(PoisonError::into_inner);
        route(&request, &mut state)
    };

    match response {
        // `force_close`: hang up without answering (`dmap.py:219-220`).
        None => Ok(()),
        Some(bytes) => {
            stream.write_all(&bytes).await?;
            stream.shutdown().await
        }
    }
}

/// Dispatch one request. `None` asks the caller to drop the connection without answering.
fn route(request: &Request, state: &mut FakeDmapState) -> Option<Vec<u8>> {
    state.requests.push(request.target.clone());
    verify_headers(request, state);

    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/login") => Some(handle_login(request, state)),
        ("GET", "/ctrl-int/1/playstatusupdate") => handle_playstatus(request, state),
        ("GET", "/ctrl-int/1/nowplayingartwork") => Some(handle_artwork(request, state)),
        ("POST", "/ctrl-int/1/controlpromptentry") => Some(handle_remote_button(request, state)),
        ("POST", "/ctrl-int/1/setproperty") => Some(handle_set_property(request, state)),
        ("POST", path) if is_playback_button(path) => Some(handle_playback_button(request, state)),
        _ => Some(http_response(404, &[])),
    }
}

fn is_playback_button(path: &str) -> bool {
    path.strip_prefix("/ctrl-int/1/")
        .is_some_and(|button| PLAYBACK_BUTTONS.contains(&button))
}

/// `handle_login` (`dmap.py:153-161`).
fn handle_login(request: &Request, state: &mut FakeDmapState) -> Vec<u8> {
    verify_login_id(request, state);

    let (session, status) = state.login_response;
    // Upstream records the session even on a failed login; harmless, because a client that saw a
    // non-200 never sends it.
    state.session = Some(session);

    let body = container_tag("mlog", &uint32_tag("mlid", session));
    http_response(status, &body)
}

/// `handle_playstatus` (`dmap.py:211-278`).
fn handle_playstatus(request: &Request, state: &mut FakeDmapState) -> Option<Vec<u8>> {
    if let Some(denied) = verify_session(request, state) {
        return Some(denied);
    }

    if state.playing.force_close {
        return None;
    }

    let Some(revision) = request.number("revision-number") else {
        state
            .protocol_errors
            .push("playstatusupdate without a revision-number".to_owned());
        return Some(http_response(500, &[]));
    };
    if i64::from(state.playing.revision) != revision {
        // Not what a real device answers; upstream returns 500 purely so the client notices
        // (`dmap.py:224-226`), and `test_reset_revision_if_push_updates_fail` depends on it.
        return Some(http_response(500, &[]));
    }

    let playing = &state.playing;
    let mut body = Vec::new();
    if let Some(playstatus) = playing.play_state() {
        body.extend(uint32_tag("caps", playstatus));
    }
    for (key, value) in [
        ("cann", &playing.title),
        ("cana", &playing.artist),
        ("canl", &playing.album),
        ("cang", &playing.genre),
    ] {
        if let Some(value) = value {
            body.extend(string_tag(key, value));
        }
    }

    if let Some(total_time) = playing.total_time {
        body.extend(uint32_tag("cast", total_time.saturating_mul(1000)));
        if let Some(position) = playing.position {
            // `cant` is the time *remaining*, which is what makes the client's subtraction
            // observable (`dmap.py:260-262`).
            let remaining = total_time.saturating_sub(position);
            body.extend(uint32_tag("cant", remaining.saturating_mul(1000)));
        }
    }

    if let Some(media_kind) = playing.media_kind {
        body.extend(uint32_tag("cmmk", media_kind));
    }
    if let Some(repeat) = playing.repeat {
        body.extend(uint8_tag("carp", repeat as u8));
    }
    if let Some(shuffle) = playing.shuffle {
        body.extend(uint8_tag("cash", shuffle as u8));
    }
    if let Some(controls) = state.volume_controls {
        body.extend(uint8_tag("cavc", u8::from(controls)));
    }
    body.extend(uint32_tag("cmsr", state.playing.revision.saturating_add(1)));

    Some(http_response(200, &container_tag("cmst", &body)))
}

/// `handle_artwork` (`dmap.py:197-209`).
fn handle_artwork(request: &Request, state: &mut FakeDmapState) -> Vec<u8> {
    if let Some(denied) = verify_session(request, state) {
        return denied;
    }

    if let Some(height) = request.number("mh") {
        state.last_artwork_height = u32::try_from(height).ok();
    }
    if let Some(width) = request.number("mw") {
        state.last_artwork_width = u32::try_from(width).ok();
    }

    // Upstream passes `artwork_status` straight to `web.Response(status=...)`, which means its
    // fixture can only serve artwork after a use case has set both fields. Defaulting to an empty
    // 200 is what a device with no artwork actually answers, and it is what
    // `Metadata::artwork` must map to `None`.
    let status = state.playing.artwork_status.unwrap_or(200);
    let body = state.playing.artwork.clone().unwrap_or_default();
    http_response(status, &body)
}

/// `handle_playback_button` (`dmap.py:163-169`).
fn handle_playback_button(request: &Request, state: &mut FakeDmapState) -> Vec<u8> {
    if let Some(denied) = verify_session(request, state) {
        return denied;
    }

    state.last_button_pressed = Some(request.last_segment().to_owned());
    state.buttons_press_count = state.buttons_press_count.saturating_add(1);
    http_response(200, &[])
}

/// `handle_remote_button` (`dmap.py:171-195`).
fn handle_remote_button(request: &Request, state: &mut FakeDmapState) -> Vec<u8> {
    if let Some(denied) = verify_session(request, state) {
        return denied;
    }

    let button = parser::parse(&request.body)
        .ok()
        .and_then(|parsed| parser::first_str(&parsed, &["cmbe"]).map(str::to_owned));
    state.last_button_pressed =
        button.map(|value| convert_button(&value, state.buttons_press_count));
    state.buttons_press_count = state.buttons_press_count.saturating_add(1);
    http_response(200, &[])
}

/// `_convert_button` (`dmap.py:181-195`): recognise the last step of a seven-step D-pad drag.
///
/// The count is read *before* this request is added to it, so the match is on the seventh
/// `controlpromptentry` of a gesture — which is what makes the six preceding `touchDown`/`touchMove`
/// steps mandatory rather than decorative.
fn convert_button(value: &str, presses_before: u32) -> String {
    if presses_before == 6 {
        let direction = match value {
            "touchUp&time=6&point=20,250" => Some("up"),
            "touchUp&time=6&point=20,275" => Some("down"),
            "touchUp&time=7&point=50,100" => Some("left"),
            "touchUp&time=7&point=75,100" => Some("right"),
            _ => None,
        };
        if let Some(direction) = direction {
            return direction.to_owned();
        }
    }
    value.to_owned()
}

/// `handle_set_property` (`dmap.py:280-297`).
fn handle_set_property(request: &Request, state: &mut FakeDmapState) -> Vec<u8> {
    if let Some(denied) = verify_session(request, state) {
        return denied;
    }

    let Some((property, value)) = request
        .query
        .iter()
        .find(|(key, _)| key.starts_with("dacp."))
        .cloned()
    else {
        return http_response(500, &[]);
    };
    state.properties_set.push((property.clone(), value.clone()));

    let Ok(number) = value.parse::<i64>() else {
        return http_response(500, &[]);
    };
    match property.as_str() {
        "dacp.playingtime" => {
            state.playing.position = u32::try_from(number / 1000).ok();
        }
        "dacp.shufflestate" => {
            // The device only knows two shuffle states; `Albums` is not one of them
            // (`dmap.py:288-290`), which is why the client maps it to `Songs` on the way out.
            state.playing.shuffle = Some(if number == 1 {
                pyatv_core::consts::ShuffleState::Songs
            } else {
                pyatv_core::consts::ShuffleState::Off
            });
        }
        "dacp.repeatstate" => {
            state.playing.repeat = match number {
                0 => Some(pyatv_core::consts::RepeatState::Off),
                1 => Some(pyatv_core::consts::RepeatState::Track),
                2 => Some(pyatv_core::consts::RepeatState::All),
                _ => return http_response(500, &[]),
            };
        }
        _ => return http_response(500, &[]),
    }

    http_response(200, &[])
}

/// `_verify_headers` (`dmap.py:299-305`), collecting instead of asserting.
fn verify_headers(request: &Request, state: &mut FakeDmapState) {
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
}

/// `_verify_auth_parameters(check_login_id=True)` (`dmap.py:315-324`).
fn verify_login_id(request: &Request, state: &mut FakeDmapState) {
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
fn verify_session(request: &Request, state: &mut FakeDmapState) -> Option<Vec<u8>> {
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
