//! Request parsing and routing for the fake RAOP receiver.
//!
//! The route table is `FakeRaopService.__init__`'s (`tests/fake_device/raop.py:357-365`), with the
//! AirPlay 2 additions this fixture needs on top: `/pair-setup`, `/pair-verify`, and the two
//! property-list shapes of `SETUP`.

use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::{Tlv8, TlvValue};
use tokio::sync::Mutex;

use super::udp::{self, UdpCapture};
use super::{FakeRaopOptions, FakeRaopState, RaopVersion, Session, control_keys};
use crate::rtsp::digest::digest_response;

/// The realm the digest challenge names (`REALM = "raop"`, `raop.py:35`).
pub const REALM: &str = "raop";

/// The nonce the challenge carries. Fixed rather than random, so a test can predict the response.
pub const NONCE: &str = "0123456789abcdef0123456789abcdef";

const BPLIST: &str = "application/x-apple-binary-plist";
const TLV8: &str = "application/octet-stream";

/// One parsed request.
#[derive(Debug)]
pub struct FakeRequest {
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FakeRequest {
    /// Case-insensitive header lookup, matching upstream's `CaseInsensitiveDict`.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One response to send.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub reason: String,
    pub cseq: String,
    pub content_type: Option<&'static str>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    fn new(status: u16, reason: &str, cseq: &str) -> Self {
        Self {
            status,
            reason: reason.to_owned(),
            cseq: cseq.to_owned(),
            content_type: None,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn ok(cseq: &str) -> Self {
        Self::new(200, "OK", cseq)
    }

    fn with_body(mut self, content_type: &'static str, body: Vec<u8>) -> Self {
        self.content_type = Some(content_type);
        self.body = body;
        self
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// Parse one `Content-Length`-framed request off the front of `input`.
pub fn parse_request(input: &[u8]) -> Option<(FakeRequest, usize)> {
    let boundary = input.windows(4).position(|window| window == b"\r\n\r\n")?;
    let body_start = boundary + 4;

    let header_block = std::str::from_utf8(&input[..boundary]).ok()?;
    let mut lines = header_block.split("\r\n");
    let start_line = lines.next()?;
    let mut parts = start_line.split(' ');
    let method = parts.next()?.to_owned();
    let path = parts.next()?.to_owned();
    let protocol = parts.next().unwrap_or("HTTP/1.1").to_owned();

    let headers: Vec<(String, String)> = lines
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect();

    let length: usize = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("Content-Length"))
        .map_or(Ok(0), |(_, value)| value.parse())
        .ok()?;

    let body = input.get(body_start..body_start + length)?.to_vec();

    Some((
        FakeRequest {
            method,
            path,
            protocol,
            headers,
            body,
        },
        body_start + length,
    ))
}

/// Serialise a reply, echoing the request's protocol token as a real receiver does.
pub fn encode_response(reply: &Reply, protocol: &str) -> Vec<u8> {
    let mut head = format!(
        "{protocol} {} {}\r\nServer: pyatv-rs-fake-raop/1.0\r\nCSeq: {}\r\n",
        reply.status, reply.reason, reply.cseq
    );
    for (name, value) in &reply.headers {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    if let Some(content_type) = reply.content_type {
        let _ = write!(head, "Content-Type: {content_type}\r\n");
    }
    if !reply.body.is_empty() {
        let _ = write!(head, "Content-Length: {}\r\n", reply.body.len());
    }
    head.push_str("\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(&reply.body);
    out
}

/// Route one request.
#[allow(
    clippy::too_many_arguments,
    reason = "a route table needs the request, the receiver's state, its options, the connection's \
              own state, the pairing accessory and the peer address; bundling them into a context \
              struct would only move the same six fields"
)]
pub async fn handle(
    request: &FakeRequest,
    state: &Arc<FakeRaopState>,
    options: &FakeRaopOptions,
    session: &mut Session,
    accessory: &Arc<Mutex<ReferenceAccessory>>,
    peer: Option<IpAddr>,
) -> (Reply, Option<SessionKeys>) {
    let cseq = request.header("CSeq").unwrap_or("1").to_owned();

    // `/auth-setup` and the pairing routes are reachable before authentication; everything else
    // is gated (`requires_auth`, `raop.py:66-78`).
    // `/info` is deliberately outside the gate: upstream's `handle_info` is the one route with no
    // `@verify_password` or `@requires_auth` decorator (`raop.py:538`), and it has to be, because
    // `StreamClient.initialize` reads it *before* the `ANNOUNCE` that answers the challenge.
    let gated = !matches!(
        request.path.as_str(),
        "/info" | "/auth-setup" | "/pair-setup" | "/pair-verify" | "/pair-pin-start"
    );
    if gated && options.require_auth_setup && !session.auth_setup_done {
        return (Reply::new(403, "Forbidden", &cseq), None);
    }
    if let Some(authorization) = request.header("Authorization") {
        *state.authorization.lock().await = Some(authorization.to_owned());
    }
    if gated && let Some(reply) = password_check(request, options, session, &cseq) {
        return (reply, None);
    }

    match (request.method.as_str(), request.path.as_str()) {
        (_, "/pair-pin-start") => (Reply::ok(&cseq), None),
        (_, "/pair-setup") => {
            let outcome = accessory.lock().await.handle_pair_setup(&request.body);
            match outcome {
                Ok(tlv) => (Reply::ok(&cseq).with_body(TLV8, tlv), None),
                Err(error) => (Reply::new(500, &error.to_string(), &cseq), None),
            }
        }
        (_, "/pair-verify") => {
            let outcome = accessory.lock().await.handle_pair_verify(&request.body);
            match outcome {
                Ok(tlv) => {
                    let keys = if sequence_number(&request.body) == Some(3) {
                        control_keys(accessory).await
                    } else {
                        None
                    };
                    (Reply::ok(&cseq).with_body(TLV8, tlv), keys)
                }
                Err(error) => (Reply::new(500, &error.to_string(), &cseq), None),
            }
        }
        ("POST", "/auth-setup") => {
            // "Just check if decent sized payload is there" (`raop.py:524-531`).
            if request.body.len() == 1 + 32 {
                session.auth_setup_done = true;
                state.auth_setups.fetch_add(1, Ordering::SeqCst);
                (Reply::ok(&cseq), None)
            } else {
                (Reply::new(403, "Forbidden", &cseq), None)
            }
        }
        ("GET", "/info") => (info(options, &cseq), None),
        ("POST", "/feedback") => {
            state.feedbacks.fetch_add(1, Ordering::SeqCst);
            if options.refuse_feedback {
                (Reply::new(501, "Not implemented", &cseq), None)
            } else {
                (Reply::ok(&cseq), None)
            }
        }
        ("ANNOUNCE", _) => {
            state.announces.fetch_add(1, Ordering::SeqCst);
            *state.sdp.lock().await = String::from_utf8(request.body.clone()).ok();
            (Reply::ok(&cseq), None)
        }
        ("SETUP", _) => {
            state.setups.fetch_add(1, Ordering::SeqCst);
            (
                setup(request, state, options, session, peer, &cseq).await,
                None,
            )
        }
        ("RECORD", _) => {
            state.records.fetch_add(1, Ordering::SeqCst);
            (Reply::ok(&cseq), None)
        }
        ("FLUSH", _) => {
            state.flushes.fetch_add(1, Ordering::SeqCst);
            state.streaming_started.store(true, Ordering::SeqCst);
            (Reply::ok(&cseq), None)
        }
        ("TEARDOWN", _) => {
            state.teardowns.fetch_add(1, Ordering::SeqCst);
            (Reply::ok(&cseq), None)
        }
        ("SET_PARAMETER", _) => (set_parameter(request, state, options, &cseq).await, None),
        _ => (Reply::new(404, "File not found", &cseq), None),
    }
}

/// `verify_password` (`raop.py:81-121`): challenge once, then check the response.
fn password_check(
    request: &FakeRequest,
    options: &FakeRaopOptions,
    session: &mut Session,
    cseq: &str,
) -> Option<Reply> {
    let password = options.password.as_deref()?;
    let nonce = session
        .nonce
        .get_or_insert_with(|| NONCE.to_owned())
        .clone();

    // The challenge carries `WWW-Authenticate` every time, not only the first: upstream's fixture
    // omits it on a re-challenge (`raop.py:117-120`) because its own client never re-tries, and a
    // client that did would be told to give up for the wrong reason.
    let challenge = || {
        Some(Reply::new(401, "Unauthorized", cseq).with_header(
            "WWW-Authenticate",
            &format!("Digest realm=\"{REALM}\", nonce=\"{nonce}\""),
        ))
    };

    let Some(authorization) = request.header("Authorization") else {
        return challenge();
    };
    let expected = digest_response(
        &request.method,
        &request.path,
        "pyatv",
        REALM,
        password,
        &nonce,
    );

    if authorization == expected {
        None
    } else {
        challenge()
    }
}

/// `handle_info` (`raop.py:538-560`).
fn info(options: &FakeRaopOptions, cseq: &str) -> Reply {
    if options.refuse_info {
        return Reply::new(400, "Bad Request", cseq);
    }

    let mut info = plist::Dictionary::new();
    if let Some(volume) = options.initial_volume {
        info.insert("initialVolume".to_owned(), volume.into());
    }
    Reply::ok(cseq).with_body(BPLIST, encode(&info))
}

/// `handle_setup` (`raop.py:423-441`), plus the two AirPlay 2 shapes upstream has no equivalent of.
async fn setup(
    request: &FakeRequest,
    state: &Arc<FakeRaopState>,
    options: &FakeRaopOptions,
    session: &mut Session,
    peer: Option<IpAddr>,
    cseq: &str,
) -> Reply {
    if options.version == RaopVersion::V1 {
        let Some(transport) = request.header("Transport") else {
            return Reply::new(400, "Bad Request", cseq);
        };
        // The *client's* header carries `control_port` and `timing_port` but no `server_port` —
        // that one is the receiver's answer, so `transport_ports` (which requires it) is the wrong
        // parser for this direction (`raop.py:429`).
        let (_, options) = crate::raop::protocol_v1::parse_transport(transport);
        let control_port = options
            .get("control_port")
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);

        let (audio, control, timing) = open_sockets(state, None, peer, control_port).await;
        return Reply::ok(cseq)
            .with_header(
                "Transport",
                &format!(
                    "RTP/AVP/UDP;unicast;mode=record;server_port={audio};\
                     control_port={control};timing_port={timing}"
                ),
            )
            .with_header("Session", "1");
    }

    let Ok(body) = plist::from_bytes::<plist::Value>(&request.body) else {
        return Reply::new(400, "Bad Request", cseq);
    };
    let Some(dictionary) = body.as_dictionary() else {
        return Reply::new(400, "Bad Request", cseq);
    };

    let stream = dictionary
        .get("streams")
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary);

    let Some(stream) = stream else {
        // The base `SETUP`: allocate an event port and answer with it.
        *state.base_setup.lock().await = Some(body.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let port = listener
            .local_addr()
            .expect("a bound listener must have an address")
            .port();

        let served = Arc::clone(state);
        tokio::spawn(async move { super::serve_event_channel(listener, served).await });

        let mut reply = plist::Dictionary::new();
        reply.insert("eventPort".to_owned(), u64::from(port).into());
        return Reply::ok(cseq).with_body(BPLIST, encode(&reply));
    };

    *state.audio_setup.lock().await = Some(body.clone());

    let key: Option<[u8; 32]> = stream
        .get("shk")
        .and_then(|value| match value {
            plist::Value::Data(data) => Some(data.clone()),
            _ => None,
        })
        .and_then(|data| <[u8; 32]>::try_from(data.as_slice()).ok());
    session.audio_key = key;

    let control_port = stream
        .get("controlPort")
        .and_then(plist::Value::as_unsigned_integer)
        .and_then(|port| u16::try_from(port).ok())
        .unwrap_or(0);
    let (audio, control, _) = open_sockets(state, key, peer, control_port).await;

    let mut stream_reply = plist::Dictionary::new();
    stream_reply.insert("dataPort".to_owned(), u64::from(audio).into());
    stream_reply.insert("controlPort".to_owned(), u64::from(control).into());
    stream_reply.insert("type".to_owned(), 96u64.into());

    let mut reply = plist::Dictionary::new();
    reply.insert(
        "streams".to_owned(),
        plist::Value::Array(vec![plist::Value::Dictionary(stream_reply)]),
    );
    Reply::ok(cseq).with_body(BPLIST, encode(&reply))
}

/// Bind and start the audio, control and timing sockets, returning their ports.
///
/// `FakeRaopService.start` (`raop.py:368-395`), except that the timing socket is a *client* here:
/// the controller runs the timing server and the receiver polls it, so this end needs the
/// controller's port, which arrives in the `Transport` header on AirPlay 1 and in the base `SETUP`
/// on AirPlay 2. Only the AirPlay 1 path has it in hand at `SETUP` time, so the AirPlay 2 poller is
/// not started; nothing in the port's behaviour depends on it.
async fn open_sockets(
    state: &Arc<FakeRaopState>,
    key: Option<[u8; 32]>,
    peer: Option<IpAddr>,
    control_port: u16,
) -> (u16, u16, u16) {
    let capture: Arc<UdpCapture> = Arc::clone(&state.udp);

    let audio = udp::bind().await;
    let control = udp::bind().await;
    let timing = udp::bind().await;

    let audio_socket = Arc::clone(&audio.socket);
    let audio_capture = Arc::clone(&capture);
    tokio::spawn(async move { udp::serve_audio(audio_socket, audio_capture, key).await });

    let control_socket = Arc::clone(&control.socket);
    let control_capture = Arc::clone(&capture);
    tokio::spawn(async move { udp::serve_control(control_socket, control_capture).await });

    let _ = (peer, control_port);

    (audio.port, control.port, timing.port)
}

/// `handle_set_parameter` (`raop.py:443-485`), plus a `progress:` branch upstream answers `501` to.
async fn set_parameter(
    request: &FakeRequest,
    state: &Arc<FakeRaopState>,
    options: &FakeRaopOptions,
    cseq: &str,
) -> Reply {
    let content_type = request.header("Content-Type").unwrap_or("");

    if content_type == "application/x-dmap-tagged" {
        *state.metadata.lock().await = Some(request.body.clone());
        return Reply::ok(cseq);
    }
    if content_type == "image/jpeg" {
        *state.artwork.lock().await = Some(request.body.clone());
        return Reply::ok(cseq);
    }

    let body = String::from_utf8_lossy(&request.body).into_owned();

    if let Some(value) = body.strip_prefix("volume:") {
        if options.delayed_set_volume && !state.streaming_started.load(Ordering::SeqCst) {
            return Reply::new(500, "Not supported here", cseq);
        }
        if let Ok(level) = value.trim().parse::<f32>() {
            state.volumes.lock().await.push(level);
        }
        return Reply::ok(cseq);
    }

    if let Some(value) = body.strip_prefix("progress:") {
        *state.progress.lock().await = Some(value.trim().to_owned());
        return Reply::ok(cseq);
    }

    Reply::new(501, "Not implemented", cseq)
}

fn encode(dictionary: &plist::Dictionary) -> Vec<u8> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, &plist::Value::Dictionary(dictionary.clone()))
        .expect("encodes");
    out
}

/// Read the `SeqNo` out of a TLV8 body, so M3 can be told from M1.
fn sequence_number(body: &[u8]) -> Option<u8> {
    Tlv8::decode(body)
        .ok()?
        .get(TlvValue::SeqNo)
        .and_then(|value| value.first())
        .copied()
}
