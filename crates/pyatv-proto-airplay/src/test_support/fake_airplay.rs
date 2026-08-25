//! A hermetic AirPlay 2 receiver, speaking real HAP over real TCP sockets.
//!
//! Port of `tests/fake_device/airplay.py::FakeAirPlayService` and the `AirPlayServerAuth` routes it
//! inherits (`pyatv/protocols/airplay/server_auth.py:150-264`), extended past what upstream has:
//! pyatv's own fake device stops at AirPlay-1-era device auth and `/play`, and **nothing anywhere in
//! its test tree ever answers a remote-control `SETUP`, allocates an `eventPort`/`dataPort`, or
//! frames a `DataHeader`** (`docs/research/airplay-control-mrp-tunnel-port-spec.md` §16.2). This
//! receiver does, so the tunnel has an end-to-end test upstream cannot offer.
//!
//! The crypto is [`pyatv_pairing::server::ReferenceAccessory`], pyatv's `server_auth.py` accessory
//! with its fixed key material; this file adds the HTTP routing and the RTSP verbs on top.
//!
//! Routing rules:
//!
//! | Route | Rule |
//! |---|---|
//! | `/pair-pin-start` | always `200`, empty body (`server_auth.py:153-162`) |
//! | `/pair-setup` | `X-Apple-HKP: 3` or `4` runs pair-setup, anything else is `501` (`server_auth.py:164-178`) |
//! | `/pair-verify` | `X-Apple-HKP: 3` runs pair-verify, anything else is `501` (`server_auth.py:232-242`) |
//! | `SETUP` with `isRemoteControlOnly` | allocates an `eventPort` |
//! | `SETUP` with `streams` | allocates a `dataPort` and derives keys from the body's `seed` |
//! | `RECORD` | counted, `200` |
//! | `POST /feedback` | counted, `200` |
//! | `GET /info` | a small property list |
//! | anything else | `404` (`pyatv/support/http.py:590`) |
//!
//! Everything after pair-verify M4 is HAP-encrypted on this side too, so the tests exercise the
//! real `Control-Salt` derivation and the real 1024-byte framing rather than a plaintext stand-in.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use pyatv_pairing::hkdf_derive::{
    data_stream_salt,
    transport::{AIRPLAY_CONTROL, AIRPLAY_DATA_STREAM, AIRPLAY_EVENTS},
};
use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::session::HapSession;
use pyatv_pairing::{Tlv8, TlvValue};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use super::fake_bridge::serve_data_bridge;
use super::fake_channels::{bind_loopback, serve_data, serve_event};
use super::fake_play::{self, PlayMode, PlayState};

/// Content type every property-list body carries.
const BPLIST: &str = "application/x-apple-binary-plist";

/// Content type every TLV8 body carries.
///
/// pyatv's own fake labels the pair-*setup* TLVs `application/x-apple-binary-plist`
/// (`server_auth.py:201,227`) and only the pair-*verify* ones `application/octet-stream`
/// (`server_auth.py:261`). Real hardware does neither: the tvOS 27 captures in
/// `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` (lines 36-52, 95) show
/// `application/octet-stream` on **both** halves of the handshake, in both directions. This
/// receiver follows the device rather than the fake, because the point of it is to catch a client
/// that has quietly grown a dependency on something only pyatv's test double does.
const TLV8: &str = "application/octet-stream";

/// How the receiver should behave during remote-control setup.
#[derive(Debug, Clone)]
pub struct FakeOptions {
    /// The PIN the device would be showing on screen.
    pub pin: u32,
    /// `skipRecord` in the event-channel `SETUP` reply. `None` omits the key, which is what every
    /// receiver pyatv was written against does.
    pub skip_record: Option<bool>,
    /// `timingPort` in the same reply. The tvOS 27 device omits it.
    pub timing_port: Option<u16>,
    /// A raw request to push at the controller once it dials the event port.
    pub event_probe: Option<Vec<u8>>,
    /// Where to forward the data channel, instead of echoing it back.
    ///
    /// Point this at a hermetic MRP device's TCP address and the receiver becomes a real tunnel
    /// rather than a mirror; see [`super::fake_bridge`].
    pub data_bridge: Option<SocketAddr>,
    /// Which `/play` header set to insist on; see [`super::fake_play`].
    pub play_mode: PlayMode,
    /// Answer every remote-control `SETUP` with `455 Method Not Valid In This State`.
    ///
    /// What a receiver that has no remote-control channel does, and the only way to exercise the
    /// "tunnel bring-up failed" path: everything up to and including pair-verify succeeds, so the
    /// failure lands where a real one would rather than at connect time.
    pub refuse_setup: bool,
}

impl Default for FakeOptions {
    fn default() -> Self {
        Self {
            pin: pyatv_pairing::server::AIRPLAY_PIN,
            skip_record: None,
            timing_port: None,
            event_probe: None,
            data_bridge: None,
            play_mode: PlayMode::default(),
            refuse_setup: false,
        }
    }
}

/// What the receiver observed, for a test to assert on.
#[derive(Debug, Default)]
pub struct FakeState {
    /// How many `RECORD` requests arrived.
    pub records: AtomicUsize,
    /// How many `POST /feedback` requests arrived.
    pub feedbacks: AtomicUsize,
    /// How many `rply` frames the controller sent on the data channel.
    pub replies_seen: AtomicUsize,
    /// Whether the controller dialled the event port.
    pub event_connected: AtomicBool,
    /// Whether the controller dialled the data port.
    pub data_connected: AtomicBool,
    /// The event-channel `SETUP` body, as the receiver decoded it.
    pub event_setup: Mutex<Option<plist::Value>>,
    /// The data-stream `SETUP` body, as the receiver decoded it.
    pub data_setup: Mutex<Option<plist::Value>>,
    /// MRP payloads the controller sent, in order.
    pub mrp_received: Mutex<Vec<Vec<u8>>>,
    /// Raw replies the controller sent on the event channel.
    pub event_replies: Mutex<Vec<String>>,
    /// What the `play_url` routes saw; see [`super::fake_play`].
    pub play: PlayState,
}

/// A running fake receiver. Dropping it stops the accept loop.
#[derive(Debug)]
pub struct FakeAirPlayDevice {
    address: SocketAddr,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    state: Arc<FakeState>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeAirPlayDevice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeAirPlayDevice {
    /// Bind to an ephemeral loopback port and start serving with default behaviour.
    pub async fn start(pin: u32) -> Self {
        Self::start_with(FakeOptions {
            pin,
            ..FakeOptions::default()
        })
        .await
    }

    /// Bind to an ephemeral loopback port and start serving.
    pub async fn start_with(options: FakeOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let address = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let accessory = Arc::new(Mutex::new(ReferenceAccessory::with_pin(options.pin)));
        let state = Arc::new(FakeState::default());

        let served = Arc::clone(&accessory);
        let served_state = Arc::clone(&state);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let accessory = Arc::clone(&served);
                let state = Arc::clone(&served_state);
                let options = options.clone();
                tokio::spawn(async move {
                    serve(stream, accessory, state, options).await;
                });
            }
        });

        Self {
            address,
            accessory,
            state,
            task,
        }
    }

    /// Where a controller should connect.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// The accessory's state, for asserting on what it accepted.
    pub fn accessory(&self) -> Arc<Mutex<ReferenceAccessory>> {
        Arc::clone(&self.accessory)
    }

    /// What the receiver observed.
    pub fn state(&self) -> Arc<FakeState> {
        Arc::clone(&self.state)
    }
}

/// Serve one control connection until the peer goes away.
async fn serve(
    stream: TcpStream,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    state: Arc<FakeState>,
    options: FakeOptions,
) {
    let (mut read_half, mut write_half) = stream.into_split();
    let mut session: Option<HapSession> = None;
    let mut buffer = Vec::new();

    loop {
        let mut chunk = [0u8; 4096];
        let Ok(read) = read_half.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }

        let plaintext = match session.as_mut() {
            Some(session) => match session.decrypt(&chunk[..read]) {
                Ok(plaintext) => plaintext,
                Err(_) => return,
            },
            None => chunk[..read].to_vec(),
        };
        buffer.extend_from_slice(&plaintext);

        while let Some((request, consumed)) = parse_request(&buffer) {
            buffer.drain(..consumed);

            let (response, enable) = handle(&request, &accessory, &state, &options).await;
            // Applied once here rather than threaded through every route, so a route added later
            // gets it for free — and so the rule is stated in one place instead of seventeen.
            let response = echo_protocol(response, &request.protocol);

            let outbound = match session.as_mut() {
                Some(session) => match session.encrypt(&response) {
                    Ok(framed) => framed,
                    Err(_) => return,
                },
                None => response,
            };
            if write_half.write_all(&outbound).await.is_err() {
                return;
            }

            // Encryption starts on the message *after* M4, exactly as `verify_connection` splices
            // it in once the exchange has completed (`auth/__init__.py:104-115`).
            if let Some(keys) = enable {
                session = Some(HapSession::new(&keys.output_key, &keys.input_key));
            }
        }
    }
}

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

/// Parse one request off the front of `input`, `Content-Length`-framed like everything else here.
fn parse_request(input: &[u8]) -> Option<(FakeRequest, usize)> {
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

/// Route one request, returning the wire response and the keys to encrypt with from then on.
async fn handle(
    request: &FakeRequest,
    accessory: &Arc<Mutex<ReferenceAccessory>>,
    state: &Arc<FakeState>,
    options: &FakeOptions,
) -> (Vec<u8>, Option<SessionKeys>) {
    let cseq = request.header("CSeq").unwrap_or("1").to_owned();
    let hkp = request.header("X-Apple-HKP");

    match (request.method.as_str(), request.path.as_str()) {
        (_, "/pair-pin-start") => (response(200, "OK", &cseq, None, &[]), None),
        (_, "/pair-setup") => {
            let body = match hkp {
                // Both HAP and transient run the same handler; the accessory tells them apart from
                // the `Flags` TLV in M1, as `_m1_setup(transient=…)` does upstream.
                Some("3" | "4") => accessory.lock().await.handle_pair_setup(&request.body),
                _ => return (response(501, "Not implemented", &cseq, None, &[]), None),
            };
            match body {
                Ok(tlv) => (response(200, "OK", &cseq, Some(TLV8), &tlv), None),
                Err(error) => (response(500, &error.to_string(), &cseq, None, &[]), None),
            }
        }
        (_, "/pair-verify") => {
            if hkp != Some("3") {
                return (response(501, "Not implemented", &cseq, None, &[]), None);
            }
            let mut accessory = accessory.lock().await;
            match accessory.handle_pair_verify(&request.body) {
                Ok(tlv) => {
                    // The accessory's roles are the mirror of the controller's: its output key is
                    // derived with `Control-Read-…` and its input key with `Control-Write-…`
                    // (`airplay/server_auth.py:296-309`).
                    let keys = (sequence_number(&request.body) == Some(3))
                        .then(|| {
                            accessory
                                .encryption_keys(
                                    AIRPLAY_CONTROL.salt,
                                    AIRPLAY_CONTROL.read_info,
                                    AIRPLAY_CONTROL.write_info,
                                )
                                .ok()
                        })
                        .flatten();
                    (response(200, "OK", &cseq, Some(TLV8), &tlv), keys)
                }
                Err(error) => (response(500, &error.to_string(), &cseq, None, &[]), None),
            }
        }
        ("SETUP", _) => (setup(request, accessory, state, options, &cseq).await, None),
        ("RECORD", _) => {
            state.records.fetch_add(1, Ordering::SeqCst);
            (response(200, "OK", &cseq, None, &[]), None)
        }
        ("POST", "/feedback") => {
            state.feedbacks.fetch_add(1, Ordering::SeqCst);
            (response(200, "OK", &cseq, None, &[]), None)
        }
        ("GET", "/info") => (response(200, "OK", &cseq, Some(BPLIST), &info_body()), None),
        _ => match fake_play::handle(request, &state.play, options.play_mode).await {
            Some(reply) => (
                response(
                    reply.status,
                    reply.reason,
                    &cseq,
                    reply.content_type,
                    &reply.body,
                ),
                None,
            ),
            None => (response(404, "File not found", &cseq, None, &[]), None),
        },
    }
}

/// Answer a remote-control `SETUP`, allocating whichever channel it asked for.
async fn setup(
    request: &FakeRequest,
    accessory: &Arc<Mutex<ReferenceAccessory>>,
    state: &Arc<FakeState>,
    options: &FakeOptions,
    cseq: &str,
) -> Vec<u8> {
    if options.refuse_setup {
        return response(455, "Method Not Valid In This State", cseq, None, &[]);
    }

    let Ok(body) = plist::from_bytes::<plist::Value>(&request.body) else {
        return response(400, "Bad request", cseq, None, &[]);
    };
    let Some(dictionary) = body.as_dictionary() else {
        return response(400, "Bad request", cseq, None, &[]);
    };

    if let Some(seed) = dictionary
        .get("streams")
        .and_then(plist::Value::as_array)
        .and_then(|streams| streams.first())
        .and_then(plist::Value::as_dictionary)
        .and_then(|stream| stream.get("seed"))
        .and_then(plist::Value::as_unsigned_integer)
    {
        *state.data_setup.lock().await = Some(body.clone());

        // Unswapped on the controller's side, so mirrored here: the receiver writes with the key
        // the controller reads with (`ap2_session.py:176-184`).
        let keys = accessory
            .lock()
            .await
            .encryption_keys(
                &data_stream_salt(seed),
                AIRPLAY_DATA_STREAM.read_info,
                AIRPLAY_DATA_STREAM.write_info,
            )
            .expect("pair-verify must have completed before SETUP");

        let (listener, port) = bind_loopback().await;
        let state = Arc::clone(state);
        match options.data_bridge {
            Some(device) => {
                tokio::spawn(async move { serve_data_bridge(listener, keys, state, device).await });
            }
            None => {
                tokio::spawn(async move { serve_data(listener, keys, state).await });
            }
        }

        let mut stream = plist::Dictionary::new();
        stream.insert("dataPort".to_owned(), u64::from(port).into());
        let mut reply = plist::Dictionary::new();
        reply.insert(
            "streams".to_owned(),
            plist::Value::Array(vec![plist::Value::Dictionary(stream)]),
        );
        return response(200, "OK", cseq, Some(BPLIST), &encode(&reply));
    }

    *state.event_setup.lock().await = Some(body.clone());

    // The controller derives this pair swapped, so this side derives it straight
    // (`ap2_session.py:140-148`).
    let keys = accessory
        .lock()
        .await
        .encryption_keys(
            AIRPLAY_EVENTS.salt,
            AIRPLAY_EVENTS.write_info,
            AIRPLAY_EVENTS.read_info,
        )
        .expect("pair-verify must have completed before SETUP");

    let (listener, port) = bind_loopback().await;
    let probe = options.event_probe.clone();
    let state_for_channel = Arc::clone(state);
    tokio::spawn(async move { serve_event(listener, keys, state_for_channel, probe).await });

    let mut reply = plist::Dictionary::new();
    reply.insert("eventPort".to_owned(), u64::from(port).into());
    if let Some(timing_port) = options.timing_port {
        reply.insert("timingPort".to_owned(), u64::from(timing_port).into());
    }
    if let Some(skip_record) = options.skip_record {
        reply.insert("skipRecord".to_owned(), skip_record.into());
    }
    response(200, "OK", cseq, Some(BPLIST), &encode(&reply))
}

/// A small stand-in for the twenty-seven-key `/info` a real receiver answers with.
fn info_body() -> Vec<u8> {
    let mut info = plist::Dictionary::new();
    info.insert("model".to_owned(), "AppleTV14,1".into());
    info.insert("name".to_owned(), "Fake".into());
    info.insert("protocolVersion".to_owned(), "1.1".into());
    encode(&info)
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

/// Rewrite a response's protocol token to the one the request used.
///
/// `format_response` builds every reply as `HttpResponse(request.protocol, request.version, …)`
/// (`server_auth.py:193-204,230-241,251-262`, `support/http.py:143-150`), so a receiver answers
/// `RTSP/1.0` to an RTSP request and `HTTP/1.1` to an HTTP one **on the same socket** — AirPlay 2
/// runs both over one connection. The tvOS 27 captures in
/// `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` show exactly that: `HTTP/1.1 200
/// OK` to `POST /pair-verify HTTP/1.1` (line 42) and `RTSP/1.0 200 OK` to `SETUP … RTSP/1.0`
/// (line 128).
///
/// [`response`] always writes `HTTP/1.1`, which is the shape pyatv's own client happens to accept
/// either way; answering as the device really does is what makes a client that has grown a
/// dependency on the constant fail here rather than on hardware.
fn echo_protocol(response: Vec<u8>, protocol: &str) -> Vec<u8> {
    const DEFAULT: &[u8] = b"HTTP/1.1";

    if protocol.as_bytes() == DEFAULT || !response.starts_with(DEFAULT) {
        return response;
    }

    let mut out = protocol.as_bytes().to_vec();
    out.extend_from_slice(&response[DEFAULT.len()..]);
    out
}

/// Serialise a response the way `format_response` does (`pyatv/support/http.py:143-167`):
/// `Server` first, then the caller's headers, then `Content-Length` only for a non-empty body.
///
/// The protocol token is a placeholder that [`echo_protocol`] replaces with the request's.
fn response(
    code: u16,
    message: &str,
    cseq: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> Vec<u8> {
    let mut head =
        format!("HTTP/1.1 {code} {message}\r\nServer: pyatv-rs-fake/1.0\r\nCSeq: {cseq}\r\n");
    if let Some(content_type) = content_type {
        let _ = write!(head, "Content-Type: {content_type}\r\n");
    }
    if !body.is_empty() {
        let _ = write!(head, "Content-Length: {}\r\n", body.len());
    }
    head.push_str("\r\n");

    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}
