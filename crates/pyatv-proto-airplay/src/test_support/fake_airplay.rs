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

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

mod routes;

use routes::{echo_protocol, handle};

use super::fake_play::{PlayMode, PlayState};

/// Content type every property-list body carries.
pub(super) const BPLIST: &str = "application/x-apple-binary-plist";

/// Content type every TLV8 body carries.
///
/// pyatv's own fake labels the pair-*setup* TLVs `application/x-apple-binary-plist`
/// (`server_auth.py:201,227`) and only the pair-*verify* ones `application/octet-stream`
/// (`server_auth.py:261`). Real hardware does neither: the tvOS 27 captures in
/// `docs/research/airplay-tunnel-auth-experiment-2026-08-24.md` (lines 36-52, 95) show
/// `application/octet-stream` on **both** halves of the handshake, in both directions. This
/// receiver follows the device rather than the fake, because the point of it is to catch a client
/// that has quietly grown a dependency on something only pyatv's test double does.
pub(super) const TLV8: &str = "application/octet-stream";

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
