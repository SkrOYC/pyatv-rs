//! A hermetic RAOP receiver, in both protocol generations.
//!
//! Port of `tests/fake_device/raop.py::FakeRaopService` plus the three datagram protocols beside it
//! (`raop.py:189-341`), extended in the two places upstream's fixture stops short:
//!
//! * **AirPlay 2 exists here.** pyatv's fake answers `ANNOUNCE` and a `Transport`-header `SETUP`
//!   and nothing else — it has no pair-verify, no property-list `SETUP`, no event channel and no
//!   audio decryption, so *none* of pyatv's RAOP tests ever exercise `airplayv2.py`
//!   (`docs/research/airplay-playurl-raop-port-spec.md` §12.1). This one does, and decrypts the
//!   audio it receives, so a wrong `shk` or a wrong nonce fails a test rather than passing quietly.
//! * **`SET_PARAMETER progress:` is understood.** Upstream's fixture answers `501` to it, because
//!   its own service never advertises the `md` bit that makes pyatv send one.
//!
//! Everything else follows upstream: the `initialVolume` in `/info`, the `500` some receivers give
//! to a volume set before `FLUSH`, the digest challenge, and the `/auth-setup`-gates-everything
//! rule.

pub mod routes;
pub mod udp;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use pyatv_pairing::hkdf_derive::transport::AIRPLAY_CONTROL;
use pyatv_pairing::pairing::SessionKeys;
use pyatv_pairing::server::ReferenceAccessory;
use pyatv_pairing::session::HapSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use self::udp::UdpCapture;
use crate::raop::AudioProperties;

/// Which protocol generation the receiver should speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RaopVersion {
    /// SDP `ANNOUNCE`, a `Transport` header, plaintext audio, no pair-verify.
    V1,
    /// Two property-list `SETUP`s, an event channel, ChaCha20-Poly1305 audio.
    #[default]
    V2,
}

/// How the receiver should behave.
#[derive(Debug, Clone)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "this is upstream's `RaopServiceFlags` bitflag set (`raop.py:38-63`) spelled out as \
              named fields; a bitflags type would read worse at every call site"
)]
pub struct FakeRaopOptions {
    /// Which generation to speak.
    pub version: RaopVersion,
    /// The PIN the device would be showing, for the AirPlay 2 pairing path.
    pub pin: u32,
    /// A password to challenge for, `None` for an open device (`state.password`).
    pub password: Option<String>,
    /// Answer `/info` with an `initialVolume` (`INITIAL_AUDIO_LEVEL`).
    pub initial_volume: Option<f64>,
    /// Refuse `SET_PARAMETER volume` with `500` until `FLUSH` has arrived (`DELAYED_SET_VOLUME`).
    pub delayed_set_volume: bool,
    /// Refuse everything until `/auth-setup` has been performed (`AUTH_REQUIRED`).
    pub require_auth_setup: bool,
    /// Answer `POST /feedback` with `501` (`FEEDBACK_SUPPORTED` cleared).
    pub refuse_feedback: bool,
    /// Answer `GET /info` with `400` (`INFO_SUPPORTED` cleared).
    pub refuse_info: bool,
    /// The audio format to advertise, which the tests read back as TXT properties.
    pub audio: AudioProperties,
}

impl Default for FakeRaopOptions {
    fn default() -> Self {
        Self {
            version: RaopVersion::default(),
            pin: pyatv_pairing::server::AIRPLAY_PIN,
            password: None,
            initial_volume: None,
            delayed_set_volume: false,
            require_auth_setup: false,
            refuse_feedback: false,
            refuse_info: false,
            audio: AudioProperties::default(),
        }
    }
}

/// What the receiver observed.
#[derive(Debug, Default)]
pub struct FakeRaopState {
    /// How many `ANNOUNCE` requests arrived.
    pub announces: AtomicUsize,
    /// How many `SETUP` requests arrived, of either shape.
    pub setups: AtomicUsize,
    /// How many `RECORD` requests arrived.
    pub records: AtomicUsize,
    /// How many `FLUSH` requests arrived.
    pub flushes: AtomicUsize,
    /// How many `TEARDOWN` requests arrived.
    pub teardowns: AtomicUsize,
    /// How many `POST /feedback` requests arrived.
    pub feedbacks: AtomicUsize,
    /// How many `POST /auth-setup` requests arrived and were accepted.
    pub auth_setups: AtomicUsize,
    /// Whether `FLUSH` has arrived, which is what `delayed_set_volume` keys off.
    pub streaming_started: AtomicBool,
    /// Whether the controller dialled the AirPlay 2 event port.
    pub event_connected: AtomicBool,
    /// Every volume the controller set, in dBFS and in order.
    pub volumes: Mutex<Vec<f32>>,
    /// The last `progress:` value, verbatim.
    pub progress: Mutex<Option<String>>,
    /// The last `application/x-dmap-tagged` body, verbatim.
    pub metadata: Mutex<Option<Vec<u8>>>,
    /// The last `image/jpeg` body.
    pub artwork: Mutex<Option<Vec<u8>>>,
    /// The `ANNOUNCE` SDP body.
    pub sdp: Mutex<Option<String>>,
    /// The `Authorization` header of the request that satisfied the digest challenge.
    pub authorization: Mutex<Option<String>>,
    /// The base `SETUP` body, as the receiver decoded it.
    pub base_setup: Mutex<Option<plist::Value>>,
    /// The audio-stream `SETUP` body, as the receiver decoded it.
    pub audio_setup: Mutex<Option<plist::Value>>,
    /// What arrived over UDP.
    pub udp: Arc<UdpCapture>,
}

impl FakeRaopState {
    /// Every audio payload concatenated in sequence-number order, as upstream's `raw_audio` does.
    pub async fn raw_audio(&self) -> Vec<u8> {
        let mut frames = self.udp.audio.lock().await.clone();
        frames.sort_by_key(|frame| frame.seqno);
        frames.into_iter().flat_map(|frame| frame.payload).collect()
    }
}

/// A running fake receiver. Dropping it stops the accept loop and every socket with it.
#[derive(Debug)]
pub struct FakeRaopDevice {
    address: SocketAddr,
    audio: AudioProperties,
    state: Arc<FakeRaopState>,
    task: tokio::task::JoinHandle<()>,
}

/// The `sr`/`ch`/`ss`/`et`/`md` a discovery record would carry, as a TXT map.
fn txt_properties(audio: AudioProperties) -> std::collections::HashMap<String, String> {
    [
        ("sr", audio.sample_rate.to_string()),
        ("ch", audio.channels.to_string()),
        ("ss", audio.sample_size.to_string()),
        // `et=0` is "unencrypted", and `md=0,1,2` is text, artwork and progress — the full set, so
        // a test sees every metadata call the client can make.
        ("et", "0".to_owned()),
        ("md", "0,1,2".to_owned()),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value))
    .collect()
}

impl Drop for FakeRaopDevice {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl FakeRaopDevice {
    /// Bind to an ephemeral loopback port and start serving with default behaviour.
    pub async fn start() -> Self {
        Self::start_with(FakeRaopOptions::default()).await
    }

    /// Bind to an ephemeral loopback port and start serving.
    pub async fn start_with(options: FakeRaopOptions) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("binding a loopback port must succeed in tests");
        let address = listener
            .local_addr()
            .expect("a bound listener must have an address");

        let audio = options.audio;
        let state = Arc::new(FakeRaopState::default());
        let served_state = Arc::clone(&state);
        // One accessory for the whole device, not one per connection: pair-setup runs on its own
        // short-lived connection and pair-verify has to find the controller it registered.
        let accessory = Arc::new(Mutex::new(ReferenceAccessory::with_pin(options.pin)));

        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = Arc::clone(&served_state);
                let accessory = Arc::clone(&accessory);
                let options = options.clone();
                tokio::spawn(async move {
                    serve(stream, state, accessory, options).await;
                });
            }
        });

        Self {
            address,
            audio,
            state,
            task,
        }
    }

    /// Where a controller should connect.
    pub fn address(&self) -> SocketAddr {
        self.address
    }

    /// What the receiver observed.
    pub fn state(&self) -> Arc<FakeRaopState> {
        Arc::clone(&self.state)
    }

    /// The TXT properties a discovery record would carry for this receiver.
    ///
    /// `sr`/`ch`/`ss` are what `get_audio_properties` reads and `et`/`md` what
    /// `get_encryption_types`/`get_metadata_types` read (`raop/parsers.py`).
    pub fn properties(&self) -> std::collections::HashMap<String, String> {
        txt_properties(self.audio)
    }
}

/// Per-connection state the routes mutate.
#[derive(Debug, Default)]
pub struct Session {
    /// Set once a digest challenge has gone out, so the retry can be checked against it.
    pub nonce: Option<String>,
    /// Set once `/auth-setup` succeeded.
    pub auth_setup_done: bool,
    /// The `shk` from the audio-stream `SETUP`, which keys the audio decryption.
    pub audio_key: Option<[u8; 32]>,
}

/// Serve one RTSP connection until the peer goes away.
async fn serve(
    stream: TcpStream,
    state: Arc<FakeRaopState>,
    accessory: Arc<Mutex<ReferenceAccessory>>,
    options: FakeRaopOptions,
) {
    let peer = stream.peer_addr().ok();
    let (mut read_half, mut write_half) = stream.into_split();
    let mut hap: Option<HapSession> = None;
    let mut session = Session::default();
    let mut buffer = Vec::new();

    loop {
        let mut chunk = [0u8; 4096];
        let Ok(read) = read_half.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }

        let plaintext = match hap.as_mut() {
            Some(hap) => match hap.decrypt(&chunk[..read]) {
                Ok(plaintext) => plaintext,
                Err(_) => return,
            },
            None => chunk[..read].to_vec(),
        };
        buffer.extend_from_slice(&plaintext);

        while let Some((request, consumed)) = routes::parse_request(&buffer) {
            buffer.drain(..consumed);

            let (reply, enable) = routes::handle(
                &request,
                &state,
                &options,
                &mut session,
                &accessory,
                peer.map(|peer| peer.ip()),
            )
            .await;
            let response = routes::encode_response(&reply, &request.protocol);

            let outbound = match hap.as_mut() {
                Some(hap) => match hap.encrypt(&response) {
                    Ok(framed) => framed,
                    Err(_) => return,
                },
                None => response,
            };
            if write_half.write_all(&outbound).await.is_err() {
                return;
            }

            if let Some(keys) = enable {
                hap = Some(HapSession::new(&keys.output_key, &keys.input_key));
            }
        }
    }
}

/// Derive the accessory's half of the control-channel keys, once pair-verify M4 has gone out.
///
/// The roles are the mirror of the controller's: the receiver's output key is the controller's
/// input key (`airplay/server_auth.py:296-309`).
pub(crate) async fn control_keys(
    accessory: &Arc<Mutex<ReferenceAccessory>>,
) -> Option<SessionKeys> {
    accessory
        .lock()
        .await
        .encryption_keys(
            AIRPLAY_CONTROL.salt,
            AIRPLAY_CONTROL.read_info,
            AIRPLAY_CONTROL.write_info,
        )
        .ok()
}

/// Accept one event-channel connection and drain it.
///
/// The controller opens this socket and pushes nothing down it during a RAOP session; it exists
/// only because `_setup_base` refuses to continue without one (`airplayv2.py:86-104`).
pub(crate) async fn serve_event_channel(listener: TcpListener, state: Arc<FakeRaopState>) {
    let Ok((mut stream, _)) = listener.accept().await else {
        return;
    };
    state.event_connected.store(true, Ordering::SeqCst);

    let mut chunk = [0u8; 4096];
    while let Ok(read) = stream.read(&mut chunk).await {
        if read == 0 {
            return;
        }
    }
}
