//! The `play_url` surface of the hermetic receiver: `/play`, `/playback-info` and the property
//! calls that follow them.
//!
//! Port of `FakeAirPlayService`'s play routes (`tests/fake_device/airplay.py:68-153`) and the use
//! cases that drive them (`airplay.py:239-274`), with two deliberate additions upstream's fixture
//! does not have:
//!
//! * **An `AirPlay` 2 header mode.** pyatv's fixture asserts `User-Agent: MediaControl/1.0`
//!   unconditionally, so it only ever validates the `AirPlay` 1 header set — its `play_url` tests
//!   never exercise `AirPlayV2` at all (`docs/research/airplay-playurl-raop-port-spec.md` §12.2,
//!   which flags this as a genuine coverage gap upstream). [`PlayMode`] picks which set to demand.
//! * **A `/stop` route.** There is no `/stop` anywhere in pyatv's play path; it is here precisely so
//!   a test can assert that stopping a playback sends nothing.
//!
//! `/playback-info` is a queue of canned answers, popped one per poll, exactly as upstream's is,
//! falling back to `{readyToPlay: false, uuid: 123}` when the queue runs dry.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::Mutex;

use super::fake_airplay::FakeRequest;

/// Which header set `/play` should insist on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PlayMode {
    /// `User-Agent: MediaControl/1.0`, a `Start-Position` key and an `X-Apple-Session-ID` in the
    /// body — what `airplayv1.py` sends and what pyatv's own fixture asserts.
    AirPlayV1,
    /// `User-Agent: AirPlay/550.10` plus `X-Apple-ProtocolVersion`, `X-Apple-Session-ID` and
    /// `X-Apple-Stream-ID`, a `Start-Position-Seconds` key and a `uuid` — what `airplayv2.py`
    /// sends and what nothing upstream checks.
    #[default]
    AirPlayV2,
}

/// One canned `/playback-info` answer (`AirPlayPlaybackResponse`, `airplay.py:57`).
#[derive(Debug, Clone)]
pub struct PlaybackAnswer {
    /// The status to answer with. `403` is upstream's "no permission" case, and it is not a body
    /// the poll parses — it is an error the poll propagates.
    pub status: u16,
    /// The property list to send, or `None` for an empty body.
    pub body: Option<plist::Value>,
}

impl PlaybackAnswer {
    /// `{readyToPlay: false, uuid: 123}` — nothing is playing (`airplay.py:248-253`).
    #[must_use]
    pub fn idle() -> Self {
        let mut body = plist::Dictionary::new();
        body.insert("readyToPlay".to_owned(), false.into());
        body.insert("uuid".to_owned(), 123i64.into());
        Self {
            status: 200,
            body: Some(plist::Value::Dictionary(body)),
        }
    }

    /// `{duration: …}` — the one key the poll reads (`airplay.py:255-261`).
    #[must_use]
    pub fn playing(duration: f64) -> Self {
        let mut body = plist::Dictionary::new();
        body.insert("duration".to_owned(), duration.into());
        Self {
            status: 200,
            body: Some(plist::Value::Dictionary(body)),
        }
    }

    /// `{error: {code, domain}}`, which aborts the poll. Upstream's fixture has no use case for
    /// this, but `player.py:96-102` reads it and a real receiver sends it.
    #[must_use]
    pub fn failed(code: i64, domain: &str) -> Self {
        let mut error = plist::Dictionary::new();
        error.insert("code".to_owned(), code.into());
        error.insert("domain".to_owned(), domain.into());

        let mut body = plist::Dictionary::new();
        body.insert("error".to_owned(), plist::Value::Dictionary(error));
        Self {
            status: 200,
            body: Some(plist::Value::Dictionary(body)),
        }
    }

    /// A `403` with no body (`airplay_playback_playing_no_permission`, `airplay.py:272-274`).
    #[must_use]
    pub fn forbidden() -> Self {
        Self {
            status: 403,
            body: None,
        }
    }
}

/// What the receiver saw and what it should answer with.
#[derive(Debug, Default)]
pub struct PlayState {
    /// How many `POST /play` requests arrived, whatever they were answered with
    /// (`state.play_count`, `airplay.py:85`).
    pub plays: AtomicUsize,
    /// How many `POST /play` requests are still to be refused with `500`
    /// (`state.injected_play_fails`, `airplay.py:94-98`).
    pub play_failures: AtomicUsize,
    /// How many `GET /playback-info` polls arrived.
    pub polls: AtomicUsize,
    /// How many `POST /rate?…` calls arrived.
    pub rates: AtomicUsize,
    /// How many `GET /stop` requests arrived. Upstream sends none, ever.
    pub stops: AtomicUsize,
    /// The `Content-Location` of the last play (`state.last_airplay_url`).
    pub url: Mutex<Option<String>>,
    /// Its `Start-Position`/`Start-Position-Seconds` (`state.last_airplay_start`).
    pub position: Mutex<Option<f64>>,
    /// Its session identifier — `X-Apple-Session-ID` from the body on `AirPlay` 1, `uuid` on
    /// `AirPlay` 2 (`state.last_airplay_uuid`).
    pub session_id: Mutex<Option<String>>,
    /// The `/play` body as the receiver decoded it, for asserting on the whole dictionary.
    pub body: Mutex<Option<plist::Value>>,
    /// Every `setProperty` target and its `value`, in arrival order.
    pub properties: Mutex<Vec<(String, plist::Value)>>,
    /// The `/playback-info` answers still queued, oldest first.
    pub answers: Mutex<Vec<PlaybackAnswer>>,
    /// A status to answer every `/play` with instead of `200`, or zero to answer normally.
    ///
    /// Upstream spells this as two booleans that both mean `503`
    /// (`always_auth_fail`/`has_authenticated`, `airplay.py:88-92`); a status is more useful,
    /// because the driver's branching is on the number.
    pub forced_status: std::sync::atomic::AtomicU16,
}

impl PlayState {
    /// Queue answers for the next polls, in the order they should be given.
    pub async fn queue(&self, answers: impl IntoIterator<Item = PlaybackAnswer>) {
        self.answers.lock().await.extend(answers);
    }

    /// Refuse the next `count` plays with `500` (`airplay_play_failure`, `airplay.py:244-246`).
    pub fn fail_plays(&self, count: usize) {
        self.play_failures.store(count, Ordering::SeqCst);
    }

    /// Answer every `/play` with `status` (`airplay_always_fail_authentication`,
    /// `airplay.py:266-268`, which uses `503`).
    pub fn refuse_plays(&self, status: u16) {
        self.forced_status.store(status, Ordering::SeqCst);
    }
}

/// What one route decided to answer.
#[derive(Debug)]
pub struct PlayReply {
    /// Status code.
    pub status: u16,
    /// Reason phrase.
    pub reason: &'static str,
    /// Content type, when there is a body.
    pub content_type: Option<&'static str>,
    /// Body bytes.
    pub body: Vec<u8>,
}

impl PlayReply {
    /// `200 OK` with nothing in it.
    fn empty(status: u16, reason: &'static str) -> Self {
        Self {
            status,
            reason,
            content_type: None,
            body: Vec::new(),
        }
    }
}

/// Route one request if it belongs to the play surface, or `None` if it does not.
///
/// # Panics
///
/// Panics when a `/play` request does not carry the header set `mode` demands, which is how
/// upstream's fixture reports the same thing (`airplay.py:100-102` uses bare `assert`s).
pub async fn handle(request: &FakeRequest, state: &PlayState, mode: PlayMode) -> Option<PlayReply> {
    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/play") => Some(play(request, state, mode).await),
        ("GET", "/playback-info") => Some(playback_info(state).await),
        ("GET" | "POST", "/stop") => {
            state.stops.fetch_add(1, Ordering::SeqCst);
            Some(PlayReply::empty(200, "OK"))
        }
        ("POST", path) if path.starts_with("/rate") => {
            state.rates.fetch_add(1, Ordering::SeqCst);
            Some(PlayReply::empty(200, "OK"))
        }
        ("PUT", path) if path.starts_with("/setProperty") => {
            Some(set_property(request, state, path).await)
        }
        _ => None,
    }
}

/// `handle_airplay_play` (`airplay.py:83-136`).
async fn play(request: &FakeRequest, state: &PlayState, mode: PlayMode) -> PlayReply {
    state.plays.fetch_add(1, Ordering::SeqCst);

    // `if self.state.always_auth_fail` (`airplay.py:88-92`), which precedes everything else.
    let forced = state.forced_status.load(Ordering::SeqCst);
    if forced != 0 {
        return PlayReply::empty(forced, "Refused");
    }

    // `if self.state.injected_play_fails > 0` (`airplay.py:94-98`) — counted, and counted before
    // the headers are looked at, so a retry test never trips a header assertion.
    if state
        .play_failures
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return PlayReply::empty(500, "Internal Server Error");
    }

    let expected_agent = match mode {
        PlayMode::AirPlayV1 => "MediaControl/1.0",
        PlayMode::AirPlayV2 => "AirPlay/550.10",
    };
    assert_eq!(request.header("User-Agent"), Some(expected_agent));
    assert_eq!(
        request.header("Content-Type"),
        Some("application/x-apple-binary-plist")
    );
    if mode == PlayMode::AirPlayV2 {
        assert_eq!(request.header("X-Apple-ProtocolVersion"), Some("1"));
        assert_eq!(request.header("X-Apple-Stream-ID"), Some("1"));
        assert!(
            request
                .header("X-Apple-Session-ID")
                .is_some_and(|id| !id.is_empty()),
            "AirPlay 2 carries the session identifier in a header, not the body"
        );
    }

    let Ok(body) = plist::from_bytes::<plist::Value>(&request.body) else {
        return PlayReply::empty(400, "Bad Request");
    };
    let Some(dictionary) = body.as_dictionary() else {
        return PlayReply::empty(400, "Bad Request");
    };

    let (position_key, session_key) = match mode {
        PlayMode::AirPlayV1 => ("Start-Position", "X-Apple-Session-ID"),
        PlayMode::AirPlayV2 => ("Start-Position-Seconds", "uuid"),
    };

    *state.url.lock().await = dictionary
        .get("Content-Location")
        .and_then(plist::Value::as_string)
        .map(str::to_owned);
    *state.position.lock().await = dictionary.get(position_key).and_then(number);
    *state.session_id.lock().await = dictionary
        .get(session_key)
        .and_then(plist::Value::as_string)
        .map(str::to_owned);
    *state.body.lock().await = Some(body.clone());

    PlayReply::empty(200, "OK")
}

/// `handle_airplay_playback_info` (`airplay.py:138-153`).
async fn playback_info(state: &PlayState) -> PlayReply {
    state.polls.fetch_add(1, Ordering::SeqCst);

    let mut answers = state.answers.lock().await;
    let answer = if answers.is_empty() {
        PlaybackAnswer::idle()
    } else {
        answers.remove(0)
    };
    drop(answers);

    let body = answer.body.as_ref().map(encode).unwrap_or_default();
    PlayReply {
        status: answer.status,
        reason: "...",
        content_type: if body.is_empty() {
            None
        } else {
            Some("application/x-apple-binary-plist")
        },
        body,
    }
}

/// Record one `setProperty` and accept it.
async fn set_property(request: &FakeRequest, state: &PlayState, path: &str) -> PlayReply {
    let value = plist::from_bytes::<plist::Value>(&request.body)
        .ok()
        .and_then(|body| {
            body.as_dictionary()
                .and_then(|dictionary| dictionary.get("value").cloned())
        })
        .unwrap_or(plist::Value::Boolean(false));

    state.properties.lock().await.push((path.to_owned(), value));

    PlayReply::empty(200, "OK")
}

/// Read a plist number whichever way it was encoded — an integer from the facade's truncating call
/// path, a real from a fractional one.
fn number(value: &plist::Value) -> Option<f64> {
    value.as_real().or_else(|| {
        #[expect(
            clippy::cast_precision_loss,
            reason = "a start position is seconds, so no realistic value loses precision here"
        )]
        value.as_signed_integer().map(|number| number as f64)
    })
}

fn encode(value: &plist::Value) -> Vec<u8> {
    let mut out = Vec::new();
    plist::to_writer_binary(&mut out, value).expect("encodes");
    out
}
