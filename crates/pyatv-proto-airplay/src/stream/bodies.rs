//! The exact requests `play_url` puts on the wire: paths, header sets and property-list bodies.
//!
//! Everything here is a constant of the protocol rather than a decision, so it lives apart from the
//! code that sequences it and is tested against pyatv's own encoder in
//! `tests/airplay_play_kat.rs`. The reference is
//! `docs/research/airplay-playurl-raop-port-spec.md` §2.2 (`AirPlay` 1) and §2.3 (`AirPlay` 2).

use plist::{Dictionary, Value};

use crate::codec::BPLIST_CONTENT_TYPE;

/// Where the play request goes (`airplayv1.py:133`, `airplayv2.py:257`).
pub const PLAY_PATH: &str = "/play";

/// Where the progress poll goes (`player.py:84`).
pub const PLAYBACK_INFO_PATH: &str = "/playback-info";

/// `POST /rate?value=1.000000` — the one follow-up upstream calls "most important", because the
/// stream starts paused without it (`airplayv2.py:252-253`).
pub const RATE_PATH: &str = "/rate?value=1.000000";

/// The four `PUT /setProperty?…` targets, in the order upstream sends them
/// (`airplayv2.py:246-272`). `/rate` is sent between the second and the third; see
/// [`super::ap2`].
pub const SET_PROPERTY_PATHS: [&str; 4] = [
    "/setProperty?isInterestedInDateRange",
    "/setProperty?actionAtItemEnd",
    "/setProperty?forwardEndTime",
    "/setProperty?reverseEndTime",
];

/// The user agent `AirPlay` 1 plays under (`airplayv1.py:20`).
pub const V1_USER_AGENT: &str = "MediaControl/1.0";

/// The user agent `AirPlay` 2 plays under (`airplayv2.py:28`).
pub const V2_USER_AGENT: &str = "AirPlay/550.10";

/// `AirPlay` 1's `/play` headers, in dict order (`airplayv1.py:19-22`).
///
/// pyatv's own fake receiver asserts both of these verbatim
/// (`tests/fake_device/airplay.py:100-102`), so they are load-bearing at least against that.
#[must_use]
pub fn v1_play_headers() -> [(&'static str, &'static str); 2] {
    [
        ("User-Agent", V1_USER_AGENT),
        ("Content-Type", BPLIST_CONTENT_TYPE),
    ]
}

/// `AirPlay` 2's `/play` headers, in dict order (`airplayv2.py:27-33`).
///
/// `session_id` is `X-Apple-Session-ID`. Upstream evaluates `str(uuid4()).lower()` **once, in the
/// module-level dict literal**, so every `AirPlayV2` in a process shares one value; this port draws
/// a fresh one per call, which `docs/research/airplay-playurl-raop-port-spec.md` §16.1 recommends
/// and which is what `AirPlay` 1 already does correctly (`airplayv1.py:127`).
#[must_use]
pub fn v2_play_headers(session_id: &str) -> [(&str, &str); 5] {
    [
        ("User-Agent", V2_USER_AGENT),
        ("Content-Type", BPLIST_CONTENT_TYPE),
        ("X-Apple-ProtocolVersion", "1"),
        ("X-Apple-Session-ID", session_id),
        ("X-Apple-Stream-ID", "1"),
    ]
}

/// `AirPlay` 1's `/play` body — three keys and nothing else (`airplayv1.py:126-130`).
///
/// `session_id` is a lowercase `str(uuid4())`, drawn per call upstream too.
#[must_use]
pub fn v1_play_body(url: &str, position: f64, session_id: &str) -> Value {
    let mut body = Dictionary::new();
    body.insert("Content-Location".to_owned(), url.into());
    body.insert("Start-Position".to_owned(), number(position));
    body.insert("X-Apple-Session-ID".to_owned(), session_id.into());
    Value::Dictionary(body)
}

/// `AirPlay` 2's `/play` body — twenty-one keys, most of them decoration (`airplayv2.py:213-236`).
///
/// Upstream's own comment is "Most fields are not needed here, but keeping them for reference".
/// They are reproduced in full anyway: which of them a receiver actually reads is not knowable from
/// this side, and the millisecond-timing fields in particular look like a capture pyatv copied
/// wholesale, so dropping any of them would be guessing.
///
/// `uuid` is the per-instance `str(uuid4())` of `airplayv2.py:49`, lowercase.
#[must_use]
pub fn v2_play_body(url: &str, position: f64, uuid: &str) -> Value {
    let mut body = Dictionary::new();
    body.insert("Content-Location".to_owned(), url.into());
    body.insert("Start-Position-Seconds".to_owned(), number(position));
    body.insert("uuid".to_owned(), uuid.into());
    body.insert("streamType".to_owned(), 1i64.into());
    body.insert("mediaType".to_owned(), "file".into());
    body.insert("mightSupportStorePastisKeyRequests".to_owned(), true.into());
    body.insert("playbackRestrictions".to_owned(), 0i64.into());
    body.insert("secureConnectionMs".to_owned(), 22i64.into());
    body.insert("volume".to_owned(), 1.0f64.into());
    body.insert("infoMs".to_owned(), 122i64.into());
    body.insert("connectMs".to_owned(), 18i64.into());
    body.insert("authMs".to_owned(), 0i64.into());
    body.insert("bonjourMs".to_owned(), 0i64.into());
    body.insert("referenceRestrictions".to_owned(), 3i64.into());
    body.insert("SenderMACAddress".to_owned(), SENDER_MAC.into());
    body.insert("model".to_owned(), SENDER_MODEL.into());
    body.insert("postAuthMs".to_owned(), 0i64.into());
    body.insert("clientBundleID".to_owned(), CLIENT_BUNDLE_ID.into());
    body.insert("clientProcName".to_owned(), CLIENT_BUNDLE_ID.into());
    body.insert("osBuildVersion".to_owned(), PLAY_OS_BUILD.into());
    body.insert("rate".to_owned(), 1.0f64.into());
    Value::Dictionary(body)
}

/// The `AirPlay` 2 base `SETUP` body `play_url` and RAOP share (`airplayv2.py:57-72`).
///
/// **Not** [`crate::ap2::remote_control_setup_body`]. The remote-control tunnel sends a different,
/// eleven-key body with `isRemoteControlOnly: true` and `timingProtocol: "None"`; this one is
/// fifteen keys with `timingProtocol: "NTP"` and a real `timingPort`, and every identity value is a
/// hardcoded literal rather than a [`crate::ap2::InfoSettings`] field. Upstream keeps two
/// independent copies of this dictionary and they genuinely differ, so this port keeps two too
/// (`docs/research/airplay-playurl-raop-port-spec.md` §2.3.1).
///
/// `session_uuid` is an uppercase `str(uuid4()).upper()`, per call.
#[must_use]
pub fn v2_base_setup_body(timing_port: u16, session_uuid: &str) -> Value {
    let mut body = Dictionary::new();
    body.insert("deviceID".to_owned(), SENDER_MAC.into());
    body.insert("sessionUUID".to_owned(), session_uuid.into());
    body.insert("timingPort".to_owned(), i64::from(timing_port).into());
    body.insert("timingProtocol".to_owned(), "NTP".into());
    body.insert("isMultiSelectAirPlay".to_owned(), true.into());
    body.insert("groupContainsGroupLeader".to_owned(), false.into());
    body.insert("macAddress".to_owned(), SENDER_MAC.into());
    body.insert("model".to_owned(), SENDER_MODEL.into());
    body.insert("name".to_owned(), "pyatv".into());
    body.insert("osBuildVersion".to_owned(), SETUP_OS_BUILD.into());
    body.insert("osName".to_owned(), "iPhone OS".into());
    body.insert("osVersion".to_owned(), "16.5".into());
    body.insert("senderSupportsRelay".to_owned(), false.into());
    body.insert("sourceVersion".to_owned(), SETUP_SOURCE_VERSION.into());
    body.insert("statsCollectionEnabled".to_owned(), false.into());
    Value::Dictionary(body)
}

/// `{"value": …}`, the shape every `setProperty` body has (`airplayv2.py:246-272`).
#[must_use]
pub fn set_property_body(value: Value) -> Value {
    let mut body = Dictionary::new();
    body.insert("value".to_owned(), value);
    Value::Dictionary(body)
}

/// The four zeroes `forwardEndTime`/`reverseEndTime` carry — a `CMTime` with every field cleared
/// (`airplayv2.py:262-272`).
#[must_use]
pub fn end_time_value() -> Value {
    let mut time = Dictionary::new();
    time.insert("flags".to_owned(), 0i64.into());
    time.insert("value".to_owned(), 0i64.into());
    time.insert("epoch".to_owned(), 0i64.into());
    time.insert("timescale".to_owned(), 0i64.into());
    Value::Dictionary(time)
}

/// The bodies of the four `setProperty` calls, in [`SET_PROPERTY_PATHS`] order.
#[must_use]
pub fn set_property_bodies() -> [Value; 4] {
    [
        set_property_body(true.into()),
        set_property_body(0i64.into()),
        set_property_body(end_time_value()),
        set_property_body(end_time_value()),
    ]
}

/// `SenderMACAddress`, `deviceID` and `macAddress` (`airplayv2.py:58,64,228`).
///
/// A literal in upstream's play path, unlike the tunnel's, which takes the controller's configured
/// address. Kept literal so a receiver sees what it would see from pyatv.
const SENDER_MAC: &str = "AA:BB:CC:DD:EE:FF";

/// `model` in both the `SETUP` and the `/play` body (`airplayv2.py:65,229`).
const SENDER_MODEL: &str = "iPhone14,3";

/// `clientBundleID` and `clientProcName`, which are the same string (`airplayv2.py:231-232`).
const CLIENT_BUNDLE_ID: &str = "dev.pyatv.GPU";

/// `osBuildVersion` in the `/play` body — a *different* build number from the one the `SETUP` body
/// carries, in upstream as here (`airplayv2.py:233` against `airplayv2.py:66`).
const PLAY_OS_BUILD: &str = "20G1116";

/// `osBuildVersion` in the base `SETUP` body (`airplayv2.py:66`).
const SETUP_OS_BUILD: &str = "20F66";

/// `sourceVersion` in the base `SETUP` body. Also different from the tunnel's `550.10`
/// (`airplayv2.py:69` against `ap2_session.py:123`).
const SETUP_SOURCE_VERSION: &str = "690.7.1";

/// Render a start position the way `plistlib` would have.
///
/// Upstream reaches these bodies by two routes with two different Python types. `AirPlayStream`
/// truncates with `int(kwargs.get("position", 0))` (`__init__.py:130`), so the facade always
/// produces a plist *integer*; calling `AirPlayPlayer.play_url` directly with a float — which only
/// upstream's own tests do — produces a *real*. Emitting an integer for a whole number and a real
/// otherwise reproduces both, for every value either route can actually produce.
fn number(position: f64) -> Value {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the guard is exactly that the value is a whole number in range, so the cast is \
                  lossless"
    )]
    if position.fract() == 0.0 && position.abs() < 9.007_199_254_740_992e15 {
        Value::Integer((position as i64).into())
    } else {
        Value::Real(position)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SET_PROPERTY_PATHS, end_time_value, number, set_property_bodies, v1_play_body,
        v1_play_headers, v2_base_setup_body, v2_play_body, v2_play_headers,
    };
    use crate::rtsp::{decode_plist, encode_plist};

    /// Three keys, no more (`airplayv1.py:126-130`).
    #[test]
    fn the_airplay_1_body_carries_exactly_three_keys() {
        let body = v1_play_body("http://example/video.mp4", 0.0, "abc");
        let dictionary = body.as_dictionary().expect("a dictionary");

        let mut keys: Vec<&str> = dictionary.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            ["Content-Location", "Start-Position", "X-Apple-Session-ID"]
        );
        assert_eq!(
            dictionary["Content-Location"].as_string(),
            Some("http://example/video.mp4")
        );
    }

    /// Twenty-one keys, the full decorative set (`airplayv2.py:213-236`).
    #[test]
    fn the_airplay_2_body_carries_all_twenty_one_keys() {
        let body = v2_play_body("http://example/video.mp4", 0.0, "abc");
        let dictionary = body.as_dictionary().expect("a dictionary");

        assert_eq!(dictionary.len(), 21);
        assert_eq!(dictionary["rate"].as_real(), Some(1.0));
        assert_eq!(dictionary["volume"].as_real(), Some(1.0));
        assert_eq!(dictionary["streamType"].as_signed_integer(), Some(1));
        assert_eq!(dictionary["mediaType"].as_string(), Some("file"));
        assert_eq!(
            dictionary["mightSupportStorePastisKeyRequests"].as_boolean(),
            Some(true)
        );
        assert_eq!(
            dictionary["clientProcName"].as_string(),
            Some("dev.pyatv.GPU")
        );
        assert_eq!(dictionary["osBuildVersion"].as_string(), Some("20G1116"));
    }

    /// The base `SETUP` is fifteen keys and is *not* the tunnel's eleven — different
    /// `timingProtocol`, different `sourceVersion`, different `osBuildVersion`
    /// (`docs/research/airplay-playurl-raop-port-spec.md` §2.3.1).
    #[test]
    fn the_base_setup_body_is_not_the_tunnels() {
        let body = v2_base_setup_body(6002, "A-B-C");
        let dictionary = body.as_dictionary().expect("a dictionary");

        assert_eq!(dictionary.len(), 15);
        assert_eq!(dictionary["timingProtocol"].as_string(), Some("NTP"));
        assert_eq!(dictionary["timingPort"].as_signed_integer(), Some(6002));
        assert_eq!(dictionary["sourceVersion"].as_string(), Some("690.7.1"));
        assert_eq!(dictionary["osBuildVersion"].as_string(), Some("20F66"));
        assert!(!dictionary.contains_key("isRemoteControlOnly"));

        let tunnel =
            crate::ap2::remote_control_setup_body(&crate::ap2::InfoSettings::default(), "A-B-C");
        assert_ne!(body, tunnel);
    }

    /// A whole position is an integer and a fractional one is a real, matching upstream's two call
    /// routes.
    #[test]
    fn a_whole_position_encodes_as_an_integer() {
        assert_eq!(number(0.0).as_signed_integer(), Some(0));
        assert_eq!(number(42.0).as_signed_integer(), Some(42));
        assert_eq!(number(0.8).as_real(), Some(0.8));
    }

    /// Every body has to survive the binary encoder the wire uses.
    #[test]
    fn the_bodies_round_trip_through_a_binary_plist() {
        for body in [
            v1_play_body("http://example/video.mp4", 0.0, "abc"),
            v2_play_body("http://example/video.mp4", 0.8, "abc"),
            v2_base_setup_body(0, "A-B-C"),
            end_time_value(),
        ] {
            let encoded = encode_plist(&body).expect("encodes");
            assert!(encoded.starts_with(b"bplist00"));
            assert_eq!(decode_plist(&encoded).expect("decodes"), body);
        }
    }

    /// One body per path, and the two end-time bodies are identical.
    #[test]
    fn every_set_property_path_has_a_body() {
        let bodies = set_property_bodies();

        assert_eq!(bodies.len(), SET_PROPERTY_PATHS.len());
        assert_eq!(
            bodies[0].as_dictionary().expect("a dictionary")["value"].as_boolean(),
            Some(true)
        );
        assert_eq!(
            bodies[1].as_dictionary().expect("a dictionary")["value"].as_signed_integer(),
            Some(0)
        );
        assert_eq!(bodies[2], bodies[3]);
    }

    /// The header sets differ between versions, and pyatv's own fake asserts the `AirPlay` 1 one.
    #[test]
    fn the_header_sets_are_the_ones_upstream_sends() {
        assert_eq!(
            v1_play_headers(),
            [
                ("User-Agent", "MediaControl/1.0"),
                ("Content-Type", "application/x-apple-binary-plist"),
            ]
        );

        let headers = v2_play_headers("deadbeef");
        assert_eq!(headers[0], ("User-Agent", "AirPlay/550.10"));
        assert_eq!(headers[3], ("X-Apple-Session-ID", "deadbeef"));
        assert_eq!(headers[4], ("X-Apple-Stream-ID", "1"));
    }
}
