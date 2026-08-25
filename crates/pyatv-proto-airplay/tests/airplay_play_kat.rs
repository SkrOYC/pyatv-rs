//! Known-answer tests for the `play_url` bodies, against vectors generated from pyatv.
//!
//! pyatv builds these dictionaries inline with no factory to call, so
//! `tests/kat/gen_airplay_play_kat.py` reads them out of the checkout's own source with `ast`,
//! substitutes the per-call values and lets `plistlib` encode the result. Agreeing with the vector
//! therefore means agreeing with pyatv's literals and key order, not with a second reading of them.
//!
//! Bodies are compared **after decoding**: `plistlib` and the Rust `plist` crate lay out the offset
//! table differently and both are valid, so byte equality would be stricter than the format.

use std::sync::LazyLock;

use pyatv_proto_airplay::rtsp::decode_plist;
use pyatv_proto_airplay::stream::bodies;

/// The vectors generated from pyatv b277a4c.
static KAT: LazyLock<serde_json::Value> = LazyLock::new(|| {
    let raw = include_str!("kat/airplay_play_kat.json");
    serde_json::from_str(raw).expect("the vector file must be valid JSON")
});

fn text(path: &[&str]) -> String {
    let mut node = &*KAT;
    for key in path {
        node = node
            .get(key)
            .unwrap_or_else(|| panic!("no vector at {key}"));
    }
    node.as_str().expect("a string vector").to_owned()
}

/// Decode one `plists` entry.
fn expected(name: &str) -> plist::Value {
    let hex = text(&["plists", name]);
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&hex[index..index + 2], 16).expect("the vector must be hex")
        })
        .collect();

    decode_plist(&bytes).expect("pyatv's own output must decode")
}

/// The key names pyatv's dictionary carries, in source order.
fn keys(name: &str) -> Vec<String> {
    KAT["keys"][name]
        .as_array()
        .expect("a key list")
        .iter()
        .map(|key| key.as_str().expect("a key name").to_owned())
        .collect()
}

fn url() -> String {
    text(&["session", "url"])
}

fn position() -> f64 {
    KAT["session"]["position"]
        .as_f64()
        .expect("a numeric position")
}

/// `AirPlayV1.play_url`'s three-key body, from pyatv's own `plistlib` output.
#[test]
fn the_airplay_1_play_body_matches_pyatv() {
    let session_id = text(&["session", "v1_session_id"]);

    assert_eq!(
        bodies::v1_play_body(&url(), position(), &session_id),
        expected("v1_play")
    );
}

/// `AirPlayV2.play_url`'s twenty-one-key body, including every decorative millisecond field.
#[test]
fn the_airplay_2_play_body_matches_pyatv() {
    let uuid = text(&["session", "v2_uuid"]);

    assert_eq!(
        bodies::v2_play_body(&url(), position(), &uuid),
        expected("v2_play")
    );
}

/// `AirPlayV2._setup_base`'s fifteen-key body — the one that is *not* the tunnel's.
#[test]
fn the_airplay_2_base_setup_body_matches_pyatv() {
    let session_uuid = text(&["session", "setup_session_uuid"]);
    let timing_port = KAT["session"]["timing_port"]
        .as_u64()
        .and_then(|port| u16::try_from(port).ok())
        .expect("a port");

    assert_eq!(
        bodies::v2_base_setup_body(timing_port, &session_uuid),
        expected("v2_base_setup")
    );
}

/// The three distinct `setProperty` bodies (`airplayv2.py:246-272`).
#[test]
fn the_set_property_bodies_match_pyatv() {
    let bodies = bodies::set_property_bodies();

    assert_eq!(bodies[0], expected("set_property_true"));
    assert_eq!(bodies[1], expected("set_property_zero"));
    assert_eq!(bodies[2], expected("set_property_end_time"));
    assert_eq!(bodies[3], expected("set_property_end_time"));
}

/// Key *order* as well as key set: a property list is a dictionary, but pyatv's insertion order is
/// what a capture would show and there is no reason to diverge from it.
#[test]
fn the_bodies_carry_pyatvs_keys_in_pyatvs_order() {
    for (name, body) in [
        (
            "v1_play",
            bodies::v1_play_body(&url(), position(), "session"),
        ),
        ("v2_play", bodies::v2_play_body(&url(), position(), "uuid")),
        ("v2_base_setup", bodies::v2_base_setup_body(6002, "session")),
    ] {
        let ours: Vec<String> = body
            .as_dictionary()
            .expect("a dictionary")
            .keys()
            .cloned()
            .collect();

        assert_eq!(ours, keys(name), "{name}");
    }
}

/// The header sets, which are module-level dictionaries upstream and so are read verbatim —
/// values *and* order, since that is what a capture of pyatv would show.
#[test]
fn the_header_sets_match_pyatv() {
    let session_id = text(&["session", "v2_uuid"]);

    for (name, ours) in [
        (
            "v1_play",
            bodies::v1_play_headers()
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>(),
        ),
        (
            "v2_play",
            bodies::v2_play_headers(&session_id)
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>(),
        ),
    ] {
        let theirs: Vec<(String, String)> = KAT["headers"][name]
            .as_array()
            .expect("a header list")
            .iter()
            .map(|pair| {
                let pair = pair.as_array().expect("a name/value pair");
                (
                    pair[0].as_str().expect("a header name").to_owned(),
                    pair[1].as_str().expect("a header value").to_owned(),
                )
            })
            .collect();

        assert_eq!(ours, theirs, "{name}");
    }
}
