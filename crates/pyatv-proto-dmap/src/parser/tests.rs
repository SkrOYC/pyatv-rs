//! Codec known-answers, ported from `tests/protocols/dmap/test_parser.py`.
//!
//! Upstream parses against a thirteen-row synthetic table rather than the real one, so that the
//! codec is tested independently of the tag dictionary. [`TEST_TAGS`] is that table, transcribed
//! from `test_parser.py:10-24`.

use super::{
    DmapEntry, DmapValue, MAX_DEPTH, first, first_str, first_uint, parse, parse_with, pprint,
};
use crate::tags::{
    TagDefinition, TagType, UNKNOWN_TAG, bool_tag, container_tag, raw_tag, string_tag, uint8_tag,
    uint16_tag, uint32_tag, uint64_tag,
};

/// `TEST_TAGS` (`tests/protocols/dmap/test_parser.py:10-24`).
const TEST_TAGS: &[(&str, TagType, &str)] = &[
    ("uuu8", TagType::Uint, "uint8"),
    ("uu16", TagType::Uint, "uint16"),
    ("uu32", TagType::Uint, "uint32"),
    ("uu64", TagType::Uint, "uint64"),
    ("bola", TagType::Bool, "bool"),
    ("bolb", TagType::Bool, "bool"),
    ("stra", TagType::String, "string"),
    ("strb", TagType::String, "string"),
    ("cona", TagType::Container, "container"),
    ("conb", TagType::Container, "container 2"),
    ("igno", TagType::Ignore, "ignore"),
    ("plst", TagType::Bplist, "bplist"),
    ("byte", TagType::Bytes, "bytes"),
];

/// `lookup_tag` for [`TEST_TAGS`] (`test_parser.py:27-28`).
fn lookup_tag(key: &str) -> TagDefinition {
    TEST_TAGS
        .iter()
        .find(|(candidate, _, _)| *candidate == key)
        .map_or(UNKNOWN_TAG, |(_, tag_type, name)| TagDefinition {
            tag_type: *tag_type,
            name,
        })
}

fn parse_test(data: &[u8]) -> Vec<DmapEntry> {
    parse_with(data, &lookup_tag).expect("the fixtures are well formed")
}

/// A minimal binary property list holding `{"key": "value"}`, so the bplist path is exercised
/// without depending on a writer this crate does not have.
fn binary_plist() -> Vec<u8> {
    let mut out = Vec::new();
    let mut dictionary = plist::Dictionary::new();
    dictionary.insert("key".to_owned(), plist::Value::String("value".to_owned()));
    plist::Value::Dictionary(dictionary)
        .to_writer_binary(&mut out)
        .expect("a two-entry plist serialises");
    out
}

/// `test_empty_data` (`test_parser.py:31-32`).
#[test]
fn empty_data_parses_to_nothing() {
    assert_eq!(parse_test(b""), Vec::<DmapEntry>::new());
}

/// `test_parse_uint_of_various_lengths` (`test_parser.py:35-47`) — the whole point of the codec
/// having one reader for four writers.
#[test]
fn uints_of_every_width_read_back() {
    let data = [
        uint8_tag("uuu8", 12),
        uint16_tag("uu16", 37_888),
        uint32_tag("uu32", 305_419_896),
        uint64_tag("uu64", 8_982_983_289_232),
    ]
    .concat();

    let parsed = parse_test(&data);
    assert_eq!(parsed.len(), 4);
    assert_eq!(first_uint(&parsed, &["uuu8"]), Some(12));
    assert_eq!(first_uint(&parsed, &["uu16"]), Some(37_888));
    assert_eq!(first_uint(&parsed, &["uu32"]), Some(305_419_896));
    assert_eq!(first_uint(&parsed, &["uu64"]), Some(8_982_983_289_232));
}

/// `test_parse_bool` (`test_parser.py:50-55`).
#[test]
fn booleans_read_back() {
    let data = [bool_tag("bola", true), bool_tag("bolb", false)].concat();

    let parsed = parse_test(&data);
    assert_eq!(parsed.len(), 2);
    assert_eq!(
        first(&parsed, &["bola"]).and_then(DmapValue::as_bool),
        Some(true)
    );
    assert_eq!(
        first(&parsed, &["bolb"]).and_then(DmapValue::as_bool),
        Some(false)
    );
}

/// `read_bool` is `read_uint(...) == 1` at *any* width (`tags.py:17-19`), so a two-byte `0x0001` is
/// `true` and everything that is not exactly one is `false`. There is no "not a boolean".
#[test]
fn booleans_are_not_width_specific() {
    for (encoded, expected) in [
        (uint8_tag("bola", 1), true),
        (uint16_tag("bola", 1), true),
        (uint32_tag("bola", 1), true),
        (uint8_tag("bola", 0), false),
        (uint8_tag("bola", 2), false),
        (uint32_tag("bola", 0x0001_0000), false),
    ] {
        let parsed = parse_test(&encoded);
        assert_eq!(
            first(&parsed, &["bola"]).and_then(DmapValue::as_bool),
            Some(expected),
            "{encoded:?}"
        );
    }
}

/// `test_parse_strings` (`test_parser.py:58-63`), including the empty string.
#[test]
fn strings_read_back() {
    let data = [string_tag("stra", ""), string_tag("strb", "test string")].concat();

    let parsed = parse_test(&data);
    assert_eq!(parsed.len(), 2);
    assert_eq!(first_str(&parsed, &["stra"]), Some(""));
    assert_eq!(first_str(&parsed, &["strb"]), Some("test string"));
}

/// `test_parse_binary_plist` (`test_parser.py:66-71`).
#[test]
fn binary_plists_read_back() {
    let parsed = parse_test(&raw_tag("plst", &binary_plist()));

    assert_eq!(parsed.len(), 1);
    let value = first(&parsed, &["plst"])
        .and_then(DmapValue::as_plist)
        .expect("plst decodes");
    assert_eq!(
        value.as_dictionary().and_then(|it| it.get("key")),
        Some(&plist::Value::String("value".to_owned()))
    );
}

/// `test_parse_bytes` (`test_parser.py:74-78`) — the known-answer for `read_bytes`' rendering.
#[test]
fn bytes_render_as_lowercase_hex() {
    let parsed = parse_test(&raw_tag("byte", b"\x01\xaa\xff\x45"));

    assert_eq!(parsed.len(), 1);
    assert_eq!(first_str(&parsed, &["byte"]), Some("0x01aaff45"));
}

/// `test_parse_value_in_container` (`test_parser.py:81-90`).
#[test]
fn values_inside_a_container_read_back() {
    let inner = [uint8_tag("uuu8", 36), uint16_tag("uu16", 13_000)].concat();
    let parsed = parse_test(&container_tag("cona", &inner));

    assert_eq!(parsed.len(), 1);
    let nested = first(&parsed, &["cona"])
        .and_then(DmapValue::as_container)
        .expect("cona is a container");
    assert_eq!(nested.len(), 2);
    assert_eq!(first_uint(nested, &["uuu8"]), Some(36));
    assert_eq!(first_uint(nested, &["uu16"]), Some(13_000));
}

/// `test_extract_simplified_container` (`test_parser.py:93-98`): the multi-level path lookup.
#[test]
fn a_path_walks_through_nested_containers() {
    let inner = container_tag("conb", &uint8_tag("uuu8", 12));
    let parsed = parse_test(&container_tag("cona", &inner));

    assert_eq!(first_uint(&parsed, &["cona", "conb", "uuu8"]), Some(12));
}

/// `test_ignore_value` (`test_parser.py:101-104`): an ignored tag parses to nothing, not an error.
#[test]
fn an_ignored_tag_has_no_value() {
    let parsed = parse_test(&uint8_tag("igno", 44));

    assert_eq!(parsed.len(), 1);
    assert!(
        first(&parsed, &["igno"]).is_some_and(DmapValue::is_none),
        "an ignored tag is present but valueless"
    );
}

/// An unknown key is a `None` value the walker still steps past, so following tags still parse
/// (`tag_definitions.py:19-20,127-132`).
#[test]
fn an_unknown_tag_does_not_stop_the_walk() {
    let data = [raw_tag("zzzz", b"\x01\x02\x03"), uint8_tag("uuu8", 7)].concat();

    let parsed = parse_test(&data);
    assert_eq!(parsed.len(), 2);
    assert!(parsed[0].value.is_none());
    assert_eq!(first_uint(&parsed, &["uuu8"]), Some(7));
}

/// `test_simple_pprint` (`test_parser.py:107-116`), byte for byte.
#[test]
fn pprint_matches_pyatvs_layout() {
    let inner = container_tag("conb", &uint8_tag("uuu8", 12));
    let parsed = parse_test(&container_tag("cona", &inner));

    assert_eq!(
        pprint(&parsed, &lookup_tag),
        concat!(
            "cona: [container, container]\n",
            "  conb: [container, container 2]\n",
            "    uuu8: 12 [uint, uint8]\n",
        )
    );
}

/// Repeated keys are how DMAP encodes lists, so they must not collapse into one another.
#[test]
fn repeated_keys_are_kept_in_order() {
    let data = [uint8_tag("uuu8", 1), uint8_tag("uuu8", 2)].concat();

    let parsed = parse_test(&data);
    assert_eq!(parsed.len(), 2);
    assert_eq!(
        first_uint(&parsed, &["uuu8"]),
        Some(1),
        "`first` means the first, not the only"
    );
    assert_eq!(parsed[1].value.as_uint(), Some(2));
}

/// Upstream's over-run rule: a path that continues past a leaf returns the leaf, not `None`
/// (`parser.py:56-65`).
#[test]
fn a_path_that_overruns_a_leaf_returns_the_leaf() {
    let parsed = parse_test(&uint8_tag("uuu8", 12));

    assert_eq!(first_uint(&parsed, &["uuu8", "nope"]), Some(12));
    assert!(first(&parsed, &["nope"]).is_none());
    assert!(first(&parsed, &[]).is_none());
}

/// pyatv reads past the end of the buffer without complaint; refusing is strictly safer and cannot
/// change the result for a well-formed message.
#[test]
fn truncated_payloads_are_rejected() {
    for bad in [
        b"cmpg\x00\x00".as_slice(),
        b"cmpg\x00\x00\x00\x08\x01\x02".as_slice(),
        b"cmst\x00\x00\x00\x0ccaps\x00\x00\x00\x08\x00".as_slice(),
    ] {
        assert!(parse(bad).is_err(), "{bad:?} should be rejected");
    }
}

/// A tag key that is not UTF-8 cannot be looked up, so it is an error rather than a silent skip.
#[test]
fn a_non_utf8_key_is_rejected() {
    assert!(parse(b"\xff\xfe\xfd\xfc\x00\x00\x00\x00").is_err());
}

/// No DMAP writer produces an integer wider than eight bytes, and truncating one silently would
/// hide a malformed response.
#[test]
fn an_oversized_integer_is_rejected() {
    let oversized = raw_tag("caps", &[0u8; 9]);
    assert!(parse(&oversized).is_err());
}

/// A hostile response must not be able to overflow the stack.
#[test]
fn nesting_is_depth_capped() {
    let mut payload = uint8_tag("uuu8", 1);
    for _ in 0..=MAX_DEPTH {
        payload = container_tag("cona", &payload);
    }

    assert!(parse_with(&payload, &lookup_tag).is_err());
}

/// The real table, exercised end to end on the shape a device actually sends.
#[test]
fn a_playstatus_response_parses_against_the_real_table() {
    let body = [
        uint32_tag("caps", 4),
        string_tag("cann", "dummy"),
        uint32_tag("cmsr", 1),
    ]
    .concat();
    let parsed = parse(&container_tag("cmst", &body)).expect("well formed");

    assert_eq!(first_uint(&parsed, &["cmst", "caps"]), Some(4));
    assert_eq!(first_str(&parsed, &["cmst", "cann"]), Some("dummy"));
    assert_eq!(first_uint(&parsed, &["cmst", "cmsr"]), Some(1));
}
