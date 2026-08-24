//! Ported from pyatv `tests/support/test_dns.py`:
//! `test_happy_service_instance_names`, `test_sad_service_instance_names`, `test_qname_encode`,
//! `test_domain_name_parsing` and `test_string_parsing`, with their fixtures byte for byte.

use super::{
    NameCompressor, ServiceInstanceName, encode_name, encode_name_labels, name_to_labels,
    parse_character_string, parse_name,
};
use crate::dns::{DnsError, Reader};

fn encoded(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    encode_name(name, &mut out);
    out
}

fn encoded_labels(labels: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    encode_name_labels(labels, &mut out);
    out
}

fn parse_at(raw: &[u8], offset: usize) -> (String, usize) {
    let mut reader = Reader::new(raw);
    reader.seek(offset).expect("offset is inside the fixture");
    let name = parse_name(&mut reader).expect("fixture parses");
    (name, reader.position())
}

// --- ServiceInstanceName -------------------------------------------------------------------

/// pyatv `test_happy_service_instance_names`, ids `ptr`, `no_dot`, `with_dot`.
#[test]
fn splits_happy_service_instance_names() {
    let cases = [
        ("_http._tcp.local", None, "_http._tcp", "local"),
        ("foo._http._tcp.local", Some("foo"), "_http._tcp", "local"),
        (
            "foo.bar._http._tcp.local",
            Some("foo.bar"),
            "_http._tcp",
            "local",
        ),
    ];

    for (name, instance, service, domain) in cases {
        let split = ServiceInstanceName::split_name(name).expect("is a service name");
        assert_eq!(split.instance.as_deref(), instance, "instance of {name}");
        assert_eq!(split.service, service, "service of {name}");
        assert_eq!(split.domain, domain, "domain of {name}");
    }
}

/// pyatv `test_sad_service_instance_names`, ids `no_proto`, `no_service`, `split`, `reversed`.
#[test]
fn rejects_names_that_are_not_service_names() {
    for name in [
        "_http.local",
        "._tcp.local",
        "_http.foo._tcp.local",
        "_tcp._http.local",
    ] {
        assert!(
            matches!(
                ServiceInstanceName::split_name(name),
                Err(DnsError::NotAServiceName { .. })
            ),
            "{name} should not split"
        );
    }
}

/// A name with fewer than two labels cannot contain a `_service._proto` pair.
#[test]
fn rejects_names_with_too_few_labels() {
    assert!(ServiceInstanceName::split_name("local").is_err());
    assert!(ServiceInstanceName::split_name("").is_err());
}

/// The protocol label is matched case-insensitively, as `next_label.lower()` does in pyatv.
#[test]
fn matches_the_protocol_label_case_insensitively() {
    let split = ServiceInstanceName::split_name("Foo._HTTP._TCP.local").expect("is a service name");
    assert_eq!(split.instance.as_deref(), Some("Foo"));
    assert_eq!(split.service, "_HTTP._TCP");
}

#[test]
fn rebuilds_the_ptr_name_and_the_full_name() {
    let split = ServiceInstanceName::split_name("Living.Room._airplay._tcp.local").unwrap();
    assert_eq!(split.ptr_name(), "_airplay._tcp.local");
    assert_eq!(split.to_string(), "Living.Room._airplay._tcp.local");

    // pyatv's `__str__` filters out empty components, so a missing instance or domain vanishes.
    let ptr = ServiceInstanceName::split_name("_airplay._tcp.local").unwrap();
    assert_eq!(ptr.to_string(), "_airplay._tcp.local");
    let no_domain = ServiceInstanceName::split_name("foo._airplay._tcp").unwrap();
    assert_eq!(no_domain.domain, "");
    assert_eq!(no_domain.to_string(), "foo._airplay._tcp");
}

// --- qname_encode --------------------------------------------------------------------------

/// pyatv `test_qname_encode`, every entry of its `encode_domain_names` table.
#[test]
fn encodes_domain_names_like_pyatv() {
    // ids: root, empty, example.com, unicode
    assert_eq!(encoded("."), b"\x00");
    assert_eq!(encoded(""), b"\x00");
    assert_eq!(encoded("example.com"), b"\x07example\x03com\x00");
    assert_eq!(
        encoded("Bücher.example"),
        b"\x07B\xc3\xbccher\x07example\x00"
    );

    // id: example.com_list
    assert_eq!(
        encoded_labels(&["example", "com"]),
        b"\x07example\x03com\x00"
    );

    // ids: dotted_instance, dotted_instance_list — the instance label keeps its dot.
    let dotted = b"\x0aDot.Within\x05_http\x04_tcp\x07example\x05local\x00";
    assert_eq!(encoded("Dot.Within._http._tcp.example.local"), dotted);
    assert_eq!(
        encoded_labels(&["Dot.Within", "_http", "_tcp", "example", "local"]),
        dotted
    );
}

/// pyatv `test_qname_encode`, id `truncated_ascii`: a 104-byte label is cut to 63 bytes.
#[test]
fn truncates_an_over_long_ascii_label() {
    let long = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
                abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.test";
    assert_eq!(
        encoded(long),
        b"\x3fabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijk\x04test\x00"
    );
}

/// pyatv `test_qname_encode`, id `truncated_unicode`.
///
/// Two things at once: the input is NFD (か + U+3099) and must be composed to NFC before encoding,
/// and truncation must land on a codepoint boundary rather than at exactly 63 bytes. The leading
/// `a` is what forces 63 to fall inside a three-byte kana, so the label ends up 61 bytes long.
#[test]
fn composes_to_nfc_and_truncates_on_a_codepoint_boundary() {
    let name = "a\u{304B}\u{3099}\u{3042}\u{3044}\u{3046}\u{3048}\u{304A}\u{304B}\u{304D}\u{304F}\
                \u{3051}\u{3053}\u{3055}\u{3057}\u{3059}\u{305B}\u{305D}\u{305F}\u{3061}\u{3064}\
                \u{3066}\u{3068}\u{306A}\u{306B}\u{306C}\u{306D}\u{306E}\u{306F}\u{3072}\u{3075}\
                \u{3078}\u{307B}\u{307E}\u{307F}\u{3080}\u{3081}\u{3082}.test";

    let expected: &[u8] = b"\x3d\
        a\xe3\x81\x8c\xe3\x81\x82\xe3\x81\x84\xe3\x81\x86\xe3\x81\x88\xe3\x81\x8a\
        \xe3\x81\x8b\xe3\x81\x8d\xe3\x81\x8f\xe3\x81\x91\xe3\x81\x93\xe3\x81\x95\
        \xe3\x81\x97\xe3\x81\x99\xe3\x81\x9b\xe3\x81\x9d\xe3\x81\x9f\xe3\x81\xa1\
        \xe3\x81\xa4\xe3\x81\xa6\
        \x04test\
        \x00";

    assert_eq!(encoded(name), expected);
}

/// An empty label ends the name; pyatv breaks out of its encode loop there.
#[test]
fn stops_encoding_at_the_first_empty_label() {
    assert_eq!(encoded_labels(&["foo", "", "bar"]), b"\x03foo\x00");
}

#[test]
fn a_label_sequence_without_a_root_gets_one() {
    assert_eq!(name_to_labels("example.com"), ["example", "com", ""]);
    assert_eq!(name_to_labels("example.com."), ["example", "com", ""]);
}

// --- parse_domain_name ---------------------------------------------------------------------

/// pyatv `test_domain_name_parsing`, every entry of its `decode_domain_names` table.
///
/// The expected end position matters as much as the name: after a compressed name the cursor has to
/// come back to just past the pointer so the caller can keep parsing.
#[test]
fn parses_domain_names_like_pyatv() {
    // id: simple
    let raw = b"\x03foo\x07example\x03com\x00";
    assert_eq!(parse_at(raw, 0), ("foo.example.com".into(), raw.len()));

    // id: null
    assert_eq!(parse_at(b"\x00", 0), (String::new(), 1));

    // id: compressed — ends two bytes from the end, just past the pointer.
    let raw = b"aaaa\x04test\x00\x05label\xc0\x04\xab\xcd";
    assert_eq!(parse_at(raw, 10), ("label.test".into(), raw.len() - 2));

    // id: multi_compressed — two levels of compression, still ends just past the *first* pointer.
    let raw = b"aaaa\x04test\x00\x05label\xc0\x04\x03foo\xc0\x0a\xab\xcd";
    assert_eq!(parse_at(raw, 18), ("foo.label.test".into(), raw.len() - 2));

    // id: idna
    let raw = b"\x0dxn--bcher-kva\x07example\x00";
    assert_eq!(parse_at(raw, 0), ("bücher.example".into(), raw.len()));

    // id: nbsp — pyatv issue #919, Apple puts U+00A0 between "Apple" and "TV".
    let raw = b"\x10Apple\xc2\xa0TV (4167)\x05local\x00";
    assert_eq!(
        parse_at(raw, 0),
        ("Apple\u{a0}TV (4167).local".into(), raw.len())
    );

    // id: unicode — non-ASCII plus a dot inside the instance label.
    let raw = b"\x1d\xe5\xb1\x85\xe9\x96\x93 Apple\xc2\xa0TV. En Espa\xc3\xb1ol\x05local\x00";
    assert_eq!(
        parse_at(raw, 0),
        ("居間 Apple\u{a0}TV. En Español.local".into(), raw.len())
    );
}

/// pyatv asserts on the reserved label types and loops forever on a self-referential pointer.
/// Neither is acceptable for data that arrives from the network.
#[test]
fn malformed_names_produce_errors_not_panics() {
    // A pointer to itself.
    let mut reader = Reader::new(b"\xc0\x00");
    assert_eq!(parse_name(&mut reader), Err(DnsError::CompressionLoop));

    // A two-pointer cycle.
    let mut reader = Reader::new(b"\xc0\x02\xc0\x00");
    assert_eq!(parse_name(&mut reader), Err(DnsError::CompressionLoop));

    // Label type 0b01 is reserved.
    let mut reader = Reader::new(b"\x40\x00");
    assert_eq!(
        parse_name(&mut reader),
        Err(DnsError::ReservedLabelType { flags: 1 })
    );
    // ...and so is 0b10.
    let mut reader = Reader::new(b"\x80\x00");
    assert_eq!(
        parse_name(&mut reader),
        Err(DnsError::ReservedLabelType { flags: 2 })
    );

    // A pointer past the end of the message.
    let mut reader = Reader::new(b"\xc0\xff");
    assert!(matches!(
        parse_name(&mut reader),
        Err(DnsError::OffsetOutOfBounds { .. })
    ));

    // A label longer than what is left.
    let mut reader = Reader::new(b"\x10abc");
    assert!(matches!(
        parse_name(&mut reader),
        Err(DnsError::UnexpectedEof { .. })
    ));

    // A name with no terminator at all.
    let mut reader = Reader::new(b"\x03foo");
    assert!(matches!(
        parse_name(&mut reader),
        Err(DnsError::UnexpectedEof { .. })
    ));

    // A label that is not valid UTF-8.
    let mut reader = Reader::new(b"\x02\xff\xfe\x00");
    assert!(matches!(
        parse_name(&mut reader),
        Err(DnsError::LabelNotUtf8 { .. })
    ));

    // An ACE label whose payload is not punycode.
    let mut reader = Reader::new(b"\x06xn--!!\x00");
    assert!(matches!(
        parse_name(&mut reader),
        Err(DnsError::InvalidPunycode { .. })
    ));
}

// --- parse_string --------------------------------------------------------------------------

/// pyatv `test_string_parsing`, every entry of its `decode_strings` table.
///
/// The point of the 63/64/128/192/255 cases is that a character-string length byte has no
/// compression flags, so lengths that would be a pointer in a domain name are ordinary here.
#[test]
fn parses_character_strings_like_pyatv() {
    fn parse(raw: &[u8]) -> (Vec<u8>, usize) {
        let mut reader = Reader::new(raw);
        let value = parse_character_string(&mut reader).expect("fixture parses");
        (value.to_vec(), reader.position())
    }

    // id: null
    assert_eq!(parse(b"\x00"), (Vec::new(), 1));

    for length in [63usize, 64, 128, 192, 255] {
        let mut raw = vec![u8::try_from(length).unwrap()];
        raw.extend(std::iter::repeat_n(b'0', length));
        assert_eq!(
            parse(&raw),
            (vec![b'0'; length], length + 1),
            "character-string of length {length}"
        );
    }

    // id: trailing — only the declared bytes are consumed.
    let mut raw = vec![0x0a];
    raw.extend(std::iter::repeat_n(b'2', 10));
    raw.extend(std::iter::repeat_n(b'9', 17));
    assert_eq!(parse(&raw), (vec![b'2'; 10], 11));
}

#[test]
fn a_truncated_character_string_is_an_error() {
    let mut reader = Reader::new(b"\x0aabc");
    assert!(matches!(
        parse_character_string(&mut reader),
        Err(DnsError::UnexpectedEof { .. })
    ));
}

// --- compression on the way out ------------------------------------------------------------

/// The compressor has no pyatv counterpart; these pin the invariant that whatever it writes,
/// [`parse_name`] reads back unchanged.
#[test]
fn compresses_shared_suffixes_and_round_trips() {
    let mut out = vec![0u8; crate::dns::HEADER_LENGTH];
    let mut compressor = NameCompressor::new();

    compressor.encode("_airplay._tcp.local", &mut out);
    let after_first = out.len();
    compressor.encode("Living Room._airplay._tcp.local", &mut out);
    let after_second = out.len();
    compressor.encode("_airplay._tcp.local", &mut out);

    // The second name adds its instance label plus a two-byte pointer, not the whole suffix.
    assert_eq!(after_second - after_first, 1 + "Living Room".len() + 2);
    // The third is a bare pointer back to the first.
    assert_eq!(out.len() - after_second, 2);

    let mut reader = Reader::new(&out);
    reader.seek(crate::dns::HEADER_LENGTH).unwrap();
    assert_eq!(parse_name(&mut reader).unwrap(), "_airplay._tcp.local");
    assert_eq!(
        parse_name(&mut reader).unwrap(),
        "Living Room._airplay._tcp.local"
    );
    assert_eq!(parse_name(&mut reader).unwrap(), "_airplay._tcp.local");
    assert_eq!(reader.position(), out.len());
}

/// A name written past offset 0x3FFF cannot be pointed at; the compressor must fall back to writing
/// it in full rather than emitting a truncated pointer.
#[test]
fn does_not_point_past_the_fourteen_bit_offset_limit() {
    let mut out = vec![0u8; 0x4000];
    let mut compressor = NameCompressor::new();
    compressor.encode("example.com", &mut out);
    let first = out.len();
    compressor.encode("example.com", &mut out);

    assert_eq!(out.len() - first, first - 0x4000, "written in full twice");
}
