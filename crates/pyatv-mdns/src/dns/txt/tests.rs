//! Ported from pyatv `tests/support/test_dns.py`: `test_dns_sd_txt_parse_single`,
//! `_multiple`, `_binary`, `_long` and `test_dns_sd_txt_format`, plus coverage for the
//! `decode_value` / `_decode_properties` pair in pyatv `core/mdns.py`.

use super::{TxtRecords, decode_value, parse_txt, python_bytes_repr};
use crate::dns::{DnsError, Reader};

/// Parse `length` bytes of TXT RDATA out of `data`, returning the map and the end position.
///
/// The pyatv tests append trailing junk after the RDATA to prove the parser stops on the declared
/// length rather than running to the end of the buffer, so the position is asserted every time.
fn parse(data: &[u8], length: usize) -> (TxtRecords, usize) {
    let mut reader = Reader::new(data);
    let records = parse_txt(&mut reader, length).expect("fixture parses");
    (records, reader.position())
}

fn expect(records: &TxtRecords, key: &str, value: &[u8]) {
    assert_eq!(
        records.get(key).map(Vec::as_slice),
        Some(value),
        "key {key}"
    );
}

/// pyatv `test_dns_sd_txt_parse_single`.
#[test]
fn parses_a_single_key() {
    let data = b"\x07foo=bar";
    let mut extra = data.to_vec();
    extra.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef].repeat(3));

    let (records, position) = parse(&extra, data.len());
    assert_eq!(position, data.len());
    assert_eq!(records.len(), 1);
    expect(&records, "foo", b"bar");
}

/// pyatv `test_dns_sd_txt_parse_multiple`.
#[test]
fn parses_multiple_keys() {
    let data = b"\x07foo=bar\x09spam=eggs";
    let mut extra = data.to_vec();
    extra.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef].repeat(2));

    let (records, position) = parse(&extra, data.len());
    assert_eq!(position, data.len());
    assert_eq!(records.len(), 2);
    expect(&records, "foo", b"bar");
    expect(&records, "spam", b"eggs");
}

/// pyatv `test_dns_sd_txt_parse_binary`: `0xFEED` is neither UTF-8 nor ASCII, so a value that is
/// not kept as opaque bytes would blow up here.
#[test]
fn parses_a_binary_value() {
    let data = b"\x06foo=\xfe\xed";
    let mut extra = data.to_vec();
    extra.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef].repeat(3));

    let (records, position) = parse(&extra, data.len());
    assert_eq!(position, data.len());
    expect(&records, "foo", b"\xfe\xed");
}

/// pyatv `test_dns_sd_txt_parse_long`: a 204-byte chunk, longer than any domain label, which would
/// be read as a compression pointer if TXT parsing reused the domain-name code.
#[test]
fn parses_a_long_value() {
    let mut data = vec![0xcc];
    data.extend_from_slice(b"foo=");
    data.extend_from_slice(&[0xca, 0xfe].repeat(100));
    let mut extra = data.clone();
    extra.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef].repeat(3));

    let (records, position) = parse(&extra, data.len());
    assert_eq!(position, data.len());
    expect(&records, "foo", &[0xca, 0xfe].repeat(100));
}

/// pyatv's `parse_txt_dict` rules for the awkward chunks.
#[test]
fn applies_the_pyatv_rules_for_odd_chunks() {
    // No "=" at all: present with an empty value.
    let (records, _) = parse(b"\x04flag", 5);
    expect(&records, "flag", b"");

    // An empty key is skipped entirely.
    let (records, _) = parse(b"\x06=value\x07foo=bar", 15);
    assert_eq!(records.len(), 1);
    expect(&records, "foo", b"bar");

    // A trailing "=" means an empty value, not a missing one.
    let (records, _) = parse(b"\x04foo=", 5);
    expect(&records, "foo", b"");

    // Only the first "=" separates; later ones belong to the value.
    let (records, _) = parse(b"\x0bfoo=a=b=c=d", 12);
    expect(&records, "foo", b"a=b=c=d");

    // A zero-length chunk becomes an empty key with an empty value, as in pyatv.
    let (records, _) = parse(b"\x00", 1);
    assert_eq!(records.len(), 1);
    expect(&records, "", b"");

    // A non-ASCII key in a "key=value" chunk is dropped and parsing continues...
    let (records, _) = parse(b"\x06\xff\xfe=bar\x07foo=bar", 15);
    assert_eq!(records.len(), 1);
    expect(&records, "foo", b"bar");
}

/// The asymmetry in pyatv's `parse_txt_dict`: a non-ASCII *valueless* key is fatal, because that
/// branch decodes without the `try`/`except` the keyed branch has. `core/mdns.py` catches the
/// resulting `UnicodeDecodeError` and drops the whole datagram.
#[test]
fn a_non_ascii_valueless_key_is_fatal() {
    let mut reader = Reader::new(b"\x02\xff\xfe");
    assert!(matches!(
        parse_txt(&mut reader, 3),
        Err(DnsError::NonAsciiTxtKey { .. })
    ));
}

/// pyatv reads straight past the end of the RDATA when a chunk length lies. Refusing is safer and
/// cannot change the outcome for a well-formed record.
#[test]
fn a_chunk_that_overruns_the_record_is_rejected() {
    let mut reader = Reader::new(b"\x20foo=bar\xde\xad\xbe\xef");
    assert!(matches!(
        parse_txt(&mut reader, 8),
        Err(DnsError::TxtChunkOverrunsRecord { .. })
    ));
}

#[test]
fn rdata_longer_than_the_message_is_rejected() {
    let mut reader = Reader::new(b"\x07foo=bar");
    assert!(matches!(
        parse_txt(&mut reader, 64),
        Err(DnsError::UnexpectedEof { .. })
    ));
}

/// Keys are lowercased on insert and looked up case-insensitively, as pyatv's
/// `CaseInsensitiveDict` does.
#[test]
fn keys_are_case_insensitive() {
    let (records, _) = parse(b"\x0cModel=J305AP", 13);
    expect(&records, "model", b"J305AP");
    expect(&records, "MODEL", b"J305AP");
    expect(&records, "MoDeL", b"J305AP");
    assert!(records.contains_key("mOdEl"));
    // The stored key is the lowered form.
    assert_eq!(records.iter().next().map(|(key, _)| key), Some("model"));
}

/// A repeated key replaces the earlier value in place, matching Python's `dict`.
#[test]
fn a_repeated_key_replaces_in_place() {
    let (records, _) = parse(b"\x05a=one\x05b=two\x07A=three", 20);
    assert_eq!(records.len(), 2);
    expect(&records, "a", b"three");
    assert_eq!(
        records.iter().map(|(key, _)| key).collect::<Vec<_>>(),
        ["a", "b"]
    );
}

/// pyatv `test_dns_sd_txt_format`. The two byte/str key permutations in the pyatv parameter list
/// collapse into one case here, because [`TxtRecords`] keys are always `str` and values always
/// bytes.
#[test]
fn formats_a_txt_record() {
    let mut records = TxtRecords::new();
    records.insert("foo", b"bar".to_vec());
    assert_eq!(records.encode(), b"\x07foo=bar");

    records.insert("spam", b"eggs".to_vec());
    assert_eq!(records.encode(), b"\x07foo=bar\x09spam=eggs");
}

#[test]
fn txt_records_round_trip_through_the_wire_form() {
    let mut records = TxtRecords::new();
    records.insert("Model", b"J305AP".to_vec());
    records.insert("flags", b"0x18644".to_vec());
    records.insert("binary", vec![0x00, 0xff, 0x3d, 0xfe]);

    let encoded = records.encode();
    let mut reader = Reader::new(&encoded);
    let decoded = parse_txt(&mut reader, encoded.len()).expect("round-trips");
    assert_eq!(decoded, records);
    assert_eq!(reader.position(), encoded.len());
}

// --- decode_value / _decode_properties -----------------------------------------------------

/// pyatv `core/mdns.py::decode_value`: both non-breaking-space encodings become plain spaces.
#[test]
fn decodes_values_and_folds_non_breaking_spaces() {
    assert_eq!(decode_value(b"bar"), "bar");
    assert_eq!(decode_value(b"Apple\xc2\xa0TV"), "Apple TV");
    assert_eq!(decode_value(b"Apple\x00\xa0TV"), "Apple TV");
    assert_eq!(decode_value(b""), "");
    // Non-ASCII that is valid UTF-8 survives untouched.
    assert_eq!(decode_value("Español".as_bytes()), "Español");
}

/// When the value is not UTF-8, pyatv falls back to `str(value)` — Python's `bytes` repr — and that
/// string is what a user sees in `Service.properties`.
#[test]
fn falls_back_to_the_python_bytes_repr() {
    assert_eq!(decode_value(b"\xfe\xed"), "b'\\xfe\\xed'");
    assert_eq!(decode_value(b"ok\xff"), "b'ok\\xff'");
}

/// `CPython`'s `bytes_repr` rules, which the fallback has to match exactly.
#[test]
fn renders_the_python_bytes_repr_the_way_cpython_does() {
    assert_eq!(python_bytes_repr(b""), "b''");
    assert_eq!(python_bytes_repr(b"abc"), "b'abc'");
    assert_eq!(
        python_bytes_repr(b"\x00\x1f\x7f\x80"),
        "b'\\x00\\x1f\\x7f\\x80'"
    );
    assert_eq!(python_bytes_repr(b"tab\tnl\ncr\r"), "b'tab\\tnl\\ncr\\r'");
    assert_eq!(python_bytes_repr(b"back\\slash"), "b'back\\\\slash'");
    // A double quote is left alone while the quote character is a single quote...
    assert_eq!(python_bytes_repr(b"say \"hi\""), "b'say \"hi\"'");
    // ...an apostrophe with no double quote around switches the quoting instead of escaping...
    assert_eq!(python_bytes_repr(b"it's"), "b\"it's\"");
    // ...and when both are present the single quote wins and gets escaped.
    assert_eq!(python_bytes_repr(b"it's \"x\""), "b'it\\'s \"x\"'");
}

#[test]
fn decodes_every_property() {
    let (records, _) = parse(b"\x0cModel=J305AP\x07name=\xfe\xed", 21);
    let properties = records.decode_properties();
    assert_eq!(properties.get("model").map(String::as_str), Some("J305AP"));
    assert_eq!(
        properties.get("NAME").map(String::as_str),
        Some("b'\\xfe\\xed'")
    );
}

#[test]
fn an_empty_map_reports_itself_empty() {
    let records = TxtRecords::new();
    assert!(records.is_empty());
    assert_eq!(records.len(), 0);
    assert!(records.encode().is_empty());
    assert!(records.decode_properties().is_empty());
}
