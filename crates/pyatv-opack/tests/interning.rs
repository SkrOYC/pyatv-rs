//! Regression tests for the back-reference numbering, including the case pyatv gets wrong.
//!
//! pyatv's encoder and decoder disagree about which values take a slot in the object table, so
//! pyatv can emit payloads it cannot itself parse. This crate aligns both sides on the decoder's
//! rule; these tests pin that alignment down, since the pyatv vectors cannot — every one of them
//! happens to intern its containers after the last value a pointer refers to.

use bytes::Bytes;
use pyatv_opack::{Value, pack, unpack};

fn round_trips(value: &Value) -> Value {
    let bytes = pack(value).expect("value must encode");
    let (decoded, consumed) = unpack(&bytes).expect("our own output must decode");
    assert_eq!(consumed, bytes.len(), "decoder left trailing bytes");
    assert_eq!(
        pack(&decoded).expect("a decoded value must re-encode"),
        bytes,
        "re-encoding must be byte-for-byte identical"
    );
    decoded
}

/// `pack([[1, 2], "a", "a"])`.
///
/// pyatv interns the inner list at index 0 and `"a"` at index 1, emits `0xA1` for the repeated
/// `"a"`, and then fails to decode its own output because its decoder never records the list.
/// Here the list takes no slot, so `"a"` is index 0 and the repeat is `0xA0`.
#[test]
fn containers_do_not_take_a_slot() {
    let value = Value::Array(vec![
        Value::Array(vec![Value::Uint(1), Value::Uint(2)]),
        Value::from("a"),
        Value::from("a"),
    ]);

    let bytes = pack(&value).expect("value must encode");
    assert_eq!(
        &bytes[..],
        [0xD3, 0xD2, 0x09, 0x0A, 0x41, 0x61, 0xA0],
        "the repeat should point at index 0, not index 1"
    );
    assert_eq!(round_trips(&value), value);
}

/// The mirror image: pyatv's encoder skips the empty string because its encoding is one byte
/// long, while its decoder records it, shifting every later index the other way.
#[test]
fn empty_strings_and_byte_strings_take_a_slot() {
    let value = Value::Array(vec![
        Value::from(""),
        Value::from("a"),
        Value::from("a"),
        Value::from(""),
    ]);

    let bytes = pack(&value).expect("value must encode");
    assert_eq!(
        &bytes[..],
        [0xD4, 0x40, 0x41, 0x61, 0xA1, 0xA0],
        "the empty string should occupy index 0"
    );
    assert_eq!(round_trips(&value), value);

    let empty_data = Value::Array(vec![
        Value::Data(Bytes::new()),
        Value::from("a"),
        Value::Data(Bytes::new()),
    ]);
    assert_eq!(
        &pack(&empty_data).expect("value must encode")[..],
        [0xD3, 0x70, 0x41, 0x61, 0xA0]
    );
    assert_eq!(round_trips(&empty_data), empty_data);
}

/// Booleans, null and small integers are never interned, so they must not consume an index.
#[test]
fn one_byte_primitives_do_not_take_a_slot() {
    let value = Value::Array(vec![
        Value::Bool(true),
        Value::Null,
        Value::Uint(0x27),
        Value::from("a"),
        Value::from("a"),
    ]);

    assert_eq!(
        &pack(&value).expect("value must encode")[..],
        [0xD5, 0x01, 0x04, 0x2F, 0x41, 0x61, 0xA0]
    );
    assert_eq!(round_trips(&value), value);
}

/// Values that Python would call equal but Rust does not must each take their own slot, or the
/// byte-keyed encoder table and the value-keyed decoder table drift apart.
#[test]
fn numerically_equal_values_of_different_types_take_separate_slots() {
    let value = Value::Array(vec![
        Value::Float(1.0),
        Value::Uint(0x28),
        Value::from("x"),
        Value::from("x"),
    ]);

    let bytes = pack(&value).expect("value must encode");
    // Float at index 0, the 0x28 integer at index 1, "x" at index 2, so the repeat is 0xA2.
    assert_eq!(bytes.last(), Some(&0xA2));
    assert_eq!(
        round_trips(&value),
        Value::Array(vec![
            Value::Float(1.0),
            Value::SizedUint {
                value: 0x28,
                width: pyatv_opack::UintWidth::One
            },
            Value::from("x"),
            Value::from("x"),
        ])
    );
}

/// The table is shared across the whole document, so a repeat inside a nested container points
/// back at something spelled out in an outer one.
#[test]
fn the_table_spans_the_whole_document() {
    let value = Value::Dict(vec![
        (Value::from("outer"), Value::from("shared")),
        (
            Value::from("inner"),
            Value::Dict(vec![(Value::from("key"), Value::from("shared"))]),
        ),
    ]);

    // "outer" is index 0, "shared" index 1, "inner" index 2, "key" index 3, so the nested repeat
    // of "shared" has to come back as 0xA1.
    assert_eq!(
        &pack(&value).expect("value must encode")[..],
        [
            0xE2, 0x45, 0x6F, 0x75, 0x74, 0x65, 0x72, 0x46, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64,
            0x45, 0x69, 0x6E, 0x6E, 0x65, 0x72, 0xE1, 0x43, 0x6B, 0x65, 0x79, 0xA1,
        ]
    );
    assert_eq!(round_trips(&value), value);
}

/// Every [`pack`] call starts a fresh table, so two documents appended to one buffer never share
/// back-references.
#[test]
fn each_document_starts_a_fresh_table() {
    let document = Value::array(["a", "a"]);
    let once = pack(&document).expect("value must encode");

    let mut twice = bytes::BytesMut::new();
    pyatv_opack::encode(&document, &mut twice).expect("value must encode");
    pyatv_opack::encode(&document, &mut twice).expect("value must encode");

    assert_eq!(&twice[..once.len()], &once[..]);
    assert_eq!(&twice[once.len()..], &once[..]);
}
