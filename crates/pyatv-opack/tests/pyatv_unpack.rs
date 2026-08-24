//! Decoder vectors ported one-for-one from pyatv's `tests/support/test_opack.py`.
//!
//! pyatv returns `(value, remaining_bytes)`; this crate returns `(value, bytes_consumed)`, so
//! `assert ... == (x, b"")` becomes an assertion that the whole input was consumed.

use bytes::Bytes;
use pyatv_opack::{Error, UintWidth, Value, unpack};

const MORE_PTR: &[u8] = include_bytes!("fixtures/more_ptr.opack");

/// Decode `input` and assert it was consumed in full, as every pyatv vector expects.
fn whole(input: &[u8]) -> Value {
    let (value, consumed) = unpack(input).expect("vector must decode");
    assert_eq!(consumed, input.len(), "vector left trailing bytes");
    value
}

fn sized(value: u64, width: UintWidth) -> Value {
    Value::SizedUint { value, width }
}

fn string_of(unit: char, count: usize) -> Value {
    Value::from(std::iter::repeat_n(unit, count).collect::<String>())
}

fn data_of(byte: u8, count: usize) -> Value {
    Value::Data(Bytes::from(vec![byte; count]))
}

/// `test_opack.py:205-207`.
#[test]
fn unpack_unsupported_type() {
    assert_eq!(
        unpack(&[0x00]),
        Err(Error::UnknownTag {
            tag: 0x00,
            offset: 0
        })
    );
}

/// `test_opack.py:210-213`.
#[test]
fn unpack_boolean() {
    assert_eq!(whole(&[0x01]), Value::Bool(true));
    assert_eq!(whole(&[0x02]), Value::Bool(false));
}

/// `test_opack.py:215-217`.
#[test]
fn unpack_none() {
    assert_eq!(whole(&[0x04]), Value::Null);
}

/// `test_opack.py:219-223`.
#[test]
fn unpack_uuid() {
    let bytes = [
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56,
        0x78,
    ];
    let mut input = vec![0x05];
    input.extend(bytes);
    assert_eq!(whole(&input), Value::Uuid(bytes));
}

/// `test_opack.py:226-228`, where pyatv notes "this is not implemented, it only parses the time
/// stamp as an integer". This crate keeps the timestamp in a distinct variant so it cannot be
/// re-encoded as an ordinary integer.
#[test]
fn unpack_absolute_time() {
    assert_eq!(
        whole(&[0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        Value::AbsoluteTime(1)
    );
}

/// `test_opack.py:231-234`.
#[test]
fn unpack_small_integers() {
    assert_eq!(whole(&[0x08]), Value::Uint(0));
    assert_eq!(whole(&[0x17]), Value::Uint(0xF));
    assert_eq!(whole(&[0x2F]), Value::Uint(0x27));
}

/// `test_opack.py:237-241`.
#[test]
fn unpack_larger_integers() {
    assert_eq!(whole(&[0x30, 0x28]), sized(0x28, UintWidth::One));
    assert_eq!(whole(&[0x31, 0xFF, 0x01]), sized(0x1FF, UintWidth::Two));
    assert_eq!(
        whole(&[0x32, 0xFF, 0xFF, 0xFF, 0x01]),
        sized(0x01FF_FFFF, UintWidth::Four)
    );
    assert_eq!(
        whole(&[0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]),
        sized(0x01FF_FFFF_FFFF_FFFF, UintWidth::Eight)
    );
}

/// `test_opack.py:244-248`: pyatv checks the `size` attribute its `_sized_int` attaches.
#[test]
fn unpack_sized_integers() {
    assert_eq!(whole(&[0x30, 0x01]), sized(1, UintWidth::One));
    assert_eq!(whole(&[0x31, 0x01, 0x00]), sized(1, UintWidth::Two));
    assert_eq!(
        whole(&[0x32, 0x01, 0x00, 0x00, 0x00]),
        sized(1, UintWidth::Four)
    );
    assert_eq!(
        whole(&[0x33, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        sized(1, UintWidth::Eight)
    );
}

/// `test_opack.py:251-252` (named `test_pack_unfloat32` upstream, but it decodes).
#[test]
fn unpack_float32() {
    assert_eq!(whole(&[0x35, 0x00, 0x00, 0x80, 0x3F]), Value::Float32(1.0));
}

/// `test_opack.py:255-256`.
#[test]
fn unpack_float64() {
    assert_eq!(
        whole(&[0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F]),
        Value::Float(1.0)
    );
}

/// `test_opack.py:259-262`.
#[test]
fn unpack_short_strings() {
    assert_eq!(whole(&[0x41, 0x61]), Value::from("a"));
    assert_eq!(whole(&[0x43, 0x61, 0x62, 0x63]), Value::from("abc"));

    let mut input = vec![0x60];
    input.extend(std::iter::repeat_n(0x61, 0x20));
    assert_eq!(whole(&input), string_of('a', 0x20));
}

/// `test_opack.py:265-267`.
#[test]
fn unpack_longer_strings() {
    let mut input = vec![0x61, 0x21];
    input.extend(std::iter::repeat_n(0x61, 33));
    assert_eq!(whole(&input), string_of('a', 33));

    let mut input = vec![0x62, 0x00, 0x01];
    input.extend(std::iter::repeat_n(0x61, 256));
    assert_eq!(whole(&input), string_of('a', 256));
}

/// `test_opack.py:270-273`.
#[test]
fn unpack_short_raw_bytes() {
    assert_eq!(whole(&[0x71, 0xAC]), data_of(0xAC, 1));
    assert_eq!(
        whole(&[0x73, 0x12, 0x34, 0x56]),
        Value::Data(Bytes::from_static(&[0x12, 0x34, 0x56]))
    );

    let mut input = vec![0x90];
    input.extend(std::iter::repeat_n(0xAD, 0x20));
    assert_eq!(whole(&input), data_of(0xAD, 0x20));
}

/// `test_opack.py:276-279`.
#[test]
fn unpack_longer_raw_bytes() {
    let mut input = vec![0x91, 0x21];
    input.extend(std::iter::repeat_n(0x61, 33));
    assert_eq!(whole(&input), data_of(0x61, 33));

    let mut input = vec![0x92, 0x00, 0x01];
    input.extend(std::iter::repeat_n(0x61, 256));
    assert_eq!(whole(&input), data_of(0x61, 256));

    let mut input = vec![0x93, 0x00, 0x00, 0x01, 0x00];
    input.extend(std::iter::repeat_n(0x61, 65536));
    assert_eq!(whole(&input), data_of(0x61, 65536));
}

/// `test_opack.py:282-285`.
#[test]
fn unpack_array() {
    assert_eq!(whole(&[0xD0]), Value::Array(Vec::new()));
    assert_eq!(
        whole(&[0xD3, 0x09, 0x44, 0x74, 0x65, 0x73, 0x74, 0x02]),
        Value::Array(vec![
            Value::Uint(1),
            Value::from("test"),
            Value::Bool(false)
        ])
    );
    assert_eq!(
        whole(&[0xD1, 0xD1, 0x01]),
        Value::Array(vec![Value::Array(vec![Value::Bool(true)])])
    );
}

/// `test_opack.py:288-292`: the object table is shared across sibling containers, so the second
/// open-ended list's back-references start at index 1.
#[test]
fn unpack_endless_array() {
    let mut list1 = vec![0xDF, 0x41, 0x61];
    list1.extend(std::iter::repeat_n(0xA0, 15));
    list1.push(0x03);
    let mut list2 = vec![0xDF, 0x41, 0x62];
    list2.extend(std::iter::repeat_n(0xA1, 15));
    list2.push(0x03);

    assert_eq!(whole(&list1), Value::array(["a"; 16]));

    let mut nested = vec![0xD2];
    nested.extend(&list1);
    nested.extend(&list2);
    assert_eq!(
        whole(&nested),
        Value::Array(vec![Value::array(["a"; 16]), Value::array(["b"; 16])])
    );
}

/// `test_opack.py:295-298`.
#[test]
fn unpack_dict() {
    assert_eq!(whole(&[0xE0]), Value::Dict(Vec::new()));
    assert_eq!(
        whole(&[0xE2, 0x41, 0x61, 0x14, 0x02, 0x04]),
        Value::Dict(vec![
            (Value::from("a"), Value::Uint(12)),
            (Value::Bool(false), Value::Null),
        ])
    );
    assert_eq!(
        whole(&[0xE1, 0x01, 0xE1, 0x41, 0x61, 0x0A]),
        Value::Dict(vec![(
            Value::Bool(true),
            Value::Dict(vec![(Value::from("a"), Value::Uint(2))]),
        )])
    );
}

/// `test_opack.py:301-304`.
#[test]
fn unpack_endless_dict() {
    let mut input = vec![0xEF];
    for code in 97u8..127 {
        input.extend([0x41, code]);
    }
    input.push(0x03);

    let expected: Vec<(Value, Value)> = (97u8..127)
        .step_by(2)
        .map(|code| {
            (
                Value::from(char::from(code).to_string()),
                Value::from(char::from(code + 1).to_string()),
            )
        })
        .collect();
    assert_eq!(whole(&input), Value::Dict(expected));
}

/// `test_opack.py:307-316`.
#[test]
fn unpack_ptr() {
    assert_eq!(whole(&[0xD2, 0x41, 0x61, 0xA0]), Value::array(["a", "a"]));
    assert_eq!(
        whole(&[
            0xD4, 0x43, 0x66, 0x6F, 0x6F, 0x43, 0x62, 0x61, 0x72, 0xA0, 0xA1
        ]),
        Value::array(["foo", "bar", "foo", "bar"])
    );
    assert_eq!(
        whole(&[
            0xE3, 0x41, 0x61, 0x41, 0x62, 0x41, 0x63, 0xE1, 0x41, 0x64, 0xA0, 0xA3, 0x01
        ]),
        Value::Dict(vec![
            (Value::from("a"), Value::from("b")),
            (
                Value::from("c"),
                Value::Dict(vec![(Value::from("d"), Value::from("a"))]),
            ),
            (Value::from("d"), Value::Bool(true)),
        ])
    );
}

/// `test_opack.py:319-393`, decoding the same 1127-byte fixture `pack_more_ptr` produces.
#[test]
fn unpack_more_ptr() {
    let data: Vec<Value> = (0..257u32)
        .map(|code| {
            let character = char::from_u32(code).expect("code points below 0x101 are all valid");
            Value::Data(Bytes::from(character.to_string().into_bytes()))
        })
        .collect();
    let mut expected = data.clone();
    expected.extend(data);

    assert_eq!(whole(MORE_PTR), Value::Array(expected));
}

/// `test_opack.py:396-400`.
///
/// Note the index widths: `0xC1..=0xC4` carry `tag - 0xC0` bytes, i.e. 1/2/**3**/**4** — not the
/// 1/2/4/8 that pyatv's own encoder writes and that `docs/research/mrp-companion.md` §4.5
/// records. These four vectors are what pin the decoder to the 1/2/3/4 reading.
#[test]
fn unpack_uid() {
    let expected = Value::Array(vec![
        sized(1, UintWidth::One),
        sized(2, UintWidth::One),
        sized(2, UintWidth::One),
    ]);
    assert_eq!(
        whole(&[0xDF, 0x30, 0x01, 0x30, 0x02, 0xC1, 0x01, 0x03]),
        expected
    );
    assert_eq!(
        whole(&[0xDF, 0x30, 0x01, 0x30, 0x02, 0xC2, 0x01, 0x00, 0x03]),
        expected
    );
    assert_eq!(
        whole(&[0xDF, 0x30, 0x01, 0x30, 0x02, 0xC3, 0x01, 0x00, 0x00, 0x03]),
        expected
    );
    assert_eq!(
        whole(&[
            0xDF, 0x30, 0x01, 0x30, 0x02, 0xC4, 0x01, 0x00, 0x00, 0x00, 0x03
        ]),
        expected
    );
}
