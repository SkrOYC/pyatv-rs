//! Encoder vectors ported one-for-one from pyatv's `tests/support/test_opack.py`.
//!
//! Every expected byte string is copied verbatim from the Python source; the Rust test name is the
//! Python test name with the `test_` prefix dropped, and each carries the Python line range it
//! came from.

use bytes::Bytes;
use pyatv_opack::{Error, UintWidth, Value, pack};

/// The exact expected output of `test_pack_more_ptr` (`test_opack.py:126-199`), extracted from the
/// Python literal.
const MORE_PTR: &[u8] = include_bytes!("fixtures/more_ptr.opack");

fn packed(value: &Value) -> Vec<u8> {
    pack(value).expect("value must be encodable").to_vec()
}

fn repeat_string(unit: &str, count: usize) -> Value {
    Value::from(unit.repeat(count))
}

fn repeat_data(byte: u8, count: usize) -> Value {
    Value::Data(Bytes::from(vec![byte; count]))
}

/// `test_opack.py:17-19`.
///
/// Python raises `TypeError` for anything outside its supported set. Rust has no such failure
/// mode: [`Value`] can only hold encodable shapes, and the sole variant `pack` rejects is
/// [`Value::AbsoluteTime`] (covered by [`pack_absolute_time`]). This test pins that claim down so
/// a future variant cannot quietly become unencodable.
#[test]
fn pack_unsupported_type() {
    let every_other_variant = [
        Value::Null,
        Value::Bool(true),
        Value::Uint(1),
        Value::SizedUint {
            value: 1,
            width: UintWidth::Eight,
        },
        Value::Float(1.0),
        Value::Float32(1.0),
        Value::from("a"),
        Value::Data(Bytes::from_static(b"a")),
        Value::Uuid([0; 16]),
        Value::Array(vec![Value::Null]),
        Value::Dict(vec![(Value::Null, Value::Null)]),
    ];
    for value in every_other_variant {
        assert!(pack(&value).is_ok(), "{value:?} should be encodable");
    }
}

/// `test_opack.py:22-25`.
#[test]
fn pack_boolean() {
    assert_eq!(packed(&Value::Bool(true)), [0x01]);
    assert_eq!(packed(&Value::Bool(false)), [0x02]);
}

/// `test_opack.py:27-29`.
#[test]
fn pack_none() {
    assert_eq!(packed(&Value::Null), [0x04]);
}

/// `test_opack.py:31-36`, `UUID("{12345678-1234-5678-1234-567812345678}")`.
#[test]
fn pack_uuid() {
    let uuid = Value::Uuid([
        0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56,
        0x78,
    ]);
    assert_eq!(
        packed(&uuid),
        [
            0x05, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x12,
            0x34, 0x56, 0x78
        ]
    );
}

/// `test_opack.py:38-41`, where pyatv raises `NotImplementedError` for a `datetime`.
#[test]
fn pack_absolute_time() {
    assert_eq!(
        pack(&Value::AbsoluteTime(1)),
        Err(Error::UnpackOnlyTag { tag: 0x06 })
    );
}

/// `test_opack.py:43-46`.
#[test]
fn pack_small_integers() {
    assert_eq!(packed(&Value::Uint(0)), [0x08]);
    assert_eq!(packed(&Value::Uint(0xF)), [0x17]);
    assert_eq!(packed(&Value::Uint(0x27)), [0x2F]);
}

/// `test_opack.py:49-53`.
#[test]
fn pack_larger_integers() {
    assert_eq!(packed(&Value::Uint(0x28)), [0x30, 0x28]);
    assert_eq!(packed(&Value::Uint(0x1FF)), [0x31, 0xFF, 0x01]);
    assert_eq!(
        packed(&Value::Uint(0x01FF_FFFF)),
        [0x32, 0xFF, 0xFF, 0xFF, 0x01]
    );
    assert_eq!(
        packed(&Value::Uint(0x01FF_FFFF_FFFF_FFFF)),
        [0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01]
    );
}

/// `test_opack.py:56-60`, pyatv's `_sized_int` round-trip guarantee.
#[test]
fn pack_sized_integers() {
    let sized = |width| Value::SizedUint { value: 0x1, width };
    assert_eq!(packed(&sized(UintWidth::One)), [0x30, 0x01]);
    assert_eq!(packed(&sized(UintWidth::Two)), [0x31, 0x01, 0x00]);
    assert_eq!(
        packed(&sized(UintWidth::Four)),
        [0x32, 0x01, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        packed(&sized(UintWidth::Eight)),
        [0x33, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
    );
}

/// `test_opack.py:63-64`.
#[test]
fn pack_float64() {
    assert_eq!(
        packed(&Value::Float(1.0)),
        [0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F]
    );
}

/// `test_opack.py:67-70`.
#[test]
fn pack_short_strings() {
    assert_eq!(packed(&Value::from("a")), [0x41, 0x61]);
    assert_eq!(packed(&Value::from("abc")), [0x43, 0x61, 0x62, 0x63]);

    let mut expected = vec![0x60];
    expected.extend(std::iter::repeat_n(0x61, 0x20));
    assert_eq!(packed(&repeat_string("a", 0x20)), expected);
}

/// `test_opack.py:73-75`.
#[test]
fn pack_longer_strings() {
    let mut expected = vec![0x61, 0x21];
    expected.extend(std::iter::repeat_n(0x61, 33));
    assert_eq!(packed(&repeat_string("a", 33)), expected);

    let mut expected = vec![0x62, 0x00, 0x01];
    expected.extend(std::iter::repeat_n(0x61, 256));
    assert_eq!(packed(&repeat_string("a", 256)), expected);
}

/// `test_opack.py:78-81`.
#[test]
fn pack_short_raw_bytes() {
    assert_eq!(packed(&repeat_data(0xAC, 1)), [0x71, 0xAC]);
    assert_eq!(
        packed(&Value::Data(Bytes::from_static(&[0x12, 0x34, 0x56]))),
        [0x73, 0x12, 0x34, 0x56]
    );

    let mut expected = vec![0x90];
    expected.extend(std::iter::repeat_n(0xAD, 0x20));
    assert_eq!(packed(&repeat_data(0xAD, 0x20)), expected);
}

/// `test_opack.py:84-87`.
#[test]
fn pack_longer_raw_bytes() {
    let mut expected = vec![0x91, 0x21];
    expected.extend(std::iter::repeat_n(0x61, 33));
    assert_eq!(packed(&repeat_data(0x61, 33)), expected);

    let mut expected = vec![0x92, 0x00, 0x01];
    expected.extend(std::iter::repeat_n(0x61, 256));
    assert_eq!(packed(&repeat_data(0x61, 256)), expected);

    let mut expected = vec![0x93, 0x00, 0x00, 0x01, 0x00];
    expected.extend(std::iter::repeat_n(0x61, 65536));
    assert_eq!(packed(&repeat_data(0x61, 65536)), expected);
}

/// `test_opack.py:90-93`.
#[test]
fn pack_array() {
    assert_eq!(packed(&Value::Array(Vec::new())), [0xD0]);
    assert_eq!(
        packed(&Value::Array(vec![
            Value::Uint(1),
            Value::from("test"),
            Value::Bool(false)
        ])),
        [0xD3, 0x09, 0x44, 0x74, 0x65, 0x73, 0x74, 0x02]
    );
    assert_eq!(
        packed(&Value::Array(vec![Value::Array(vec![Value::Bool(true)])])),
        [0xD1, 0xD1, 0x01]
    );
}

/// `test_opack.py:96-97`: fifteen elements trip the `0xF` nibble, so the tail is fourteen
/// back-references plus the `0x03` terminator.
#[test]
fn pack_endless_array() {
    let mut expected = vec![0xDF, 0x41, 0x61];
    expected.extend(std::iter::repeat_n(0xA0, 14));
    expected.push(0x03);
    assert_eq!(packed(&Value::array(["a"; 15])), expected);
}

/// `test_opack.py:100-103`.
#[test]
fn pack_dict() {
    assert_eq!(packed(&Value::Dict(Vec::new())), [0xE0]);
    assert_eq!(
        packed(&Value::Dict(vec![
            (Value::from("a"), Value::Uint(12)),
            (Value::Bool(false), Value::Null),
        ])),
        [0xE2, 0x41, 0x61, 0x14, 0x02, 0x04]
    );
    assert_eq!(
        packed(&Value::Dict(vec![(
            Value::Bool(true),
            Value::Dict(vec![(Value::from("a"), Value::Uint(2))]),
        )])),
        [0xE1, 0x01, 0xE1, 0x41, 0x61, 0x0A]
    );
}

/// `test_opack.py:106-109`: `dict((chr(x), chr(x + 1)) for x in range(97, 127, 2))`.
#[test]
fn pack_endless_dict() {
    let entries: Vec<(Value, Value)> = (97u8..127)
        .step_by(2)
        .map(|code| {
            (
                Value::from(char::from(code).to_string()),
                Value::from(char::from(code + 1).to_string()),
            )
        })
        .collect();
    assert_eq!(entries.len(), 15);

    let mut expected = vec![0xEF];
    for code in 97u8..127 {
        expected.extend([0x41, code]);
    }
    expected.push(0x03);
    assert_eq!(packed(&Value::Dict(entries)), expected);
}

/// `test_opack.py:112-121`.
#[test]
fn pack_ptr() {
    assert_eq!(packed(&Value::array(["a", "a"])), [0xD2, 0x41, 0x61, 0xA0]);
    assert_eq!(
        packed(&Value::array(["foo", "bar", "foo", "bar"])),
        [
            0xD4, 0x43, 0x66, 0x6F, 0x6F, 0x43, 0x62, 0x61, 0x72, 0xA0, 0xA1
        ]
    );
    assert_eq!(
        packed(&Value::Dict(vec![
            (Value::from("a"), Value::from("b")),
            (
                Value::from("c"),
                Value::Dict(vec![(Value::from("d"), Value::from("a"))]),
            ),
            (Value::from("d"), Value::Bool(true)),
        ])),
        [
            0xE3, 0x41, 0x61, 0x41, 0x62, 0x41, 0x63, 0xE1, 0x41, 0x64, 0xA0, 0xA3, 0x01
        ]
    );
}

/// `test_opack.py:124-199`: 514 byte strings, exercising inline, one-byte and two-byte
/// back-reference indices in a single message.
#[test]
fn pack_more_ptr() {
    let data: Vec<Value> = (0..257u32)
        .map(|code| {
            let character = char::from_u32(code).expect("code points below 0x101 are all valid");
            Value::Data(Bytes::from(character.to_string().into_bytes()))
        })
        .collect();

    let mut doubled = data.clone();
    doubled.extend(data);
    assert_eq!(packed(&Value::Array(doubled)), MORE_PTR);
}
