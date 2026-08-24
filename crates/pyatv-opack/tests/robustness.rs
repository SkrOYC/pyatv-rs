//! Hostile-input tests.
//!
//! pyatv's `_unpack` indexes `data[0]` and slices without checking, so every malformed payload is
//! an `IndexError`, a `UnicodeDecodeError` or — for deep nesting — a `RecursionError`. This
//! decoder has to turn all of those into ordinary [`Error`] values, because the bytes come
//! straight off a socket.

use pyatv_opack::{Error, MAX_DEPTH, UintWidth, Value, pack, unpack};

/// Every fixture used by the truncation and mutation sweeps: one well-formed encoding per tag
/// family, plus the two large vectors from pyatv's own suite.
fn corpus() -> Vec<Vec<u8>> {
    let mut long_string = vec![0x61, 0x21];
    long_string.extend(std::iter::repeat_n(0x61, 33));
    let mut long_data = vec![0x92, 0x00, 0x01];
    long_data.extend(std::iter::repeat_n(0x61, 256));
    let mut endless = vec![0xDF, 0x41, 0x61];
    endless.extend(std::iter::repeat_n(0xA0, 15));
    endless.push(0x03);

    vec![
        vec![0x01],
        vec![0x02],
        vec![0x04],
        vec![0x08],
        vec![0x2F],
        vec![0x05, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        vec![0x06, 0x01, 0, 0, 0, 0, 0, 0, 0],
        vec![0x30, 0x28],
        vec![0x31, 0xFF, 0x01],
        vec![0x32, 0xFF, 0xFF, 0xFF, 0x01],
        vec![0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01],
        vec![0x35, 0x00, 0x00, 0x80, 0x3F],
        vec![0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F],
        vec![0x41, 0x61],
        long_string,
        vec![0x71, 0xAC],
        long_data,
        vec![0xD0],
        vec![0xD3, 0x09, 0x44, 0x74, 0x65, 0x73, 0x74, 0x02],
        endless,
        vec![0xE0],
        vec![0xE2, 0x41, 0x61, 0x14, 0x02, 0x04],
        vec![
            0xE3, 0x41, 0x61, 0x41, 0x62, 0x41, 0x63, 0xE1, 0x41, 0x64, 0xA0, 0xA3, 0x01,
        ],
        vec![0xDF, 0x30, 0x01, 0x30, 0x02, 0xC1, 0x01, 0x03],
        include_bytes!("fixtures/more_ptr.opack").to_vec(),
    ]
}

/// Truncate every fixture at every possible length; nothing may panic, and nothing may claim to
/// have consumed bytes that were not there.
#[test]
fn truncation_at_every_length_is_an_error_not_a_panic() {
    for fixture in corpus() {
        for length in 0..fixture.len() {
            let truncated = &fixture[..length];
            match unpack(truncated) {
                Err(_) => {}
                Ok((value, consumed)) => {
                    panic!(
                        "truncating {fixture:02X?} to {length} bytes decoded as {value:?} \
                         ({consumed} bytes consumed)"
                    );
                }
            }
        }
        // The untruncated fixture must still decode, so the sweep above is testing something.
        assert!(unpack(&fixture).is_ok(), "{fixture:02X?} should decode");
    }
}

/// Substitute every byte value at every position of the short fixtures. This reaches every tag,
/// including the undefined ones and the pathological `0x3F` "32 768-byte integer" tag, and asserts
/// only that the decoder returns rather than aborts.
#[test]
fn single_byte_mutations_never_panic() {
    for fixture in corpus().into_iter().filter(|f| f.len() <= 16) {
        for position in 0..fixture.len() {
            for replacement in 0..=u8::MAX {
                let mut mutated = fixture.clone();
                mutated[position] = replacement;
                let _ = unpack(&mutated);
            }
        }
    }
}

/// Every byte that neither pyatv nor this crate defines must be reported, not guessed at.
#[test]
fn undefined_tags_are_rejected() {
    let undefined = [0x00u8, 0x03, 0x07]
        .into_iter()
        .chain(0x65..=0x6F)
        .chain(0x95..=0x9F)
        .chain(0xC5..=0xCF);
    for tag in undefined {
        assert_eq!(
            unpack(&[tag]),
            Err(Error::UnknownTag { tag, offset: 0 }),
            "tag {tag:#04x} should be rejected"
        );
    }
}

/// `0x34` and `0x37..=0x3F` ask pyatv for a 16- to 32 768-byte integer (`opack.py:167`). Nothing
/// that wide fits a `u64`, so they are rejected rather than truncated.
#[test]
fn over_wide_integer_tags_are_rejected() {
    for tag in [0x34u8].into_iter().chain(0x37..=0x3F) {
        assert_eq!(
            unpack(&[tag, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::IntegerTooWide { tag, offset: 0 }),
            "tag {tag:#04x} should be rejected"
        );
    }
}

/// A back-reference into an empty or short table is an error, not an index panic.
#[test]
fn back_references_are_range_checked() {
    assert_eq!(
        unpack(&[0xA0]),
        Err(Error::BadBackReference { index: 0, len: 0 })
    );
    assert_eq!(
        unpack(&[0xD2, 0x41, 0x61, 0xA5]),
        Err(Error::BadBackReference { index: 5, len: 1 })
    );
    assert_eq!(
        unpack(&[0xC1, 0xFF]),
        Err(Error::BadBackReference { index: 255, len: 0 })
    );
}

/// Strings are validated, not reinterpreted.
#[test]
fn invalid_utf8_is_rejected() {
    assert_eq!(unpack(&[0x41, 0xFF]), Err(Error::InvalidUtf8 { offset: 0 }));
    assert_eq!(
        unpack(&[0xD1, 0x42, 0xC3, 0x28]),
        Err(Error::InvalidUtf8 { offset: 1 })
    );
}

/// Nesting is capped in both directions, so anything this crate can encode it can also decode.
#[test]
fn nesting_is_capped() {
    let at_limit = vec![0xD1; MAX_DEPTH];
    let mut deepest = at_limit.clone();
    deepest.push(0x04);
    assert!(unpack(&deepest).is_ok(), "{MAX_DEPTH} levels must decode");

    let mut too_deep = vec![0xD1; MAX_DEPTH + 1];
    too_deep.push(0x04);
    assert_eq!(
        unpack(&too_deep),
        Err(Error::DepthLimitExceeded { limit: MAX_DEPTH })
    );

    // A million levels is the case that would blow the stack without the cap.
    let mut absurd = vec![0xD1; 1_000_000];
    absurd.push(0x04);
    assert_eq!(
        unpack(&absurd),
        Err(Error::DepthLimitExceeded { limit: MAX_DEPTH })
    );

    let mut nested = Value::Null;
    for _ in 0..=MAX_DEPTH {
        nested = Value::Array(vec![nested]);
    }
    assert_eq!(
        pack(&nested),
        Err(Error::DepthLimitExceeded { limit: MAX_DEPTH })
    );
}

/// A pinned width that cannot hold its number is refused rather than silently widened.
#[test]
fn sized_integer_overflow_is_rejected() {
    assert_eq!(
        pack(&Value::SizedUint {
            value: 0x100,
            width: UintWidth::One
        }),
        Err(Error::SizedIntegerOverflow {
            value: 0x100,
            bytes: 1
        })
    );
    assert!(
        pack(&Value::SizedUint {
            value: 0xFF,
            width: UintWidth::One
        })
        .is_ok()
    );
    assert!(
        pack(&Value::SizedUint {
            value: u64::MAX,
            width: UintWidth::Eight
        })
        .is_ok()
    );
}

/// pyatv's dictionary test is `(tag & 0xE0) == 0xE0` (`opack.py:209`), not `& 0xF0`, so tags
/// `0xF0..=0xFF` decode as dictionaries too. Nothing is known to emit them, but the reference
/// implementation accepts them and so does this one.
#[test]
fn high_dictionary_tags_decode_like_pyatv() {
    let (value, consumed) = unpack(&[0xF1, 0x01, 0x02]).expect("0xF1 is a one-entry dictionary");
    assert_eq!(consumed, 3);
    assert_eq!(
        value,
        Value::Dict(vec![(Value::Bool(true), Value::Bool(false))])
    );
}

/// Trailing bytes belong to the caller, exactly as in pyatv where `unpack` returns them.
#[test]
fn trailing_bytes_are_left_for_the_caller() {
    let (value, consumed) = unpack(&[0x08, 0xFF, 0xFF]).expect("a small integer decodes");
    assert_eq!((value, consumed), (Value::Uint(0), 1));
}
