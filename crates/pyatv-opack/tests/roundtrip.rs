//! Property tests over the whole value space.
//!
//! The pyatv vectors pin specific byte strings; these pin the two invariants that have to hold for
//! every value, in particular that the encoder's byte-keyed object table and the decoder's
//! value-keyed one stay in step (`opack.py:116-130` versus `opack.py:238-239`).

use bytes::Bytes;
use proptest::prelude::*;
use pyatv_opack::{UintWidth, Value, pack, unpack};

/// The single transformation a round trip is allowed to make: an integer at or above `0x28` is
/// written with an explicit width and therefore returns as [`Value::SizedUint`].
fn as_decoded(value: &Value) -> Value {
    match value {
        Value::Uint(number) if *number >= 0x28 => Value::SizedUint {
            value: *number,
            width: UintWidth::narrowest_for(*number),
        },
        Value::Array(items) => Value::Array(items.iter().map(as_decoded).collect()),
        Value::Dict(entries) => Value::Dict(
            entries
                .iter()
                .map(|(key, entry)| (as_decoded(key), as_decoded(entry)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn width_of(index: u8) -> UintWidth {
    match index {
        0 => UintWidth::One,
        1 => UintWidth::Two,
        2 => UintWidth::Four,
        _ => UintWidth::Eight,
    }
}

fn sized_uint() -> impl Strategy<Value = Value> {
    (0u8..4, any::<u64>()).prop_map(|(index, raw)| {
        let width = width_of(index);
        let bytes = width.byte_count();
        let value = if bytes >= 8 {
            raw
        } else {
            raw & ((1u64 << (bytes * 8)) - 1)
        };
        Value::SizedUint { value, width }
    })
}

/// Any value the encoder accepts. [`Value::AbsoluteTime`] is excluded on purpose: it decodes but
/// never encodes, which `robustness.rs` and `pyatv_pack.rs` cover instead. NaN is excluded because
/// it makes the structural comparison meaningless, not because the codec mishandles it — the
/// byte-level property below would hold for NaN too.
fn any_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<u64>().prop_map(Value::Uint),
        sized_uint(),
        any::<f64>()
            .prop_filter("NaN is not comparable", |number| !number.is_nan())
            .prop_map(Value::Float),
        any::<f32>()
            .prop_filter("NaN is not comparable", |number| !number.is_nan())
            .prop_map(Value::Float32),
        ".{0,50}".prop_map(Value::from),
        proptest::collection::vec(any::<u8>(), 0..300)
            .prop_map(|raw| Value::Data(Bytes::from(raw))),
        any::<[u8; 16]>().prop_map(Value::Uuid),
    ];

    leaf.prop_recursive(4, 96, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..18).prop_map(Value::Array),
            proptest::collection::vec((inner.clone(), inner), 0..18).prop_map(Value::Dict),
        ]
    })
}

proptest! {
    /// Encoding, decoding and re-encoding must reproduce the original bytes exactly. This is the
    /// property that would break if the two object tables ever numbered entries differently.
    #[test]
    fn round_trip_is_byte_exact(value in any_value()) {
        let bytes = pack(&value).expect("generated values are always encodable");
        let (decoded, consumed) = unpack(&bytes).expect("our own output must decode");

        prop_assert_eq!(consumed, bytes.len(), "decoder left trailing bytes");
        prop_assert_eq!(
            pack(&decoded).expect("a decoded value must re-encode"),
            bytes
        );
    }

    /// Decoding must preserve the structure, including dictionary order and duplicate keys.
    #[test]
    fn round_trip_preserves_structure(value in any_value()) {
        let bytes = pack(&value).expect("generated values are always encodable");
        let (decoded, _) = unpack(&bytes).expect("our own output must decode");
        prop_assert_eq!(decoded, as_decoded(&value));
    }

    /// Arbitrary bytes must produce a value or an error, never a panic, and never a claim to have
    /// consumed more than was supplied.
    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Ok((_, consumed)) = unpack(&bytes) {
            prop_assert!(consumed <= bytes.len());
        }
    }

    /// The same, biased towards byte sequences that actually look like OPACK: mutating real
    /// encodings reaches far more of the decoder than uniform random bytes do.
    #[test]
    fn mutated_encodings_never_panic(
        value in any_value(),
        position in any::<prop::sample::Index>(),
        replacement in any::<u8>(),
    ) {
        let mut bytes = pack(&value).expect("generated values are always encodable").to_vec();
        let index = position.index(bytes.len());
        bytes[index] = replacement;
        if let Ok((_, consumed)) = unpack(&bytes) {
            prop_assert!(consumed <= bytes.len());
        }
    }
}
