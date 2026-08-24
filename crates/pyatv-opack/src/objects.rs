//! The OPACK object back-reference tables.
//!
//! OPACK interns repeated values: after a value has appeared once, later occurrences are replaced
//! by a one-to-three byte index into an append-only table that is threaded through the *entire*
//! top-level `pack`/`unpack` call, nested containers included.
//!
//! The two directions key the table differently, and pyatv does so too:
//!
//! * the encoder dedupes by the **exact encoded byte sequence** (`opack.py:116-130`);
//! * the decoder dedupes by **value** (`opack.py:238-239`).
//!
//! That much is reproduced faithfully. What is *not* reproduced is pyatv's answer to the second
//! question a back-reference table has to answer: which values get an index at all. pyatv gives
//! two different answers on the two sides, and they do not agree:
//!
//! * the encoder records anything whose encoding is longer than one byte — **including
//!   containers**, and **excluding** the empty string and the empty byte string (`opack.py:129`);
//! * the decoder records everything except booleans, null, small integers and **containers**,
//!   which means it **does** record the empty string and the empty byte string
//!   (`opack.py:208`, `opack.py:225`, `opack.py:238-239`).
//!
//! Either difference desynchronises the numbering. `pack([[1, 2], "a", "a"])` is enough to show
//! it: pyatv's encoder interns the inner list at index 0 and `"a"` at index 1, emitting `0xA1`
//! for the repeat, while its own decoder skips the list, records `"a"` at index 0 and then reads
//! `0xA1` as an out-of-range index. pyatv produces a payload it cannot itself parse. Its test
//! suite never catches this because in every vector the containers happen to be interned after
//! the last value a pointer refers to.
//!
//! This crate therefore aligns both sides on the **decoder's** rule, which is the one with
//! demonstrated real-device validation — pyatv decodes live Companion traffic every day, while
//! nothing checks that a device would accept what its encoder emits. See `ser::is_interned`. On
//! pyatv's entire OPACK test suite the two rules produce byte-identical output, which is exactly
//! why the discrepancy survived.
//!
//! A second, smaller divergence is fixed the same way: pyatv's decoder compares with Python
//! equality, so it treats `1`, `1.0` and `_sized_int(1, 2)` as the same value and skips recording
//! the later ones, shifting every subsequent index. Rust's typed [`PartialEq`] on [`Value`] keeps
//! them distinct, which is what the encoder's byte-keyed table already assumed.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use crate::value::Value;

/// Encoder-side table, keyed by encoded bytes (`opack.py:116-130`).
#[derive(Debug, Default)]
pub(crate) struct PackTable {
    indices: HashMap<Box<[u8]>, usize>,
}

impl PackTable {
    /// The index a previously emitted encoding was recorded at, if any.
    pub(crate) fn lookup(&self, encoded: &[u8]) -> Option<usize> {
        self.indices.get(encoded).copied()
    }

    /// Record an encoding that was emitted inline.
    ///
    /// Whether a value is interned at all is decided by the caller — see `ser::is_interned` — so
    /// that the encoder and the decoder agree on the numbering.
    pub(crate) fn record(&mut self, encoded: &[u8]) {
        let next = self.indices.len();
        self.indices.entry(Box::from(encoded)).or_insert(next);
    }
}

/// Decoder-side table, keyed by value (`opack.py:238-239`).
///
/// The bucket map exists only so the "have I seen this value already?" test is not a linear scan;
/// a hostile payload made of thousands of distinct short strings would otherwise cost quadratic
/// time. Buckets are keyed by a hash that is *consistent with*, but coarser than, [`PartialEq`],
/// and candidates are always confirmed with `==`.
#[derive(Debug, Default)]
pub(crate) struct UnpackTable {
    values: Vec<Value>,
    buckets: HashMap<u64, Vec<usize>>,
}

impl UnpackTable {
    /// How many values have been recorded.
    pub(crate) fn len(&self) -> usize {
        self.values.len()
    }

    /// Resolve a back-reference index.
    pub(crate) fn get(&self, index: usize) -> Option<&Value> {
        self.values.get(index)
    }

    /// Record a decoded value unless an equal one is already present.
    pub(crate) fn record(&mut self, value: &Value) {
        let digest = digest_of(value);
        let bucket = self.buckets.entry(digest).or_default();
        if bucket.iter().any(|&index| self.values[index] == *value) {
            return;
        }
        bucket.push(self.values.len());
        self.values.push(value.clone());
    }
}

/// Hash a value in a way that agrees with [`PartialEq`] for every non-NaN input.
fn digest_of(value: &Value) -> u64 {
    let mut hasher = DefaultHasher::new();
    hash_into(value, &mut hasher);
    hasher.finish()
}

fn hash_into(value: &Value, hasher: &mut DefaultHasher) {
    std::mem::discriminant(value).hash(hasher);
    match value {
        Value::Null => {}
        Value::Bool(flag) => flag.hash(hasher),
        Value::Uint(number) | Value::AbsoluteTime(number) => number.hash(hasher),
        Value::SizedUint { value, width } => {
            value.hash(hasher);
            width.hash(hasher);
        }
        Value::Float(number) => number.to_bits().hash(hasher),
        Value::Float32(number) => number.to_bits().hash(hasher),
        Value::String(text) => text.hash(hasher),
        Value::Data(bytes) => bytes.hash(hasher),
        Value::Uuid(bytes) => bytes.hash(hasher),
        Value::Array(items) => {
            for item in items {
                hash_into(item, hasher);
            }
        }
        Value::Dict(entries) => {
            for (key, entry) in entries {
                hash_into(key, hasher);
                hash_into(entry, hasher);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{PackTable, UnpackTable};
    use crate::value::{UintWidth, Value};

    #[test]
    fn pack_table_numbers_entries_in_insertion_order() {
        let mut table = PackTable::default();
        table.record(&[0x40]);
        table.record(&[0x41, 0x61]);
        table.record(&[0x41, 0x62]);
        table.record(&[0x41, 0x61]);
        assert_eq!(table.lookup(&[0x40]), Some(0));
        assert_eq!(table.lookup(&[0x41, 0x61]), Some(1));
        assert_eq!(table.lookup(&[0x41, 0x62]), Some(2));
        assert_eq!(table.lookup(&[0x08]), None);
    }

    #[test]
    fn unpack_table_dedupes_by_typed_equality() {
        let mut table = UnpackTable::default();
        table.record(&Value::String("a".into()));
        table.record(&Value::String("a".into()));
        assert_eq!(table.len(), 1);

        // Python would treat all three of these as equal and record only the first.
        table.record(&Value::SizedUint {
            value: 1,
            width: UintWidth::One,
        });
        table.record(&Value::SizedUint {
            value: 1,
            width: UintWidth::Two,
        });
        table.record(&Value::Float(1.0));
        assert_eq!(table.len(), 4);
        assert_eq!(table.get(0), Some(&Value::String("a".into())));
        assert_eq!(table.get(4), None);
    }
}
