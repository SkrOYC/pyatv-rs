//! OPACK decoder — a port of `_unpack` in `pyatv/support/opack.py:135-241`.
//!
//! Every read is bounds-checked against the input slice and no allocation is ever sized from an
//! attacker-controlled length prefix before the bytes have been proven to exist, so a truncated or
//! hostile payload produces an [`Error`], never a panic and never a huge allocation. Container
//! nesting is capped at [`MAX_DEPTH`].
//!
//! Two decoder behaviours differ from pyatv on purpose:
//!
//! * pyatv treats the whole `0x30..=0x3F` range as an integer of `2 ** (tag & 0xF)` bytes
//!   (`opack.py:166-167`), which runs to 32 768 bytes at `0x3F`. Only `0x30..=0x33` fit a `u64`,
//!   so the rest raise [`Error::IntegerTooWide`].
//! * pyatv's `_unpack` indexes `data[0]` unchecked, so every truncation is an `IndexError` rather
//!   than a diagnosable failure.
//!
//! One pyatv oddity *is* reproduced: the dictionary test is `(tag & 0xE0) == 0xE0`
//! (`opack.py:209`), not `& 0xF0`, so `0xF0..=0xFF` also decode as dictionaries with
//! `tag & 0xF` entries. Nothing is known to emit those tags, but the reference implementation
//! accepts them and the goal is to accept whatever a device might send.
//!
//! # The materialised-byte budget
//!
//! Bounds-checking every read is not enough on its own, because OPACK's back-reference mechanism
//! lets one input byte *produce* a value. `0xA0` is a single byte that yields whatever the first
//! interned value was, so a one-megabyte frame holding one 60 000-byte string followed by ~988 000
//! `0xA0` bytes inside a `0xDF` array decodes to a 988 000-element vector — and, before
//! [`Value::String`] became an [`Arc`], to roughly 56 GB of copied text. Neither the depth cap nor
//! the length checks see any of that: nothing is ever "too long", there are simply a great many
//! short things.
//!
//! [`unpack`] therefore charges a budget for the bytes a decode *materialises*:
//!
//! * a string or byte string costs its length;
//! * every container element and every resolved back-reference costs [`ELEMENT_COST`], the size of
//!   one [`Value`] slot in the vector holding it.
//!
//! Back-references cost a slot and not the referenced value's length because, with the [`Arc`] and
//! [`bytes::Bytes`] payloads, resolving one really is a refcount bump — charging the full length
//! would reject the legitimate payloads interning exists to produce.
//!
//! The default ceiling is `max(4 × input length, 64 KiB)`, capped at [`MAX_BUDGET`]. Four times the
//! input covers any payload whose expansion is proportional to what was sent, and the 64 KiB floor
//! keeps small frames — every real Companion message is a few kilobytes — well clear of it. The
//! one shape it *does* refuse is a very large, very dense array of single-byte values, which costs
//! [`ELEMENT_COST`] per input byte; no Apple protocol sends one, and [`unpack_with_budget`] is
//! there for a caller that disagrees.

use std::sync::Arc;

use bytes::Bytes;

use crate::objects::UnpackTable;
use crate::tags;
use crate::value::{UintWidth, Value};
use crate::{Error, MAX_DEPTH, Result};

/// Decode one OPACK value from the front of `input`, returning it and the number of bytes
/// consumed.
///
/// Trailing bytes are not an error — the caller decides what to do with the remainder, exactly as
/// pyatv's `unpack()` returns `(value, remaining)` (`opack.py:135-137`).
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] on a truncated payload, [`Error::UnknownTag`] for a tag byte
/// pyatv's reference implementation does not define, [`Error::IntegerTooWide`] for the
/// unrepresentable integer widths, [`Error::InvalidUtf8`] for a malformed string,
/// [`Error::BadBackReference`] for a pointer past the end of the object table,
/// [`Error::LengthOverflow`] for a length that does not fit this target's `usize`,
/// [`Error::DepthLimitExceeded`] when containers nest deeper than [`MAX_DEPTH`], and
/// [`Error::BudgetExceeded`] when the payload decodes to far more than it occupies on the wire —
/// see the module docs.
pub fn unpack(input: &[u8]) -> Result<(Value, usize)> {
    unpack_with_budget(input, default_budget(input.len()))
}

/// [`unpack`] with an explicit materialised-byte ceiling.
///
/// For the rare caller that legitimately decodes something the default budget refuses — a huge,
/// dense array of single-byte values is the only known shape — or one that wants a tighter bound
/// than the default on a payload from an untrusted peer.
///
/// # Errors
///
/// As [`unpack`].
pub fn unpack_with_budget(input: &[u8], budget: usize) -> Result<(Value, usize)> {
    let mut decoder = Decoder {
        input,
        offset: 0,
        table: UnpackTable::default(),
        depth: 0,
        budget,
        spent: 0,
    };
    let value = decoder.value()?;
    Ok((value, decoder.offset))
}

/// What one [`Value`] slot in a container's backing vector costs the budget.
///
/// The real size of the enum, so the budget tracks the allocation a decode actually performs
/// rather than a number picked to look tidy.
pub const ELEMENT_COST: usize = size_of::<Value>();

/// The budget floor, so that a small frame is never refused for being small.
pub const MIN_BUDGET: usize = 64 * 1024;

/// The budget ceiling, whatever the input length suggests.
pub const MAX_BUDGET: usize = 16 * 1024 * 1024;

/// `max(4 × len, MIN_BUDGET)`, capped at [`MAX_BUDGET`].
#[must_use]
pub const fn default_budget(input_len: usize) -> usize {
    let scaled = input_len.saturating_mul(4);
    if scaled < MIN_BUDGET {
        MIN_BUDGET
    } else if scaled > MAX_BUDGET {
        MAX_BUDGET
    } else {
        scaled
    }
}

/// Decoder state, including the back-reference table.
#[derive(Debug)]
struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    table: UnpackTable,
    depth: usize,
    /// Ceiling on the bytes this decode may materialise; see the module docs.
    budget: usize,
    /// How much of it has been charged so far.
    spent: usize,
}

impl<'a> Decoder<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Error::UnexpectedEof {
            consumed: self.offset,
        })?;
        let slice = self
            .input
            .get(self.offset..end)
            .ok_or(Error::UnexpectedEof {
                consumed: self.offset,
            })?;
        self.offset = end;
        Ok(slice)
    }

    fn tag(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn peek(&self) -> Result<u8> {
        self.input
            .get(self.offset)
            .copied()
            .ok_or(Error::UnexpectedEof {
                consumed: self.offset,
            })
    }

    /// Read `count` little-endian bytes as a `u64`. `count` is never above eight.
    fn le_uint(&mut self, count: usize) -> Result<u64> {
        let mut buffer = [0u8; 8];
        buffer[..count].copy_from_slice(self.take(count)?);
        Ok(u64::from_le_bytes(buffer))
    }

    /// Read a length or index prefix and narrow it to a `usize`.
    fn le_len(&mut self, count: usize, start: usize) -> Result<usize> {
        let raw = self.le_uint(count)?;
        usize::try_from(raw).map_err(|_| Error::LengthOverflow {
            length: raw,
            offset: start,
        })
    }

    fn enter(&mut self) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::DepthLimitExceeded { limit: MAX_DEPTH });
        }
        self.depth += 1;
        Ok(())
    }

    /// Charge `bytes` against the materialised-byte budget.
    ///
    /// Saturating rather than wrapping: an overflowing total is by definition over budget, and the
    /// reported figure is a diagnostic rather than a measurement.
    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.spent = self.spent.saturating_add(bytes);
        if self.spent > self.budget {
            return Err(Error::BudgetExceeded {
                limit: self.budget,
                offset: self.offset,
            });
        }
        Ok(())
    }

    /// Decode one value, recording it in the back-reference table where pyatv would
    /// (`opack.py:238-239`).
    fn value(&mut self) -> Result<Value> {
        let start = self.offset;
        let tag = self.tag()?;

        // The `bool` is pyatv's `add_to_object_list`. Back-references are marked `false` because
        // pyatv's follow-up `value not in object_list` test can never succeed for them.
        let (value, record) = match tag {
            tags::TRUE => (Value::Bool(true), false),
            tags::FALSE => (Value::Bool(false), false),
            tags::NULL => (Value::Null, false),
            tags::UUID => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(self.take(16)?);
                (Value::Uuid(bytes), true)
            }
            tags::ABSOLUTE_TIME => (Value::AbsoluteTime(self.le_uint(8)?), true),
            tags::SMALL_INT_BIAS..=tags::SMALL_INT_MAX_TAG => {
                (Value::Uint(u64::from(tag - tags::SMALL_INT_BIAS)), false)
            }
            tags::UINT_1..=tags::UINT_8 => (self.sized_uint(tag)?, true),
            tags::UINT_TOO_WIDE_LOW
            | tags::UINT_TOO_WIDE_HIGH_FIRST..=tags::UINT_TOO_WIDE_HIGH_LAST => {
                return Err(Error::IntegerTooWide { tag, offset: start });
            }
            tags::FLOAT32 => {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(self.take(4)?);
                (Value::Float32(f32::from_le_bytes(bytes)), true)
            }
            tags::FLOAT64 => (Value::Float(f64::from_bits(self.le_uint(8)?)), true),
            tags::STRING_INLINE_BASE..=tags::STRING_INLINE_MAX_TAG => {
                let length = usize::from(tag - tags::STRING_INLINE_BASE);
                (self.string(length, start)?, true)
            }
            tags::STRING_LEN_MIN_TAG..=tags::STRING_LEN_MAX_TAG => {
                // 0x61..=0x64 carry 1/2/3/4 length bytes: `noof_bytes = tag & 0xF`.
                let length = self.le_len(usize::from(tag & 0x0F), start)?;
                (self.string(length, start)?, true)
            }
            tags::DATA_INLINE_BASE..=tags::DATA_INLINE_MAX_TAG => {
                let length = usize::from(tag - tags::DATA_INLINE_BASE);
                (self.data(length)?, true)
            }
            tags::DATA_LEN_MIN_TAG..=tags::DATA_LEN_MAX_TAG => {
                // 0x91..=0x94 carry 1/2/4/8 length bytes: `noof_bytes = 1 << ((tag & 0xF) - 1)`.
                let width = 1usize << ((tag & 0x0F) - 1);
                let length = self.le_len(width, start)?;
                (self.data(length)?, true)
            }
            tags::POINTER_INLINE_BASE..=tags::POINTER_INLINE_MAX_TAG => {
                let index = usize::from(tag - tags::POINTER_INLINE_BASE);
                (self.back_reference(index)?, false)
            }
            tags::POINTER_LEN_MIN_TAG..=tags::POINTER_LEN_MAX_TAG => {
                // 0xC1..=0xC4 carry 1/2/3/4 index bytes: `length = tag - 0xC0`.
                let width = usize::from(tag - tags::POINTER_LEN_BASE);
                let index = self.le_len(width, start)?;
                (self.back_reference(index)?, false)
            }
            tags::ARRAY_BASE..=tags::ARRAY_MAX_TAG => (self.array(tag - tags::ARRAY_BASE)?, false),
            _ if tag & 0xE0 == tags::DICT_BASE => (self.dict(tag & 0x0F)?, false),
            _ => return Err(Error::UnknownTag { tag, offset: start }),
        };

        if record {
            self.table.record(&value);
        }
        Ok(value)
    }

    /// Decode a `0x30..=0x33` integer. The caller has already matched the tag, so `from_tag`
    /// cannot fail; the fallback is there only to avoid an unreachable panic.
    fn sized_uint(&mut self, tag: u8) -> Result<Value> {
        let width = UintWidth::from_tag(tag).unwrap_or(UintWidth::One);
        Ok(Value::SizedUint {
            value: self.le_uint(width.byte_count())?,
            width,
        })
    }

    fn string(&mut self, length: usize, start: usize) -> Result<Value> {
        // Charged after `take`, so a length prefix that is merely a lie about a truncated buffer
        // still reports the truncation rather than the budget.
        let bytes = self.take(length)?;
        let text = core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8 { offset: start })?;
        self.charge(length)?;
        Ok(Value::String(Arc::from(text)))
    }

    fn data(&mut self, length: usize) -> Result<Value> {
        let bytes = Bytes::copy_from_slice(self.take(length)?);
        self.charge(length)?;
        Ok(Value::Data(bytes))
    }

    /// Resolve a back-reference, charging one [`Value`] slot for the clone.
    ///
    /// One slot and not the referenced value's length: only scalars are ever interned (containers
    /// are recorded by neither side, see [`crate::ser`]), and every scalar payload is either
    /// inline, an [`Arc`] or a [`Bytes`], so the clone is O(1) whatever the value's length.
    fn back_reference(&mut self, index: usize) -> Result<Value> {
        self.charge(ELEMENT_COST)?;
        self.table
            .get(index)
            .cloned()
            .ok_or(Error::BadBackReference {
                index,
                len: self.table.len(),
            })
    }

    fn array(&mut self, count: u8) -> Result<Value> {
        self.enter()?;
        let mut items = Vec::new();
        if count == tags::CONTAINER_ENDLESS_COUNT {
            while self.peek()? != tags::TERMINATOR {
                self.charge(ELEMENT_COST)?;
                items.push(self.value()?);
            }
            self.offset += 1;
        } else {
            for _ in 0..count {
                self.charge(ELEMENT_COST)?;
                items.push(self.value()?);
            }
        }
        self.depth -= 1;
        Ok(Value::Array(items))
    }

    fn dict(&mut self, count: u8) -> Result<Value> {
        self.enter()?;
        let mut entries = Vec::new();
        if count == tags::CONTAINER_ENDLESS_COUNT {
            while self.peek()? != tags::TERMINATOR {
                self.charge(2 * ELEMENT_COST)?;
                let key = self.value()?;
                entries.push((key, self.value()?));
            }
            self.offset += 1;
        } else {
            for _ in 0..count {
                self.charge(2 * ELEMENT_COST)?;
                let key = self.value()?;
                entries.push((key, self.value()?));
            }
        }
        self.depth -= 1;
        Ok(Value::Dict(entries))
    }
}
