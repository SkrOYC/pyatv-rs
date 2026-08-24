//! OPACK encoder — a port of `_pack` in `pyatv/support/opack.py:38-132`.
//!
//! Two of pyatv's documented gaps are reproduced deliberately:
//!
//! * **Absolute time cannot be packed.** pyatv raises `NotImplementedError` for a `datetime`
//!   (`opack.py:46-47`); [`Value::AbsoluteTime`] returns [`Error::UnpackOnlyTag`] here.
//! * **Negative integers are unrepresentable.** [`Value`] has no signed variant at all, so the
//!   corruption pyatv produces for `pack(-1)` cannot be expressed.
//!
//! Two things pyatv does are *not* reproduced.
//!
//! Its module docstring claims "Pack implementation does not implement UID referencing"
//! (`opack.py:5`), but `opack.py:116-131` plainly does emit back-references and
//! `tests/support/test_opack.py:112-199` locks the exact bytes in. The docstring is stale, so
//! this encoder interns too.
//!
//! It interns a slightly different *set* of values, though. pyatv decides by encoded length, which
//! makes its encoder intern containers and skip empty strings — neither of which its own decoder
//! agrees with, so pyatv can emit a payload it cannot itself parse. This encoder uses the
//! decoder's rule instead; see the `is_interned` helper below. Every vector in pyatv's suite
//! encodes to the same bytes either way.

use bytes::{BufMut, BytesMut};

use crate::objects::PackTable;
use crate::tags;
use crate::value::{UintWidth, Value};
use crate::{Error, MAX_DEPTH, Result};

/// Encode a value into a fresh buffer.
///
/// # Errors
///
/// Returns [`Error::UnpackOnlyTag`] for [`Value::AbsoluteTime`],
/// [`Error::SizedIntegerOverflow`] when a [`Value::SizedUint`] does not fit its pinned width,
/// [`Error::ValueTooLong`] for a string above `u32::MAX` bytes, and
/// [`Error::DepthLimitExceeded`] when containers nest deeper than [`MAX_DEPTH`].
pub fn pack(value: &Value) -> Result<BytesMut> {
    let mut out = BytesMut::new();
    encode(value, &mut out)?;
    Ok(out)
}

/// Append a complete OPACK document to `out`.
///
/// Each call starts a fresh back-reference table, exactly as pyatv's `pack()` does
/// (`opack.py:33-35`), so appending two documents to one buffer never produces a back-reference
/// that crosses between them.
///
/// # Errors
///
/// As [`pack`].
pub fn encode(value: &Value, out: &mut BytesMut) -> Result<()> {
    let mut encoder = Encoder {
        table: PackTable::default(),
        depth: 0,
    };
    encoder.value(value, out)
}

/// Encoder state: the interning table and the current container nesting depth.
#[derive(Debug)]
struct Encoder {
    table: PackTable,
    depth: usize,
}

impl Encoder {
    /// Encode one value, replacing it with a back-reference if an identical encoding was already
    /// emitted (`opack.py:116-130`).
    fn value(&mut self, value: &Value, out: &mut BytesMut) -> Result<()> {
        let mark = out.len();
        self.write(value, out)?;

        if let Some(index) = self.table.lookup(&out[mark..]) {
            if let Some((bytes, len)) = pointer_bytes(index) {
                out.truncate(mark);
                out.put_slice(&bytes[..len]);
            }
            // Otherwise the index is beyond what this crate will emit; the value simply stays
            // inline. The table is untouched either way, so the decoder's numbering stays in
            // step — a decoder does not record a value that equals one it has already seen.
            return Ok(());
        }

        if is_interned(value) {
            self.table.record(&out[mark..]);
        }
        Ok(())
    }

    /// Encode one value without consulting the back-reference table.
    fn write(&mut self, value: &Value, out: &mut BytesMut) -> Result<()> {
        match value {
            Value::Null => out.put_u8(tags::NULL),
            Value::Bool(true) => out.put_u8(tags::TRUE),
            Value::Bool(false) => out.put_u8(tags::FALSE),
            Value::Uint(number) => write_uint(*number, out),
            Value::SizedUint { value, width } => write_sized_uint(*value, *width, out)?,
            Value::Float(number) => {
                out.put_u8(tags::FLOAT64);
                out.put_f64_le(*number);
            }
            Value::Float32(number) => {
                out.put_u8(tags::FLOAT32);
                out.put_f32_le(*number);
            }
            Value::String(text) => write_string(text, out)?,
            Value::Data(bytes) => write_data(bytes, out),
            Value::Uuid(bytes) => {
                out.put_u8(tags::UUID);
                out.put_slice(bytes);
            }
            Value::AbsoluteTime(_) => {
                return Err(Error::UnpackOnlyTag {
                    tag: tags::ABSOLUTE_TIME,
                });
            }
            Value::Array(items) => {
                self.enter()?;
                out.put_u8(container_tag(tags::ARRAY_BASE, items.len()));
                for item in items {
                    self.value(item, out)?;
                }
                finish_container(items.len(), out);
                self.depth -= 1;
            }
            Value::Dict(entries) => {
                self.enter()?;
                out.put_u8(container_tag(tags::DICT_BASE, entries.len()));
                for (key, entry) in entries {
                    self.value(key, out)?;
                    self.value(entry, out)?;
                }
                finish_container(entries.len(), out);
                self.depth -= 1;
            }
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<()> {
        if self.depth >= MAX_DEPTH {
            return Err(Error::DepthLimitExceeded { limit: MAX_DEPTH });
        }
        self.depth += 1;
        Ok(())
    }
}

/// Whether a value takes a slot in the back-reference table.
///
/// This is the decoder's rule, applied to both sides: everything except booleans, null, small
/// integers and containers (`opack.py:146`, `opack.py:149`, `opack.py:152`, `opack.py:161`,
/// `opack.py:208`, `opack.py:225`). It deliberately differs from pyatv's encoder, which keys off
/// the encoded length instead and so interns containers while skipping the empty string — see
/// the `objects` module for why that combination cannot round-trip. On pyatv's own vectors the
/// two rules agree byte for byte.
fn is_interned(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Dict(_) => false,
        Value::Uint(number) => *number >= tags::SMALL_INT_LIMIT,
        Value::SizedUint { .. }
        | Value::Float(_)
        | Value::Float32(_)
        | Value::String(_)
        | Value::Data(_)
        | Value::Uuid(_)
        | Value::AbsoluteTime(_) => true,
    }
}

/// `base + min(count, 0xF)` (`opack.py:102`, `opack.py:108`).
fn container_tag(base: u8, count: usize) -> u8 {
    // Any count that does not even fit a `u8` is well past the `0xF` nibble, so it saturates.
    let nibble = u8::try_from(count)
        .unwrap_or(tags::CONTAINER_ENDLESS_COUNT)
        .min(tags::CONTAINER_ENDLESS_COUNT);
    base + nibble
}

/// Containers whose count reached the `0xF` nibble are terminated explicitly
/// (`opack.py:105-106`, `opack.py:111-112`).
fn finish_container(count: usize, out: &mut BytesMut) {
    if count >= usize::from(tags::CONTAINER_ENDLESS_COUNT) {
        out.put_u8(tags::TERMINATOR);
    }
}

/// The narrowest integer encoding pyatv would choose (`opack.py:48-59`).
fn write_uint(number: u64, out: &mut BytesMut) {
    // `number < 0x28` fits in the tag byte, so 0 encodes as 0x08 and 0x27 as 0x2F.
    if let Ok(small) = u8::try_from(number)
        && u64::from(small) < tags::SMALL_INT_LIMIT
    {
        out.put_u8(small + tags::SMALL_INT_BIAS);
    } else {
        write_sized(number, UintWidth::narrowest_for(number), out);
    }
}

/// Encode at a pinned width, as pyatv does for an integer carrying a `size` hint
/// (`opack.py:49-59`).
fn write_sized_uint(number: u64, width: UintWidth, out: &mut BytesMut) -> Result<()> {
    let bytes = width.byte_count();
    if bytes < 8 && number >= 1u64 << (bytes * 8) {
        return Err(Error::SizedIntegerOverflow {
            value: number,
            bytes,
        });
    }
    write_sized(number, width, out);
    Ok(())
}

fn write_sized(number: u64, width: UintWidth, out: &mut BytesMut) {
    out.put_u8(width.tag());
    out.put_slice(&number.to_le_bytes()[..width.byte_count()]);
}

/// UTF-8 strings: inline up to 32 bytes, then 1/2/3/4-byte little-endian length prefixes
/// (`opack.py:62-81`).
fn write_string(text: &str, out: &mut BytesMut) -> Result<()> {
    let encoded = text.as_bytes();
    let length = encoded.len();
    if let Ok(nibble) = u8::try_from(length)
        && length <= tags::STRING_INLINE_MAX_LEN
    {
        out.put_u8(tags::STRING_INLINE_BASE + nibble);
    } else {
        let wide = u64::try_from(length).unwrap_or(u64::MAX);
        // Note the 3-byte step at 0x63, which the byte-string family below does not have.
        let width: u8 = if wide <= 0xFF {
            1
        } else if wide <= 0xFFFF {
            2
        } else if wide <= 0x00FF_FFFF {
            3
        } else if wide <= 0xFFFF_FFFF {
            4
        } else {
            return Err(Error::ValueTooLong {
                kind: "string",
                length,
            });
        };
        out.put_u8(tags::STRING_LEN_BASE + width);
        put_length(wide, usize::from(width), out);
    }
    out.put_slice(encoded);
    Ok(())
}

/// Byte strings: inline up to 32 bytes, then 1/2/4/8-byte little-endian length prefixes
/// (`opack.py:82-100`). Every `usize` fits the 8-byte form, so this cannot fail.
fn write_data(bytes: &[u8], out: &mut BytesMut) {
    let length = bytes.len();
    if let Ok(nibble) = u8::try_from(length)
        && length <= tags::DATA_INLINE_MAX_LEN
    {
        out.put_u8(tags::DATA_INLINE_BASE + nibble);
    } else {
        let wide = u64::try_from(length).unwrap_or(u64::MAX);
        let (tag_offset, width): (u8, usize) = if wide <= 0xFF {
            (1, 1)
        } else if wide <= 0xFFFF {
            (2, 2)
        } else if wide <= 0xFFFF_FFFF {
            (3, 4)
        } else {
            (4, 8)
        };
        out.put_u8(tags::DATA_LEN_BASE + tag_offset);
        put_length(wide, width, out);
    }
    out.put_slice(bytes);
}

/// Write the low `width` bytes of `length`, little-endian.
fn put_length(length: u64, width: usize, out: &mut BytesMut) {
    out.put_slice(&length.to_le_bytes()[..width]);
}

/// The shortest back-reference encoding for `index`, or `None` when this crate declines to emit
/// one.
///
/// `0xC3` and `0xC4` are deliberately never emitted: pyatv's encoder and decoder disagree about
/// how many index bytes they carry (see [`tags::POINTER_LEN_BASE`]), and reaching index `0x1_0000`
/// would take 65 537 distinct interned sub-values in a single message. Callers fall back to
/// emitting the value inline, which keeps both tables aligned.
fn pointer_bytes(index: usize) -> Option<([u8; 3], usize)> {
    if index <= tags::POINTER_INLINE_MAX_INDEX {
        let offset = u8::try_from(index).ok()?;
        Some(([tags::POINTER_INLINE_BASE + offset, 0, 0], 1))
    } else if let Ok(byte) = u8::try_from(index) {
        Some(([tags::POINTER_LEN_BASE + 1, byte, 0], 2))
    } else if let Ok(short) = u16::try_from(index) {
        let [low, high] = short.to_le_bytes();
        Some(([tags::POINTER_LEN_BASE + 2, low, high], 3))
    } else {
        None
    }
}
