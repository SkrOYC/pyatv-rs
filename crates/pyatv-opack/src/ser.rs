//! OPACK encoder.
//!
//! Only the small-integer and boolean/null paths are implemented so far; they are the ones whose
//! encoding is unambiguous from `pyatv/support/opack.py` without a captured payload to check
//! against. Everything else is deliberately left as a stub rather than guessed at, because a
//! plausible-but-wrong OPACK encoder fails silently against real hardware.

use bytes::{BufMut, BytesMut};

use crate::tags;
use crate::value::Value;
use crate::{Error, Result};

/// Encode a value into a fresh buffer.
///
/// # Errors
///
/// Returns [`Error::UnpackOnlyTag`] for values pyatv can decode but never emits.
pub fn pack(value: &Value) -> Result<BytesMut> {
    let mut out = BytesMut::new();
    encode(value, &mut out)?;
    Ok(out)
}

/// Append the encoding of `value` to `out`.
///
/// # Errors
///
/// Returns [`Error::UnpackOnlyTag`] for values pyatv can decode but never emits.
pub fn encode(value: &Value, out: &mut BytesMut) -> Result<()> {
    match value {
        Value::Null => out.put_u8(tags::NULL),
        Value::Bool(true) => out.put_u8(tags::TRUE),
        Value::Bool(false) => out.put_u8(tags::FALSE),
        Value::Uint(number) => encode_uint(*number, out),
        Value::Uuid(bytes) => {
            out.put_u8(tags::UUID);
            out.put_slice(bytes);
        }
        Value::Int(_) => {
            // pyatv's own module docstring records this gap: absolute time can be unpacked as an
            // integer but never packed. Signed values only ever arrive from that path.
            return Err(Error::UnpackOnlyTag {
                tag: tags::ABSOLUTE_TIME,
            });
        }
        // TODO(step-1): implement the length-prefixed tag families. Each needs the "count fits in
        // the tag's low nibble, otherwise emit an explicit length and terminate with 0x03" rule
        // from docs/research/rust-crates.md §6, plus the back-reference table that dedupes repeated
        // values by encoded bytes on the pack side. Do not ship these without device-captured
        // vectors.
        Value::Float(_) | Value::String(_) | Value::Data(_) | Value::Array(_) | Value::Dict(_) => {
            todo!("OPACK encoding for length-prefixed and container tags")
        }
    }
    Ok(())
}

/// Encode an unsigned integer using the narrowest representation pyatv would choose.
fn encode_uint(number: u64, out: &mut BytesMut) {
    if let Ok(small) = u8::try_from(number)
        && small < tags::SMALL_INT_LIMIT
    {
        out.put_u8(small + tags::SMALL_INT_BIAS);
    } else if let Ok(byte) = u8::try_from(number) {
        out.put_u8(tags::INT_U8);
        out.put_u8(byte);
    } else if let Ok(short) = u16::try_from(number) {
        out.put_u8(tags::INT_U16);
        out.put_u16_le(short);
    } else if let Ok(word) = u32::try_from(number) {
        out.put_u8(tags::INT_U32);
        out.put_u32_le(word);
    } else {
        out.put_u8(tags::INT_U64);
        out.put_u64_le(number);
    }
}

#[cfg(test)]
mod tests {
    use super::pack;
    use crate::value::Value;

    /// The single-byte integer rule from `pyatv/support/opack.py`: values below `0x28` are encoded
    /// as `value + 8`, so `0` is `0x08` and `0x27` is `0x2f`.
    #[test]
    fn small_integers_are_biased_by_eight() {
        assert_eq!(&pack(&Value::Uint(0)).unwrap()[..], &[0x08]);
        assert_eq!(&pack(&Value::Uint(1)).unwrap()[..], &[0x09]);
        assert_eq!(&pack(&Value::Uint(0x27)).unwrap()[..], &[0x2f]);
    }

    /// `0x28` no longer fits the biased single-byte form and takes the `0x30` prefix instead.
    #[test]
    fn integers_at_the_boundary_take_a_width_prefix() {
        assert_eq!(&pack(&Value::Uint(0x28)).unwrap()[..], &[0x30, 0x28]);
        assert_eq!(&pack(&Value::Uint(0xff)).unwrap()[..], &[0x30, 0xff]);
        assert_eq!(
            &pack(&Value::Uint(0x0100)).unwrap()[..],
            &[0x31, 0x00, 0x01]
        );
    }

    #[test]
    fn booleans_and_null_are_single_tag_bytes() {
        assert_eq!(&pack(&Value::Bool(true)).unwrap()[..], &[0x01]);
        assert_eq!(&pack(&Value::Bool(false)).unwrap()[..], &[0x02]);
        assert_eq!(&pack(&Value::Null).unwrap()[..], &[0x04]);
    }
}
