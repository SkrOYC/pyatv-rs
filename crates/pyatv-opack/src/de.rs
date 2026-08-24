//! OPACK decoder.
//!
//! Mirrors [`crate::ser`]: the tags whose meaning is unambiguous from `pyatv/support/opack.py` are
//! decoded, the rest are stubbed. The decoder must also maintain the back-reference table that the
//! `0xA0` pointer tags index into — pyatv dedupes by value on the unpack side and by encoded bytes
//! on the pack side, an asymmetry worth reproducing rather than tidying up, since it is what real
//! devices interoperate with.

use crate::tags;
use crate::value::Value;
use crate::{Error, Result};

/// Decode one OPACK value from the front of `input`, returning it and the number of bytes consumed.
///
/// # Errors
///
/// Returns [`Error::UnexpectedEof`] on a truncated payload and [`Error::UnknownTag`] for a tag byte
/// pyatv's reference implementation does not define.
pub fn unpack(input: &[u8]) -> Result<(Value, usize)> {
    let mut decoder = Decoder {
        input,
        offset: 0,
        seen: Vec::new(),
    };
    let value = decoder.value()?;
    Ok((value, decoder.offset))
}

/// Decoder state, including the back-reference table.
#[derive(Debug)]
struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
    /// Values in first-seen order, indexed by the `0xA0` pointer tags.
    seen: Vec<Value>,
}

impl Decoder<'_> {
    fn take(&mut self, count: usize) -> Result<&[u8]> {
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

    fn value(&mut self) -> Result<Value> {
        let offset = self.offset;
        let tag = self.tag()?;

        let value = match tag {
            tags::TRUE => Value::Bool(true),
            tags::FALSE => Value::Bool(false),
            tags::NULL => Value::Null,
            tags::UUID => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(self.take(16)?);
                Value::Uuid(bytes)
            }
            tags::INT_U8 => Value::Uint(u64::from(self.take(1)?[0])),
            tags::INT_U16 => Value::Uint(u64::from(u16::from_le_bytes(
                self.take(2)?.try_into().map_err(|_| Error::Malformed {
                    kind: "u16",
                    offset,
                })?,
            ))),
            tags::INT_U32 => Value::Uint(u64::from(u32::from_le_bytes(
                self.take(4)?.try_into().map_err(|_| Error::Malformed {
                    kind: "u32",
                    offset,
                })?,
            ))),
            tags::INT_U64 => Value::Uint(u64::from_le_bytes(self.take(8)?.try_into().map_err(
                |_| Error::Malformed {
                    kind: "u64",
                    offset,
                },
            )?)),
            byte if (tags::SMALL_INT_BIAS..tags::SMALL_INT_BIAS + tags::SMALL_INT_LIMIT)
                .contains(&byte) =>
            {
                Value::Uint(u64::from(byte - tags::SMALL_INT_BIAS))
            }
            // TODO(step-1): decode the string (0x40), data (0x70), array (0xD0), dict (0xE0) and
            // pointer (0xA0) tag families, honouring the 0x03 terminator for containers whose
            // length did not fit in the tag nibble, and push every non-pointer value onto
            // `self.seen` so pointers resolve. See docs/research/rust-crates.md §6.
            _ => return Err(Error::UnknownTag { tag, offset }),
        };

        self.seen.push(value.clone());
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::unpack;
    use crate::ser::pack;
    use crate::value::Value;

    /// Round-trip the integer and scalar paths that are fully implemented.
    #[test]
    fn scalars_round_trip() {
        for value in [
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Uint(0),
            Value::Uint(0x27),
            Value::Uint(0x28),
            Value::Uint(0xff),
            Value::Uint(0x0100),
            Value::Uint(0x0001_0000),
            Value::Uint(0x0000_0001_0000_0000),
            Value::Uuid([0xab; 16]),
        ] {
            let encoded = pack(&value).unwrap();
            let (decoded, consumed) = unpack(&encoded).unwrap();
            assert_eq!(decoded, value, "round trip failed for {value:?}");
            assert_eq!(consumed, encoded.len(), "trailing bytes for {value:?}");
        }
    }

    #[test]
    fn truncated_input_is_reported_not_panicked_on() {
        assert!(unpack(&[]).is_err());
        assert!(unpack(&[0x31, 0x00]).is_err());
    }
}
