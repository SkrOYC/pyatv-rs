//! The little bit of protobuf wire format needed to reach a proto2 extension field.
//!
//! `prost` drops `extend` blocks at codegen time and discards unknown fields at decode time (see
//! `docs/research/mrp-protobuf-spike.md`), so the extension payload can only be recovered from the
//! serialised `ProtocolMessage` itself. That is cheap: an extension is an ordinary field with a
//! known tag number, so all this module does is walk the top-level fields of a message, hand back
//! the bytes of the one that is wanted, and splice a field into a buffer in tag order.
//!
//! Nothing here recurses into submessages — the extension payload is handed to `prost` for that.
//!
//! The varint reader is [`crate::variant`], which already implements protobuf's base-128 encoding
//! for MRP's outer length prefix.

use crate::{Error, Result, variant};

/// Protobuf wire types, as encoded in the low three bits of a field key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// Base-128 integer.
    Varint,
    /// Eight raw bytes.
    Fixed64,
    /// Varint byte count followed by that many bytes: submessages, strings and byte fields.
    LengthDelimited,
    /// Four raw bytes.
    Fixed32,
}

impl WireType {
    /// The three-bit tag encoding of this wire type.
    #[must_use]
    pub const fn code(self) -> u64 {
        match self {
            Self::Varint => 0,
            Self::Fixed64 => 1,
            Self::LengthDelimited => 2,
            Self::Fixed32 => 5,
        }
    }

    /// Decode a wire type, rejecting the two deprecated group codes.
    fn from_code(code: u64, offset: usize) -> Result<Self> {
        match code {
            0 => Ok(Self::Varint),
            1 => Ok(Self::Fixed64),
            2 => Ok(Self::LengthDelimited),
            5 => Ok(Self::Fixed32),
            3 | 4 => Err(Error::WireFormat {
                offset,
                reason: "group wire types are not used by the MRP corpus",
            }),
            _ => Err(Error::WireFormat {
                offset,
                reason: "unknown wire type",
            }),
        }
    }
}

/// One top-level field of a serialised message.
#[derive(Debug, Clone, Copy)]
pub struct Field<'a> {
    /// Field (tag) number.
    pub number: u32,
    /// How the value is encoded.
    pub wire_type: WireType,
    /// The value, with the key and any length prefix stripped.
    pub value: &'a [u8],
    /// Offset of the field key within the buffer being scanned.
    pub start: usize,
    /// Offset one past the last byte of the field.
    pub end: usize,
}

/// A forward-only scan over the top-level fields of a serialised message.
#[derive(Debug)]
pub struct Scanner<'a> {
    buffer: &'a [u8],
    offset: usize,
}

impl<'a> Scanner<'a> {
    /// Start scanning `buffer`.
    #[must_use]
    pub const fn new(buffer: &'a [u8]) -> Self {
        Self { buffer, offset: 0 }
    }

    /// The next field, or `None` at the end of the buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] on a truncated field, an unknown or group wire type, or a
    /// length prefix that runs past the end of the buffer, and [`Error::Framing`] if a varint is
    /// malformed.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>> {
        if self.offset >= self.buffer.len() {
            return Ok(None);
        }

        let start = self.offset;
        let (key, consumed) = variant::read(&self.buffer[start..])?;
        self.offset += consumed;

        let number = u32::try_from(key >> 3).map_err(|_| Error::WireFormat {
            offset: start,
            reason: "field number out of range",
        })?;
        if number == 0 {
            return Err(Error::WireFormat {
                offset: start,
                reason: "field number zero is not valid",
            });
        }
        let wire_type = WireType::from_code(key & 0x07, start)?;

        let value = match wire_type {
            WireType::Varint => {
                let (_, consumed) = variant::read(&self.buffer[self.offset..])?;
                self.take(consumed, start)?
            }
            WireType::Fixed64 => self.take(8, start)?,
            WireType::Fixed32 => self.take(4, start)?,
            WireType::LengthDelimited => {
                let (length, consumed) = variant::read(&self.buffer[self.offset..])?;
                self.offset += consumed;
                let length = usize::try_from(length).map_err(|_| Error::WireFormat {
                    offset: start,
                    reason: "length prefix does not fit in memory",
                })?;
                self.take(length, start)?
            }
        };

        Ok(Some(Field {
            number,
            wire_type,
            value,
            start,
            end: self.offset,
        }))
    }

    /// Consume `count` bytes, failing if the buffer is short.
    fn take(&mut self, count: usize, start: usize) -> Result<&'a [u8]> {
        let end = self.offset.checked_add(count).ok_or(Error::WireFormat {
            offset: start,
            reason: "field length overflows the buffer",
        })?;
        let slice = self.buffer.get(self.offset..end).ok_or(Error::WireFormat {
            offset: start,
            reason: "field is truncated",
        })?;
        self.offset = end;
        Ok(slice)
    }
}

/// The value of the length-delimited field numbered `number`, if the message carries one.
///
/// The *last* occurrence wins, which is what proto2 specifies for an `optional` field appearing
/// more than once, and what every reference implementation does.
///
/// # Errors
///
/// Propagates any scan error, and returns [`Error::WireFormat`] if the field is present but not
/// length-delimited — an extension declared as a message or a string can never be anything else,
/// so that combination means the buffer is not the message it claims to be.
pub fn find_length_delimited(buffer: &[u8], number: u32) -> Result<Option<&[u8]>> {
    let mut scanner = Scanner::new(buffer);
    let mut found = None;

    while let Some(field) = scanner.next_field()? {
        if field.number != number {
            continue;
        }
        if field.wire_type != WireType::LengthDelimited {
            return Err(Error::WireFormat {
                offset: field.start,
                reason: "extension field is not length-delimited",
            });
        }
        found = Some(field.value);
    }

    Ok(found)
}

/// Append a length-delimited field to `out`.
///
/// The length conversion is a `try_from` rather than an `as` cast. It cannot fail on any target
/// this builds for — a `usize` is at most 64 bits everywhere — but `as` would silently truncate on
/// one where it could, and a truncated protobuf length is a corrupt message rather than a loud
/// failure. `u64::MAX` as the fallback keeps that case producing something no parser will accept.
pub fn write_length_delimited(number: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&variant::write(
        (u64::from(number) << 3) | WireType::LengthDelimited.code(),
    ));
    out.extend_from_slice(&variant::write(
        u64::try_from(payload.len()).unwrap_or(u64::MAX),
    ));
    out.extend_from_slice(payload);
}

/// Insert a length-delimited field into `buffer`, keeping fields in ascending tag order.
///
/// Any existing field with the same number is replaced. Tag order is not required by protobuf, but
/// it is what the Python reference implementation emits, so matching it lets the known-answer
/// vectors compare whole serialised messages byte for byte instead of field by field.
///
/// # Errors
///
/// Propagates any scan error from `buffer`.
pub fn splice_length_delimited(buffer: &[u8], number: u32, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(buffer.len() + payload.len() + 8);
    let mut scanner = Scanner::new(buffer);
    let mut written = false;

    while let Some(field) = scanner.next_field()? {
        if field.number == number {
            continue;
        }
        if field.number > number && !written {
            write_length_delimited(number, payload, &mut out);
            written = true;
        }
        out.extend_from_slice(&buffer[field.start..field.end]);
    }

    if !written {
        write_length_delimited(number, payload, &mut out);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{Scanner, WireType, find_length_delimited, splice_length_delimited};

    /// `08 01` is field 1, varint, value 1 — a `ProtocolMessage.type` of `SEND_COMMAND_MESSAGE`.
    #[test]
    fn scans_a_varint_field() {
        let mut scanner = Scanner::new(&[0x08, 0x01]);
        let field = scanner.next_field().unwrap().unwrap();

        assert_eq!(field.number, 1);
        assert_eq!(field.wire_type, WireType::Varint);
        assert_eq!(field.value, &[0x01]);
        assert_eq!((field.start, field.end), (0, 2));
        assert!(scanner.next_field().unwrap().is_none());
    }

    #[test]
    fn scans_every_wire_type() {
        // field 1 varint, field 2 fixed64, field 3 length-delimited, field 4 fixed32.
        let buffer = [
            0x08, 0x96, 0x01, 0x11, 1, 2, 3, 4, 5, 6, 7, 8, 0x1A, 0x02, 0xAA, 0xBB, 0x25, 9, 9, 9,
            9,
        ];
        let mut scanner = Scanner::new(&buffer);
        let mut seen = Vec::new();
        while let Some(field) = scanner.next_field().unwrap() {
            seen.push((field.number, field.wire_type, field.value.len()));
        }

        assert_eq!(
            seen,
            vec![
                (1, WireType::Varint, 2),
                (2, WireType::Fixed64, 8),
                (3, WireType::LengthDelimited, 2),
                (4, WireType::Fixed32, 4),
            ]
        );
    }

    #[test]
    fn finds_a_length_delimited_field_and_ignores_the_rest() {
        // field 1 varint 4, field 9 length-delimited "hi", field 85 length-delimited "id".
        let buffer = [
            0x08, 0x04, 0x4A, 0x02, b'h', b'i', 0xAA, 0x05, 0x02, b'i', b'd',
        ];

        assert_eq!(find_length_delimited(&buffer, 9).unwrap(), Some(&b"hi"[..]));
        assert_eq!(
            find_length_delimited(&buffer, 85).unwrap(),
            Some(&b"id"[..])
        );
        assert_eq!(find_length_delimited(&buffer, 6).unwrap(), None);
    }

    /// proto2 says the last occurrence of a repeated `optional` field wins.
    #[test]
    fn later_occurrences_win() {
        let buffer = [0x4A, 0x01, b'a', 0x4A, 0x01, b'b'];
        assert_eq!(find_length_delimited(&buffer, 9).unwrap(), Some(&b"b"[..]));
    }

    #[test]
    fn rejects_a_field_of_the_wrong_wire_type() {
        assert!(find_length_delimited(&[0x48, 0x01], 9).is_err());
    }

    #[test]
    fn rejects_truncated_and_invalid_fields() {
        // Length prefix of 4 with only two bytes left.
        assert!(find_length_delimited(&[0x4A, 0x04, 0xAA, 0xBB], 9).is_err());
        // Wire type 3 (start group).
        assert!(find_length_delimited(&[0x4B, 0x01], 9).is_err());
        // Field number zero.
        assert!(find_length_delimited(&[0x00, 0x01], 9).is_err());
    }

    #[test]
    fn splices_in_tag_order() {
        // Envelope with fields 1 and 85; the extension is field 9 and belongs between them.
        let buffer = [0x08, 0x04, 0xAA, 0x05, 0x02, b'i', b'd'];
        let spliced = splice_length_delimited(&buffer, 9, b"hi").unwrap();

        assert_eq!(
            spliced,
            vec![
                0x08, 0x04, 0x4A, 0x02, b'h', b'i', 0xAA, 0x05, 0x02, b'i', b'd'
            ]
        );
    }

    #[test]
    fn splices_after_every_lower_tag() {
        let buffer = [0x08, 0x04];
        assert_eq!(
            splice_length_delimited(&buffer, 9, b"hi").unwrap(),
            vec![0x08, 0x04, 0x4A, 0x02, b'h', b'i']
        );
    }

    #[test]
    fn splicing_replaces_an_existing_field() {
        let buffer = [0x08, 0x04, 0x4A, 0x01, b'a', 0xAA, 0x05, 0x01, b'x'];
        let spliced = splice_length_delimited(&buffer, 9, b"bb").unwrap();

        assert_eq!(
            spliced,
            vec![0x08, 0x04, 0x4A, 0x02, b'b', b'b', 0xAA, 0x05, 0x01, b'x']
        );
    }

    /// A payload longer than 127 bytes needs a two-byte length prefix; check the boundary.
    #[test]
    fn splices_a_long_payload() {
        let payload = vec![0x7Fu8; 200];
        let spliced = splice_length_delimited(&[], 9, &payload).unwrap();

        assert_eq!(&spliced[..3], &[0x4A, 0xC8, 0x01]);
        assert_eq!(
            find_length_delimited(&spliced, 9).unwrap(),
            Some(&payload[..])
        );
    }
}
