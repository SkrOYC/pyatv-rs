//! The base-128 varint that length-prefixes direct-connection MRP frames.
//!
//! Ported from `pyatv/support/variant.py`. This is bit-compatible with protobuf's own varint, but
//! it sits *outside* any protobuf message — it is a raw length prefix on the socket — so it is
//! implemented here rather than borrowed from `prost`'s internals. See
//! `docs/research/mrp-companion.md` §1.2.
//!
//! The prefixed length covers whatever is actually on the wire: the serialised protobuf before
//! pair-verify completes, and the ciphertext plus its 16-byte Poly1305 tag afterwards.

use crate::{Error, Result};

/// A varint never needs more than ten bytes to carry a `u64`.
pub const MAX_LEN: usize = 10;

/// Encode `value` as a base-128 varint, least significant group first.
#[must_use]
pub fn write(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    let mut remaining = value;

    loop {
        let group = u8::try_from(remaining & 0x7F).unwrap_or(0);
        remaining >>= 7;
        if remaining == 0 {
            out.push(group);
            break;
        }
        out.push(group | 0x80);
    }

    out
}

/// Decode a varint from the front of `input`, returning it and how many bytes it occupied.
///
/// # Errors
///
/// Returns [`Error::Framing`] if `input` ends before the continuation bit clears, or if the varint
/// runs past [`MAX_LEN`] bytes.
pub fn read(input: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0u64;

    for (index, byte) in input.iter().take(MAX_LEN).enumerate() {
        result |= u64::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok((result, index + 1));
        }
    }

    Err(Error::Framing(if input.len() < MAX_LEN {
        format!("varint truncated after {} bytes", input.len())
    } else {
        format!("varint longer than {MAX_LEN} bytes")
    }))
}

#[cfg(test)]
mod tests {
    use super::{MAX_LEN, read, write};

    /// Values below 128 are a single byte with the continuation bit clear.
    #[test]
    fn small_values_are_one_byte() {
        assert_eq!(write(0), vec![0x00]);
        assert_eq!(write(1), vec![0x01]);
        assert_eq!(write(127), vec![0x7F]);
    }

    /// 128 is the first value needing a continuation: `0x80 0x01`, least significant group first.
    #[test]
    fn multi_byte_values_are_little_endian_base_128() {
        assert_eq!(write(128), vec![0x80, 0x01]);
        assert_eq!(write(300), vec![0xAC, 0x02]);
        assert_eq!(write(16_384), vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn round_trips_across_every_width_boundary() {
        for value in [
            0,
            1,
            127,
            128,
            300,
            16_383,
            16_384,
            2_097_151,
            2_097_152,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let encoded = write(value);
            assert_eq!(read(&encoded).unwrap(), (value, encoded.len()));
        }
    }

    /// The decoder must report how much it consumed so the caller can find the payload.
    #[test]
    fn reports_its_own_length_and_leaves_the_payload_alone() {
        let mut frame = write(300);
        frame.extend_from_slice(b"payload");

        let (length, consumed) = read(&frame).unwrap();
        assert_eq!(length, 300);
        assert_eq!(consumed, 2);
        assert_eq!(&frame[consumed..], b"payload");
    }

    #[test]
    fn truncated_and_overlong_varints_are_rejected() {
        assert!(read(&[]).is_err());
        assert!(read(&[0x80]).is_err());
        assert!(read(&[0x80; MAX_LEN]).is_err());
    }
}
