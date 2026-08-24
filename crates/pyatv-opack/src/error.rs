//! OPACK codec errors.

/// Something went wrong packing or unpacking an OPACK payload.
///
/// Every variant that carries an `offset` reports the position of the *tag byte* that started the
/// offending value, counted from the start of the buffer handed to [`crate::unpack`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input ended in the middle of a value.
    #[error("unexpected end of input after {consumed} bytes")]
    UnexpectedEof {
        /// How many bytes had been consumed when the input ran out.
        consumed: usize,
    },

    /// A tag byte that pyatv's reference implementation does not define.
    #[error("unknown OPACK tag {tag:#04x} at offset {offset}")]
    UnknownTag {
        /// The offending tag byte.
        tag: u8,
        /// Offset of the tag byte within the input.
        offset: usize,
    },

    /// A tag that is understood on the unpack side but has no pack-side encoding.
    ///
    /// pyatv's `opack.py:4` documents absolute time (`0x06`) as exactly this case; the port keeps
    /// the same asymmetry rather than inventing an encoding that no device would accept.
    #[error("tag {tag:#04x} can be unpacked but not packed")]
    UnpackOnlyTag {
        /// The offending tag byte.
        tag: u8,
    },

    /// An integer tag asked for a width this crate cannot represent.
    ///
    /// pyatv's decoder treats the whole `0x30..=0x3F` range as "integer of `2 ** (tag & 0xF)`
    /// bytes" (`opack.py:166-167`), which reaches 32 768 bytes at `0x3F`. Only `0x30..=0x33` fit a
    /// [`u64`], so the wider tags are rejected instead of silently truncated.
    #[error("integer tag {tag:#04x} at offset {offset} is wider than 8 bytes")]
    IntegerTooWide {
        /// The offending tag byte.
        tag: u8,
        /// Offset of the tag byte within the input.
        offset: usize,
    },

    /// A back-reference pointed outside the table of values seen so far.
    #[error("back-reference {index} is out of range ({len} values seen)")]
    BadBackReference {
        /// The requested index.
        index: usize,
        /// How many values had been recorded.
        len: usize,
    },

    /// A string value was not valid UTF-8.
    #[error("invalid UTF-8 in string at offset {offset}")]
    InvalidUtf8 {
        /// Offset of the string's tag byte within the input.
        offset: usize,
    },

    /// A length or index prefix did not fit in a [`usize`] on this target.
    #[error("length prefix {length} at offset {offset} does not fit in a pointer-sized integer")]
    LengthOverflow {
        /// The decoded length.
        length: u64,
        /// Offset of the tag byte within the input.
        offset: usize,
    },

    /// Containers were nested more deeply than [`crate::MAX_DEPTH`].
    ///
    /// OPACK has no depth field, so a hostile `0xD1` repeated a million times would otherwise
    /// recurse until the stack ran out. Real Companion payloads nest three or four levels.
    #[error("container nesting exceeded the limit of {limit}")]
    DepthLimitExceeded {
        /// The configured limit.
        limit: usize,
    },

    /// A string or byte string was longer than OPACK's widest length prefix can describe.
    #[error("{kind} of {length} bytes is too long to encode")]
    ValueTooLong {
        /// Either `"string"` or `"data"`.
        kind: &'static str,
        /// The length that could not be encoded.
        length: usize,
    },

    /// A [`crate::Value::SizedUint`] carried a number too large for its pinned width.
    ///
    /// pyatv raises `OverflowError` from `int.to_bytes()` in the same situation
    /// (`opack.py:53-59`); silently widening or truncating would change the bytes on the wire.
    #[error("{value} does not fit in the pinned {bytes}-byte integer encoding")]
    SizedIntegerOverflow {
        /// The number that did not fit.
        value: u64,
        /// The pinned width, in bytes.
        bytes: usize,
    },
}
