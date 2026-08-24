//! OPACK codec errors.

/// Something went wrong packing or unpacking an OPACK payload.
#[derive(Debug, thiserror::Error)]
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
    /// pyatv's `opack.py` documents absolute time (`0x06`) as exactly this case; the port keeps the
    /// same asymmetry rather than inventing an encoding that no device would accept.
    #[error("tag {tag:#04x} can be unpacked but not packed")]
    UnpackOnlyTag {
        /// The offending tag byte.
        tag: u8,
    },

    /// A back-reference pointed outside the table of values seen so far.
    #[error("back-reference {index} is out of range ({len} values seen)")]
    BadBackReference {
        /// The requested index.
        index: usize,
        /// How many values had been recorded.
        len: usize,
    },

    /// A string or UUID field did not contain valid data.
    #[error("malformed {kind} value at offset {offset}")]
    Malformed {
        /// What kind of value failed to decode, e.g. `"utf-8 string"`.
        kind: &'static str,
        /// Offset of the value within the input.
        offset: usize,
    },
}
