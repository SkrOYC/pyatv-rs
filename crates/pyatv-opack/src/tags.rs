//! OPACK tag bytes, transcribed from `pyatv/support/opack.py`.
//!
//! Values here are confirmed in `docs/research/rust-crates.md` §6. Ranges rather than single bytes
//! are the norm: OPACK packs a value's length or magnitude into the low nibble of its tag wherever
//! it fits, and only falls back to an explicit length prefix when it does not.

/// `true`.
pub const TRUE: u8 = 0x01;
/// `false`.
pub const FALSE: u8 = 0x02;
/// Null / absent.
pub const NULL: u8 = 0x04;
/// A 16-byte UUID follows.
pub const UUID: u8 = 0x05;
/// Absolute time. pyatv can unpack this as an integer but never packs it.
pub const ABSOLUTE_TIME: u8 = 0x06;

/// Integers below this value are encoded in a single byte as `value + 8`.
pub const SMALL_INT_LIMIT: u8 = 0x28;
/// Bias added to a small integer to produce its single-byte tag.
pub const SMALL_INT_BIAS: u8 = 0x08;

/// One little-endian byte of unsigned integer follows.
pub const INT_U8: u8 = 0x30;
/// Two little-endian bytes of unsigned integer follow.
pub const INT_U16: u8 = 0x31;
/// Four little-endian bytes of unsigned integer follow.
pub const INT_U32: u8 = 0x32;
/// Eight little-endian bytes of unsigned integer follow.
pub const INT_U64: u8 = 0x33;

/// Base tag for strings whose byte length fits in the low nibble.
pub const STRING_BASE: u8 = 0x40;
/// Base tag for byte strings whose length fits in the low nibble.
pub const DATA_BASE: u8 = 0x70;
/// Base tag for arrays whose element count fits in the low nibble.
pub const ARRAY_BASE: u8 = 0xD0;
/// Base tag for dictionaries whose entry count fits in the low nibble.
pub const DICT_BASE: u8 = 0xE0;
/// Base tag for back-references into the table of already-seen values.
pub const POINTER_BASE: u8 = 0xA0;

/// Terminates an array or dictionary whose length did not fit in its tag nibble.
pub const TERMINATOR: u8 = 0x03;

/// The largest count or length encodable directly in a tag's low nibble.
pub const INLINE_LEN_MAX: u8 = 0x0F;
