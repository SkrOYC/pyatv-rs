//! OPACK tag bytes, transcribed from pyatv's `pyatv/support/opack.py`.
//!
//! Every constant here is cited against that file (`opack.py:LL-LL`). Ranges rather than single
//! bytes are the norm: OPACK packs a value's length or magnitude into the low nibble of its tag
//! wherever it fits and only falls back to an explicit length prefix when it does not.
//!
//! The corresponding prose table lives in `docs/research/mrp-companion.md` §4.5. Two entries in
//! that table are wrong and this module follows the Python source instead — see
//! [`POINTER_LEN_BASE`].

/// `true` (`opack.py:43`, `opack.py:144`).
pub const TRUE: u8 = 0x01;
/// `false` (`opack.py:43`, `opack.py:147`).
pub const FALSE: u8 = 0x02;
/// Terminates an array or dictionary whose element count did not fit in its tag nibble
/// (`opack.py:106`, `opack.py:199`). Never a value tag in its own right.
pub const TERMINATOR: u8 = 0x03;
/// Null / absent (`opack.py:40`, `opack.py:150`).
pub const NULL: u8 = 0x04;
/// A 16-byte UUID follows (`opack.py:45`, `opack.py:153`).
pub const UUID: u8 = 0x05;
/// Absolute time: eight little-endian bytes follow. pyatv can unpack this but never packs it
/// (`opack.py:4`, `opack.py:156-158`).
pub const ABSOLUTE_TIME: u8 = 0x06;

/// Bias added to a small integer to produce its single-byte tag (`opack.py:51`).
pub const SMALL_INT_BIAS: u8 = 0x08;
/// Largest single-byte small-integer tag, i.e. the value `0x27` (`opack.py:159`).
pub const SMALL_INT_MAX_TAG: u8 = 0x2F;
/// Integers strictly below this are encoded in a single byte as `value + 8` (`opack.py:50`).
pub const SMALL_INT_LIMIT: u64 = 0x28;

/// One little-endian byte of unsigned integer follows (`opack.py:53`).
pub const UINT_1: u8 = 0x30;
/// Two little-endian bytes of unsigned integer follow (`opack.py:55`).
pub const UINT_2: u8 = 0x31;
/// Four little-endian bytes of unsigned integer follow (`opack.py:57`).
pub const UINT_4: u8 = 0x32;
/// Eight little-endian bytes of unsigned integer follow (`opack.py:59`).
pub const UINT_8: u8 = 0x33;
/// Four bytes of IEEE-754 binary32 follow, little-endian (`opack.py:162-163`).
pub const FLOAT32: u8 = 0x35;
/// Eight bytes of IEEE-754 binary64 follow, little-endian (`opack.py:61`, `opack.py:164-165`).
pub const FLOAT64: u8 = 0x36;

/// Base tag for strings whose UTF-8 byte length fits in the tag (`opack.py:65`, `opack.py:174`).
pub const STRING_INLINE_BASE: u8 = 0x40;
/// Largest string length encodable directly in the tag byte (`opack.py:64`).
pub const STRING_INLINE_MAX_LEN: usize = 0x20;
/// Base for length-prefixed strings: `STRING_LEN_BASE + n` carries an `n`-byte little-endian
/// length, for `n` in `1..=4` (`opack.py:68-81`, `opack.py:177-179`).
pub const STRING_LEN_BASE: u8 = 0x60;

/// Base tag for byte strings whose length fits in the tag (`opack.py:84`, `opack.py:184`).
pub const DATA_INLINE_BASE: u8 = 0x70;
/// Largest byte-string length encodable directly in the tag byte (`opack.py:83`).
pub const DATA_INLINE_MAX_LEN: usize = 0x20;
/// Base for length-prefixed byte strings. Unlike strings the widths double rather than increment:
/// `0x91`/`0x92`/`0x93`/`0x94` carry 1/2/4/8 length bytes (`opack.py:87-100`, `opack.py:187-188`).
pub const DATA_LEN_BASE: u8 = 0x90;

/// Base tag for back-references whose index fits in the tag (`opack.py:120`, `opack.py:226`).
pub const POINTER_INLINE_BASE: u8 = 0xA0;
/// Largest back-reference index encodable directly in the tag byte (`opack.py:119`).
pub const POINTER_INLINE_MAX_INDEX: usize = 0x20;
/// Base for length-prefixed back-references: `POINTER_LEN_BASE + n` carries an `n`-byte
/// little-endian index for `n` in `1..=4`.
///
/// # pyatv disagrees with itself here
///
/// `opack.py:229` decodes `n = tag - 0xC0`, so `0xC3` reads three index bytes and `0xC4` reads
/// four; `tests/support/test_opack.py:396-400` locks that in. The encoder at `opack.py:125-128`
/// instead writes four bytes for `0xC3` and eight for `0xC4`, and
/// `docs/research/mrp-companion.md` §4.5 copied the encoder's widths into its table. The two
/// halves of pyatv can therefore not round-trip an index above `0xFFFF`. This crate follows the
/// decoder (and pyatv's own tests) and simply refuses to *emit* `0xC3`/`0xC4` — see
/// [`crate::ser`] — so it never has to guess which side Apple implements.
pub const POINTER_LEN_BASE: u8 = 0xC0;

/// Base tag for arrays whose element count fits in the low nibble (`opack.py:102`,
/// `opack.py:194`).
pub const ARRAY_BASE: u8 = 0xD0;
/// Base tag for dictionaries whose entry count fits in the low nibble (`opack.py:108`,
/// `opack.py:209`).
pub const DICT_BASE: u8 = 0xE0;
/// A container tag nibble of `0xF` means "open-ended": elements run until [`TERMINATOR`]
/// (`opack.py:105`, `opack.py:198`).
pub const CONTAINER_ENDLESS_COUNT: u8 = 0x0F;

/// Largest inline-string tag, i.e. a 32-byte string (`opack.py:174`).
pub const STRING_INLINE_MAX_TAG: u8 = 0x60;
/// Smallest length-prefixed string tag (`opack.py:177`).
pub const STRING_LEN_MIN_TAG: u8 = 0x61;
/// Largest length-prefixed string tag (`opack.py:177`).
pub const STRING_LEN_MAX_TAG: u8 = 0x64;

/// Largest inline byte-string tag, i.e. a 32-byte value (`opack.py:184`).
pub const DATA_INLINE_MAX_TAG: u8 = 0x90;
/// Smallest length-prefixed byte-string tag (`opack.py:187`).
pub const DATA_LEN_MIN_TAG: u8 = 0x91;
/// Largest length-prefixed byte-string tag (`opack.py:187`).
pub const DATA_LEN_MAX_TAG: u8 = 0x94;

/// Largest inline back-reference tag, i.e. index `0x20` (`opack.py:226`).
pub const POINTER_INLINE_MAX_TAG: u8 = 0xC0;
/// Smallest index-prefixed back-reference tag (`opack.py:228`).
pub const POINTER_LEN_MIN_TAG: u8 = 0xC1;
/// Largest index-prefixed back-reference tag (`opack.py:228`).
pub const POINTER_LEN_MAX_TAG: u8 = 0xC4;

/// Largest array tag; `0xDF` is the open-ended form (`opack.py:194`).
pub const ARRAY_MAX_TAG: u8 = 0xDF;

/// Integer tags between `0x30` and `0x3F` that are neither a supported width nor a float.
///
/// pyatv reads `2 ** (tag & 0xF)` bytes for these (`opack.py:167`), which is 16 bytes at `0x34`
/// and 32 768 at `0x3F`. See [`crate::Error::IntegerTooWide`].
pub const UINT_TOO_WIDE_LOW: u8 = 0x34;
/// First tag of the upper unsupported integer-width run, `0x37..=0x3F`.
pub const UINT_TOO_WIDE_HIGH_FIRST: u8 = 0x37;
/// Last tag of the upper unsupported integer-width run.
pub const UINT_TOO_WIDE_HIGH_LAST: u8 = 0x3F;
