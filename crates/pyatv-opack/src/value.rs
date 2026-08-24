//! The recursive OPACK value model.

use bytes::Bytes;

use crate::tags;

/// Width of an explicitly sized unsigned integer on the wire.
///
/// Mirrors the `_sized_int` helper pyatv attaches to decoded integers (`opack.py:19-30`) so a
/// payload decoded from a device re-encodes to the identical bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UintWidth {
    /// One byte, tag `0x30`.
    One,
    /// Two bytes, tag `0x31`.
    Two,
    /// Four bytes, tag `0x32`.
    Four,
    /// Eight bytes, tag `0x33`.
    Eight,
}

impl UintWidth {
    /// How many little-endian bytes follow the tag.
    #[must_use]
    pub const fn byte_count(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }

    /// The tag byte that introduces this width.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::One => tags::UINT_1,
            Self::Two => tags::UINT_2,
            Self::Four => tags::UINT_4,
            Self::Eight => tags::UINT_8,
        }
    }

    /// The narrowest width that can hold `value`.
    ///
    /// This is the ladder pyatv walks at `opack.py:52-59`; note it starts at one byte, so values
    /// below `0x28` reach it only when a width was pinned explicitly.
    #[must_use]
    pub const fn narrowest_for(value: u64) -> Self {
        if value <= 0xFF {
            Self::One
        } else if value <= 0xFFFF {
            Self::Two
        } else if value <= 0xFFFF_FFFF {
            Self::Four
        } else {
            Self::Eight
        }
    }

    /// Decode a `0x30..=0x33` tag byte.
    pub(crate) const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            tags::UINT_1 => Some(Self::One),
            tags::UINT_2 => Some(Self::Two),
            tags::UINT_4 => Some(Self::Four),
            tags::UINT_8 => Some(Self::Eight),
            _ => None,
        }
    }
}

/// A dynamically typed OPACK value.
///
/// # Ordering
///
/// Dictionaries are an ordered `Vec` of pairs rather than a map. OPACK is order-sensitive on the
/// wire — its back-reference mechanism indexes values by the order they were first seen — so
/// preserving insertion order is a correctness requirement, not a convenience. Keys are themselves
/// `Value`s because the format permits any value as a key (pyatv's own test suite packs a dict
/// keyed by `False`, `test_opack.py:102`), though every payload Companion produces uses strings.
/// Duplicate keys are kept as-is; pyatv collapses them because it decodes into a Python `dict`.
///
/// # Equality
///
/// [`PartialEq`] is derived, so it is *typed*: `Uint(1)`, `SizedUint { value: 1, .. }` and
/// `Float(1.0)` are three different values even though Python considers all three equal. That is
/// deliberate — see [`Value::SizedUint`] — and it is what keeps the encoder's and decoder's
/// back-reference tables in step. Use [`Value::as_u64`] to compare integers numerically. Floats
/// compare with IEEE-754 semantics, so `Float(f64::NAN) != Float(f64::NAN)`.
///
/// # Signed integers
///
/// There is no signed variant because OPACK has no signed encoding. pyatv's `pack()` accepts a
/// negative `int` and emits a corrupt byte (or raises `ValueError`); its Companion client works
/// around this by casting to `float` first, with the comment "opack fails with negative integers"
/// (`pyatv/protocols/companion/__init__.py:372`). Do the same: use [`Value::Float`].
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Absent value, tag `0x04`.
    Null,
    /// Boolean, tags `0x01` and `0x02`.
    Bool(bool),
    /// Unsigned integer encoded as narrowly as pyatv would encode it.
    Uint(u64),
    /// Unsigned integer pinned to an explicit on-wire width.
    ///
    /// [`crate::unpack`] produces this for the `0x30..=0x33` forms so that re-packing a decoded
    /// payload reproduces the original bytes, exactly as pyatv's `_sized_int` does
    /// (`opack.py:19-30`, `test_opack.py:56-60`). It is *not* equal to [`Value::Uint`] with the
    /// same number.
    SizedUint {
        /// The number itself.
        value: u64,
        /// The width to emit.
        width: UintWidth,
    },
    /// Double-precision float, tag `0x36`.
    Float(f64),
    /// Single-precision float, tag `0x35`.
    ///
    /// pyatv decodes this tag but never emits it, widening to a Python `float` and re-encoding as
    /// `0x36`. Keeping a distinct variant lets a decoded payload round-trip byte for byte.
    Float32(f32),
    /// UTF-8 string.
    String(String),
    /// Opaque bytes.
    Data(Bytes),
    /// A 16-byte UUID, tag `0x05`, stored raw and unparsed (big-endian RFC 4122 byte order, the
    /// same layout Python's `UUID(bytes=...)` takes).
    Uuid([u8; 16]),
    /// Absolute time, tag `0x06`, as the raw little-endian `u64` pyatv decodes.
    ///
    /// Packing one fails with [`crate::Error::UnpackOnlyTag`]: neither pyatv nor this crate knows
    /// the encoding, and re-emitting the number as a plain integer would change the type on the
    /// wire (`opack.py:4`, `opack.py:46-47`).
    AbsoluteTime(u64),
    /// Ordered sequence.
    Array(Vec<Value>),
    /// Ordered mapping, in wire order.
    Dict(Vec<(Value, Value)>),
}

impl Value {
    /// Build a dictionary from an iterator of pairs.
    ///
    /// ```
    /// use pyatv_opack::Value;
    ///
    /// let message = Value::dict([("_i", Value::from("_systemInfo")), ("_t", Value::from(2u64))]);
    /// assert_eq!(message.get("_t").and_then(Value::as_u64), Some(2));
    /// ```
    pub fn dict<I, K, V>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<Self>,
        V: Into<Self>,
    {
        Self::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
        )
    }

    /// Build an array from an iterator of values.
    ///
    /// ```
    /// use pyatv_opack::Value;
    ///
    /// assert_eq!(Value::array(["a", "b"]), Value::Array(vec!["a".into(), "b".into()]));
    /// ```
    pub fn array<I, V>(values: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<Self>,
    {
        Self::Array(values.into_iter().map(Into::into).collect())
    }

    /// Wrap sixteen raw bytes as a UUID value.
    #[must_use]
    pub const fn uuid(bytes: [u8; 16]) -> Self {
        Self::Uuid(bytes)
    }

    /// Whether this is [`Value::Null`].
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Read this value as a boolean, if it is one.
    #[must_use]
    pub const fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// Read this value as an unsigned integer, whatever width it was encoded at.
    ///
    /// Deliberately does *not* cover [`Value::AbsoluteTime`], which is a timestamp rather than a
    /// number.
    #[must_use]
    pub const fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(value) | Self::SizedUint { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Read this value as a float, widening [`Value::Float32`].
    #[must_use]
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Self::Float(value) => Some(*value),
            Self::Float32(value) => Some(f64::from(*value)),
            _ => None,
        }
    }

    /// Borrow this value as a string, if it is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Borrow this value as raw bytes, if it is a data value.
    #[must_use]
    pub const fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Data(value) => Some(value),
            _ => None,
        }
    }

    /// Borrow this value as an array, if it is one.
    #[must_use]
    pub fn as_array(&self) -> Option<&[Self]> {
        match self {
            Self::Array(values) => Some(values),
            _ => None,
        }
    }

    /// Borrow this value as a dictionary's entries, if it is one.
    #[must_use]
    pub fn as_dict(&self) -> Option<&[(Self, Self)]> {
        match self {
            Self::Dict(entries) => Some(entries),
            _ => None,
        }
    }

    /// Look up a string key in a dictionary value, returning the first match in wire order.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        match self {
            Self::Dict(entries) => entries
                .iter()
                .find(|(entry_key, _)| entry_key.as_str() == Some(key))
                .map(|(_, value)| value),
            _ => None,
        }
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

macro_rules! from_unsigned {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl From<$ty> for Value {
                fn from(value: $ty) -> Self {
                    Self::Uint(u64::from(value))
                }
            }
        )+
    };
}

from_unsigned!(u8, u16, u32, u64);

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::String(value.to_owned())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl From<Bytes> for Value {
    fn from(value: Bytes) -> Self {
        Self::Data(value)
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Self::Data(Bytes::from(value))
    }
}

impl From<&[u8]> for Value {
    fn from(value: &[u8]) -> Self {
        Self::Data(Bytes::copy_from_slice(value))
    }
}

impl From<Vec<Value>> for Value {
    fn from(value: Vec<Self>) -> Self {
        Self::Array(value)
    }
}

impl<T> From<Option<T>> for Value
where
    T: Into<Value>,
{
    fn from(value: Option<T>) -> Self {
        value.map_or(Self::Null, Into::into)
    }
}
