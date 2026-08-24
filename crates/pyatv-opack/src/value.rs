//! The recursive OPACK value model.

use bytes::Bytes;

/// A dynamically typed OPACK value.
///
/// Dictionaries are an ordered `Vec` of pairs rather than a map. OPACK is order-sensitive on the
/// wire — its back-reference mechanism indexes values by the order they were first seen — so
/// preserving insertion order is a correctness requirement, not a convenience. Keys are themselves
/// `Value`s because the format permits any value as a key, though every payload pyatv produces
/// uses strings.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Absent value, tag `0x04`.
    Null,
    /// Boolean, tags `0x01` and `0x02`.
    Bool(bool),
    /// Unsigned integer of any width.
    Uint(u64),
    /// Signed integer. pyatv only produces these when unpacking absolute-time values.
    Int(i64),
    /// Double-precision float.
    Float(f64),
    /// UTF-8 string.
    String(String),
    /// Opaque bytes.
    Data(Bytes),
    /// A 16-byte UUID, tag `0x05`, stored raw and unparsed.
    Uuid([u8; 16]),
    /// Ordered sequence.
    Array(Vec<Value>),
    /// Ordered mapping, in wire order.
    Dict(Vec<(Value, Value)>),
}

impl Value {
    /// Build a dictionary from an iterator of string-keyed pairs.
    pub fn dict<I, K>(entries: I) -> Self
    where
        I: IntoIterator<Item = (K, Self)>,
        K: Into<String>,
    {
        Self::Dict(
            entries
                .into_iter()
                .map(|(key, value)| (Self::String(key.into()), value))
                .collect(),
        )
    }

    /// Borrow this value as a string, if it is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) => Some(value),
            _ => None,
        }
    }

    /// Read this value as an unsigned integer, if it is one.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    /// Borrow this value as raw bytes, if it is a data value.
    #[must_use]
    pub fn as_bytes(&self) -> Option<&Bytes> {
        match self {
            Self::Data(value) => Some(value),
            _ => None,
        }
    }

    /// Look up a string key in a dictionary value.
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

impl From<u64> for Value {
    fn from(value: u64) -> Self {
        Self::Uint(value)
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
