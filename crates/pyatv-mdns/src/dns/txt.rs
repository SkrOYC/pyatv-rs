//! DNS-SD TXT record encoding, decoding, and the case-insensitive map they live in.
//!
//! Ports `parse_txt_dict` / `format_txt_dict` from pyatv `support/dns.py`, the
//! `CaseInsensitiveDict` from `support/collections.py` that holds the result, and the
//! `decode_value` / `_decode_properties` pair from `core/mdns.py` that turns the raw byte values
//! into strings.
//!
//! TXT values are opaque binary per RFC 6763 section 6.5 and Apple does put non-UTF-8 bytes in
//! them, so [`TxtRecords`] keeps values as bytes. Only [`TxtRecords::decode_properties`] commits to
//! a string, and it reproduces pyatv's charset fallbacks exactly.

use super::DnsError;
use super::reader::Reader;

/// An insertion-ordered map whose string keys compare case-insensitively.
///
/// pyatv's `CaseInsensitiveDict` lowercases keys on insert and compares on the lowered form, so
/// `properties["Model"]` and `properties["model"]` are the same entry. This does the same with
/// ASCII lowercasing: DNS-SD TXT keys are ASCII-only by RFC 6763 section 6.4, which
/// [`parse_txt`] enforces, so full Unicode case folding would only add locale surprises.
///
/// Backed by a `Vec` rather than a `HashMap` because TXT records carry a handful of keys at most,
/// and because preserving insertion order keeps [`TxtRecords::encode`] deterministic — matching
/// Python's ordered `dict`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CaseInsensitiveMap<V> {
    entries: Vec<(String, V)>,
}

impl<V> CaseInsensitiveMap<V> {
    /// An empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert a value, replacing any existing entry whose key matches case-insensitively.
    ///
    /// The stored key is lowercased, as in pyatv. Replacing an entry keeps its original position,
    /// again matching Python's `dict`.
    pub fn insert(&mut self, key: &str, value: V) -> Option<V> {
        let key = key.to_ascii_lowercase();
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            return Some(core::mem::replace(&mut slot.1, value));
        }
        self.entries.push((key, value));
        None
    }

    /// Look a value up, ignoring key case.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&V> {
        let key = key.to_ascii_lowercase();
        self.entries.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// Whether a key is present, ignoring case.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entries in insertion order. Keys are already lowercased.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &V)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }
}

impl<V> FromIterator<(String, V)> for CaseInsensitiveMap<V> {
    fn from_iter<T: IntoIterator<Item = (String, V)>>(iter: T) -> Self {
        let mut map = Self::new();
        for (key, value) in iter {
            map.insert(&key, value);
        }
        map
    }
}

/// The raw key/value pairs of a DNS-SD TXT record. Values are opaque bytes.
pub type TxtRecords = CaseInsensitiveMap<Vec<u8>>;

/// TXT values decoded to strings, as pyatv's `Service.properties`.
pub type Properties = CaseInsensitiveMap<String>;

/// Parse `length` bytes of DNS-SD TXT RDATA into a map.
///
/// Follows pyatv's `parse_txt_dict`:
///
/// * A chunk with no `=` is a valueless key and maps to an empty value.
/// * A chunk with an empty key (`=value`) is dropped.
/// * A chunk whose key is not ASCII is dropped.
///
/// # Errors
///
/// * [`DnsError::NonAsciiTxtKey`] if a *valueless* chunk is not ASCII. This asymmetry is pyatv's:
///   `parse_txt_dict` wraps the keyed path in `try/except UnicodeDecodeError` but decodes the
///   valueless path bare, so a non-ASCII flag aborts the whole message parse. `core/mdns.py`
///   catches that and drops the datagram, so it is load-bearing behaviour, not dead code.
/// * [`DnsError::TxtChunkOverrunsRecord`] if a chunk length runs past the end of the RDATA.
///   pyatv does not check this and will happily read into the following record; refusing is
///   strictly safer and cannot change the result for a well-formed message.
/// * [`DnsError::UnexpectedEof`] if the RDATA itself runs past the end of the message.
pub fn parse_txt(reader: &mut Reader<'_>, length: usize) -> Result<TxtRecords, DnsError> {
    let start = reader.position();
    let stop = start
        .checked_add(length)
        .filter(|stop| *stop <= reader.message().len())
        .ok_or(DnsError::UnexpectedEof {
            needed: length,
            available: reader.remaining(),
        })?;

    let mut output = TxtRecords::new();
    while reader.position() < stop {
        let chunk_length = usize::from(reader.read_u8()?);
        if reader.position() + chunk_length > stop {
            return Err(DnsError::TxtChunkOverrunsRecord {
                chunk_length,
                remaining: stop - reader.position(),
            });
        }
        let chunk = reader.read_slice(chunk_length)?;

        let Some(separator) = chunk.iter().position(|&byte| byte == b'=') else {
            // No "=" at all: the key is present with no value.
            let key = core::str::from_utf8(chunk)
                .ok()
                .filter(|key| key.is_ascii())
                .ok_or_else(|| DnsError::NonAsciiTxtKey {
                    key: chunk.to_vec(),
                })?;
            output.insert(key, Vec::new());
            continue;
        };

        let (key, value) = chunk.split_at(separator);
        let value = &value[1..];
        if key.is_empty() {
            // Missing keys are skipped.
            continue;
        }
        // Keys are explicitly ASCII only; a non-ASCII key is dropped rather than fatal.
        let Some(key) = core::str::from_utf8(key).ok().filter(|k| k.is_ascii()) else {
            tracing::debug!(?key, "non-ASCII DNS-SD key encountered");
            continue;
        };
        output.insert(key, value.to_vec());
    }

    Ok(output)
}

impl TxtRecords {
    /// Encode as DNS-SD TXT RDATA: one length-prefixed `key=value` chunk per entry.
    ///
    /// Mirrors pyatv's `format_txt_dict`, which defers to `zeroconf.ServiceInfo.text`.
    ///
    /// **Deviation:** zeroconf writes a bare `key` (no `=`) when a property's value is `None`, and
    /// `key=` when it is empty bytes. [`TxtRecords`] has no `None`, because `parse_txt` collapses
    /// both onto empty bytes, so this always writes `key=`. Chunks longer than 255 bytes cannot be
    /// represented and are skipped, matching the DNS character-string limit.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (key, value) in self.iter() {
            let length = key.len() + 1 + value.len();
            let Ok(length) = u8::try_from(length) else {
                tracing::warn!(key, length, "TXT entry exceeds 255 bytes, skipping");
                continue;
            };
            out.push(length);
            out.extend_from_slice(key.as_bytes());
            out.push(b'=');
            out.extend_from_slice(value);
        }
        out
    }

    /// Decode every value to a string using pyatv's `_decode_properties`.
    #[must_use]
    pub fn decode_properties(&self) -> Properties {
        self.iter()
            .map(|(key, value)| (key.to_owned(), decode_value(value)))
            .collect()
    }
}

/// Decode one TXT value the way pyatv's `core/mdns.py` does.
///
/// The two non-breaking-space sequences `C2 A0` (UTF-8 U+00A0) and `00 A0` (UTF-16-ish leftovers
/// Apple emits) are replaced with a plain space before decoding — see pyatv issue #919, where an
/// Apple TV named "Apple TV (4167)" uses U+00A0 between "Apple" and "TV" and the name has to match
/// what the user typed.
///
/// If the result is still not valid UTF-8, pyatv falls back to `str(value)`, which in Python is the
/// `repr` of a `bytes` object. [`python_bytes_repr`] reproduces that byte for byte, because that
/// string is what ends up in `Service.properties` and therefore in user-visible output.
#[must_use]
pub fn decode_value(value: &[u8]) -> String {
    let mut replaced = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index..].starts_with(b"\xc2\xa0") || value[index..].starts_with(b"\x00\xa0") {
            replaced.push(b' ');
            index += 2;
        } else {
            replaced.push(value[index]);
            index += 1;
        }
    }

    String::from_utf8(replaced).unwrap_or_else(|_| python_bytes_repr(value))
}

/// Render bytes exactly as `CPython`'s `repr(bytes)` does, e.g. `b'\xfe\xed'`.
///
/// Transcribed from `CPython`'s `bytes_repr`: the quote is `'` unless the data contains `'` and no
/// `"`; only the chosen quote and the backslash are escaped; tab, newline and carriage return get
/// their short escapes; everything else outside printable ASCII becomes `\xNN` with lowercase hex.
#[must_use]
pub fn python_bytes_repr(value: &[u8]) -> String {
    let quote = if value.contains(&b'\'') && !value.contains(&b'"') {
        b'"'
    } else {
        b'\''
    };

    let mut out = String::with_capacity(value.len() + 3);
    out.push('b');
    out.push(char::from(quote));
    for &byte in value {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\t' => out.push_str("\\t"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            _ if byte == quote => {
                out.push('\\');
                out.push(char::from(byte));
            }
            0x20..=0x7E => out.push(char::from(byte)),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                out.push('\\');
                out.push('x');
                out.push(char::from(HEX[usize::from(byte >> 4)]));
                out.push(char::from(HEX[usize::from(byte & 0x0F)]));
            }
        }
    }
    out.push(char::from(quote));
    out
}

#[cfg(test)]
mod tests;
