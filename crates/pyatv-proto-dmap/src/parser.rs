//! The DMAP binary codec: a typed, eagerly built parse tree.
//!
//! Wire format (`pyatv/protocols/dmap/parser.py:1-9`):
//!
//! ```text
//! | Key (4 bytes ASCII) | Length (4 bytes big-endian u32) | Data (Length bytes) |
//! ```
//!
//! The length field is a `u32` for *every* tag including containers — `container_tag` is an alias
//! for `raw_tag` upstream — so container-ness is not on the wire and comes from [`crate::tags`].
//!
//! # Shape
//!
//! pyatv parses to a list of single-key dicts, e.g. `[{"cmst": [{"caps": 4}, {"cmsr": 12}]}]`,
//! which preserves repeated keys in order rather than collapsing them into a map. Repetition is not
//! incidental: several `mlit` entries inside one `mlcl` container is how DMAP represents a list. A
//! `Vec<DmapEntry>` is the direct equivalent, and [`first`] reproduces `parser.first`'s multi-level
//! path lookup on top of it.
//!
//! The tree is built eagerly, typing every leaf as it goes, rather than leaving containers as
//! opaque bytes to be re-walked on demand. `build_playing_instance` alone reads about fifteen
//! fields out of one response (`pyatv/protocols/dmap/__init__.py:105-190`); re-parsing the same
//! container bytes fifteen times to serve them is work with nothing to show for it.
//!
//! # Robustness
//!
//! Every read is bounds-checked and nesting is depth-capped ([`MAX_DEPTH`]). pyatv's `_parse`
//! recurses per tag with no bound at all and slices past the end of the buffer without complaint,
//! so a truncated or hostile response crashes it or silently yields short values. Here both are
//! errors.

use core::fmt::Write as _;

use crate::tags::{self, TagDefinition, TagType};
use crate::{Error, Result};

/// Length of a tag key in bytes.
pub const KEY_LEN: usize = 4;

/// Length of the big-endian length field in bytes.
pub const LENGTH_LEN: usize = 4;

/// Combined header length preceding every value.
pub const HEADER_LEN: usize = KEY_LEN + LENGTH_LEN;

/// Deepest container nesting accepted.
///
/// pyatv has no limit; its `_parse` recurses once per *tag*, not just per container, so a long flat
/// response is enough to exhaust `CPython`'s stack. Real DMAP nests three deep at most
/// (`mlog`/`mlcl`/`mlit`), so this is generous by an order of magnitude and exists only to keep a
/// malicious response from overflowing the stack.
pub const MAX_DEPTH: usize = 32;

/// One typed value from a DMAP payload.
///
/// Not [`Eq`]: a [`Self::Bplist`] can hold a float.
#[derive(Debug, Clone, PartialEq)]
pub enum DmapValue {
    /// Nested entries, in wire order.
    Container(Vec<DmapEntry>),
    /// A big-endian unsigned integer of whatever width the length field declared.
    Uint(u64),
    /// `read_bool` (`tags.py:17-19`): the integer read as exactly `1`, at any width.
    Bool(bool),
    /// UTF-8 text.
    String(String),
    /// `read_bytes` (`tags.py:29-31`): lowercase hex with a `0x` prefix and no separators.
    ///
    /// A string rather than the raw bytes because that is what pyatv's readers produce and what its
    /// tests assert (`tests/protocols/dmap/test_parser.py:74-78`), and because every consumer of a
    /// bytes-typed tag in pyatv treats it as an opaque identifier.
    Bytes(String),
    /// A decoded binary property list.
    Bplist(plist::Value),
    /// No value: an `ignore`-typed tag, or one the table does not know.
    ///
    /// pyatv returns Python's `None` for both (`tags.py:34-36`, `tag_definitions.py:19-20`) and
    /// never raises for an unrecognised key.
    None,
}

impl DmapValue {
    /// The integer, if this is one.
    #[must_use]
    pub fn as_uint(&self) -> Option<u64> {
        match self {
            Self::Uint(value) => Some(*value),
            _ => None,
        }
    }

    /// The boolean, if this is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(value) => Some(*value),
            _ => None,
        }
    }

    /// The text, if this is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(value) | Self::Bytes(value) => Some(value.as_str()),
            _ => None,
        }
    }

    /// The nested entries, if this is a container.
    #[must_use]
    pub fn as_container(&self) -> Option<&[DmapEntry]> {
        match self {
            Self::Container(entries) => Some(entries),
            _ => None,
        }
    }

    /// The property list, if this is one.
    #[must_use]
    pub fn as_plist(&self) -> Option<&plist::Value> {
        match self {
            Self::Bplist(value) => Some(value),
            _ => None,
        }
    }

    /// Whether this is the absent value pyatv models as `None`.
    #[must_use]
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl core::fmt::Display for DmapValue {
    /// Python's `str(value)`, which is what [`pprint`] interpolates.
    ///
    /// **Divergence:** a [`Self::Bplist`] prints as its Rust debug form rather than as a Python
    /// `dict` repr. One tag has that type (`ceSD`), nothing in this crate reads it, and `pprint` is
    /// a debug aid — reproducing `CPython`'s container repr for it would be effort spent on a string
    /// no test and no caller inspects.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Container(entries) => write!(f, "{entries:?}"),
            Self::Uint(value) => write!(f, "{value}"),
            Self::Bool(value) => f.write_str(if *value { "True" } else { "False" }),
            Self::String(value) | Self::Bytes(value) => f.write_str(value),
            Self::Bplist(value) => write!(f, "{value:?}"),
            Self::None => f.write_str("None"),
        }
    }
}

/// One key/value pair from a DMAP payload.
#[derive(Debug, Clone, PartialEq)]
pub struct DmapEntry {
    /// The four-character key, e.g. `cmst`.
    pub key: String,
    /// The typed value.
    pub value: DmapValue,
}

/// Parse a DMAP payload using the real tag table.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the input ends inside an entry header, if an entry's declared
/// length runs past the end of the payload, if a key is not valid UTF-8, if a string value is not
/// valid UTF-8, if a property list will not decode, or if nesting exceeds [`MAX_DEPTH`].
pub fn parse(data: &[u8]) -> Result<Vec<DmapEntry>> {
    parse_with(data, &tags::lookup_tag)
}

/// Parse a DMAP payload against a caller-supplied tag table.
///
/// `parse(data, tag_lookup)` (`parser.py:51-53`), whose `tag_lookup` argument exists so pyatv's own
/// codec tests can use a small synthetic table instead of the real one
/// (`tests/protocols/dmap/test_parser.py:10-28`). Same purpose here.
///
/// # Errors
///
/// See [`parse`].
pub fn parse_with(data: &[u8], lookup: &dyn Fn(&str) -> TagDefinition) -> Result<Vec<DmapEntry>> {
    parse_level(data, lookup, 0)
}

fn parse_level(
    data: &[u8],
    lookup: &dyn Fn(&str) -> TagDefinition,
    depth: usize,
) -> Result<Vec<DmapEntry>> {
    if depth > MAX_DEPTH {
        return Err(Error::Malformed(format!(
            "DMAP nesting deeper than {MAX_DEPTH} levels"
        )));
    }

    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let header = data
            .get(offset..offset + HEADER_LEN)
            .ok_or_else(|| Error::Malformed(format!("truncated header at offset {offset}")))?;

        let key = core::str::from_utf8(&header[..KEY_LEN])
            .map_err(|_| Error::Malformed(format!("non-UTF-8 tag key at offset {offset}")))?
            .to_owned();
        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        offset += HEADER_LEN;

        let payload = data.get(offset..offset + length).ok_or_else(|| {
            Error::Malformed(format!(
                "tag {key} claims {length} bytes but only {} remain",
                data.len() - offset
            ))
        })?;
        offset += length;

        let value = read_value(&key, lookup(&key).tag_type, payload, lookup, depth)?;
        entries.push(DmapEntry { key, value });
    }

    Ok(entries)
}

fn read_value(
    key: &str,
    tag_type: TagType,
    payload: &[u8],
    lookup: &dyn Fn(&str) -> TagDefinition,
    depth: usize,
) -> Result<DmapValue> {
    Ok(match tag_type {
        TagType::Container => DmapValue::Container(parse_level(payload, lookup, depth + 1)?),
        // Any width, big-endian. A value wider than eight bytes cannot be held, and no DMAP tag is
        // wider than `uint64_tag` writes, so it is rejected rather than silently truncated.
        TagType::Uint => DmapValue::Uint(read_uint(key, payload)?),
        TagType::Bool => DmapValue::Bool(read_uint(key, payload)? == 1),
        TagType::String => DmapValue::String(
            core::str::from_utf8(payload)
                .map_err(|_| Error::Malformed(format!("tag {key} is not valid UTF-8")))?
                .to_owned(),
        ),
        TagType::Bytes => DmapValue::Bytes(hex_string(payload)),
        TagType::Bplist => DmapValue::Bplist(
            plist::Value::from_reader(std::io::Cursor::new(payload)).map_err(|error| {
                Error::Malformed(format!(
                    "tag {key} is not a decodable property list: {error}"
                ))
            })?,
        ),
        TagType::Ignore | TagType::Unknown => {
            if tag_type == TagType::Unknown {
                // `_read_unknown` logs at warning level (`tag_definitions.py:19-20`). Downgraded to
                // debug: an unknown tag is normal traffic from a firmware newer than the table, and
                // warning on every one of them would be noise, not a signal.
                tracing::debug!(key, bytes = payload.len(), "unknown DMAP tag");
            }
            DmapValue::None
        }
    })
}

/// `read_uint` (`tags.py:12-14`): big-endian, however many bytes there are.
///
/// # Errors
///
/// Returns [`Error::TypeMismatch`] for a payload wider than eight bytes, which no DMAP writer can
/// produce. pyatv would return an arbitrary-precision integer; there is no such thing here, and
/// silently keeping the low eight bytes would be worse than refusing.
fn read_uint(key: &str, payload: &[u8]) -> Result<u64> {
    if payload.len() > 8 {
        return Err(Error::TypeMismatch {
            tag: key.to_owned(),
            expected: "uint",
            length: payload.len(),
        });
    }
    Ok(payload
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)))
}

/// `"0x" + binascii.hexlify(...)` (`tags.py:29-31`): lowercase, no separators.
fn hex_string(payload: &[u8]) -> String {
    let mut out = String::with_capacity(2 + payload.len() * 2);
    out.push_str("0x");
    for byte in payload {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Look a value up by path, as `parser.first(data, *path)` (`parser.py:56-65`).
///
/// The path walks one container level per element. Two upstream behaviours are reproduced exactly
/// because callers depend on them:
///
/// * a **missing** key anywhere along the path yields `None`, never an error;
/// * a path that runs *past* a leaf returns the leaf rather than `None` — pyatv's guard is
///   `if not (path and isinstance(dmap_data, list)): return dmap_data`, so `first(x, "a", "b")`
///   where `a` is an integer gives back that integer.
///
/// An empty path yields `None`, matching a lookup that asks for nothing.
///
/// ```
/// use pyatv_proto_dmap::parser::{first, parse};
/// use pyatv_proto_dmap::tags::{container_tag, uint32_tag};
///
/// let playstatus = container_tag("cmst", &uint32_tag("caps", 4));
/// let parsed = parse(&playstatus)?;
///
/// assert_eq!(first(&parsed, &["cmst", "caps"]).and_then(|it| it.as_uint()), Some(4));
/// assert!(first(&parsed, &["cmst", "cann"]).is_none());
/// # Ok::<(), pyatv_proto_dmap::Error>(())
/// ```
#[must_use]
pub fn first<'a>(entries: &'a [DmapEntry], path: &[&str]) -> Option<&'a DmapValue> {
    let (head, rest) = path.split_first()?;
    let value = entries
        .iter()
        .find(|entry| entry.key == *head)
        .map(|entry| &entry.value)?;

    match value {
        _ if rest.is_empty() => Some(value),
        DmapValue::Container(nested) => first(nested, rest),
        // Upstream returns the leaf rather than `None` when the path over-runs.
        leaf => Some(leaf),
    }
}

/// [`first`], read as an integer.
#[must_use]
pub fn first_uint(entries: &[DmapEntry], path: &[&str]) -> Option<u64> {
    first(entries, path).and_then(DmapValue::as_uint)
}

/// [`first`], read as a boolean.
#[must_use]
pub fn first_bool(entries: &[DmapEntry], path: &[&str]) -> Option<bool> {
    first(entries, path).and_then(DmapValue::as_bool)
}

/// [`first`], read as text.
#[must_use]
pub fn first_str<'a>(entries: &'a [DmapEntry], path: &[&str]) -> Option<&'a str> {
    first(entries, path).and_then(DmapValue::as_str)
}

/// Render a parse tree the way pyatv's `pprint` does (`parser.py:68-84`).
///
/// Two spaces of indent per level, `key: [type, name]` for a container and
/// `key: value [type, name]` for a leaf, one entry per line, each line newline-terminated. This is
/// what `DaapRequester._log_response` writes to the debug log (`daap.py:178-184`), so keeping the
/// format identical means a log line from this port and one from pyatv can be diffed.
///
/// **Divergence:** pyatv raises `InvalidDmapDataError` when handed something that is neither a
/// `dict` nor a `list` (`parser.py:82-83`, and `test_print_invalid_input_raises_exception` covers
/// it). That branch is unreachable here — the argument is a parse tree by type — so there is
/// nothing to raise and no error return.
#[must_use]
pub fn pprint(entries: &[DmapEntry], lookup: &dyn Fn(&str) -> TagDefinition) -> String {
    let mut out = String::new();
    pprint_level(entries, lookup, 0, &mut out);
    out
}

fn pprint_level(
    entries: &[DmapEntry],
    lookup: &dyn Fn(&str) -> TagDefinition,
    indent: usize,
    out: &mut String,
) {
    for entry in entries {
        let tag = lookup(&entry.key);
        let pad = " ".repeat(indent);
        match &entry.value {
            DmapValue::Container(nested) => {
                let _ = writeln!(out, "{pad}{}: {tag}", entry.key);
                pprint_level(nested, lookup, indent + 2, out);
            }
            value => {
                let _ = writeln!(out, "{pad}{}: {value} {tag}", entry.key);
            }
        }
    }
}

#[cfg(test)]
mod tests;
