//! The DMAP binary TLV walker.
//!
//! Wire format, from `docs/research/airplay-raop-dmap.md` §11.2:
//!
//! ```text
//! | Key (4 bytes ASCII) | Length (4 bytes big-endian u32) | Data (Length bytes) |
//! ```
//!
//! Two consequences shape this module. First, container-ness is not on the wire — it comes from the
//! static table in [`crate::tags`], so the walker below returns raw leaves and leaves typing to a
//! second pass. Second, repeated keys are legal and are how DMAP represents lists: several `mlit`
//! entries inside one `mlcl` container. Entries are therefore kept as an ordered `Vec` rather than
//! collapsed into a map.

use bytes::Bytes;

use crate::{Error, Result};

/// Length of a tag key in bytes.
pub const KEY_LEN: usize = 4;

/// Length of the big-endian length field in bytes.
pub const LENGTH_LEN: usize = 4;

/// Combined header length preceding every value.
pub const HEADER_LEN: usize = KEY_LEN + LENGTH_LEN;

/// One entry in a DMAP payload, still untyped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmapValue {
    /// The four-character key, e.g. `cmst`.
    pub key: String,
    /// The raw data bytes, whose interpretation needs the tag table.
    pub data: Bytes,
}

impl DmapValue {
    /// Read the data as a big-endian unsigned integer of whatever width it happens to be.
    ///
    /// DMAP's integer tags are fixed-width per tag, so the caller normally knows the width from the
    /// table; this handles all of them uniformly for convenience.
    #[must_use]
    pub fn as_uint(&self) -> Option<u64> {
        if self.data.is_empty() || self.data.len() > 8 {
            return None;
        }
        Some(
            self.data
                .iter()
                .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte)),
        )
    }

    /// Read the data as a UTF-8 string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.data).ok()
    }

    /// Read the data as a boolean, encoded as a single `0x00` or `0x01` byte.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self.data.as_ref() {
            [0x00] => Some(false),
            [0x01] => Some(true),
            _ => None,
        }
    }
}

/// Walk one level of a DMAP payload, returning its entries in wire order.
///
/// Container data is returned unparsed; call [`parse`] again on it once the tag table says the tag
/// is a container.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if the input ends inside an entry header, or if an entry's declared
/// length runs past the end of the payload.
pub fn parse(input: &[u8]) -> Result<Vec<DmapValue>> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < input.len() {
        let header = input
            .get(offset..offset + HEADER_LEN)
            .ok_or_else(|| Error::Malformed(format!("truncated header at offset {offset}")))?;

        let key = std::str::from_utf8(&header[..KEY_LEN])
            .map_err(|_| Error::Malformed(format!("non-ASCII tag key at offset {offset}")))?
            .to_owned();

        let length = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        offset += HEADER_LEN;

        let data = input.get(offset..offset + length).ok_or_else(|| {
            Error::Malformed(format!(
                "tag {key} claims {length} bytes but only {} remain",
                input.len() - offset
            ))
        })?;
        offset += length;

        entries.push(DmapValue {
            key,
            data: Bytes::copy_from_slice(data),
        });
    }

    Ok(entries)
}

/// The first entry with the given key, if any.
///
/// Repeated keys are legal, so this is "first" rather than "the".
#[must_use]
pub fn first<'a>(entries: &'a [DmapValue], key: &str) -> Option<&'a DmapValue> {
    entries.iter().find(|entry| entry.key == key)
}

#[cfg(test)]
mod tests {
    use super::{DmapValue, first, parse};

    /// `cmpg` carrying a 64-bit pairing GUID, big-endian.
    #[test]
    fn parses_a_single_entry() {
        let payload = b"cmpg\x00\x00\x00\x08\x01\x23\x45\x67\x89\xAB\xCD\xEF";

        let entries = parse(payload).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "cmpg");
        assert_eq!(entries[0].as_uint(), Some(0x0123_4567_89AB_CDEF));
    }

    /// Repeated keys are how DMAP encodes lists, so they must not overwrite one another.
    #[test]
    fn repeated_keys_are_kept_in_order() {
        let payload = b"mlit\x00\x00\x00\x01\x01mlit\x00\x00\x00\x01\x02";

        let entries = parse(payload).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data.as_ref(), &[0x01]);
        assert_eq!(entries[1].data.as_ref(), &[0x02]);
        assert_eq!(first(&entries, "mlit"), Some(&entries[0]));
    }

    /// Containers come back as raw bytes and are parsed again by the caller.
    #[test]
    fn containers_parse_recursively() {
        let payload = b"cmst\x00\x00\x00\x0ccaps\x00\x00\x00\x04\x00\x00\x00\x04";

        let outer = parse(payload).unwrap();
        assert_eq!(outer[0].key, "cmst");

        let inner = parse(&outer[0].data).unwrap();
        assert_eq!(inner[0].key, "caps");
        assert_eq!(inner[0].as_uint(), Some(4));
    }

    #[test]
    fn strings_and_booleans_decode() {
        let payload = b"minm\x00\x00\x00\x05Hellocmik\x00\x00\x00\x01\x01";

        let entries = parse(payload).unwrap();
        assert_eq!(entries[0].as_str(), Some("Hello"));
        assert_eq!(entries[1].as_bool(), Some(true));
    }

    #[test]
    fn truncated_payloads_are_rejected() {
        assert!(parse(b"cmpg\x00\x00").is_err());
        assert!(parse(b"cmpg\x00\x00\x00\x08\x01\x02").is_err());
    }

    #[test]
    fn an_empty_payload_yields_no_entries() {
        assert_eq!(parse(b"").unwrap(), Vec::<DmapValue>::new());
    }
}
