//! Building DMAP payloads: the encode half of `pyatv/protocols/dmap/tags.py:39-88`.
//!
//! Every function produces one complete tag — four ASCII key bytes, a four-byte big-endian length,
//! then the data — and payloads are built by concatenation, exactly as pyatv does with `+`.
//!
//! # Why the width is in the function name here but nowhere else
//!
//! These are the only place in DMAP where an integer width is chosen rather than read. pyatv's
//! callers pick one per call site (`uint8_tag("cmcc", 0x30)`, `uint64_tag("cmpg", guid)`), and
//! those choices are wire-visible, so they are reproduced call site by call site. The *reader* side
//! never assumes a width; see [`super`].

/// A tag whose data is `value` verbatim (`raw_tag`, `tags.py:79-83`).
#[must_use]
pub fn raw_tag(key: &str, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + value.len());
    out.extend_from_slice(key.as_bytes());
    // A payload longer than 4 GiB cannot be represented in the length field; saturating keeps this
    // total rather than panicking on a value no device could ever send anyway.
    out.extend_from_slice(&u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(value);
    out
}

/// A container tag.
///
/// `container_tag` is literally `raw_tag` upstream (`tags.py:86-88`: "Same as raw"). Containers are
/// indistinguishable from opaque blobs on the wire, which is precisely why [`super::TAGS`] has to
/// exist for parsing to be possible at all.
#[must_use]
pub fn container_tag(key: &str, data: &[u8]) -> Vec<u8> {
    raw_tag(key, data)
}

/// A tag whose data is `value`'s UTF-8 bytes (`string_tag`, `tags.py:70-76`).
///
/// # Divergence: the length field counts bytes, not characters
///
/// Upstream writes `len(value).to_bytes(4, "big")` — the length of the Python `str`, in
/// *characters* — in front of `value.encode("utf-8")`, its length in *bytes*. For anything outside
/// ASCII those two disagree, the declared length is short, and every tag after it in the payload is
/// read from the wrong offset: the message is not merely wrong, it is unparseable from that point
/// on.
///
/// This is reachable rather than theoretical. `cmnm` in the pairing response carries the
/// controller's display name, which the user chooses (`pairing.py:136`) and which pyatv defaults to
/// `core.settings.info.name`; a name with an accent in it produces a payload a device cannot read.
/// `cmbe` carries command words, which are ASCII today only because this client picks them.
///
/// Writing the byte length is therefore deliberate. It is the only length a reader can use, it is
/// what every DMAP *decoder* — including pyatv's own `parser.py` — assumes, and it is identical to
/// upstream's output for every ASCII value, which is everything pyatv's fixtures and this port's
/// known-answer vectors contain.
#[must_use]
pub fn string_tag(key: &str, value: &str) -> Vec<u8> {
    raw_tag(key, value.as_bytes())
}

/// A one-byte integer tag (`uint8_tag`, `tags.py:39-43`).
#[must_use]
pub fn uint8_tag(key: &str, value: u8) -> Vec<u8> {
    raw_tag(key, &value.to_be_bytes())
}

/// A two-byte integer tag (`uint16_tag`, `tags.py:46-50`).
#[must_use]
pub fn uint16_tag(key: &str, value: u16) -> Vec<u8> {
    raw_tag(key, &value.to_be_bytes())
}

/// A four-byte integer tag (`uint32_tag`, `tags.py:53-57`).
#[must_use]
pub fn uint32_tag(key: &str, value: u32) -> Vec<u8> {
    raw_tag(key, &value.to_be_bytes())
}

/// An eight-byte integer tag (`uint64_tag`, `tags.py:60-64`).
#[must_use]
pub fn uint64_tag(key: &str, value: u64) -> Vec<u8> {
    raw_tag(key, &value.to_be_bytes())
}

/// A one-byte boolean tag (`bool_tag`, `tags.py:67-69`).
#[must_use]
pub fn bool_tag(key: &str, value: bool) -> Vec<u8> {
    uint8_tag(key, u8::from(value))
}

#[cfg(test)]
mod tests {
    use super::{
        bool_tag, container_tag, raw_tag, string_tag, uint8_tag, uint16_tag, uint32_tag, uint64_tag,
    };

    /// The four writers differ only in how many bytes they reserve; the framing is identical.
    #[test]
    fn integers_are_written_big_endian_at_the_declared_width() {
        assert_eq!(uint8_tag("uuu8", 12), b"uuu8\x00\x00\x00\x01\x0c");
        assert_eq!(uint16_tag("uu16", 37_888), b"uu16\x00\x00\x00\x02\x94\x00");
        assert_eq!(
            uint32_tag("uu32", 305_419_896),
            b"uu32\x00\x00\x00\x04\x12\x34\x56\x78"
        );
        assert_eq!(
            uint64_tag("uu64", 8_982_983_289_232),
            b"uu64\x00\x00\x00\x08\x00\x00\x08\x2b\x83\x87\x29\x90"
        );
    }

    #[test]
    fn booleans_are_a_single_byte() {
        assert_eq!(bool_tag("bola", true), b"bola\x00\x00\x00\x01\x01");
        assert_eq!(bool_tag("bolb", false), b"bolb\x00\x00\x00\x01\x00");
    }

    /// An empty string is a legal value, and `test_parse_strings` exercises it upstream.
    #[test]
    fn strings_are_measured_in_bytes() {
        assert_eq!(string_tag("stra", ""), b"stra\x00\x00\x00\x00");
        assert_eq!(
            string_tag("strb", "test string"),
            b"strb\x00\x00\x00\x0btest string"
        );
    }

    /// The divergence from upstream, and the reason for it: a two-character value that is four
    /// bytes must declare four, or everything after it in the payload is misframed.
    #[test]
    fn a_non_ascii_string_declares_its_byte_length_and_stays_parseable() {
        // Two characters, two bytes each — `len(value)` upstream would write 2.
        let tag = string_tag("cmnm", "\u{e5}\u{e4}");
        assert_eq!(tag, b"cmnm\x00\x00\x00\x04\xc3\xa5\xc3\xa4");

        // The point of the divergence: a following tag is still readable.
        let payload = [tag, uint8_tag("cmcc", 0)].concat();
        let parsed = crate::parser::parse(&payload).expect("byte lengths keep the payload framed");
        assert_eq!(
            parsed
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["cmnm", "cmcc"]
        );
    }

    /// `container_tag` is `raw_tag` (`tags.py:86-88`), and the nesting is just concatenation.
    #[test]
    fn containers_are_raw_tags_around_concatenated_children() {
        let inner = [uint8_tag("uuu8", 36), uint16_tag("uu16", 13_000)].concat();
        assert_eq!(container_tag("cona", &inner), raw_tag("cona", &inner));
        assert_eq!(
            container_tag("cona", &inner),
            b"cona\x00\x00\x00\x13uuu8\x00\x00\x00\x01\x24uu16\x00\x00\x00\x02\x32\xc8"
        );
    }
}
