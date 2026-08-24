//! Encryption and metadata capabilities advertised by a RAOP receiver.
//!
//! Ports the TXT-parsing half of `pyatv/protocols/raop/parsers.py`. The audio-format half
//! (`get_audio_properties`) is deliberately left out: it is already implemented as
//! `pyatv_proto_airplay::raop::AudioProperties::from_service`, and only the streaming code needs it,
//! so it does not have to cross into core.

use std::collections::HashMap;
use std::hash::BuildHasher;

bitflags::bitflags! {
    /// Encryption schemes a receiver advertises in its `et` TXT key.
    ///
    /// Verbatim from `pyatv/protocols/raop/parsers.py:15-23`. Note that the flag values are *not*
    /// the wire values: the TXT record carries the list `0,1,3,4,5` and
    /// [`get_encryption_types`] maps each of those onto a distinct bit.
    ///
    /// None of the `FAIR_PLAY` variants are implementable — they depend on Apple's hardware-backed
    /// key material and no public implementation exists. pyatv parses them purely so it can tell a
    /// caller that a receiver is out of reach. See `docs/research/crypto-pairing.md` §5.5.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct EncryptionType: u8 {
        /// Nothing was advertised, or nothing recognisable was.
        const UNKNOWN = 0;
        /// Wire value `0`: no encryption.
        const UNENCRYPTED = 1;
        /// Wire value `1`: RSA, legacy `AirPlay` 1 audio.
        const RSA = 2;
        /// Wire value `3`: `FairPlay`.
        const FAIR_PLAY = 4;
        /// Wire value `4`: `MFiSAP`.
        const MFI_SAP = 8;
        /// Wire value `5`: `FairPlay` SAP v2.5.
        const FAIR_PLAY_SAP_V25 = 16;
    }
}

bitflags::bitflags! {
    /// Metadata kinds a receiver accepts, from its `md` TXT key.
    ///
    /// Verbatim from `pyatv/protocols/raop/parsers.py:26-32`. As with [`EncryptionType`], the flag
    /// values differ from the wire values the TXT record lists.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct MetadataType: u8 {
        /// The receiver accepts no metadata.
        const NOT_SUPPORTED = 0;
        /// Wire value `0`: track title, artist and album.
        const TEXT = 1;
        /// Wire value `1`: cover artwork.
        const ARTWORK = 2;
        /// Wire value `2`: playback progress.
        const PROGRESS = 4;
    }
}

/// Parse the `et` TXT key into the set of encryption schemes a receiver supports.
///
/// Ports `get_encryption_types` (`pyatv/protocols/raop/parsers.py:49-72`). The value is a
/// comma-separated list of small integers, e.g. `et=0,1,3`.
///
/// Two upstream behaviours worth calling out, both reproduced:
///
/// - A missing key, or *any* non-integer element anywhere in the list, discards the whole list and
///   yields [`EncryptionType::UNKNOWN`] — upstream builds the list with a comprehension inside one
///   `try`, so a single bad element aborts the parse.
/// - An unrecognised integer maps to [`EncryptionType::UNKNOWN`], which is zero, so it is simply
///   or-ed away. `et=0,1000` is therefore just [`EncryptionType::UNENCRYPTED`].
#[must_use]
pub fn get_encryption_types<S: BuildHasher>(
    properties: &HashMap<String, String, S>,
) -> EncryptionType {
    let Some(values) = parse_type_list(properties, "et") else {
        return EncryptionType::UNKNOWN;
    };

    values.into_iter().fold(EncryptionType::UNKNOWN, |acc, it| {
        acc | match it {
            0 => EncryptionType::UNENCRYPTED,
            1 => EncryptionType::RSA,
            3 => EncryptionType::FAIR_PLAY,
            4 => EncryptionType::MFI_SAP,
            5 => EncryptionType::FAIR_PLAY_SAP_V25,
            _ => EncryptionType::UNKNOWN,
        }
    })
}

/// Parse the `md` TXT key into the set of metadata kinds a receiver accepts.
///
/// Ports `get_metadata_types` (`pyatv/protocols/raop/parsers.py:75-96`), with the same
/// all-or-nothing parsing and unknown-value handling as [`get_encryption_types`].
#[must_use]
pub fn get_metadata_types<S: BuildHasher>(properties: &HashMap<String, String, S>) -> MetadataType {
    let Some(values) = parse_type_list(properties, "md") else {
        return MetadataType::NOT_SUPPORTED;
    };

    values
        .into_iter()
        .fold(MetadataType::NOT_SUPPORTED, |acc, it| {
            acc | match it {
                0 => MetadataType::TEXT,
                1 => MetadataType::ARTWORK,
                2 => MetadataType::PROGRESS,
                _ => MetadataType::NOT_SUPPORTED,
            }
        })
}

/// `[int(x) for x in properties[key].split(",")]`, or `None` if the key is absent or any element
/// is not an integer.
fn parse_type_list<S: BuildHasher>(
    properties: &HashMap<String, String, S>,
    key: &str,
) -> Option<Vec<u32>> {
    properties
        .get(key)?
        .split(',')
        .map(|element| element.parse::<u32>().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{EncryptionType, MetadataType, get_encryption_types, get_metadata_types};

    fn properties(entries: &[(&str, &str)]) -> HashMap<String, String> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    /// Ports `tests/protocols/raop/test_parsers.py::test_parse_encryption_type`.
    #[test]
    fn encryption_types_match_upstream() {
        let cases: [(&[(&str, &str)], EncryptionType); 6] = [
            (&[("et", "0")], EncryptionType::UNENCRYPTED),
            (&[("et", "1")], EncryptionType::RSA),
            (&[("et", "3")], EncryptionType::FAIR_PLAY),
            (&[("et", "4")], EncryptionType::MFI_SAP),
            (&[("et", "5")], EncryptionType::FAIR_PLAY_SAP_V25),
            (
                &[("et", "0,1")],
                EncryptionType::UNENCRYPTED | EncryptionType::RSA,
            ),
        ];

        for (entries, expected) in cases {
            assert_eq!(
                get_encryption_types(&properties(entries)),
                expected,
                "{entries:?}"
            );
        }
    }

    /// Ports `tests/protocols/raop/test_parsers.py::test_parse_encryption_bad_types`.
    #[test]
    fn malformed_encryption_lists_yield_unknown() {
        for entries in [&[][..], &[("et", "")][..], &[("et", "foobar")][..]] {
            assert_eq!(
                get_encryption_types(&properties(entries)),
                EncryptionType::UNKNOWN,
                "{entries:?}"
            );
        }
    }

    /// Ports `tests/protocols/raop/test_parsers.py::test_parse_encryption_include_unknown_type`.
    #[test]
    fn unrecognised_encryption_values_are_ignored() {
        assert_eq!(
            get_encryption_types(&properties(&[("et", "0,1000")])),
            EncryptionType::UNKNOWN | EncryptionType::UNENCRYPTED
        );
    }

    /// One bad element discards the whole list, matching upstream's single `try` block.
    #[test]
    fn one_bad_element_discards_the_whole_encryption_list() {
        assert_eq!(
            get_encryption_types(&properties(&[("et", "0,x,1")])),
            EncryptionType::UNKNOWN
        );
    }

    /// Ports `tests/protocols/raop/test_parsers.py::test_parse_metadata_types`.
    #[test]
    fn metadata_types_match_upstream() {
        let cases: [(&[(&str, &str)], MetadataType); 4] = [
            (&[], MetadataType::NOT_SUPPORTED),
            (&[("md", "0")], MetadataType::TEXT),
            (&[("md", "1")], MetadataType::ARTWORK),
            (
                &[("md", "0,1,2")],
                MetadataType::TEXT | MetadataType::ARTWORK | MetadataType::PROGRESS,
            ),
        ];

        for (entries, expected) in cases {
            assert_eq!(
                get_metadata_types(&properties(entries)),
                expected,
                "{entries:?}"
            );
        }
    }

    #[test]
    fn metadata_wire_value_two_is_progress() {
        assert_eq!(
            get_metadata_types(&properties(&[("md", "2")])),
            MetadataType::PROGRESS
        );
    }

    /// `NOT_SUPPORTED` and `UNKNOWN` are the zero flag, so they never survive a union.
    #[test]
    fn zero_valued_flags_are_absorbed() {
        assert_eq!(EncryptionType::UNKNOWN, EncryptionType::empty());
        assert_eq!(MetadataType::NOT_SUPPORTED, MetadataType::empty());
    }
}
