//! The static DMAP tag type table.
//!
//! DMAP's wire format carries no type information, so every tag's type has to be looked up here.
//! pyatv's `tag_definitions.py` holds roughly ninety entries and the research report is explicit
//! that it should be reproduced verbatim rather than inferred: it is a fixed protocol dictionary,
//! not something derivable from traffic.
//!
//! A representative subset is transcribed below to fix the shape of the table. The rest lands with
//! the DMAP implementation proper.

/// How a tag's data should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    /// Nested DMAP entries.
    Container,
    /// Fixed-width big-endian unsigned integer; the width is the tag's data length.
    Uint,
    /// Single byte, `0x00` or `0x01`.
    Bool,
    /// Raw UTF-8, length in bytes rather than characters.
    String,
    /// Opaque bytes.
    Bytes,
    /// A binary property list.
    Bplist,
    /// Recognised but deliberately discarded.
    Ignore,
}

/// One row of the tag table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagDefinition {
    /// Four-character key as it appears on the wire.
    pub key: &'static str,
    /// How to read the data.
    pub tag_type: TagType,
    /// The dotted name pyatv records, e.g. `dmcp.playstatus`.
    pub name: &'static str,
}

/// Known tags.
///
/// Transcribed from pyatv's `tag_definitions.py`.
// TODO(step-1): complete this from the ~90 entries at
// https://github.com/postlund/pyatv/blob/master/pyatv/protocols/dmap/tag_definitions.py, per
// docs/research/airplay-raop-dmap.md §11.2.
pub const TAGS: &[TagDefinition] = &[
    TagDefinition {
        key: "cmst",
        tag_type: TagType::Container,
        name: "dmcp.playstatus",
    },
    TagDefinition {
        key: "caps",
        tag_type: TagType::Uint,
        name: "dacp.playstatus",
    },
    TagDefinition {
        key: "cann",
        tag_type: TagType::String,
        name: "daap.nowplayingtrack",
    },
    TagDefinition {
        key: "cana",
        tag_type: TagType::String,
        name: "daap.nowplayingartist",
    },
    TagDefinition {
        key: "canl",
        tag_type: TagType::String,
        name: "daap.nowplayingalbum",
    },
    TagDefinition {
        key: "cmsr",
        tag_type: TagType::Uint,
        name: "dmcp.serverrevision",
    },
    TagDefinition {
        key: "cmpg",
        tag_type: TagType::Uint,
        name: "dacp.pairingguid",
    },
    TagDefinition {
        key: "cmpa",
        tag_type: TagType::Container,
        name: "dacp.pairinganswer",
    },
    TagDefinition {
        key: "cmnm",
        tag_type: TagType::String,
        name: "dacp.devicename",
    },
    TagDefinition {
        key: "cmty",
        tag_type: TagType::String,
        name: "dacp.devicetype",
    },
    TagDefinition {
        key: "mlcl",
        tag_type: TagType::Container,
        name: "dmap.listing",
    },
    TagDefinition {
        key: "mlit",
        tag_type: TagType::Container,
        name: "dmap.listingitem",
    },
    TagDefinition {
        key: "minm",
        tag_type: TagType::String,
        name: "dmap.itemname",
    },
];

/// Look up a tag by its wire key.
#[must_use]
pub fn lookup(key: &str) -> Option<&'static TagDefinition> {
    TAGS.iter().find(|tag| tag.key == key)
}

/// Whether a tag's data should be parsed as nested entries.
///
/// Unknown tags are treated as leaves: descending into something that is not a container would
/// produce garbage, whereas keeping it as opaque bytes is recoverable.
#[must_use]
pub fn is_container(key: &str) -> bool {
    lookup(key).is_some_and(|tag| tag.tag_type == TagType::Container)
}

#[cfg(test)]
mod tests {
    use super::{TagType, is_container, lookup};

    #[test]
    fn known_tags_resolve_to_their_types() {
        assert_eq!(lookup("cmst").unwrap().tag_type, TagType::Container);
        assert_eq!(lookup("caps").unwrap().tag_type, TagType::Uint);
        assert_eq!(lookup("cann").unwrap().tag_type, TagType::String);
        assert_eq!(lookup("cmst").unwrap().name, "dmcp.playstatus");
    }

    /// Descending into an unknown tag would misparse its bytes, so unknowns stay leaves.
    #[test]
    fn unknown_tags_are_not_containers() {
        assert!(lookup("zzzz").is_none());
        assert!(!is_container("zzzz"));
    }

    #[test]
    fn container_detection_matches_the_table() {
        assert!(is_container("mlcl"));
        assert!(is_container("mlit"));
        assert!(!is_container("minm"));
    }
}
