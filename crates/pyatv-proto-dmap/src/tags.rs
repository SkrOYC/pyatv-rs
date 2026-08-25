//! The static DMAP tag type table, and the encoders that build DMAP payloads.
//!
//! DMAP's wire format carries no type information — a four-byte key and a four-byte length, and
//! nothing that says whether the bytes in between are a container, an integer or a string. Parsing
//! at all therefore requires an out-of-band dictionary, which is what [`TAGS`] is: a verbatim
//! transcription of `pyatv/protocols/dmap/tag_definitions.py:24-124`, all ninety-eight rows.
//!
//! # Widths are on the wire, never in the table
//!
//! pyatv names its *writers* `uint8_tag`/`uint16_tag`/`uint32_tag`/`uint64_tag`, but has exactly
//! one *reader*, `read_uint`, which reads however many bytes the length field says
//! (`tags.py:12-14`). The table records only that a tag is an integer. A real device is free to
//! send `caps` as one, two or four bytes depending on firmware, and pyatv's own fake device does
//! exactly that (`tests/fake_device/dmap.py:238` writes `caps` as `uint32` while `:268-274` write
//! `carp`/`cash`/`cavc` as `uint8`). So: **never hardcode a per-tag integer width**, not even as a
//! fast path.
//!
//! [`TagType::Bool`] is the same story. `read_bool` is `read_uint(...) == 1` (`tags.py:17-19`), so
//! a two-byte `0x0001` is `true` just as validly as a one-byte `0x01`, and any other value of any
//! width is `false`. There is no "not a boolean".

pub mod write;

pub use write::{
    bool_tag, container_tag, raw_tag, string_tag, uint8_tag, uint16_tag, uint32_tag, uint64_tag,
};

/// How a tag's data should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagType {
    /// Nested DMAP entries.
    Container,
    /// Big-endian unsigned integer, as wide as the length field says.
    Uint,
    /// An integer that reads as exactly `1`, of any width.
    Bool,
    /// UTF-8, length in bytes rather than characters.
    String,
    /// Opaque bytes, rendered as lowercase `0x`-prefixed hex.
    Bytes,
    /// A binary property list.
    Bplist,
    /// Recognised and deliberately discarded (`read_ignore`, `tags.py:34-36`).
    Ignore,
    /// Not in the table at all (`_read_unknown`, `tag_definitions.py:19-20`).
    ///
    /// pyatv logs a warning and returns `None`; the parser still advances correctly, because the
    /// *length* field drives the cursor, not the type.
    Unknown,
}

impl core::fmt::Display for TagType {
    /// pyatv renders a tag as `[{type}, {name}]`, deriving the type name from the reader
    /// function's own name minus the `read_` prefix (`parser.py:243-249`). These are those names.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Container => "container",
            Self::Uint => "uint",
            Self::Bool => "bool",
            Self::String => "str",
            Self::Bytes => "bytes",
            Self::Bplist => "bplist",
            Self::Ignore => "ignore",
            Self::Unknown => "unknown",
        })
    }
}

/// What the table knows about one tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TagDefinition {
    /// How to read the data.
    pub tag_type: TagType,
    /// The dotted name pyatv records, e.g. `dmcp.playstatus`.
    pub name: &'static str,
}

impl core::fmt::Display for TagDefinition {
    /// `DmapTag.__str__` (`parser.py:243-249`), which is what [`crate::parser::pprint`] prints.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "[{}, {}]", self.tag_type, self.name)
    }
}

/// What `lookup_tag` falls back to for a key not in [`TAGS`] (`tag_definitions.py:127-132`).
pub const UNKNOWN_TAG: TagDefinition = TagDefinition {
    tag_type: TagType::Unknown,
    name: "unknown tag",
};

macro_rules! tag_table {
    ($($key:literal => $tag_type:ident, $name:literal;)*) => {
        /// Every tag pyatv knows, in pyatv's own order.
        ///
        /// `_TAGS` (`pyatv/protocols/dmap/tag_definitions.py:24-124`): sixty-nine rows with real
        /// dotted names followed by twenty-nine marked "unknown tag". Two of the latter, `cmbe` and
        /// `cmcc`, are load-bearing for remote-control input despite the label — see
        /// [`crate::client::BaseDmapAppleTV`].
        pub const TAGS: &[(&str, TagDefinition)] = &[$(
            ($key, TagDefinition { tag_type: TagType::$tag_type, name: $name }),
        )*];
    };
}

tag_table! {
    "aelb" => Bool, "com.apple.itunes.like-button";
    "aels" => Uint, "com.apple.itunes.liked-state";
    "aeFP" => Uint, "com.apple.itunes.req-fplay";
    "aeGs" => Bool, "com.apple.itunes.can-be-genius-seed";
    "aeSV" => Uint, "com.apple.itunes.music-sharing-version";
    "apro" => Uint, "daap.protocolversion";
    "asai" => Uint, "daap.songalbumid";
    "asal" => String, "daap.songalbum";
    "asar" => String, "daap.songartist";
    "asgr" => Uint, "com.apple.itunes.gapless-resy";
    "astm" => Uint, "daap.songtime";
    "ated" => Bool, "daap.supportsextradata";
    "caar" => Uint, "dacp.albumrepeat";
    "caas" => Uint, "dacp.albumshuffle";
    "caci" => Container, "dacp.controlint";
    "cafe" => Bool, "dacp.fullscreenenabled";
    "cafs" => Uint, "dacp.fullscreen";
    "cana" => String, "daap.nowplayingartist";
    "cang" => String, "dacp.nowplayinggenre";
    "canl" => String, "daap.nowplayingalbum";
    "cann" => String, "daap.nowplayingtrack";
    "canp" => Bytes, "daap.nowplayingid";
    "cant" => Uint, "dacp.remainingtime";
    "capr" => Uint, "dacp.protocolversion";
    "caps" => Uint, "dacp.playstatus";
    "carp" => Uint, "dacp.repeatstate";
    "cash" => Uint, "dacp.shufflestate";
    "cast" => Uint, "dacp.tracklength";
    "casu" => Uint, "dacp.su";
    "cavc" => Bool, "dacp.volumecontrollable";
    "cave" => Bool, "dacp.dacpvisualizerenabled";
    "cavs" => Uint, "dacp.visualizer";
    "ceGS" => String, "com.apple.itunes.genius-selectable";
    "ceQR" => Container, "com.apple.itunes.playqueue-contents-response";
    "ceSD" => Bplist, "playing metadata";
    "cmcp" => Container, "dmcp.controlprompt";
    "cmmk" => Uint, "dmcp.mediakind";
    "cmnm" => String, "dacp.devicename";
    "cmpa" => Container, "dacp.pairinganswer";
    "cmpg" => Uint, "dacp.pairingguid";
    "cmpr" => Uint, "dmcp.protocolversion";
    "cmsr" => Uint, "dmcp.serverrevision";
    "cmst" => Container, "dmcp.playstatus";
    "cmty" => String, "dacp.devicetype";
    "mdcl" => Container, "dmap.dictionary";
    "miid" => Uint, "dmap.itemid";
    "minm" => String, "dmap.itemname";
    "mlcl" => Container, "dmap.listing";
    "mlid" => Uint, "dmap.sessionid";
    "mlit" => Container, "dmap.listingitem";
    "mlog" => Container, "dmap.loginresponse";
    "mpro" => Uint, "dmap.protocolversion";
    "mrco" => Uint, "dmap.returnedcount";
    "msal" => Bool, "dmap.supportsautologout";
    "msbr" => Bool, "dmap.supportsbrowse";
    "msdc" => Uint, "dmap.databasescount";
    "msed" => Bool, "dmap.supportsedit";
    "msex" => Bool, "dmap.supportsextensions";
    "msix" => Bool, "dmap.supportsindex";
    "mslr" => Bool, "dmap.loginrequired";
    "mspi" => Bool, "dmap.supportspersistentids";
    "msqy" => Bool, "dmap.supportsquery";
    "msrv" => Container, "dmap.serverinforesponse";
    "mstc" => Uint, "dmap.utctime";
    "mstm" => Uint, "dmap.timeoutinterval";
    "msto" => Uint, "dmap.utcoffset";
    "mstt" => Uint, "dmap.status";
    "msup" => Bool, "dmap.supportsupdate";
    "mtco" => Uint, "dmap.containercount";
    // Tags with (yet) unknown purpose. The name is literally "unknown tag" upstream; the *type* is
    // still known, which is what keeps the parser advancing correctly through them.
    "aead" => Bytes, "unknown tag";
    "aeFR" => Uint, "unknown tag";
    "aeSX" => Uint, "unknown tag";
    "asse" => Uint, "unknown tag";
    "atCV" => Uint, "unknown tag";
    "atSV" => Uint, "unknown tag";
    "caks" => Uint, "unknown tag";
    "caov" => Uint, "unknown tag";
    "capl" => Bytes, "unknown tag";
    "casa" => Uint, "unknown tag";
    "casc" => Uint, "unknown tag";
    "cass" => Uint, "unknown tag";
    "ceQA" => Uint, "unknown tag";
    "ceQU" => Bool, "unknown tag";
    "ceMQ" => Bool, "unknown tag";
    "ceNQ" => Uint, "unknown tag";
    "ceNR" => Bytes, "unknown tag";
    "ceQu" => Bool, "unknown tag";
    "cmbe" => String, "unknown tag";
    "cmcc" => String, "unknown tag";
    "cmce" => String, "unknown tag";
    "cmcv" => Ignore, "unknown tag";
    "cmik" => Uint, "unknown tag";
    "cmsb" => Uint, "unknown tag";
    "cmsc" => Uint, "unknown tag";
    "cmsp" => Uint, "unknown tag";
    "cmsv" => Uint, "unknown tag";
    "cmte" => String, "unknown tag";
    "mscu" => Uint, "unknown tag";
}

/// Look a tag up, or `None` if it is not in the table.
///
/// Keys are matched case-sensitively: `aeFP` and `aefp` are different tags, and the table contains
/// mixed-case keys (`ceGS`, `atCV`, `ceQu` alongside `ceQU`) that a case-insensitive match would
/// conflate.
#[must_use]
pub fn lookup(key: &str) -> Option<TagDefinition> {
    TAGS.iter()
        .find(|(candidate, _)| *candidate == key)
        .map(|(_, definition)| *definition)
}

/// `lookup_tag` (`tag_definitions.py:127-132`): the table, falling back to [`UNKNOWN_TAG`].
#[must_use]
pub fn lookup_tag(key: &str) -> TagDefinition {
    lookup(key).unwrap_or(UNKNOWN_TAG)
}

/// Whether a tag's data should be parsed as nested entries.
#[must_use]
pub fn is_container(key: &str) -> bool {
    lookup_tag(key).tag_type == TagType::Container
}

#[cfg(test)]
mod tests {
    use super::{TAGS, TagType, UNKNOWN_TAG, is_container, lookup, lookup_tag};

    /// The table is transcribed verbatim, so its size is worth pinning: sixty-nine rows with real
    /// dotted names plus twenty-nine marked "unknown tag" (`tag_definitions.py:24-124`).
    ///
    /// **Correction to `docs/research/dmap-port-spec.md` §1.1**, which says "90 entries (55 with
    /// real dotted names, 35 marked 'unknown tag')". Counted directly from the source at commit
    /// `b277a4c`, the table has 98 rows, of which 29 are "unknown tag" (the spec's 30th is the
    /// fallback `lookup_tag` returns, not a row). Every row in the spec's
    /// transcription is present and correct — the totals in its prose are what was off.
    #[test]
    fn the_table_has_every_row_pyatv_has() {
        assert_eq!(TAGS.len(), 98);
        assert_eq!(
            TAGS.iter()
                .filter(|(_, tag)| tag.name == "unknown tag")
                .count(),
            29
        );
    }

    /// Duplicate keys would make `lookup` order-dependent and silently shadow a row.
    #[test]
    fn every_key_is_distinct() {
        let mut keys: Vec<_> = TAGS.iter().map(|(key, _)| *key).collect();
        keys.sort_unstable();
        let before = keys.len();
        keys.dedup();
        assert_eq!(before, keys.len(), "the tag table has a duplicate key");
    }

    /// Every key is exactly the four bytes the wire format allocates for it.
    #[test]
    fn every_key_is_four_ascii_bytes() {
        for (key, _) in TAGS {
            assert_eq!(key.len(), 4, "{key}");
            assert!(key.is_ascii(), "{key}");
        }
    }

    #[test]
    fn known_tags_resolve_to_their_types() {
        assert_eq!(lookup_tag("cmst").tag_type, TagType::Container);
        assert_eq!(lookup_tag("caps").tag_type, TagType::Uint);
        assert_eq!(lookup_tag("cann").tag_type, TagType::String);
        assert_eq!(lookup_tag("cavc").tag_type, TagType::Bool);
        assert_eq!(lookup_tag("canp").tag_type, TagType::Bytes);
        assert_eq!(lookup_tag("ceSD").tag_type, TagType::Bplist);
        assert_eq!(lookup_tag("cmcv").tag_type, TagType::Ignore);
        assert_eq!(lookup_tag("cmst").name, "dmcp.playstatus");
    }

    /// `ceQU` and `ceQu` are two different rows; a case-insensitive lookup would merge them.
    #[test]
    fn lookup_is_case_sensitive() {
        assert_eq!(lookup("ceQU").map(|it| it.tag_type), Some(TagType::Bool));
        assert_eq!(lookup("ceQu").map(|it| it.tag_type), Some(TagType::Bool));
        assert!(lookup("cequ").is_none());
        assert!(lookup("CMST").is_none());
    }

    /// An unrecognised tag is not an error: it is a `None` value the walker still steps past.
    #[test]
    fn unknown_tags_fall_back_rather_than_failing() {
        assert!(lookup("zzzz").is_none());
        assert_eq!(lookup_tag("zzzz"), UNKNOWN_TAG);
        assert!(!is_container("zzzz"));
    }

    /// The rendering `pprint` depends on.
    #[test]
    fn a_tag_renders_the_way_pyatv_prints_it() {
        assert_eq!(
            lookup_tag("cmst").to_string(),
            "[container, dmcp.playstatus]"
        );
        assert_eq!(lookup_tag("caps").to_string(), "[uint, dacp.playstatus]");
        assert_eq!(
            lookup_tag("cann").to_string(),
            "[str, daap.nowplayingtrack]"
        );
        assert_eq!(lookup_tag("zzzz").to_string(), "[unknown, unknown tag]");
    }
}
