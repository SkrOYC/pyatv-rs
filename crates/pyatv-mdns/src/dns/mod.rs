//! A hand-written DNS / DNS-SD codec, ported from pyatv's `pyatv/support/dns.py`.
//!
//! # Why hand-written
//!
//! `docs/research/rust-crates.md` §2 left the unicast codec open between `hickory-proto` and a
//! hand-rolled implementation. This module is the hand-rolled option, and the deciding argument is
//! fidelity rather than size: pyatv's codec deviates from the RFCs in several places that Apple
//! devices depend on, and reproducing those deviations on top of a strict general-purpose DNS
//! library means fighting it. The record types that matter are PTR, SRV, TXT, A and AAAA — a small,
//! static surface, the same argument that justified hand-writing OPACK and TLV8.
//!
//! # Sans-io
//!
//! Nothing here touches a socket, a clock, or a task. [`DnsMessage::unpack`] takes a byte slice and
//! [`DnsMessage::pack`] returns one. Transport lives in [`crate::mdns`].
//!
//! # Robustness
//!
//! Every input is untrusted: an mDNS listener accepts datagrams from anyone on the link. pyatv
//! parses with `assert` statements, unbounded `BytesIO` seeks, and no compression-pointer loop
//! guard, so a malformed packet can crash or hang it. Here every read is bounds-checked, every
//! malformed case returns a [`DnsError`], pointer chains are capped, and no allocation is sized
//! from an attacker-supplied count.
//!
//! # Where this deviates from pyatv, and where pyatv deviates from the RFCs
//!
//! Each deviation is documented at the item that makes it. The load-bearing ones:
//!
//! * Names are UTF-8, NFC-normalised, never IDNA-encoded on output ([`name`]) — RFC 6763 §4.1.3.
//! * A DNS-SD instance label may contain dots and stays one label ([`ServiceInstanceName`]).
//! * `AAAA` RDATA is decoded; pyatv's `QueryType` has no `AAAA` member and leaves it raw
//!   ([`record`]).
//! * A TXT chunk with no `=` and a non-ASCII key is fatal, while a non-ASCII key in a `key=value`
//!   chunk is merely dropped. That asymmetry is pyatv's and it changes which datagrams get
//!   discarded ([`txt::parse_txt`]).
//! * [`DnsMessage::pack`] encodes each RDATA variant properly; pyatv's `pack` assumes answer RDATA
//!   is always a domain name ([`message`]).
//!
//! # Example
//!
//! ```
//! use pyatv_mdns::dns::{DnsMessage, QueryType};
//!
//! let query = DnsMessage::query(0x35FF, ["_airplay._tcp.local"], QueryType::PTR);
//! let wire = query.pack();
//!
//! let parsed = DnsMessage::unpack(&wire).expect("round-trips");
//! assert_eq!(parsed.questions[0].qname, "_airplay._tcp.local");
//! assert!(parsed.questions[0].wants_unicast_response());
//! ```

pub mod message;
pub mod name;
pub mod punycode;
pub mod record;
pub mod txt;

mod reader;

pub use message::{DEFAULT_FLAGS, DEFAULT_QUERY_ID, DnsHeader, DnsMessage};
pub use name::{MAX_LABEL_LENGTH, NameCompressor, ServiceInstanceName};
pub use reader::Reader;
pub use record::{
    CLASS_IN, DnsQuestion, DnsResource, QCLASS_IN_UNICAST, QueryType, RecordData, SrvData,
    UNICAST_RESPONSE,
};
pub use txt::{CaseInsensitiveMap, Properties, TxtRecords, decode_value};

/// Length of the fixed DNS message header, RFC 1035 section 4.1.1.
pub const HEADER_LENGTH: usize = 12;

/// Everything that can go wrong while decoding a DNS message.
///
/// pyatv signals these with `assert`, `struct.error`, `ValueError`, `UnicodeDecodeError`, or by not
/// signalling at all. They are enumerated here so a caller can tell a truncated datagram from a
/// hostile one, and so that no input path can panic.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DnsError {
    /// The message ended while more bytes were still required.
    #[error("message ended early: needed {needed} more bytes, {available} available")]
    UnexpectedEof {
        /// Bytes the read asked for.
        needed: usize,
        /// Bytes actually left in the message.
        available: usize,
    },

    /// A compression pointer, or an internal seek, addressed a byte outside the message.
    #[error("offset {offset} is outside the {length}-byte message")]
    OffsetOutOfBounds {
        /// The offset that was requested.
        offset: usize,
        /// Total message length.
        length: usize,
    },

    /// Compression pointers chained past the allowed depth, which in practice means they loop.
    #[error("domain name follows too many compression pointers; it is probably a loop")]
    CompressionLoop,

    /// A label length byte used one of the two label types RFC 1035 section 4.1.4 reserves.
    #[error("reserved label type 0b{flags:02b} in domain name")]
    ReservedLabelType {
        /// The two high bits of the length byte, as a value of 1 or 2.
        flags: u8,
    },

    /// A domain label was not valid UTF-8. DNS-SD requires Net-Unicode, so this is malformed input.
    #[error("domain label is not valid UTF-8: {label:02x?}")]
    LabelNotUtf8 {
        /// The raw label bytes.
        label: Vec<u8>,
    },

    /// An `xn--` label's payload was not valid Punycode.
    #[error("domain label is not valid punycode: {label:02x?}")]
    InvalidPunycode {
        /// The raw label bytes, including the `xn--` prefix.
        label: Vec<u8>,
    },

    /// The name is neither a service name nor a service instance name.
    ///
    /// pyatv raises `ValueError` here and `core/mdns.py` uses it to skip records whose owner name
    /// is not a DNS-SD service, so this is an expected outcome, not necessarily a fault.
    #[error("'{name}' is not a service domain, nor a service instance name")]
    NotAServiceName {
        /// The name that failed to split.
        name: String,
    },

    /// Decoding a record's RDATA consumed a different number of bytes than its length field claims.
    #[error("RDATA length field says {expected} bytes but decoding consumed {consumed}")]
    RdataLengthMismatch {
        /// The record's `RDLENGTH` field.
        expected: usize,
        /// Bytes the decoder actually consumed.
        consumed: usize,
    },

    /// An `A` or `AAAA` record's RDATA was not the fixed size the type requires.
    #[error("an {qtype} record must have exactly {expected} bytes of data (not {length})")]
    InvalidAddressLength {
        /// The record type whose length was wrong.
        qtype: QueryType,
        /// The length the type requires: 4 for `A`, 16 for `AAAA`.
        expected: usize,
        /// The length that was found.
        length: usize,
    },

    /// A TXT character-string claimed more bytes than the record has left.
    #[error("TXT chunk claims {chunk_length} bytes but only {remaining} remain in the record")]
    TxtChunkOverrunsRecord {
        /// The chunk's length byte.
        chunk_length: usize,
        /// Bytes left in the RDATA.
        remaining: usize,
    },

    /// A valueless TXT key was not ASCII. RFC 6763 section 6.4 requires TXT keys to be ASCII.
    #[error("non-ASCII DNS-SD key with no value: {key:02x?}")]
    NonAsciiTxtKey {
        /// The raw key bytes.
        key: Vec<u8>,
    },
}

impl From<DnsError> for pyatv_core::Error {
    /// A malformed DNS message surfaces as an invalid response at the crate boundary.
    fn from(error: DnsError) -> Self {
        Self::InvalidResponse(error.to_string())
    }
}
