//! The DNS message header and the message itself.
//!
//! Ports `DnsHeader` and `DnsMessage` from pyatv `support/dns.py`, plus the query-building half of
//! `create_service_queries` from `core/mdns.py`.

use super::name::NameCompressor;
use super::reader::Reader;
use super::record::{DnsQuestion, DnsResource, QueryType};
use super::{DnsError, HEADER_LENGTH};

/// The flags pyatv puts on every message it builds, from `DnsMessage.__init__`.
///
/// `0x0120` is `RD` (recursion desired, bit 8) plus bit 5, which RFC 1035 reserves and RFC 2535
/// later assigned to `AD`. Neither is meaningful for multicast DNS — RFC 6762 section 18 says
/// senders should zero everything but `QR` and `OPCODE`, and responders must ignore the rest — but
/// this is what pyatv puts on the wire and devices answer it, so it is reproduced verbatim rather
/// than "corrected".
pub const DEFAULT_FLAGS: u16 = 0x0120;

/// The transaction ID pyatv uses for scan queries, from `core/mdns.py`.
pub const DEFAULT_QUERY_ID: u16 = 0x35FF;

/// The fixed twelve-byte header at the front of every DNS message, RFC 1035 section 4.1.1.
///
/// Only produced by [`DnsMessage::unpack`]; the section counts on a [`DnsMessage`] come from the
/// lengths of its record vectors, so they cannot drift out of sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    /// Transaction ID, echoed by the responder.
    pub id: u16,
    /// `QR`, `OPCODE`, `AA`, `TC`, `RD`, `RA`, `Z` and `RCODE`, packed.
    pub flags: u16,
    /// Number of entries in the question section.
    pub qdcount: u16,
    /// Number of entries in the answer section.
    pub ancount: u16,
    /// Number of entries in the authority section.
    pub nscount: u16,
    /// Number of entries in the additional section.
    pub arcount: u16,
}

impl DnsHeader {
    /// Read a header from the start of a message.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::UnexpectedEof`] if fewer than [`HEADER_LENGTH`] bytes are available.
    pub fn unpack(reader: &mut Reader<'_>) -> Result<Self, DnsError> {
        Ok(Self {
            id: reader.read_u16()?,
            flags: reader.read_u16()?,
            qdcount: reader.read_u16()?,
            ancount: reader.read_u16()?,
            nscount: reader.read_u16()?,
            arcount: reader.read_u16()?,
        })
    }

    /// The header's twelve wire bytes.
    #[must_use]
    pub fn pack(&self) -> [u8; HEADER_LENGTH] {
        let mut out = [0u8; HEADER_LENGTH];
        let fields = [
            self.id,
            self.flags,
            self.qdcount,
            self.ancount,
            self.nscount,
            self.arcount,
        ];
        for (index, value) in fields.into_iter().enumerate() {
            out[index * 2..index * 2 + 2].copy_from_slice(&value.to_be_bytes());
        }
        out
    }

    /// Whether the `QR` bit is set, marking this a response rather than a query.
    #[must_use]
    pub const fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }
}

/// A complete DNS message: header, questions, and the three record sections.
///
/// The additional section is called `resources` to match pyatv's field name, so that a reader
/// comparing the two does not have to translate.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsMessage {
    /// Transaction ID.
    pub msg_id: u16,
    /// Header flags. Defaults to [`DEFAULT_FLAGS`] via [`DnsMessage::new`].
    pub flags: u16,
    /// The question section.
    pub questions: Vec<DnsQuestion>,
    /// The answer section.
    pub answers: Vec<DnsResource>,
    /// The authority section.
    pub authorities: Vec<DnsResource>,
    /// The additional section.
    pub resources: Vec<DnsResource>,
}

impl DnsMessage {
    /// An empty message with pyatv's default flags.
    #[must_use]
    pub fn new(msg_id: u16) -> Self {
        Self {
            msg_id,
            flags: DEFAULT_FLAGS,
            ..Self::default()
        }
    }

    /// Build the query pyatv sends when scanning: one question per name, plus the QU bit.
    ///
    /// This is the message half of `core/mdns.py`'s `create_service_queries`. Chunking the service
    /// list across several datagrams stays with the caller, since that is a transport concern.
    ///
    /// ```
    /// use pyatv_mdns::dns::{DnsMessage, QCLASS_IN_UNICAST, QueryType};
    ///
    /// let query = DnsMessage::query(0x35FF, ["_airplay._tcp.local"], QueryType::PTR);
    /// assert_eq!(query.questions.len(), 1);
    /// assert_eq!(query.questions[0].qclass, QCLASS_IN_UNICAST);
    /// assert_eq!(&query.pack()[..2], &[0x35, 0xFF]);
    /// ```
    #[must_use]
    pub fn query<I, S>(msg_id: u16, names: I, qtype: QueryType) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            questions: names
                .into_iter()
                .map(|name| DnsQuestion::new(name, qtype))
                .collect(),
            ..Self::new(msg_id)
        }
    }

    /// The header this message would be packed with.
    ///
    /// Section counts are taken from the record vectors, so they always describe what
    /// [`Self::pack`] will write.
    #[must_use]
    pub fn header(&self) -> DnsHeader {
        DnsHeader {
            id: self.msg_id,
            flags: self.flags,
            qdcount: truncating_count(self.questions.len()),
            ancount: truncating_count(self.answers.len()),
            nscount: truncating_count(self.authorities.len()),
            arcount: truncating_count(self.resources.len()),
        }
    }

    /// Parse a complete DNS message.
    ///
    /// Every section is parsed strictly: a truncated record, an out-of-range compression pointer, a
    /// pointer loop, or RDATA whose decoded length disagrees with its length field all produce an
    /// error rather than a partial message. pyatv is looser — it asserts, over-reads, or loops — and
    /// `core/mdns.py` only catches `UnicodeDecodeError`, so several of those turn into a crashed
    /// receive loop upstream.
    ///
    /// # Errors
    ///
    /// Any [`DnsError`]. See [`DnsResource::unpack`] and [`super::name::parse_name`].
    pub fn unpack(msg: &[u8]) -> Result<Self, DnsError> {
        let mut reader = Reader::new(msg);
        let header = DnsHeader::unpack(&mut reader)?;

        // Counts are attacker-controlled, so nothing is pre-allocated from them: the vectors grow
        // only as records actually parse, and a lying count fails on the first short read.
        let mut message = Self {
            msg_id: header.id,
            flags: header.flags,
            ..Self::default()
        };

        for _ in 0..header.qdcount {
            message.questions.push(DnsQuestion::unpack(&mut reader)?);
        }
        for _ in 0..header.ancount {
            message.answers.push(DnsResource::unpack(&mut reader)?);
        }
        for _ in 0..header.nscount {
            message.authorities.push(DnsResource::unpack(&mut reader)?);
        }
        for _ in 0..header.arcount {
            message.resources.push(DnsResource::unpack(&mut reader)?);
        }

        Ok(message)
    }

    /// Serialise the message, writing every name in full.
    ///
    /// This is the byte-for-byte counterpart of pyatv's `DnsMessage.pack` for the query path, which
    /// is the only path pyatv actually puts on the wire.
    ///
    /// **Deviation:** pyatv's `pack` writes answer RDATA as `qname_encode(answer.rd)` — it assumes
    /// every answer's RDATA is a domain name — and writes authority and additional RDATA as raw
    /// bytes. Both are artefacts of `pack` only ever being used for queries and for `atvproxy`'s
    /// hand-built fakes. Here each RDATA variant is encoded according to its own type, so a message
    /// that has been unpacked can be packed again.
    #[must_use]
    pub fn pack(&self) -> Vec<u8> {
        self.pack_inner(None)
    }

    /// Serialise the message, replacing repeated name suffixes with compression pointers.
    ///
    /// Use this when the output has to resemble what a real responder emits — a device's response
    /// repeats `_airplay._tcp.local` in every record and compresses all but the first.
    #[must_use]
    pub fn pack_compressed(&self) -> Vec<u8> {
        self.pack_inner(Some(NameCompressor::new()))
    }

    fn pack_inner(&self, compressor: Option<NameCompressor>) -> Vec<u8> {
        let mut compressor = compressor;
        let mut out = Vec::new();
        out.extend_from_slice(&self.header().pack());

        for question in &self.questions {
            question.write(compressor.as_mut(), &mut out);
        }
        for record in self
            .answers
            .iter()
            .chain(&self.authorities)
            .chain(&self.resources)
        {
            record.write(compressor.as_mut(), &mut out);
        }

        out
    }
}

/// Clamp a section length to the `u16` the header field can hold.
///
/// A message with more than 65535 records in one section cannot be represented; clamping keeps the
/// header honest about what a reader will find rather than wrapping to a small number.
fn truncating_count(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

impl core::fmt::Display for DnsMessage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "MsgId=0x{:04X} Flags=0x{:04X} Questions={} Answers={} Authorities={} Resources={}",
            self.msg_id,
            self.flags,
            self.questions.len(),
            self.answers.len(),
            self.authorities.len(),
            self.resources.len()
        )
    }
}

#[cfg(test)]
mod tests;
