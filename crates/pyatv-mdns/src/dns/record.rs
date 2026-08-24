//! Questions, resource records, and the RDATA shapes this crate decodes.
//!
//! Ports `QueryType`, `DnsQuestion`, `DnsResource`, `parse_srv_dict` and `QueryType.parse_rdata`
//! from pyatv `support/dns.py`.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::DnsError;
use super::name::{self, NameCompressor};
use super::reader::Reader;
use super::txt::{self, TxtRecords};

/// The `IN` (Internet) class, RFC 1035 section 3.2.4.
pub const CLASS_IN: u16 = 0x0001;

/// Top bit of a question's class: "unicast response requested", the QU bit of RFC 6762 section 5.4.
///
/// The same bit in a *resource record*'s class means "cache flush" instead (RFC 6762 section 10.2),
/// which is why [`DnsResource::qclass`] is kept as a raw `u16`.
pub const UNICAST_RESPONSE: u16 = 0x8000;

/// The question class pyatv sends for every scan query: `IN`, with the QU bit set.
///
/// From `core/mdns.py`'s `create_service_queries`. Requesting a unicast response is what makes a
/// scan work on networks that drop or rate-limit multicast replies.
pub const QCLASS_IN_UNICAST: u16 = CLASS_IN | UNICAST_RESPONSE;

/// A DNS RR type, as a 16-bit value with named constants for the ones this crate decodes.
///
/// Modelled as a newtype rather than an enum because the type space is open: pyatv's `QueryType`
/// keeps unknown types as raw integers and returns their RDATA undecoded, and so does this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct QueryType(u16);

impl QueryType {
    /// `A` — a 32-bit IPv4 address.
    pub const A: Self = Self(0x0001);
    /// `PTR` — a domain name, the DNS-SD service-instance pointer.
    pub const PTR: Self = Self(0x000C);
    /// `TXT` — DNS-SD key/value properties.
    pub const TXT: Self = Self(0x0010);
    /// `AAAA` — a 128-bit IPv6 address.
    pub const AAAA: Self = Self(0x001C);
    /// `SRV` — priority, weight, port and target host.
    pub const SRV: Self = Self(0x0021);
    /// `ANY` — the wildcard query type pyatv uses to re-query a sleep proxy.
    pub const ANY: Self = Self(0x00FF);

    /// Wrap a raw RR type value.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// The raw RR type value as it appears on the wire.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// The mnemonic for the types this crate knows, or `None` for anything else.
    #[must_use]
    pub const fn name(self) -> Option<&'static str> {
        match self {
            Self::A => Some("A"),
            Self::PTR => Some("PTR"),
            Self::TXT => Some("TXT"),
            Self::AAAA => Some("AAAA"),
            Self::SRV => Some("SRV"),
            Self::ANY => Some("ANY"),
            _ => None,
        }
    }
}

impl core::fmt::Display for QueryType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.name() {
            Some(name) => f.write_str(name),
            None => write!(f, "TYPE{}", self.0),
        }
    }
}

/// The decoded contents of an `SRV` record, RFC 2782.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SrvData {
    /// Lower is preferred.
    pub priority: u16,
    /// Relative weight among equal-priority targets.
    pub weight: u16,
    /// The port the service listens on. Never hardcode this: Apple TVs bind MRP and Companion to
    /// ephemeral ports that change across reboots.
    pub port: u16,
    /// The host name to connect to.
    pub target: String,
}

/// RDATA, decoded for the record types this crate understands and kept raw otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// `A` record payload.
    A(Ipv4Addr),
    /// `AAAA` record payload.
    Aaaa(Ipv6Addr),
    /// `PTR` record payload: a domain name.
    Ptr(String),
    /// `TXT` record payload.
    Txt(TxtRecords),
    /// `SRV` record payload.
    Srv(SrvData),
    /// Anything else, verbatim.
    Other(Vec<u8>),
}

impl RecordData {
    /// The SRV payload, if this is an SRV record.
    #[must_use]
    pub const fn as_srv(&self) -> Option<&SrvData> {
        match self {
            Self::Srv(srv) => Some(srv),
            _ => None,
        }
    }

    /// The TXT payload, if this is a TXT record.
    #[must_use]
    pub const fn as_txt(&self) -> Option<&TxtRecords> {
        match self {
            Self::Txt(txt) => Some(txt),
            _ => None,
        }
    }

    /// The target name, if this is a PTR record.
    #[must_use]
    pub fn as_ptr_name(&self) -> Option<&str> {
        match self {
            Self::Ptr(name) => Some(name.as_str()),
            _ => None,
        }
    }

    /// The address, if this is an `A` or `AAAA` record.
    #[must_use]
    pub fn as_ip_addr(&self) -> Option<std::net::IpAddr> {
        match self {
            Self::A(addr) => Some((*addr).into()),
            Self::Aaaa(addr) => Some((*addr).into()),
            _ => None,
        }
    }

    /// Append the wire form of this RDATA to `out`, prefixed by its 16-bit length.
    ///
    /// `compressor` compresses names inside PTR and SRV RDATA when present. Compression inside SRV
    /// RDATA is forbidden by RFC 2782, so `pack_compressed` passes `None` there; pyatv accepts it on
    /// the way in regardless, and so does this crate.
    pub(super) fn write_with_length(
        &self,
        compressor: Option<&mut NameCompressor>,
        out: &mut Vec<u8>,
    ) {
        // Reserve the length field and fill it in once the payload length is known.
        let length_at = out.len();
        out.extend_from_slice(&[0, 0]);

        match self {
            Self::A(addr) => out.extend_from_slice(&addr.octets()),
            Self::Aaaa(addr) => out.extend_from_slice(&addr.octets()),
            Self::Ptr(target) => match compressor {
                Some(compressor) => compressor.encode(target, out),
                None => name::encode_name(target, out),
            },
            Self::Txt(records) => out.extend_from_slice(&records.encode()),
            Self::Srv(srv) => {
                out.extend_from_slice(&srv.priority.to_be_bytes());
                out.extend_from_slice(&srv.weight.to_be_bytes());
                out.extend_from_slice(&srv.port.to_be_bytes());
                name::encode_name(&srv.target, out);
            }
            Self::Other(bytes) => out.extend_from_slice(bytes),
        }

        let length = u16::try_from(out.len() - length_at - 2).unwrap_or(u16::MAX);
        out[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
    }
}

/// One entry of a DNS message's question section.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DnsQuestion {
    /// The name being asked about.
    pub qname: String,
    /// The RR type being asked for.
    pub qtype: QueryType,
    /// The class, including the QU bit. See [`QCLASS_IN_UNICAST`].
    pub qclass: u16,
}

impl DnsQuestion {
    /// A question with the class pyatv uses: `IN`, unicast response requested.
    #[must_use]
    pub fn new(qname: impl Into<String>, qtype: QueryType) -> Self {
        Self {
            qname: qname.into(),
            qtype,
            qclass: QCLASS_IN_UNICAST,
        }
    }

    /// Whether the QU bit is set, asking the responder to answer by unicast.
    #[must_use]
    pub const fn wants_unicast_response(&self) -> bool {
        self.qclass & UNICAST_RESPONSE != 0
    }

    /// The class with the QU bit masked off.
    #[must_use]
    pub const fn class(&self) -> u16 {
        self.qclass & !UNICAST_RESPONSE
    }

    /// Read a question from the current position.
    ///
    /// # Errors
    ///
    /// Propagates any [`DnsError`] from name parsing, or [`DnsError::UnexpectedEof`] if the type
    /// and class fields are truncated.
    pub fn unpack(reader: &mut Reader<'_>) -> Result<Self, DnsError> {
        let qname = name::parse_name(reader)?;
        let qtype = QueryType::new(reader.read_u16()?);
        let qclass = reader.read_u16()?;
        Ok(Self {
            qname,
            qtype,
            qclass,
        })
    }

    /// Append the wire form of this question to `out`.
    pub(super) fn write(&self, compressor: Option<&mut NameCompressor>, out: &mut Vec<u8>) {
        match compressor {
            Some(compressor) => compressor.encode(&self.qname, out),
            None => name::encode_name(&self.qname, out),
        }
        out.extend_from_slice(&self.qtype.value().to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
    }
}

/// One resource record from the answer, authority, or additional section.
///
/// **Deviation:** pyatv's `DnsResource` also carries `rd_length`. It is derivable from the decoded
/// RDATA and keeping it would let the two disagree, so it is dropped here; [`Self::unpack`] still
/// validates it against how much RDATA was actually consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResource {
    /// The name this record is about.
    pub qname: String,
    /// The RR type.
    pub qtype: QueryType,
    /// The class, including the cache-flush bit.
    pub qclass: u16,
    /// Seconds this record may be cached. Zero means "goodbye", RFC 6762 section 10.1.
    pub ttl: u32,
    /// The decoded payload.
    pub rd: RecordData,
}

impl DnsResource {
    /// Read a resource record from the current position.
    ///
    /// # Errors
    ///
    /// * [`DnsError::UnexpectedEof`] if any fixed field or the RDATA is truncated.
    /// * [`DnsError::RdataLengthMismatch`] if decoding the RDATA did not consume exactly
    ///   `rd_length` bytes. pyatv asserts this; asserting on network input is a crash, so it is an
    ///   error here.
    /// * [`DnsError::InvalidAddressLength`] if an `A` or `AAAA` record is not 4 or 16 bytes.
    /// * Anything [`name::parse_name`] or [`txt::parse_txt`] can return.
    pub fn unpack(reader: &mut Reader<'_>) -> Result<Self, DnsError> {
        let qname = name::parse_name(reader)?;
        let qtype = QueryType::new(reader.read_u16()?);
        let qclass = reader.read_u16()?;
        let ttl = reader.read_u32()?;
        let rd_length = usize::from(reader.read_u16()?);

        let rd_start = reader.position();
        let rd = parse_rdata(reader, qtype, rd_length)?;
        let consumed = reader.position() - rd_start;
        if consumed != rd_length {
            return Err(DnsError::RdataLengthMismatch {
                expected: rd_length,
                consumed,
            });
        }

        Ok(Self {
            qname,
            qtype,
            qclass,
            ttl,
            rd,
        })
    }

    /// Append the wire form of this record to `out`.
    pub(super) fn write(&self, mut compressor: Option<&mut NameCompressor>, out: &mut Vec<u8>) {
        match compressor.as_deref_mut() {
            Some(compressor) => compressor.encode(&self.qname, out),
            None => name::encode_name(&self.qname, out),
        }
        out.extend_from_slice(&self.qtype.value().to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        self.rd.write_with_length(compressor, out);
    }
}

/// Decode RDATA according to the record type, leaving unknown types as raw bytes.
///
/// Ports `QueryType.parse_rdata`.
///
/// **Deviation:** pyatv's `QueryType` has no `AAAA` member, so pyatv returns IPv6 addresses as raw
/// bytes. They are decoded here — `core/mdns.py` only reads `A` today, so this is additive.
///
/// # Errors
///
/// See [`DnsResource::unpack`].
fn parse_rdata(
    reader: &mut Reader<'_>,
    qtype: QueryType,
    rd_length: usize,
) -> Result<RecordData, DnsError> {
    match qtype {
        QueryType::A => {
            let octets: [u8; 4] = read_address(reader, rd_length, 4)?
                .try_into()
                .expect("read_address returns exactly `expected` bytes");
            Ok(RecordData::A(Ipv4Addr::from(octets)))
        }
        QueryType::AAAA => {
            let octets: [u8; 16] = read_address(reader, rd_length, 16)?
                .try_into()
                .expect("read_address returns exactly `expected` bytes");
            Ok(RecordData::Aaaa(Ipv6Addr::from(octets)))
        }
        QueryType::PTR => Ok(RecordData::Ptr(name::parse_name(reader)?)),
        QueryType::TXT => Ok(RecordData::Txt(txt::parse_txt(reader, rd_length)?)),
        QueryType::SRV => {
            let priority = reader.read_u16()?;
            let weight = reader.read_u16()?;
            let port = reader.read_u16()?;
            // RFC 2782 forbids compression in SRV targets; pyatv accepts it anyway, so we do too.
            let target = name::parse_name(reader)?;
            // pyatv leaves a TODO about treating target == "." as "service not available here".
            // Deliberately not implemented: doing so would change which services a scan reports.
            Ok(RecordData::Srv(SrvData {
                priority,
                weight,
                port,
                target,
            }))
        }
        _ => Ok(RecordData::Other(reader.read_slice(rd_length)?.to_vec())),
    }
}

/// Read a fixed-size address payload, rejecting a length the type cannot hold.
fn read_address<'a>(
    reader: &mut Reader<'a>,
    rd_length: usize,
    expected: usize,
) -> Result<&'a [u8], DnsError> {
    if rd_length != expected {
        return Err(DnsError::InvalidAddressLength {
            qtype: if expected == 4 {
                QueryType::A
            } else {
                QueryType::AAAA
            },
            expected,
            length: rd_length,
        });
    }
    reader.read_slice(expected)
}

#[cfg(test)]
mod tests;
