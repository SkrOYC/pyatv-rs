//! Domain-name encoding and decoding, including DNS-SD service instance names.
//!
//! Ports `ServiceInstanceName`, `qname_encode` and `parse_domain_name` from pyatv
//! `support/dns.py`.
//!
//! Two pyatv-specific behaviours matter here and are reproduced deliberately:
//!
//! * **Names are UTF-8, not IDNA.** DNS-SD mandates Net-Unicode (RFC 6763 section 4.1.3) and Apple
//!   uses UTF-8 everywhere in its mDNS stack, so labels are encoded as NFC-normalised UTF-8 rather
//!   than punycode. Decoding still accepts `xn--` labels for completeness — see
//!   [`super::punycode`].
//! * **Instance labels may contain dots.** `"Dot.Within._http._tcp.local"` is *five* labels, not
//!   six, because DNS-SD instance names are a single label that may contain any character. The
//!   encoder therefore runs [`ServiceInstanceName::split_name`] first and only splits on dots when
//!   that fails.

use std::collections::HashMap;

use unicode_normalization::UnicodeNormalization;

use super::DnsError;
use super::punycode;
use super::reader::Reader;

/// The maximum encoded length of a single DNS label, RFC 1035 section 2.3.4.
pub const MAX_LABEL_LENGTH: usize = 63;

/// How many compression pointers one name may follow before it is treated as a loop.
///
/// pyatv has no such guard and will spin forever on a name that points at itself. A legal name has
/// at most 128 labels and realistic messages chain at most two or three pointers, so this bound
/// cannot reject anything a device would actually send.
const MAX_POINTER_JUMPS: usize = 64;

/// The two high bits of a label length byte, RFC 1035 section 4.1.4.
const LABEL_FLAG_MASK: u8 = 0xC0;
/// Flag value marking a compression pointer.
const LABEL_FLAG_POINTER: u8 = 0xC0;
/// Largest offset a 14-bit compression pointer can address.
const MAX_POINTER_OFFSET: u16 = 0x3FFF;

/// A DNS-SD service name, or a service *instance* name, split into its parts.
///
/// The point of this type — and the reason pyatv has it — is that a DNS-SD instance name is one
/// label that may itself contain dots, so `"Living.Room._airplay._tcp.local"` cannot be split by
/// naive dot splitting. [`Self::split_name`] finds the `_service._proto` pair instead and treats
/// everything before it as the instance.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServiceInstanceName {
    /// The instance label, or `None` for a bare service name such as `_airplay._tcp.local`.
    pub instance: Option<String>,
    /// The service and protocol labels joined, e.g. `_airplay._tcp`.
    pub service: String,
    /// Everything after the protocol label, usually `local`. May be empty.
    pub domain: String,
}

impl ServiceInstanceName {
    /// Split a name into instance (optional), service, and domain.
    ///
    /// The name is scanned for adjacent labels where the first starts with `_` and the second is
    /// `_tcp` or `_udp` (compared case-insensitively). Everything before that pair is the instance,
    /// everything after it is the domain.
    ///
    /// # Errors
    ///
    /// Returns [`DnsError::NotAServiceName`] when the name has fewer than two labels or contains no
    /// such pair. pyatv raises `ValueError` in both cases, and `core/mdns.py` uses that to skip
    /// records whose owner name is not a service instance.
    pub fn split_name(name: &str) -> Result<Self, DnsError> {
        let labels: Vec<&str> = name.split('.').collect();
        // pyatv's message says "at least three labels" but the check is for two. The check is what
        // matters: it only guards the windowing below.
        if labels.len() < 2 {
            return Err(DnsError::NotAServiceName {
                name: name.to_owned(),
            });
        }

        for index in 0..labels.len() - 1 {
            let label = labels[index];
            let next = labels[index + 1];
            if label.starts_with('_')
                && (next.eq_ignore_ascii_case("_tcp") || next.eq_ignore_ascii_case("_udp"))
            {
                let instance = labels[..index].join(".");
                return Ok(Self {
                    instance: if instance.is_empty() {
                        None
                    } else {
                        Some(instance)
                    },
                    service: format!("{label}.{next}"),
                    domain: labels[index + 2..].join("."),
                });
            }
        }

        Err(DnsError::NotAServiceName {
            name: name.to_owned(),
        })
    }

    /// The name of the PTR record that advertises this service: `service.domain`.
    #[must_use]
    pub fn ptr_name(&self) -> String {
        format!("{}.{}", self.service, self.domain)
    }
}

impl core::fmt::Display for ServiceInstanceName {
    /// Join the non-empty parts with dots, as pyatv's `__str__` does.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for part in [
            self.instance.as_deref().unwrap_or(""),
            &self.service,
            &self.domain,
        ] {
            if part.is_empty() {
                continue;
            }
            if !first {
                f.write_str(".")?;
            }
            f.write_str(part)?;
            first = false;
        }
        Ok(())
    }
}

/// Split a domain name into the labels it should be encoded as.
///
/// Ports the label-selection half of pyatv's `qname_encode`: try to read the name as a service
/// instance name so an instance label containing dots stays one label, and fall back to plain dot
/// splitting. A trailing empty label for the DNS root is always present.
#[must_use]
pub fn name_to_labels(name: &str) -> Vec<String> {
    let mut labels: Vec<String> = match ServiceInstanceName::split_name(name) {
        Ok(service_name) => {
            let mut labels = Vec::new();
            if let Some(instance) = &service_name.instance {
                labels.push(instance.clone());
            }
            // `ptr_name` is the full name with the instance dropped off.
            labels.extend(service_name.ptr_name().split('.').map(str::to_owned));
            labels
        }
        Err(_) => name.split('.').map(str::to_owned).collect(),
    };

    if labels.last().is_none_or(|label| !label.is_empty()) {
        labels.push(String::new());
    }
    labels
}

/// Append one encoded label, NFC-normalised and truncated to [`MAX_LABEL_LENGTH`] bytes.
///
/// Returns `true` when the label was the empty root label, which terminates a name.
///
/// Truncation never splits a multi-byte codepoint: pyatv drops whole characters until the encoded
/// form fits, and logs a warning. RFC 6763 section 4.1.3 requires the NFC normalisation.
fn encode_label(label: &str, out: &mut Vec<u8>) -> bool {
    let normalised: String = label.nfc().collect();
    let mut encoded = normalised.as_str();

    if encoded.len() > MAX_LABEL_LENGTH {
        // Largest char boundary at or below the limit.
        let mut end = MAX_LABEL_LENGTH;
        while !encoded.is_char_boundary(end) {
            end -= 1;
        }
        encoded = &encoded[..end];
        tracing::warn!(
            label = %normalised,
            truncated = %encoded,
            "a label is being truncated as it is over {MAX_LABEL_LENGTH} bytes long"
        );
    }

    // A truncated label is always shorter than 63 bytes, so this cast cannot wrap.
    out.push(u8::try_from(encoded.len()).unwrap_or(0));
    out.extend_from_slice(encoded.as_bytes());
    encoded.is_empty()
}

/// Encode a domain name without compression, as pyatv's `qname_encode` does.
///
/// Labels are UTF-8, NFC-normalised, and truncated to 63 bytes; a root label is always appended.
pub fn encode_name(name: &str, out: &mut Vec<u8>) {
    encode_name_labels(&name_to_labels(name), out);
}

/// Encode an explicit label sequence without compression.
///
/// This is pyatv's `qname_encode` given a list rather than a string: every element is one label
/// verbatim, dots included. A root label is appended if the sequence does not already end with one.
pub fn encode_name_labels<S: AsRef<str>>(labels: &[S], out: &mut Vec<u8>) {
    for label in labels {
        if encode_label(label.as_ref(), out) {
            // An empty label ends the name; anything after it is unreachable, and empty labels in
            // the middle of a name are illegal anyway.
            return;
        }
    }
    out.push(0);
}

/// Builds the offset table that lets repeated name suffixes be written as compression pointers.
///
/// pyatv never compresses on the way out — its encoder always writes names in full — so this has no
/// upstream counterpart. It exists because responders do compress, and round-tripping a captured
/// message through decode and encode should be able to reproduce it.
///
/// One compressor belongs to one output buffer: the recorded offsets are absolute positions in that
/// buffer, so reusing a compressor across buffers would emit pointers into nothing.
#[derive(Debug, Default)]
pub struct NameCompressor {
    /// Suffix (labels joined with NUL, which cannot occur in a label) to its offset.
    offsets: HashMap<String, u16>,
}

impl NameCompressor {
    /// A compressor with an empty offset table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Encode a name into `out`, pointing at an earlier occurrence of any matching suffix.
    ///
    /// `out` must be the buffer holding the whole message from its first byte, because compression
    /// pointers are absolute offsets into the message.
    pub fn encode(&mut self, name: &str, out: &mut Vec<u8>) {
        self.encode_labels(&name_to_labels(name), out);
    }

    /// Encode an explicit label sequence, compressing shared suffixes.
    pub fn encode_labels<S: AsRef<str>>(&mut self, labels: &[S], out: &mut Vec<u8>) {
        for index in 0..labels.len() {
            if labels[index].as_ref().is_empty() {
                out.push(0);
                return;
            }

            let suffix = labels[index..]
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
                .join("\0");

            if let Some(&offset) = self.offsets.get(&suffix) {
                let pointer = (u16::from(LABEL_FLAG_POINTER) << 8) | offset;
                out.extend_from_slice(&pointer.to_be_bytes());
                return;
            }

            if let Ok(offset) = u16::try_from(out.len())
                && offset <= MAX_POINTER_OFFSET
            {
                self.offsets.insert(suffix, offset);
            }

            encode_label(labels[index].as_ref(), out);
        }
        out.push(0);
    }
}

/// Parse a domain name at the reader's position, following any compression pointers.
///
/// On return the reader sits immediately after the name as it appeared *at the original position*:
/// after the terminating zero byte for an uncompressed name, or after the two bytes of the first
/// pointer for a compressed one. That is what pyatv does, and it is what lets the caller keep
/// parsing the record that follows.
///
/// Labels beginning with `xn--` are punycode-decoded; every other label is decoded as UTF-8.
///
/// # Errors
///
/// * [`DnsError::UnexpectedEof`] if the name runs past the end of the message.
/// * [`DnsError::OffsetOutOfBounds`] if a compression pointer addresses a byte outside the message.
/// * [`DnsError::CompressionLoop`] if pointers chain more than `MAX_POINTER_JUMPS` times. pyatv
///   would loop forever here.
/// * [`DnsError::ReservedLabelType`] for the `01` and `10` label-type flags, which RFC 1035 section
///   4.1.4 reserves. pyatv asserts on these, which is a crash on malformed input.
/// * [`DnsError::LabelNotUtf8`] or [`DnsError::InvalidPunycode`] if a label cannot be decoded.
pub fn parse_name(reader: &mut Reader<'_>) -> Result<String, DnsError> {
    let mut labels: Vec<String> = Vec::new();
    let mut resume: Option<usize> = None;
    let mut jumps = 0usize;

    loop {
        let length = reader.read_u8()?;
        if length == 0 {
            break;
        }

        match length & LABEL_FLAG_MASK {
            0x00 => labels.push(decode_label(reader.read_slice(usize::from(length))?)?),
            LABEL_FLAG_POINTER => {
                let low = reader.read_u8()?;
                let offset = usize::from(u16::from_be_bytes([length & !LABEL_FLAG_MASK, low]));
                // Remember where the name ended in the original stream, not where we jump to.
                if resume.is_none() {
                    resume = Some(reader.position());
                }
                jumps += 1;
                if jumps > MAX_POINTER_JUMPS {
                    return Err(DnsError::CompressionLoop);
                }
                reader.seek(offset)?;
            }
            flags => {
                return Err(DnsError::ReservedLabelType {
                    flags: flags >> 6_u8,
                });
            }
        }
    }

    if let Some(resume) = resume {
        reader.seek(resume)?;
    }
    Ok(labels.join("."))
}

/// Decode one raw label to a string.
fn decode_label(label: &[u8]) -> Result<String, DnsError> {
    if let Some(ace) = label.strip_prefix(punycode::ACE_PREFIX.as_bytes()) {
        let ace = core::str::from_utf8(ace).map_err(|_| DnsError::LabelNotUtf8 {
            label: label.to_vec(),
        })?;
        return punycode::decode(ace).ok_or_else(|| DnsError::InvalidPunycode {
            label: label.to_vec(),
        });
    }
    core::str::from_utf8(label)
        .map(str::to_owned)
        .map_err(|_| DnsError::LabelNotUtf8 {
            label: label.to_vec(),
        })
}

/// Read a DNS character-string: one length byte followed by that many opaque bytes.
///
/// This is *not* domain-name encoding — the length byte has no compression flags, so a
/// character-string may be up to 255 bytes long. pyatv keeps the two apart for the same reason and
/// its `test_string_parsing` cases exist precisely to pin the difference.
///
/// # Errors
///
/// Returns [`DnsError::UnexpectedEof`] if the message ends mid-string. pyatv returns a short read
/// here instead, silently.
pub fn parse_character_string<'a>(reader: &mut Reader<'a>) -> Result<&'a [u8], DnsError> {
    let length = usize::from(reader.read_u8()?);
    reader.read_slice(length)
}

#[cfg(test)]
mod tests;
