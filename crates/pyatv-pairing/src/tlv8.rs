//! TLV8: the HAP tag-length-value codec.
//!
//! Fully specified in `docs/research/crypto-pairing.md` §4, and small enough that hand-rolling it
//! is the right call — the report's §8.1 surveys the crates.io options and rejects all of them.
//!
//! Wire format: each entry is `1-byte tag | 1-byte length | value`. A value longer than 255 bytes
//! is split across consecutive entries carrying the same tag, and the decoder concatenates
//! same-tag runs back together. That concatenation is only correct when the chunks are contiguous,
//! which every pyatv writer guarantees; this decoder reproduces the same assumption rather than
//! trying to be more general than the devices are.
//!
//! Nesting is not supported: HAP TLV8 is single-level, matching pyatv's own module caveat.

use std::collections::BTreeMap;

use bytes::{BufMut, Bytes, BytesMut};

use crate::{Error, Result};

/// Maximum bytes carried by a single TLV entry before it must be split.
pub const MAX_CHUNK: usize = 255;

/// Standardised TLV tags.
///
/// `Name` and `Flags` are not in the published HAP tables but pyatv depends on both, so they are
/// carried here with the values it uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum TlvValue {
    /// Pairing method being requested.
    Method = 0x00,
    /// Pairing identifier.
    Identifier = 0x01,
    /// SRP salt.
    Salt = 0x02,
    /// SRP or Curve25519 public key.
    PublicKey = 0x03,
    /// SRP proof.
    Proof = 0x04,
    /// AEAD-encrypted sub-TLV.
    EncryptedData = 0x05,
    /// Sequence number, i.e. the M-state.
    SeqNo = 0x06,
    /// Error code.
    Error = 0x07,
    /// Seconds to back off before retrying.
    BackOff = 0x08,
    /// Certificate.
    Certificate = 0x09,
    /// Ed25519 signature.
    Signature = 0x0A,
    /// Permission bits for an added pairing.
    Permissions = 0x0B,
    /// Non-final fragment of a fragmented message.
    FragmentData = 0x0C,
    /// Final fragment of a fragmented message.
    FragmentLast = 0x0D,
    /// Human-readable name, Apple-internal.
    Name = 0x11,
    /// Pairing flags, Apple-internal.
    Flags = 0x13,
}

impl TlvValue {
    /// Map a raw tag byte onto a known tag.
    #[must_use]
    pub const fn from_tag(tag: u8) -> Option<Self> {
        Some(match tag {
            0x00 => Self::Method,
            0x01 => Self::Identifier,
            0x02 => Self::Salt,
            0x03 => Self::PublicKey,
            0x04 => Self::Proof,
            0x05 => Self::EncryptedData,
            0x06 => Self::SeqNo,
            0x07 => Self::Error,
            0x08 => Self::BackOff,
            0x09 => Self::Certificate,
            0x0A => Self::Signature,
            0x0B => Self::Permissions,
            0x0C => Self::FragmentData,
            0x0D => Self::FragmentLast,
            0x11 => Self::Name,
            0x13 => Self::Flags,
            _ => return None,
        })
    }
}

/// The pairing method being requested, carried in [`TlvValue::Method`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Method {
    /// Standard pair-setup.
    PairSetup = 0x00,
    /// Pair-setup with additional authentication.
    PairSetupWithAuth = 0x01,
    /// Pair-verify against existing credentials.
    PairVerify = 0x02,
    /// Add a pairing.
    AddPairing = 0x03,
    /// Remove a pairing.
    RemovePairing = 0x04,
    /// List pairings.
    ListPairing = 0x05,
}

/// Exchange state, carried as the value of [`TlvValue::SeqNo`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum State {
    /// First message.
    M1 = 0x01,
    /// Second message.
    M2 = 0x02,
    /// Third message.
    M3 = 0x03,
    /// Fourth message.
    M4 = 0x04,
    /// Fifth message.
    M5 = 0x05,
    /// Sixth message.
    M6 = 0x06,
}

/// Error codes a device can report in [`TlvValue::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ErrorCode {
    /// Unspecified failure.
    Unknown = 0x01,
    /// Wrong PIN or bad proof.
    Authentication = 0x02,
    /// Too many attempts; retry after the [`TlvValue::BackOff`] interval.
    BackOff = 0x03,
    /// The device already has the maximum number of pairings.
    MaxPeers = 0x04,
    /// Too many failed attempts.
    MaxTries = 0x05,
    /// Pairing is not available right now.
    Unavailable = 0x06,
    /// The device is busy.
    Busy = 0x07,
}

impl ErrorCode {
    /// Map a raw error byte onto a known code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            0x01 => Self::Unknown,
            0x02 => Self::Authentication,
            0x03 => Self::BackOff,
            0x04 => Self::MaxPeers,
            0x05 => Self::MaxTries,
            0x06 => Self::Unavailable,
            0x07 => Self::Busy,
            _ => return None,
        })
    }
}

/// Set on [`TlvValue::Flags`] to request transient (ephemeral, nothing persisted) pairing.
pub const FLAG_TRANSIENT_PAIRING: u8 = 0x10;

/// A decoded single-level TLV8 message.
///
/// Entries are keyed by raw tag byte rather than [`TlvValue`] so that tags pyatv has not catalogued
/// still round-trip instead of being dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Tlv8 {
    entries: BTreeMap<u8, Bytes>,
}

impl Tlv8 {
    /// An empty message.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a known tag, replacing any existing value.
    #[must_use]
    pub fn with(mut self, tag: TlvValue, value: impl Into<Bytes>) -> Self {
        self.entries.insert(tag as u8, value.into());
        self
    }

    /// Set a known tag to a single-byte integer value.
    #[must_use]
    pub fn with_byte(self, tag: TlvValue, value: u8) -> Self {
        self.with(tag, Bytes::from(vec![value]))
    }

    /// Read a known tag.
    #[must_use]
    pub fn get(&self, tag: TlvValue) -> Option<&Bytes> {
        self.entries.get(&(tag as u8))
    }

    /// Read a known tag, or fail with [`Error::MissingTlv`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingTlv`] when the tag is absent.
    pub fn require(&self, tag: TlvValue) -> Result<&Bytes> {
        self.get(tag).ok_or(Error::MissingTlv(tag))
    }

    /// Read a tag holding a little-endian integer.
    ///
    /// pyatv decodes `Method`, `SeqNo`, `Error` and `BackOff` as little-endian, which only becomes
    /// observable for `BackOff`, whose second-count can exceed one byte.
    #[must_use]
    pub fn get_uint(&self, tag: TlvValue) -> Option<u64> {
        let bytes = self.get(tag)?;
        let mut buffer = [0u8; 8];
        let len = bytes.len().min(8);
        buffer[..len].copy_from_slice(&bytes[..len]);
        Some(u64::from_le_bytes(buffer))
    }

    /// Whether the message carries no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every tag present, in ascending tag order.
    pub fn tags(&self) -> impl Iterator<Item = u8> + '_ {
        self.entries.keys().copied()
    }

    /// Encode to the wire format, splitting values longer than [`MAX_CHUNK`] into consecutive
    /// same-tag entries.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut out = BytesMut::new();
        for (tag, value) in &self.entries {
            if value.is_empty() {
                out.put_u8(*tag);
                out.put_u8(0);
                continue;
            }
            for chunk in value.chunks(MAX_CHUNK) {
                out.put_u8(*tag);
                // `chunks(MAX_CHUNK)` yields at most 255 bytes, so the conversion always succeeds;
                // the fallback keeps this panic-free without pretending the branch is reachable.
                out.put_u8(u8::try_from(chunk.len()).unwrap_or(u8::MAX));
                out.put_slice(chunk);
            }
        }
        out.freeze()
    }

    /// Decode a wire-format message, concatenating contiguous same-tag runs.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Tlv8`] if the input ends inside an entry header or value.
    pub fn decode(input: &[u8]) -> Result<Self> {
        let mut entries: BTreeMap<u8, BytesMut> = BTreeMap::new();
        let mut offset = 0usize;

        while offset < input.len() {
            let header = input
                .get(offset..offset + 2)
                .ok_or_else(|| Error::Tlv8(format!("truncated entry header at offset {offset}")))?;
            let (tag, length) = (header[0], header[1] as usize);
            offset += 2;

            let value = input.get(offset..offset + length).ok_or_else(|| {
                Error::Tlv8(format!(
                    "entry with tag {tag:#04x} claims {length} bytes but only {} remain",
                    input.len() - offset
                ))
            })?;
            offset += length;

            entries.entry(tag).or_default().extend_from_slice(value);
        }

        Ok(Self {
            entries: entries
                .into_iter()
                .map(|(tag, value)| (tag, value.freeze()))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{MAX_CHUNK, Tlv8, TlvValue};

    /// A hand-built M1 pair-setup request: `SeqNo = 1`, `Method = 0` (`PairSetup`).
    #[test]
    fn encodes_a_hand_built_pair_setup_m1() {
        let message = Tlv8::new()
            .with_byte(TlvValue::Method, 0x00)
            .with_byte(TlvValue::SeqNo, 0x01);

        // Tags sort ascending: Method (0x00) then SeqNo (0x06).
        assert_eq!(&message.encode()[..], &[0x00, 0x01, 0x00, 0x06, 0x01, 0x01]);
    }

    #[test]
    fn decodes_what_it_encodes() {
        let message = Tlv8::new()
            .with_byte(TlvValue::SeqNo, 0x03)
            .with(TlvValue::PublicKey, Bytes::from(vec![0xAA; 32]))
            .with(TlvValue::Proof, Bytes::from(vec![0xBB; 64]));

        let decoded = Tlv8::decode(&message.encode()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.get_uint(TlvValue::SeqNo), Some(3));
    }

    /// Values over 255 bytes must be split across same-tag entries and rejoined on decode. A
    /// 384-byte SRP public key for the 3072-bit group is the case this exists for.
    #[test]
    fn long_values_split_and_rejoin() {
        let public_key = Bytes::from(
            (0..384u32)
                .map(|index| u8::try_from(index % 256).expect("index % 256 always fits in u8"))
                .collect::<Vec<_>>(),
        );
        let message = Tlv8::new().with(TlvValue::PublicKey, public_key.clone());

        let encoded = message.encode();
        // 255 + 129 bytes of payload, each preceded by a 2-byte header.
        assert_eq!(encoded.len(), 2 + MAX_CHUNK + 2 + 129);
        assert_eq!(encoded[0], TlvValue::PublicKey as u8);
        assert_eq!(encoded[1], 255);
        assert_eq!(encoded[2 + MAX_CHUNK], TlvValue::PublicKey as u8);
        assert_eq!(encoded[3 + MAX_CHUNK], 129);

        assert_eq!(
            Tlv8::decode(&encoded).unwrap().get(TlvValue::PublicKey),
            Some(&public_key)
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(Tlv8::decode(&[0x06]).is_err());
        assert!(Tlv8::decode(&[0x06, 0x04, 0x01]).is_err());
    }

    #[test]
    fn zero_length_entries_round_trip() {
        let message = Tlv8::new().with(TlvValue::Error, Bytes::new());
        assert_eq!(&message.encode()[..], &[0x07, 0x00]);
        assert_eq!(Tlv8::decode(&message.encode()).unwrap(), message);
    }
}
