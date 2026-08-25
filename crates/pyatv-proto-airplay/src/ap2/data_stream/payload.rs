//! The property-list envelope MRP messages travel in, and the varint framing inside it.
//!
//! Port of `encode_payload`/`decode_payload`, `encode_protobufs`/`decode_protobufs` and the
//! `{"params": {"data": …}}` shape (`pyatv/protocols/airplay/channels.py:137-151,190-226,257-264,
//! 275-277`).
//!
//! **There is no OPACK here.** The envelope is an Apple binary property list — the same
//! `bplist00` format the RTSP `SETUP` bodies use — and the only discrimination is "plist envelope
//! versus the raw bytes nested in one of its fields", not a choice between two top-level codecs.
//! OPACK is exclusively a Companion concept (spec §5.2).
//!
//! This crate treats the nested bytes as opaque. It length-prefixes them on the way out and splits
//! them apart on the way in; what they mean is `pyatv-proto-mrp`'s business, and the dependency
//! direction forbids looking.

use bytes::Bytes;

use crate::rtsp::{decode_plist, encode_plist};
use crate::{Error, Result};

/// A varint never needs more than ten bytes to carry a `u64`.
const VARINT_MAX_LEN: usize = 10;

/// Refuse a message whose length prefix is implausible.
///
/// Not an upstream concept: `decode_protobufs` slices with whatever the varint claims and lets
/// Python's own bounds checking sort it out. Here the same arithmetic is `consumed + length` on
/// `usize`, which a hostile ten-group varint overflows outright — in release builds it wraps to a
/// small number and silently mis-frames the stream, and the value is not authenticated by anything,
/// because the HAP seal one layer down covers the block, not this prefix.
///
/// **Deliberately duplicated** from `pyatv_proto_mrp::transport::tunnel::MAX_MESSAGE_LEN`, which
/// caps the identical varint framing at the identical value. The two crates cannot share the
/// constant — the workspace's dependency rule forbids this crate depending on `pyatv-proto-mrp`,
/// and that rule exists so the AirPlay framing stays usable without MRP at all. The duplication is
/// noted in both places so a change to one is a prompt to check the other; the number itself is
/// [`crate::ap2::data_stream::frame::MAX_FRAME_LEN`]'s, and far above any real MRP message.
pub const MAX_MESSAGE_LEN: usize = 8 * 1024 * 1024;

/// The tag byte every `ProtocolMessage` starts with: field 1 (`type`), wire type 0.
///
/// `channels.py:204-210` explains why this is a safe discriminator: the smallest real message is
/// around forty bytes, so a leading `0x08` can never be a plausible *length* prefix. Upstream
/// applies the check to every incoming buffer unconditionally rather than gating it on the message
/// type it says causes it (`ConfigureConnectionMessage`), and so does this.
pub const PROTOCOL_MESSAGE_TAG: u8 = 0x08;

/// Encode `value` as a base-128 varint, least significant group first.
///
/// `write_variant` (`pyatv/support/variant.py:15-19`). Reimplemented here rather than borrowed from
/// `pyatv-proto-mrp`, which this crate must not depend on.
#[must_use]
pub fn write_variant(value: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    let mut remaining = value;

    loop {
        // The mask keeps this in range, so the conversion cannot fail.
        let group = u8::try_from(remaining & 0x7F).unwrap_or(0);
        remaining >>= 7;
        if remaining == 0 {
            out.push(group);
            return out;
        }
        out.push(group | 0x80);
    }
}

/// Decode a varint from the front of `input`, returning it and how many bytes it occupied.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if `input` ends before the continuation bit clears, or if the
/// varint runs past ten groups. `read_variant` (`pyatv/support/variant.py:4-13`) raises
/// `ValueError` in the first case and cannot reach the second, since Python integers do not
/// overflow.
pub fn read_variant(input: &[u8]) -> Result<(u64, usize)> {
    let mut result = 0u64;

    for (index, byte) in input.iter().take(VARINT_MAX_LEN).enumerate() {
        // Ten groups of seven bits reach bit 63, so the shift is always in range for `u64`;
        // `wrapping_shl` would be wrong here but `checked_shl` never fires below `VARINT_MAX_LEN`.
        result |= u64::from(byte & 0x7F).wrapping_shl(7 * u32::try_from(index).unwrap_or(u32::MAX));
        if byte & 0x80 == 0 {
            return Ok((result, index + 1));
        }
    }

    Err(Error::Malformed(if input.len() < VARINT_MAX_LEN {
        format!("varint truncated after {} bytes", input.len())
    } else {
        format!("varint longer than {VARINT_MAX_LEN} bytes")
    }))
}

/// Concatenate `messages`, each prefixed with its own varint length.
///
/// `encode_protobufs` (`channels.py:143-151`). Upstream only ever calls it with a single-element
/// list (`channels.py:275-277`), but the encoder is general and so is this.
#[must_use]
pub fn encode_messages(messages: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for message in messages {
        // `usize` is at most 64 bits on every target this builds for, so the conversion cannot
        // truncate; the fallback keeps the cast out of the code rather than papering over a real
        // case.
        out.extend_from_slice(&write_variant(
            u64::try_from(message.len()).unwrap_or(u64::MAX),
        ));
        out.extend_from_slice(message);
    }
    out
}

/// Split a `data` blob back into individual messages.
///
/// `decode_protobufs` (`channels.py:198-226`), including the unprefixed-message heuristic: a buffer
/// whose first byte is [`PROTOCOL_MESSAGE_TAG`] is one whole message with no length prefix.
///
/// The heuristic is only sound because a real `ProtocolMessage` is never eight bytes long — pyatv's
/// own comment puts the floor at forty, `type` plus `uniqueIdentifier`. An eight-byte message would
/// encode a length prefix of exactly `0x08` and be indistinguishable from an unprefixed one; that
/// ambiguity is inherent to the format, is inherited verbatim from upstream, and is why this
/// crate's tests use realistically sized payloads rather than short ones.
///
/// # Errors
///
/// Returns [`Error::Malformed`] if a length prefix runs past the end of the buffer or exceeds
/// [`MAX_MESSAGE_LEN`], or if a message does not start with [`PROTOCOL_MESSAGE_TAG`]. Upstream
/// asserts the same thing and then swallows the resulting exception into a log line
/// (`channels.py:220,224-225`); surfacing it is a deliberate improvement, since a silently dropped
/// frame is invisible at exactly the moment it matters.
pub fn decode_messages(data: &[u8]) -> Result<Vec<Bytes>> {
    let mut messages = Vec::new();
    let mut rest = data;

    while !rest.is_empty() {
        let message = if rest[0] == PROTOCOL_MESSAGE_TAG {
            std::mem::take(&mut rest)
        } else {
            let (length, consumed) = read_variant(rest)?;
            // Capped *before* any arithmetic: `consumed + length` on a ten-group varint overflows
            // `usize`, which panics under debug assertions and wraps in release.
            let length = usize::try_from(length)
                .ok()
                .filter(|it| *it <= MAX_MESSAGE_LEN)
                .ok_or_else(|| {
                    Error::Malformed(format!("message length {length} exceeds {MAX_MESSAGE_LEN}"))
                })?;

            let end = consumed
                .checked_add(length)
                .ok_or_else(|| Error::Malformed(format!("message length {length} overflows")))?;
            let body = rest.get(consumed..end).ok_or_else(|| {
                Error::Malformed(format!(
                    "message claims {length} bytes, {} remain",
                    rest.len().saturating_sub(consumed)
                ))
            })?;
            rest = &rest[end..];
            body
        };

        if message.first() != Some(&PROTOCOL_MESSAGE_TAG) {
            return Err(Error::Malformed(
                "message does not start with the type tag 0x08".to_owned(),
            ));
        }
        messages.push(Bytes::copy_from_slice(message));
    }

    Ok(messages)
}

/// Wrap length-prefixed message bytes in the `{"params": {"data": …}}` envelope.
///
/// # Errors
///
/// Returns [`Error::Plist`] if the envelope cannot be serialised.
pub fn encode_envelope(data: Vec<u8>) -> Result<Vec<u8>> {
    let mut params = plist::Dictionary::new();
    params.insert("data".to_owned(), plist::Value::Data(data));

    let mut body = plist::Dictionary::new();
    body.insert("params".to_owned(), plist::Value::Dictionary(params));

    encode_plist(&plist::Value::Dictionary(body))
}

/// Pull the `params.data` blob back out of an envelope.
///
/// `Ok(None)` covers both shapes upstream tolerates without failing: a payload that is not a
/// property list at all (`decode_payload` returns `None` and logs, `channels.py:190-196`) and one
/// whose `params.data` is missing (`_process_payload` returns early, `channels.py:257-261`).
pub fn decode_envelope(payload: &[u8]) -> Option<Vec<u8>> {
    let value = decode_plist(payload).ok()?;

    value
        .as_dictionary()?
        .get("params")?
        .as_dictionary()?
        .get("data")?
        .as_data()
        .map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::{
        decode_envelope, decode_messages, encode_envelope, encode_messages, read_variant,
        write_variant,
    };

    /// The same values `pyatv/support/variant.py` produces, checked at the group boundaries.
    #[test]
    fn varints_match_the_base_128_encoding() {
        assert_eq!(write_variant(0), vec![0x00]);
        assert_eq!(write_variant(127), vec![0x7F]);
        assert_eq!(write_variant(128), vec![0x80, 0x01]);
        assert_eq!(write_variant(300), vec![0xAC, 0x02]);
        assert_eq!(write_variant(16_384), vec![0x80, 0x80, 0x01]);
    }

    #[test]
    fn varints_round_trip() {
        for value in [0u64, 1, 127, 128, 300, 16_383, 16_384, u64::from(u32::MAX)] {
            let encoded = write_variant(value);
            assert_eq!(
                read_variant(&encoded).expect("reads"),
                (value, encoded.len())
            );
        }
    }

    #[test]
    fn a_truncated_varint_is_an_error() {
        assert!(read_variant(&[0x80, 0x80]).is_err());
        assert!(read_variant(&[]).is_err());
    }

    /// A single message is length-prefixed and comes back byte-identical.
    #[test]
    fn one_message_round_trips_through_the_length_prefix() {
        let message = [0x08u8, 0x2A, 0x52, 0x24, 0x41];

        let encoded = encode_messages(&[&message]);

        assert_eq!(encoded[0], 5);
        assert_eq!(
            decode_messages(&encoded).expect("decodes"),
            vec![bytes::Bytes::copy_from_slice(&message)]
        );
    }

    /// The encoder is general even though upstream never batches.
    #[test]
    fn several_messages_round_trip() {
        let first = [0x08u8, 0x01];
        let second = [0x08u8, 0x02, 0x03];

        let decoded = decode_messages(&encode_messages(&[&first, &second])).expect("decodes");

        assert_eq!(decoded.len(), 2);
        assert_eq!(&decoded[0][..], &first[..]);
        assert_eq!(&decoded[1][..], &second[..]);
    }

    /// The `ConfigureConnectionMessage` case: a buffer starting with the type tag is one whole
    /// unprefixed message (`channels.py:204-212`).
    #[test]
    fn a_leading_type_tag_means_the_whole_buffer_is_one_message() {
        let message = [0x08u8, 0x78, 0x52, 0x24, 0x41, 0x42];

        let decoded = decode_messages(&message).expect("decodes");

        assert_eq!(decoded.len(), 1);
        assert_eq!(&decoded[0][..], &message[..]);
    }

    /// A prefix that promises more than is there is an error rather than a silent drop.
    #[test]
    fn a_length_running_past_the_buffer_is_an_error() {
        assert!(decode_messages(&[0x20, 0x08, 0x01]).is_err());
    }

    /// A maximal varint is refused before it can be added to anything.
    ///
    /// Nine `0xFF` groups then `0x7F` decodes to a value near `u64::MAX`; without the cap,
    /// `consumed + length` panics under debug assertions and wraps in release, which would frame
    /// the rest of the stream against a nonsense offset.
    #[test]
    fn a_maximal_length_prefix_cannot_overflow_the_offset() {
        let hostile = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F];

        let error = super::decode_messages(&hostile).expect_err("a maximal length must be refused");
        assert!(
            error.to_string().contains("exceeds"),
            "the cap must be what rejects it: {error}"
        );
    }

    /// The cap is a real bound, not just an overflow guard.
    #[test]
    fn a_length_above_the_cap_is_refused() {
        let too_long =
            super::write_variant(u64::try_from(super::MAX_MESSAGE_LEN).expect("fits") + 1);

        assert!(super::decode_messages(&too_long).is_err());
    }

    /// Upstream asserts this and swallows the failure; here it is surfaced.
    #[test]
    fn a_message_without_the_type_tag_is_an_error() {
        assert!(decode_messages(&[0x02, 0x09, 0x01]).is_err());
    }

    /// The envelope is exactly two levels: `params` then `data`.
    #[test]
    fn the_envelope_round_trips() {
        let data = vec![0x08u8, 0x2A, 0xFF];

        let encoded = encode_envelope(data.clone()).expect("encodes");

        assert!(encoded.starts_with(b"bplist00"));
        assert_eq!(decode_envelope(&encoded), Some(data));
    }

    /// The envelope's shape is asserted against the decoded plist, not just against itself.
    #[test]
    fn the_envelope_nests_data_under_params() {
        let encoded = encode_envelope(vec![0x08]).expect("encodes");
        let value = crate::rtsp::decode_plist(&encoded).expect("decodes");

        let root = value.as_dictionary().expect("a dictionary");
        assert_eq!(root.keys().collect::<Vec<_>>(), ["params"]);

        let params = root["params"].as_dictionary().expect("a dictionary");
        assert_eq!(params.keys().collect::<Vec<_>>(), ["data"]);
        assert_eq!(params["data"].as_data(), Some(&[0x08u8][..]));
    }

    /// Both shapes upstream tolerates: a non-plist payload and a plist without `params.data`.
    #[test]
    fn an_envelope_without_data_yields_nothing() {
        assert_eq!(decode_envelope(b"not a plist"), None);

        let empty = crate::rtsp::encode_plist(&plist::Value::Dictionary(plist::Dictionary::new()))
            .expect("encodes");
        assert_eq!(decode_envelope(&empty), None);
    }
}
