//! One MRP message: the `ProtocolMessage` envelope *and* the extension payload nested inside it.
//!
//! `prost` models the envelope's seven declared fields and nothing else — it neither generates
//! code for proto2 `extend` blocks nor keeps unknown fields after a decode
//! (`docs/research/mrp-protobuf-spike.md`). A bare
//! [`ProtocolMessage`](crate::protobuf::ProtocolMessage) is therefore *lossy*: round-tripping one
//! through `prost` silently drops whatever concrete message it was carrying.
//!
//! So the unit that travels across [`crate::transport::MrpTransport`] is this type, which holds the
//! decoded envelope next to the serialised bytes the extension actually lives in. That is a
//! deliberate divergence from pyatv, where `protobuf.ProtocolMessage` is one object with working
//! extension accessors and the transport can pass it around directly
//! (`pyatv/protocols/mrp/connection.py:114-125`).

use bytes::Bytes;

use crate::protobuf::{Message as _, ProtocolMessage, extensions, protocol_message, wire};
use crate::{Error, Result};

/// A complete MRP message, envelope plus extension payload.
///
/// Cheap to clone: the serialised form is a [`Bytes`] and the envelope is seven small fields.
#[derive(Debug, Clone, PartialEq)]
pub struct MrpMessage {
    envelope: ProtocolMessage,
    encoded: Bytes,
}

impl MrpMessage {
    /// Build a message with no extension payload — a bare envelope.
    ///
    /// `messages.create(message_type)` with nothing added afterwards
    /// (`pyatv/protocols/mrp/messages.py:13-21`), e.g. `GENERIC_MESSAGE` heartbeats and
    /// `GET_KEYBOARD_SESSION_MESSAGE`.
    #[must_use]
    pub fn bare(envelope: ProtocolMessage) -> Self {
        let encoded = Bytes::from(envelope.encode_to_vec());
        Self { envelope, encoded }
    }

    /// Build a message carrying `inner` in the extension `extension` designates.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] only if `prost` produced an envelope this crate cannot
    /// re-scan, which would be a bug in one of the two.
    pub fn with_extension<M: prost::Message + Default>(
        envelope: ProtocolMessage,
        extension: &extensions::MessageExtension<M>,
        inner: &M,
    ) -> Result<Self> {
        let encoded = extension.encode(&envelope, inner)?;
        Ok(Self {
            envelope,
            encoded: Bytes::from(encoded),
        })
    }

    /// Parse bytes that arrived off a transport.
    ///
    /// The bytes are kept verbatim so the extension can be extracted later without re-encoding;
    /// only the envelope is decoded eagerly, which is all the transport and correlation layers
    /// route on (`protocol.py:283-294`).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] if `bytes` is not a well-formed `ProtocolMessage`.
    pub fn decode(bytes: Bytes) -> Result<Self> {
        let envelope = ProtocolMessage::decode(bytes.as_ref())
            .map_err(|error| Error::Decode(format!("ProtocolMessage: {error}")))?;
        Ok(Self {
            envelope,
            encoded: bytes,
        })
    }

    /// The serialised message, exactly as it goes on (or came off) the wire.
    #[must_use]
    pub fn bytes(&self) -> &Bytes {
        &self.encoded
    }

    /// The decoded envelope.
    #[must_use]
    pub fn envelope(&self) -> &ProtocolMessage {
        &self.envelope
    }

    /// `ProtocolMessage.type`, or `0` (`UNKNOWN_MESSAGE`) when the field is absent.
    #[must_use]
    pub fn message_type(&self) -> i32 {
        self.envelope.r#type.unwrap_or_default()
    }

    /// [`MrpMessage::message_type`] as the generated enum, when it names a known type.
    #[must_use]
    pub fn message_type_enum(&self) -> Option<protocol_message::Type> {
        protocol_message::Type::try_from(self.message_type()).ok()
    }

    /// `ProtocolMessage.identifier`, the request/response correlation key.
    #[must_use]
    pub fn identifier(&self) -> Option<&str> {
        self.envelope.identifier.as_deref()
    }

    /// `ProtocolMessage.errorCode`, or `0` when absent.
    #[must_use]
    pub fn error_code(&self) -> i32 {
        self.envelope.error_code.unwrap_or_default()
    }

    /// `ProtocolMessage.uniqueIdentifier`, the per-message UUID `create()` stamps on everything.
    #[must_use]
    pub fn unique_identifier(&self) -> Option<&str> {
        self.envelope.unique_identifier.as_deref()
    }

    /// Stamp `identifier` on the envelope and re-serialise.
    ///
    /// `send_and_receive` sets this on every request unless `generate_identifier=False`
    /// (`protocol.py:248-252`). Re-serialising rather than patching in place keeps field order
    /// ascending, which is what makes the output byte-identical to the reference implementation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] if the current bytes cannot be re-scanned.
    pub fn set_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        self.envelope.identifier = Some(identifier.into());
        self.rebuild()
    }

    /// Replace `ProtocolMessage.uniqueIdentifier` and re-serialise.
    ///
    /// Upstream has no equivalent — `create()` is the only writer and it always picks a fresh
    /// UUID4 (`messages.py:18`). This exists so a test can pin the one random field in an
    /// otherwise deterministic message and compare the bytes against a captured reference.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] if the current bytes cannot be re-scanned.
    pub fn set_unique_identifier(&mut self, identifier: impl Into<String>) -> Result<()> {
        self.envelope.unique_identifier = Some(identifier.into());
        self.rebuild()
    }

    /// The correlation key `send_and_receive`/`message_received` use.
    ///
    /// `identifier or "type_" + str(message.type)` (`protocol.py:257,285`). The synthetic
    /// type-keyed form exists for `CryptoPairingMessage`, whose responses never echo an
    /// identifier back.
    #[must_use]
    pub fn correlation_key(&self) -> String {
        self.identifier()
            .map_or_else(|| format!("type_{}", self.message_type()), str::to_owned)
    }

    /// Fail if the envelope reports a non-zero `errorCode`.
    ///
    /// Upstream never inspects the field on an inbound message, so this is **not** applied to every
    /// exchange — doing that would reject responses pyatv accepts. It is applied where a silent
    /// failure would be worst: the `CryptoPairingMessage` exchanges, where carrying on produces a
    /// session whose first encrypted frame is garbage.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ErrorCode`] when the field is set and non-zero.
    pub fn check_error_code(&self) -> Result<()> {
        match self.error_code() {
            0 => Ok(()),
            code => Err(Error::ErrorCode {
                code,
                message_type: self.message_type(),
            }),
        }
    }

    /// The extension payload as raw bytes, if this message type has one and it is present.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnhandledMessage`] if no extension is defined for this message type, and
    /// [`Error::WireFormat`] if the bytes are malformed.
    pub fn raw_inner(&self) -> Result<Option<&[u8]>> {
        extensions::raw_for_type(&self.encoded, self.message_type())
    }

    /// Decode the extension `extension` designates out of this message.
    ///
    /// Returns `Ok(None)` when the field is absent, which is normal for a message type whose
    /// payload the peer never populated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decode`] if the payload is not a valid `M`.
    pub fn extension<M: prost::Message + Default>(
        &self,
        extension: &extensions::MessageExtension<M>,
    ) -> Result<Option<M>> {
        extension.decode(&self.encoded)
    }

    /// Decode the extension, treating an absent payload as the message's zero value.
    ///
    /// pyatv's `extract_inner` always yields a message object — proto2 synthesises an empty
    /// submessage on access — so every read site upstream can assume one exists
    /// (`pyatv/protocols/mrp/protobuf/__init__.py`). This is that behaviour.
    ///
    /// # Errors
    ///
    /// As [`MrpMessage::extension`].
    pub fn inner<M: prost::Message + Default>(
        &self,
        extension: &extensions::MessageExtension<M>,
    ) -> Result<M> {
        Ok(self.extension(extension)?.unwrap_or_default())
    }

    /// Re-serialise after an envelope field changed, preserving the extension payload.
    fn rebuild(&mut self) -> Result<()> {
        let inner = match extensions::number_for_type(self.message_type()) {
            Some(number) => wire::find_length_delimited(&self.encoded, number)?
                .map(|payload| (number, payload.to_vec())),
            None => None,
        };

        let base = self.envelope.encode_to_vec();
        self.encoded = match inner {
            Some((number, payload)) => {
                Bytes::from(wire::splice_length_delimited(&base, number, &payload)?)
            }
            None => Bytes::from(base),
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MrpMessage;
    use crate::messages;
    use crate::protobuf::{extensions, protocol_message::Type};

    #[test]
    fn an_extension_survives_a_late_identifier_stamp() {
        let mut message = messages::set_connection_state().unwrap();
        let before = message
            .extension(&extensions::SET_CONNECTION_STATE_MESSAGE)
            .unwrap();

        message.set_identifier("ABC").unwrap();

        assert_eq!(message.identifier(), Some("ABC"));
        assert_eq!(
            message
                .extension(&extensions::SET_CONNECTION_STATE_MESSAGE)
                .unwrap(),
            before
        );
    }

    #[test]
    fn a_stamped_message_round_trips_through_the_wire_form() {
        let mut message = messages::client_updates_config().unwrap();
        message.set_identifier("ID").unwrap();

        let decoded = MrpMessage::decode(message.bytes().clone()).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.correlation_key(), "ID");
    }

    #[test]
    fn an_unidentified_message_correlates_by_type() {
        let message = messages::crypto_pairing(&[], false).unwrap();
        assert_eq!(
            message.correlation_key(),
            format!("type_{}", Type::CryptoPairingMessage as i32)
        );
    }
}
