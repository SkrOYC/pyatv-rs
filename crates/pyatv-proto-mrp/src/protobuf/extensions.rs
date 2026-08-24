//! Typed access to the proto2 extension field inside a `ProtocolMessage`.
//!
//! Every concrete MRP message is a proto2 extension of the `ProtocolMessage` envelope: the sender
//! sets `type` to a [`Type`](super::protocol_message::Type) constant and puts the payload in the
//! extension field that constant designates. pyatv reaches it with
//! `message.Extensions[SendCommandMessage_pb2.sendCommandMessage]`; `prost` has no equivalent,
//! because it neither generates anything for `extend` blocks nor keeps unknown fields around after
//! a decode. The evidence is in `docs/research/mrp-protobuf-spike.md`.
//!
//! So the envelope is handled twice, deliberately:
//!
//! - `prost` decodes [`ProtocolMessage`] for the seven declared fields (`type`, `identifier`,
//!   `errorCode`, …), which is all the transport layer routes on;
//! - the extension payload is read straight off the same serialised bytes by [`wire`](super::wire)
//!   and handed to `prost` as its own message type.
//!
//! One [`MessageExtension`] constant is generated per extension, named after it and typed by the
//! message it carries, so a call site reads much like pyatv's:
//!
//! ```
//! use pyatv_proto_mrp::protobuf::{ProtocolMessage, SendCommandMessage, extensions};
//!
//! # fn main() -> Result<(), pyatv_proto_mrp::Error> {
//! let envelope = ProtocolMessage {
//!     r#type: Some(1), // SEND_COMMAND_MESSAGE
//!     ..ProtocolMessage::default()
//! };
//! let inner = SendCommandMessage {
//!     command: Some(1), // Play
//!     ..SendCommandMessage::default()
//! };
//!
//! let bytes = extensions::SEND_COMMAND_MESSAGE.encode(&envelope, &inner)?;
//! assert_eq!(extensions::SEND_COMMAND_MESSAGE.decode(&bytes)?, Some(inner));
//! # Ok(())
//! # }
//! ```
//!
//! Note that the extension field number is *not* the `Type` value: `SEND_COMMAND_MESSAGE` is type
//! 1 but extension field 6. Use [`number_for_type`] to go from one to the other.

use core::{fmt, marker::PhantomData};

use prost::Message;

use super::{ProtocolMessage, wire};
use crate::{Error, Result};

/// Name and field number of one extension, for enumeration and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionInfo {
    /// Field name as declared in the `.proto`, e.g. `"sendCommandMessage"`.
    pub name: &'static str,
    /// Extension field number.
    pub number: u32,
}

/// A handle on one message-typed extension of `ProtocolMessage`.
///
/// Constructed only by the generated table below; `M` is the message the field carries.
pub struct MessageExtension<M> {
    name: &'static str,
    number: u32,
    // `fn() -> M` rather than `M` so the handle stays `Send`, `Sync` and `Copy` regardless of `M`.
    payload: PhantomData<fn() -> M>,
}

impl<M> MessageExtension<M> {
    /// Declare an extension. Called only by generated code.
    const fn new(name: &'static str, number: u32) -> Self {
        Self {
            name,
            number,
            payload: PhantomData,
        }
    }

    /// The field name as declared in the `.proto`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The extension field number.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }
}

impl<M: Message + Default> MessageExtension<M> {
    /// Decode this extension out of a serialised `ProtocolMessage`.
    ///
    /// Returns `Ok(None)` when the field is absent, which is normal: a device may send a message
    /// type whose payload this client never populates.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] if `envelope` is not a well-formed protobuf message, and
    /// [`Error::Decode`] if the payload is not a valid `M`.
    pub fn decode(&self, envelope: &[u8]) -> Result<Option<M>> {
        let Some(payload) = wire::find_length_delimited(envelope, self.number)? else {
            return Ok(None);
        };

        M::decode(payload)
            .map(Some)
            .map_err(|error| Error::Decode(format!("{}: {error}", self.name)))
    }

    /// Serialise `envelope` with this extension set to `value`.
    ///
    /// Fields come out in ascending tag order, matching the reference implementation byte for
    /// byte; see [`wire::splice_length_delimited`](super::wire::splice_length_delimited).
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] only if `prost` produced a buffer this crate cannot re-scan,
    /// which would be a bug in one of the two.
    pub fn encode(&self, envelope: &ProtocolMessage, value: &M) -> Result<Vec<u8>> {
        wire::splice_length_delimited(
            &envelope.encode_to_vec(),
            self.number,
            &value.encode_to_vec(),
        )
    }
}

impl<M> fmt::Debug for MessageExtension<M> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MessageExtension")
            .field("name", &self.name)
            .field("number", &self.number)
            .finish()
    }
}

/// The corpus' one scalar extension: `optional string getKeyboardSessionMessage = 29`.
///
/// Separate from [`MessageExtension`] because a string is not a `prost::Message`, and because a
/// single concrete type is less machinery than a trait covering both.
#[derive(Debug, Clone, Copy)]
pub struct StringExtension {
    name: &'static str,
    number: u32,
}

impl StringExtension {
    /// Declare an extension. Called only by generated code.
    const fn new(name: &'static str, number: u32) -> Self {
        Self { name, number }
    }

    /// The field name as declared in the `.proto`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        self.name
    }

    /// The extension field number.
    #[must_use]
    pub const fn number(&self) -> u32 {
        self.number
    }

    /// Decode this extension out of a serialised `ProtocolMessage`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] if `envelope` is malformed, and [`Error::Decode`] if the
    /// field is not valid UTF-8.
    pub fn decode(&self, envelope: &[u8]) -> Result<Option<String>> {
        let Some(payload) = wire::find_length_delimited(envelope, self.number)? else {
            return Ok(None);
        };

        core::str::from_utf8(payload)
            .map(|text| Some(text.to_owned()))
            .map_err(|error| Error::Decode(format!("{}: {error}", self.name)))
    }

    /// Serialise `envelope` with this extension set to `value`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::WireFormat`] only if `prost` produced a buffer this crate cannot re-scan.
    pub fn encode(&self, envelope: &ProtocolMessage, value: &str) -> Result<Vec<u8>> {
        wire::splice_length_delimited(&envelope.encode_to_vec(), self.number, value.as_bytes())
    }
}

/// The extension field number carrying the payload for a `ProtocolMessage.Type` value.
///
/// This is pyatv's `_EXTENSION_LOOKUP` (`pyatv/protocols/mrp/protobuf/__init__.py`), derived at
/// build time from the vendored `.proto` files by the same naming rule pyatv's own generator uses.
/// It is not the identity function: type 1 (`SEND_COMMAND_MESSAGE`) maps to field 6, and type 37
/// (`DEVICE_INFO_UPDATE_MESSAGE`) reuses type 15's field 20.
#[must_use]
pub fn number_for_type(message_type: i32) -> Option<u32> {
    TYPE_TO_NUMBER
        .binary_search_by_key(&message_type, |(value, _)| *value)
        .ok()
        .map(|index| TYPE_TO_NUMBER[index].1)
}

/// The raw payload of whichever extension `message_type` designates.
///
/// The generic half of [`MessageExtension::decode`], for a dispatcher that has a type value in
/// hand but not yet a Rust type: pair it with the matching generated constant to decode.
///
/// # Errors
///
/// Returns [`Error::UnhandledMessage`] if no extension is defined for `message_type`, and
/// [`Error::WireFormat`] if `envelope` is malformed.
pub fn raw_for_type(envelope: &[u8], message_type: i32) -> Result<Option<&[u8]>> {
    let number = number_for_type(message_type).ok_or(Error::UnhandledMessage(message_type))?;
    wire::find_length_delimited(envelope, number)
}

include!(concat!(env!("OUT_DIR"), "/mrp_extensions.rs"));

#[cfg(test)]
mod tests {
    use super::{ALL, number_for_type, raw_for_type};

    /// The vendored corpus declares 55 extensions of `ProtocolMessage`; a refresh that changes
    /// that count is a real event and should be looked at, not absorbed silently.
    #[test]
    fn every_extension_is_generated() {
        assert_eq!(ALL.len(), 55);
        assert!(ALL.iter().all(|info| info.number >= 6));
    }

    #[test]
    fn extension_numbers_are_unique_and_ordered() {
        let numbers: Vec<u32> = ALL.iter().map(|info| info.number).collect();
        let mut sorted = numbers.clone();
        sorted.sort_unstable();
        sorted.dedup();

        assert_eq!(numbers, sorted);
    }

    /// Spot-checks against pyatv's `_EXTENSION_LOOKUP`, including the two cases where the mapping
    /// is not the identity and the one where two types share a field.
    #[test]
    fn type_maps_to_the_extension_pyatv_uses() {
        assert_eq!(number_for_type(1), Some(6)); // SEND_COMMAND_MESSAGE
        assert_eq!(number_for_type(4), Some(9)); // SET_STATE_MESSAGE
        assert_eq!(number_for_type(6), Some(11)); // REGISTER_HID_DEVICE_MESSAGE
        assert_eq!(number_for_type(15), Some(20)); // DEVICE_INFO_MESSAGE
        assert_eq!(number_for_type(37), Some(20)); // DEVICE_INFO_UPDATE_MESSAGE, reused
        assert_eq!(number_for_type(34), Some(39)); // CRYPTO_PAIRING_MESSAGE
        assert_eq!(number_for_type(120), Some(94)); // CONFIGURE_CONNECTION_MESSAGE
    }

    /// pyatv's generator looks for `<MessageName>.proto` and so misses `updatePlayerMessage`,
    /// which lives in `UpdatePlayerPath.proto`; keying off the extension itself recovers it.
    /// Documented divergence, not an accident.
    #[test]
    fn update_player_message_is_mapped_where_pyatv_leaves_a_hole() {
        assert_eq!(number_for_type(58), Some(62));
    }

    #[test]
    fn types_without_an_extension_are_reported() {
        // UNKNOWN_MESSAGE and GET_STATE_MESSAGE have no inner message.
        assert_eq!(number_for_type(0), None);
        assert_eq!(number_for_type(3), None);
        assert!(raw_for_type(&[], 3).is_err());
    }
}
