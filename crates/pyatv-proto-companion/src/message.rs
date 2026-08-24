//! The Companion message envelope: `_i`, `_t`, `_x`, `_c` and the three error keys.
//!
//! Port of the dict shapes in `pyatv/protocols/companion/protocol.py:143-176` and
//! `api.py:161-186`, cross-checked against the reference device's `send_response`/`send_event`/
//! `send_error` (`tests/fake_device/companion.py:309-344`). The full key table is
//! `docs/research/companion-port-spec.md` §2.1.
//!
//! Only OPACK frames (`U_OPACK`, `E_OPACK`, `P_OPACK`) carry this envelope. Pairing frames carry a
//! completely different, flat dict keyed by `_pd`/`_pwTy`/`_auTy` — see [`crate::auth`] — and the
//! two are never mixed.

use pyatv_opack::Value;

use crate::{Error, Result};

/// Identifier: the command name on a request, echoed verbatim on its response, or the event name.
pub const KEY_IDENTIFIER: &str = "_i";
/// Message type, one of [`MessageType`].
pub const KEY_TYPE: &str = "_t";
/// Transaction identifier, correlating a response with its request.
pub const KEY_XID: &str = "_x";
/// Content: the command's arguments, or the response's result.
pub const KEY_CONTENT: &str = "_c";
/// Error message. Its **presence** is how a failed response is detected (`protocol.py:173-174`).
pub const KEY_ERROR_MESSAGE: &str = "_em";
/// Error code. The device sends it; pyatv's client never reads it.
pub const KEY_ERROR_CODE: &str = "_ec";
/// Error domain, e.g. `RPErrorDomain`. The device sends it; pyatv's client never reads it.
pub const KEY_ERROR_DOMAIN: &str = "_ed";

/// What a message is for (`protocol.py:54-59`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// An unsolicited push from the device, or a fire-and-forget send from the client.
    Event = 1,
    /// A command awaiting a response.
    Request = 2,
    /// The answer to a request, carrying the same `_x`.
    Response = 3,
}

impl MessageType {
    /// The integer that appears under `_t`.
    #[must_use]
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// Map an on-wire `_t` value.
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Event),
            2 => Some(Self::Request),
            3 => Some(Self::Response),
            _ => None,
        }
    }
}

/// The `_em`/`_ec`/`_ed` triple from a failed response.
///
/// pyatv raises on `_em` alone and drops the other two on the floor. They are kept here because a
/// device that says *why* it refused should not have that discarded on the way to the user; the
/// detection rule is still `_em`'s presence, exactly as upstream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandError {
    /// `_em`, the human-readable message.
    pub message: String,
    /// `_ec`, the numeric code, if present.
    pub code: Option<u64>,
    /// `_ed`, the error domain, if present.
    pub domain: Option<String>,
}

/// One decoded OPACK message.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
    /// `_i`. Absent on malformed messages, and pyatv tolerates that everywhere but the event path.
    pub identifier: Option<String>,
    /// `_t`. `None` when the device sent a value outside [`MessageType`].
    pub message_type: Option<MessageType>,
    /// `_x`, the correlation identifier.
    pub xid: Option<u32>,
    /// `_c`, defaulting to an empty dict when the device omits it.
    pub content: Value,
    /// The error triple, if the device reported one.
    pub error: Option<CommandError>,
}

impl Envelope {
    /// Build a request. The `_x` is added later, by the protocol layer that owns the counter.
    #[must_use]
    pub fn request(identifier: impl Into<String>, content: Value) -> Self {
        Self::outgoing(identifier, MessageType::Request, content)
    }

    /// Build an event, which the client sends fire-and-forget.
    #[must_use]
    pub fn event(identifier: impl Into<String>, content: Value) -> Self {
        Self::outgoing(identifier, MessageType::Event, content)
    }

    fn outgoing(identifier: impl Into<String>, message_type: MessageType, content: Value) -> Self {
        Self {
            identifier: Some(identifier.into()),
            message_type: Some(message_type),
            xid: None,
            content,
            error: None,
        }
    }

    /// Serialise to the OPACK dict that goes on the wire.
    ///
    /// The key order is `_i`, `_t`, `_c` — the literal order of `_send_command`'s dict
    /// (`api.py:176-180`) — with `_x` appended afterwards if set, because upstream's
    /// `send_opack` stamps it on last (`protocol.py:181-183`). Order is not cosmetic: OPACK's
    /// back-reference table indexes values by first appearance, so two orderings of the same dict
    /// are different byte strings.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = Vec::with_capacity(4);
        if let Some(identifier) = &self.identifier {
            entries.push((
                Value::from(KEY_IDENTIFIER),
                Value::from(identifier.as_str()),
            ));
        }
        if let Some(message_type) = self.message_type {
            entries.push((Value::from(KEY_TYPE), Value::from(message_type.code())));
        }
        entries.push((Value::from(KEY_CONTENT), self.content.clone()));
        if let Some(xid) = self.xid {
            entries.push((Value::from(KEY_XID), Value::from(xid)));
        }
        Value::Dict(entries)
    }

    /// Read an inbound OPACK dict.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Envelope`] if the value is not a dict at all — the one shape pyatv also
    /// refuses (`protocol.py:168-171,196-198`). Every individual key is optional, matching
    /// upstream's `.get()`-based reads, so a device that omits `_c` or sends an unknown `_t`
    /// produces an envelope rather than an error.
    pub fn from_value(value: &Value) -> Result<Self> {
        if value.as_dict().is_none() {
            return Err(Error::Envelope(format!(
                "expected a dict at the top level, got {value:?}"
            )));
        }

        let error = value.get(KEY_ERROR_MESSAGE).map(|message| CommandError {
            // `_em`'s presence is the failure signal; a non-string value still means failure.
            message: message
                .as_str()
                .map_or_else(|| format!("{message:?}"), ToOwned::to_owned),
            code: value.get(KEY_ERROR_CODE).and_then(Value::as_u64),
            domain: value
                .get(KEY_ERROR_DOMAIN)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
        });

        Ok(Self {
            identifier: value
                .get(KEY_IDENTIFIER)
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            message_type: value
                .get(KEY_TYPE)
                .and_then(Value::as_u64)
                .and_then(MessageType::from_code),
            xid: value
                .get(KEY_XID)
                .and_then(Value::as_u64)
                .and_then(|xid| u32::try_from(xid).ok()),
            content: value
                .get(KEY_CONTENT)
                .cloned()
                .unwrap_or(Value::Dict(vec![])),
            error,
        })
    }

    /// Turn a failed response into an [`Error::Rejected`], or hand back the envelope.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Rejected`] when `_em` was present.
    pub fn into_result(self) -> Result<Self> {
        match self.error {
            None => Ok(self),
            Some(error) => Err(Error::Rejected {
                command: self.identifier.unwrap_or_else(|| "<unnamed>".to_owned()),
                reason: error.message,
                code: error.code,
                domain: error.domain,
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Envelope, MessageType};
    use pyatv_opack::{Value, opack};

    #[test]
    fn message_type_codes_match_upstream() {
        assert_eq!(MessageType::Event.code(), 1);
        assert_eq!(MessageType::Request.code(), 2);
        assert_eq!(MessageType::Response.code(), 3);
        assert_eq!(MessageType::from_code(2), Some(MessageType::Request));
        assert_eq!(MessageType::from_code(0), None);
        assert_eq!(MessageType::from_code(4), None);
    }

    /// The wire order is `_i`, `_t`, `_c`, `_x`: the dict literal upstream builds, then the XID
    /// stamped on afterwards. OPACK dedupes by first appearance, so this order is part of the
    /// format.
    #[test]
    fn a_request_serialises_in_upstreams_key_order() {
        let mut envelope = Envelope::request("_systemInfo", opack! { "_bf" => 0u64 });
        envelope.xid = Some(7);

        let Value::Dict(entries) = envelope.to_value() else {
            panic!("an envelope must serialise to a dict");
        };
        let keys: Vec<&str> = entries.iter().filter_map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys, ["_i", "_t", "_c", "_x"]);
    }

    #[test]
    fn an_envelope_without_an_xid_omits_the_key() {
        let value = Envelope::event("_interest", opack! {}).to_value();
        assert!(value.get("_x").is_none());
        assert_eq!(value.get("_t").and_then(Value::as_u64), Some(1));
    }

    #[test]
    fn a_response_round_trips_through_a_value() {
        let wire = opack! {
            "_i" => "_sessionStart",
            "_x" => 42u64,
            "_t" => 3u64,
            "_c" => opack! { "_sid" => 5555u64 },
        };

        let envelope = Envelope::from_value(&wire).unwrap();
        assert_eq!(envelope.identifier.as_deref(), Some("_sessionStart"));
        assert_eq!(envelope.message_type, Some(MessageType::Response));
        assert_eq!(envelope.xid, Some(42));
        assert_eq!(
            envelope.content.get("_sid").and_then(Value::as_u64),
            Some(5555)
        );
        assert!(envelope.error.is_none());
    }

    /// Everything but the top-level dict is optional; upstream reads every key with `.get()`.
    #[test]
    fn missing_keys_decode_to_none_rather_than_failing() {
        let envelope = Envelope::from_value(&opack! {}).unwrap();
        assert_eq!(envelope.identifier, None);
        assert_eq!(envelope.message_type, None);
        assert_eq!(envelope.xid, None);
        assert_eq!(envelope.content, Value::Dict(vec![]));
    }

    #[test]
    fn a_non_dict_is_refused() {
        assert!(Envelope::from_value(&Value::from("not a dict")).is_err());
    }

    /// An out-of-range `_t` is reported as "unknown", not coerced — pyatv logs and drops such a
    /// frame (`protocol.py:233-234`).
    #[test]
    fn an_unknown_message_type_decodes_to_none() {
        let envelope = Envelope::from_value(&opack! { "_t" => 9u64 }).unwrap();
        assert_eq!(envelope.message_type, None);
    }

    /// The error triple the reference device sends (`fake_device/companion.py:331-344`).
    #[test]
    fn an_error_response_surfaces_all_three_keys() {
        let wire = opack! {
            "_i" => "_launchApp",
            "_x" => 3u64,
            "_t" => 3u64,
            "_ec" => 58822u64,
            "_ed" => "RPErrorDomain",
            "_em" => "No request handler",
        };

        let envelope = Envelope::from_value(&wire).unwrap();
        let error = envelope.error.clone().expect("_em must be detected");
        assert_eq!(error.message, "No request handler");
        assert_eq!(error.code, Some(58822));
        assert_eq!(error.domain.as_deref(), Some("RPErrorDomain"));

        match envelope.into_result() {
            Err(crate::Error::Rejected {
                command,
                reason,
                code,
                domain,
            }) => {
                assert_eq!(command, "_launchApp");
                assert_eq!(reason, "No request handler");
                assert_eq!(code, Some(58822));
                assert_eq!(domain.as_deref(), Some("RPErrorDomain"));
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// `_em` alone is enough: pyatv checks presence, not the other two keys.
    #[test]
    fn an_error_message_without_a_code_still_fails() {
        let wire = opack! { "_i" => "_x", "_em" => "nope" };
        let envelope = Envelope::from_value(&wire).unwrap();
        assert!(envelope.error.is_some());
        assert!(envelope.into_result().is_err());
    }

    #[test]
    fn a_successful_response_passes_through_into_result() {
        let wire = opack! { "_i" => "_systemInfo", "_t" => 3u64, "_x" => 1u64 };
        let envelope = Envelope::from_value(&wire).unwrap().into_result().unwrap();
        assert_eq!(envelope.identifier.as_deref(), Some("_systemInfo"));
    }
}
