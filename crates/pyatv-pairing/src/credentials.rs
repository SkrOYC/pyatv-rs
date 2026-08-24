//! Persisted credentials and their string format.
//!
//! `docs/research/crypto-pairing.md` §7 documents pyatv's on-disk format, which this port
//! replicates byte-for-byte so users can migrate an existing `pyatv` credential export. pyatv
//! distinguishes its four authentication types by inspecting which fields of one `HapCredentials`
//! struct happen to be empty, and marks transient pairing with the literal ASCII bytes
//! `"transient"` sitting in the `ltpk` slot. **Both of those are reproduced exactly** — the
//! sentinel really does live in `ltpk` (see [`HapCredentials::transient`]), because it is part of
//! the on-disk format and a credential written by either implementation has to be readable by the
//! other. What this port adds on top is [`AuthenticationType`] as a real enum plus a *fallible*
//! classifier, [`HapCredentials::try_authentication_type`], so the field combinations pyatv rejects
//! outright are distinguishable from the four it accepts.
//!
//! The field naming is confusing upstream and is kept for interop: `ltsk` is the *controller's*
//! long-term secret key while `ltpk` is the *device's* long-term public key, despite both reading
//! as if they belonged to the same party.

use crate::{Error, Result};

/// Which pairing generation a credential belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthenticationType {
    /// No credentials; the service needs none or has not been paired.
    Null,
    /// Pre-HAP AirPlay device authentication.
    Legacy,
    /// HAP pair-setup/pair-verify, used by MRP, Companion and modern AirPlay.
    Hap,
    /// Ephemeral HAP pairing with nothing persisted.
    Transient,
}

/// The sentinel pyatv stores in the `ltpk` slot to mark transient credentials.
const TRANSIENT_SENTINEL: &[u8] = b"transient";

/// Render one field's occupancy for the classifier's error message, without leaking its bytes.
fn populated(field: &[u8]) -> &'static str {
    if field.is_empty() { "empty" } else { "set" }
}

/// Credentials for one paired service.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct HapCredentials {
    /// The device's long-term Ed25519 public key.
    pub ltpk: Vec<u8>,
    /// The controller's long-term Ed25519 secret key, stored as its raw 32-byte seed.
    pub ltsk: Vec<u8>,
    /// The device's pairing identifier.
    pub atv_id: Vec<u8>,
    /// The controller's pairing identifier.
    pub client_id: Vec<u8>,
}

// Hand-written so a `Debug` print of a config can never leak the secret key. `ltsk` is the one
// field an attacker needs; the rest are public or identifiers.
impl std::fmt::Debug for HapCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HapCredentials")
            .field("ltpk", &hex::encode(&self.ltpk))
            .field("ltsk", &"<redacted>")
            .field("atv_id", &hex::encode(&self.atv_id))
            .field("client_id", &hex::encode(&self.client_id))
            .field("type", &self.authentication_type())
            .finish()
    }
}

impl HapCredentials {
    /// Credentials meaning "not paired".
    #[must_use]
    pub fn null() -> Self {
        Self::default()
    }

    /// The transient marker, for ephemeral AirPlay pairing that persists nothing.
    #[must_use]
    pub fn transient() -> Self {
        Self {
            ltpk: TRANSIENT_SENTINEL.to_vec(),
            ..Self::default()
        }
    }

    /// Classify these credentials by which fields are populated, matching pyatv's rules.
    ///
    /// This is `HapCredentials._get_auth_type` (`pyatv/auth/hap_pairing.py:47-70`) branch for
    /// branch, including its **fifth** branch: a combination that matches none of the four named
    /// types raises `InvalidCredentialsError` upstream rather than being coerced into the closest
    /// one. The two shapes that reach it in practice are `("", "", atv_id, client_id)` — a HAP
    /// credential that lost its keys — and `(ltpk, "", "", "")` — a device public key with nothing
    /// to pair it to. Both are corrupt storage, not a pairing generation.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCredentials`] for any other combination of populated fields.
    pub fn try_authentication_type(&self) -> Result<AuthenticationType> {
        // pyatv tests all-empty *before* the sentinel; the order is irrelevant because the
        // sentinel makes `ltpk` non-empty, but it is kept for a line-by-line reading.
        if self.ltpk.is_empty()
            && self.ltsk.is_empty()
            && self.atv_id.is_empty()
            && self.client_id.is_empty()
        {
            return Ok(AuthenticationType::Null);
        }
        if self.ltpk == TRANSIENT_SENTINEL {
            return Ok(AuthenticationType::Transient);
        }
        if self.ltpk.is_empty()
            && !self.ltsk.is_empty()
            && self.atv_id.is_empty()
            && !self.client_id.is_empty()
        {
            return Ok(AuthenticationType::Legacy);
        }
        if !self.ltpk.is_empty()
            && !self.ltsk.is_empty()
            && !self.atv_id.is_empty()
            && !self.client_id.is_empty()
        {
            return Ok(AuthenticationType::Hap);
        }

        Err(Error::InvalidCredentials(format!(
            "no authentication type has this shape: ltpk {}, ltsk {}, atv_id {}, client_id {}",
            populated(&self.ltpk),
            populated(&self.ltsk),
            populated(&self.atv_id),
            populated(&self.client_id),
        )))
    }

    /// Classify these credentials, treating a shape pyatv rejects as "not paired".
    ///
    /// The infallible convenience form of [`HapCredentials::try_authentication_type`], for the call
    /// sites that only want to pick a procedure. **A malformed combination reports
    /// [`AuthenticationType::Null`]**, which is the conservative answer — it selects the
    /// pass-through procedure rather than feeding half a credential into a real handshake. Use
    /// [`HapCredentials::try_authentication_type`] where the difference between "nothing stored"
    /// and "storage is corrupt" is worth reporting to the user.
    #[must_use]
    pub fn authentication_type(&self) -> AuthenticationType {
        self.try_authentication_type()
            .unwrap_or(AuthenticationType::Null)
    }

    /// Parse pyatv's colon-separated lowercase-hex credential string.
    ///
    /// Two shapes exist: four fields for [`AuthenticationType::Hap`]
    /// (`ltpk:ltsk:atv_id:client_id`) and two for [`AuthenticationType::Legacy`]
    /// (`client_id:ltsk`) — note the reversed field order in the short form.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidCredentials`] if the field count is neither two nor four, or if any
    /// field is not valid hex.
    pub fn parse(input: &str) -> Result<Self> {
        let fields: Vec<&str> = input.split(':').collect();
        let decode = |field: &str| {
            hex::decode(field).map_err(|error| {
                Error::InvalidCredentials(format!("field is not valid hex: {error}"))
            })
        };

        match fields.as_slice() {
            [device_public, controller_secret, device_id, controller_id] => Ok(Self {
                ltpk: decode(device_public)?,
                ltsk: decode(controller_secret)?,
                atv_id: decode(device_id)?,
                client_id: decode(controller_id)?,
            }),
            [controller_id, controller_secret] => Ok(Self {
                ltpk: Vec::new(),
                ltsk: decode(controller_secret)?,
                atv_id: Vec::new(),
                client_id: decode(controller_id)?,
            }),
            other => Err(Error::InvalidCredentials(format!(
                "expected 2 or 4 colon-separated fields, got {}",
                other.len()
            ))),
        }
    }
}

impl std::fmt::Display for HapCredentials {
    /// Render back into pyatv's credential string: always four colon-separated hex fields.
    ///
    /// The two-field form is **parse-only**. `HapCredentials.__str__`
    /// (`pyatv/auth/hap_pairing.py:77-86`) unconditionally joins all four fields regardless of
    /// authentication type, so a legacy credential comes back out as `":ltsk::client_id"` with two
    /// empty segments rather than in the compact form it may have been read from
    /// (`docs/research/hap-pairing-port-spec.md` §3.2 corrects the earlier research report on
    /// this). Parsing a two-field string and re-rendering it is therefore lossy in format but not
    /// in data — replicated exactly, because config files written by either implementation have to
    /// be readable by the other.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}:{}:{}:{}",
            hex::encode(&self.ltpk),
            hex::encode(&self.ltsk),
            hex::encode(&self.atv_id),
            hex::encode(&self.client_id)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthenticationType, HapCredentials};

    #[test]
    fn empty_credentials_are_null() {
        assert_eq!(
            HapCredentials::null().authentication_type(),
            AuthenticationType::Null
        );
    }

    #[test]
    fn transient_sentinel_is_recognised() {
        assert_eq!(
            HapCredentials::transient().authentication_type(),
            AuthenticationType::Transient
        );
    }

    #[test]
    fn four_field_strings_round_trip_as_hap() {
        let input = "aabb:ccdd:eeff:0011";
        let credentials = HapCredentials::parse(input).unwrap();

        assert_eq!(credentials.authentication_type(), AuthenticationType::Hap);
        assert_eq!(credentials.ltpk, vec![0xAA, 0xBB]);
        assert_eq!(credentials.ltsk, vec![0xCC, 0xDD]);
        assert_eq!(credentials.atv_id, vec![0xEE, 0xFF]);
        assert_eq!(credentials.client_id, vec![0x00, 0x11]);
        assert_eq!(credentials.to_string(), input);
    }

    /// The two-field form reverses the order: `client_id` first, then `ltsk`. It is accepted on
    /// input and never produced on output, so the round trip is lossy in format but not in data —
    /// exactly as in pyatv, see the `Display` documentation.
    #[test]
    fn two_field_strings_parse_as_legacy_and_reformat_as_four_fields() {
        let input = "0011223344556677:aabbcc";
        let credentials = HapCredentials::parse(input).unwrap();

        assert_eq!(
            credentials.authentication_type(),
            AuthenticationType::Legacy
        );
        assert_eq!(
            credentials.client_id,
            vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]
        );
        assert_eq!(credentials.ltsk, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(credentials.to_string(), ":aabbcc::0011223344556677");
        assert_eq!(
            HapCredentials::parse(&credentials.to_string()).unwrap(),
            credentials
        );
    }

    /// `NO_CREDENTIALS` renders as four empty fields, i.e. three colons
    /// (`pyatv/auth/hap_pairing.py:123`).
    #[test]
    fn null_credentials_render_as_three_colons() {
        assert_eq!(HapCredentials::null().to_string(), ":::");
    }

    /// pyatv's fifth branch: these two shapes raise `InvalidCredentialsError` rather than being
    /// classified (`pyatv/auth/hap_pairing.py:47-70`). The infallible accessor has to answer `Null`
    /// for them, which is the shape that selects the pass-through procedure.
    #[test]
    fn shapes_pyatv_rejects_are_errors_and_read_as_null() {
        let cases = [
            // A HAP credential that lost both keys.
            HapCredentials {
                ltpk: Vec::new(),
                ltsk: Vec::new(),
                atv_id: b"atv".to_vec(),
                client_id: b"client".to_vec(),
            },
            // A device public key with nothing to pair it to.
            HapCredentials {
                ltpk: vec![0xAA; 32],
                ltsk: Vec::new(),
                atv_id: Vec::new(),
                client_id: Vec::new(),
            },
            // Legacy shape missing its client identifier.
            HapCredentials {
                ltpk: Vec::new(),
                ltsk: vec![0xBB; 32],
                atv_id: Vec::new(),
                client_id: Vec::new(),
            },
            // HAP shape missing the accessory identifier.
            HapCredentials {
                ltpk: vec![0xAA; 32],
                ltsk: vec![0xBB; 32],
                atv_id: Vec::new(),
                client_id: b"client".to_vec(),
            },
        ];

        for case in cases {
            assert!(
                case.try_authentication_type().is_err(),
                "{case:?} should have no authentication type"
            );
            assert_eq!(case.authentication_type(), AuthenticationType::Null);
        }
    }

    /// The four shapes pyatv does accept must classify without an error.
    #[test]
    fn the_four_accepted_shapes_classify() {
        assert_eq!(
            HapCredentials::null().try_authentication_type().unwrap(),
            AuthenticationType::Null
        );
        assert_eq!(
            HapCredentials::transient()
                .try_authentication_type()
                .unwrap(),
            AuthenticationType::Transient
        );
        assert_eq!(
            HapCredentials::parse("0011223344556677:aabbcc")
                .unwrap()
                .try_authentication_type()
                .unwrap(),
            AuthenticationType::Legacy
        );
        assert_eq!(
            HapCredentials::parse("aabb:ccdd:eeff:0011")
                .unwrap()
                .try_authentication_type()
                .unwrap(),
            AuthenticationType::Hap
        );
    }

    /// The classifier's error message describes occupancy only; it must never echo key bytes.
    #[test]
    fn the_classifier_error_does_not_leak_key_material() {
        let credentials = HapCredentials {
            ltpk: vec![0xAA; 32],
            ltsk: Vec::new(),
            atv_id: Vec::new(),
            client_id: Vec::new(),
        };

        let message = credentials
            .try_authentication_type()
            .unwrap_err()
            .to_string();
        assert!(!message.contains(&hex::encode([0xAAu8; 32])));
        assert!(message.contains("ltsk empty"));
    }

    #[test]
    fn wrong_field_counts_are_rejected() {
        assert!(HapCredentials::parse("aabb").is_err());
        assert!(HapCredentials::parse("aa:bb:cc").is_err());
        assert!(HapCredentials::parse("nothex:aabb").is_err());
    }

    /// A `Debug` print must not expose the controller's secret key.
    #[test]
    fn debug_redacts_the_secret_key() {
        let credentials = HapCredentials::parse("aabb:ccdd:eeff:0011").unwrap();
        let rendered = format!("{credentials:?}");

        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ccdd"));
    }
}
