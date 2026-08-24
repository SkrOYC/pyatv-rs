//! Sans-io HAP pair-setup and pair-verify state machines.
//!
//! Each type here consumes the TLV8 body of one inbound message and produces the TLV8 body of the
//! next outbound one. Nothing in this module knows how those bodies reach the device: MRP wraps
//! them in a `CryptoPairingMessage` protobuf, Companion in an OPACK dict under the `_pd` key, and
//! AirPlay posts them as an HTTP body. That split follows pyatv, where `hap_srp.py` is transport-
//! agnostic and each `protocols/*/auth.py` only does framing.
//!
//! Ported from `pyatv/auth/hap_srp.py`, `pyatv/auth/hap_pairing.py` and the three
//! `pyatv/protocols/*/auth.py` drivers. `docs/research/hap-pairing-port-spec.md` is the byte-level
//! reference; every rule below cites the Python line it comes from.
//!
//! # Deliberate divergences from pyatv
//!
//! pyatv's controller performs almost no validation during pairing: its own research notes call
//! this out as the single most important decision a port has to make
//! (`docs/research/hap-pairing-port-spec.md` §11, findings 1–3). This port is stricter, on the
//! lead's instruction. Each added check has its own [`crate::Error`] variant so callers can tell
//! them apart:
//!
//! | Check | pyatv | Here |
//! |---|---|---|
//! | Accessory SRP proof in M4 | `verify_proof(self.key_proof_hash)` compares a value to itself and can never fail (`hap_srp.py:157-158`, `srptools:srptools/client.py:40-42`); the wire value is only logged (`mrp/auth.py:70-71`) | [`Error::ProofMismatch`] |
//! | Accessory signature in pair-setup M6 | `# TODO: verify signature here` (`hap_srp.py:229`) | [`Error::SetupSignature`] |
//! | Accessory signature in pair-verify M2 | verified (`hap_srp.py:100-107`) | [`Error::VerifySignature`] |
//! | Accessory identifier in pair-verify M2 | verified (`hap_srp.py:96-98`) | [`Error::IdentifierMismatch`] |
//! | `SeqNo` of every response | never inspected; state is inferred from send order | [`Error::UnexpectedState`] |
//! | Final pair-verify M4 | `# TODO: check status code` (`mrp/auth.py:114`, `companion/auth.py:162`, `airplay/auth/hap.py:136`) | [`PairVerify::handle_m4`] checks state and error TLVs |
//!
//! None of these can break interop with an honest accessory — real devices always send valid
//! proofs and signatures, pyatv simply never looks. What they do buy is detection of a
//! man-in-the-middle during pair-setup, which is the property SRP exists to provide and which
//! pyatv's controller does not currently have.
//!
//! # What is not here
//!
//! There is no `PairingType` enum. `docs/research/hap-pairing-port-spec.md` §7 checked: pyatv has
//! no such construct, and the only axis of that shape is
//! [`AuthenticationType`](crate::AuthenticationType). Inventing a parallel enum would create a
//! second source of truth for the same decision.

mod pair_setup;
mod pair_verify;
mod transient;

use bytes::Bytes;

pub use pair_setup::{PairSetup, PairSetupOptions};
pub use pair_verify::{PairVerify, SessionKeys};
pub use transient::{TRANSIENT_PIN, TransientPairSetup};

use crate::{
    Error, Result,
    srp_hap::random_seed,
    tlv8::{ErrorCode, State, Tlv8, TlvValue},
};

/// Decode a device response, rejecting error codes and unexpected states.
///
/// pyatv's `_get_pairing_data` (`pyatv/protocols/mrp/auth.py:19-23`) raises on an `Error` TLV and
/// ignores everything else, including `SeqNo`. The error check is ported as-is — it must run before
/// the state check, because an accessory that rejects a PIN answers M3 with `{SeqNo: 4, Error: 2}`
/// and the informative failure is the error code, not the state.
fn decode_response(payload: &[u8], expected: State) -> Result<Tlv8> {
    let tlv = Tlv8::decode(payload)?;

    if let Some(code) = tlv.get(TlvValue::Error).and_then(|value| value.first()) {
        return Err(
            ErrorCode::from_code(*code).map_or(Error::UnknownHapError(*code), |code| {
                Error::HapError { code }
            }),
        );
    }

    let actual = tlv
        .get(TlvValue::SeqNo)
        .and_then(|value| value.first())
        .copied()
        .ok_or(Error::MissingTlv(TlvValue::SeqNo))?;

    if actual == expected as u8 {
        Ok(tlv)
    } else {
        Err(Error::UnexpectedState {
            expected: expected as u8,
            actual,
        })
    }
}

/// A fresh controller pairing identifier: a lowercase random UUID as ASCII bytes.
///
/// `SRPAuthHandler.__init__` (`pyatv/auth/hap_srp.py:50`) uses `str(uuid.uuid4()).encode()`. The
/// identifier is regenerated per pairing attempt; the stable identity is the Ed25519 keypair, not
/// this string.
#[must_use]
pub fn random_pairing_id() -> Vec<u8> {
    let seed = random_seed();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&seed[..16]);

    // RFC 9562 §5.4: version 4 in the high nibble of octet 6, variant 10 in the top bits of octet 8.
    bytes[6] = (bytes[6] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;

    let hex = hex::encode(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
    .into_bytes()
}

/// Take an owned copy of a required TLV entry.
fn require_owned(tlv: &Tlv8, tag: TlvValue) -> Result<Bytes> {
    tlv.require(tag).cloned()
}

#[cfg(test)]
mod tests {
    use super::{decode_response, random_pairing_id};
    use crate::{
        Error,
        tlv8::{ErrorCode, State, Tlv8, TlvValue},
    };

    #[test]
    fn a_matching_state_decodes() {
        let payload = Tlv8::new().with_byte(TlvValue::SeqNo, 2).encode();
        assert!(decode_response(&payload, State::M2).is_ok());
    }

    #[test]
    fn an_unexpected_state_is_rejected() {
        let payload = Tlv8::new().with_byte(TlvValue::SeqNo, 4).encode();

        match decode_response(&payload, State::M2) {
            Err(Error::UnexpectedState { expected, actual }) => {
                assert_eq!((expected, actual), (2, 4));
            }
            other => panic!("expected an UnexpectedState error, got {other:?}"),
        }
    }

    /// A wrong PIN comes back as an error TLV alongside a perfectly valid `SeqNo`, so the error
    /// check has to win.
    #[test]
    fn an_error_tlv_beats_the_state_check() {
        let payload = Tlv8::new()
            .with_byte(TlvValue::SeqNo, 4)
            .with_byte(TlvValue::Error, ErrorCode::Authentication as u8)
            .encode();

        assert!(matches!(
            decode_response(&payload, State::M4),
            Err(Error::HapError {
                code: ErrorCode::Authentication
            })
        ));
    }

    #[test]
    fn an_uncatalogued_error_code_survives() {
        let payload = Tlv8::new().with_byte(TlvValue::Error, 0x42).encode();
        assert!(matches!(
            decode_response(&payload, State::M4),
            Err(Error::UnknownHapError(0x42))
        ));
    }

    #[test]
    fn pairing_ids_look_like_version_four_uuids() {
        let first = random_pairing_id();
        let rendered = String::from_utf8(first.clone()).unwrap();

        assert_eq!(rendered.len(), 36);
        assert_eq!(rendered.as_bytes()[14], b'4');
        assert!(matches!(rendered.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(first, random_pairing_id());
    }
}
