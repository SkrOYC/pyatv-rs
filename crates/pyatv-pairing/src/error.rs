//! Pairing and crypto errors.

/// Something went wrong during pairing, key derivation or transport encryption.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A TLV8 payload was truncated or otherwise malformed.
    #[error("malformed TLV8 payload: {0}")]
    Tlv8(String),

    /// The device reported a HAP error code.
    #[error("device reported HAP error {code:?}")]
    HapError {
        /// The code from the `Error` TLV entry.
        code: crate::tlv8::ErrorCode,
    },

    /// The exchange arrived at an unexpected state.
    #[error("unexpected pairing state: expected M{expected}, got M{actual}")]
    UnexpectedState {
        /// State the local machine was waiting for.
        expected: u8,
        /// State the device sent.
        actual: u8,
    },

    /// A required TLV entry was absent.
    #[error("required TLV entry {0:?} missing from device response")]
    MissingTlv(crate::tlv8::TlvValue),

    /// SRP proof verification failed.
    #[error("SRP proof did not verify")]
    ProofMismatch,

    /// An AEAD open or seal operation failed.
    #[error("{operation} failed: authentication tag did not verify")]
    Aead {
        /// Which direction failed, `"decrypt"` or `"encrypt"`.
        operation: &'static str,
    },

    /// A credential string could not be parsed.
    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),

    /// A device response was structurally wrong, or a protocol value was out of range.
    #[error("malformed device response: {0}")]
    MalformedResponse(String),

    /// Key material had the wrong length.
    #[error("expected {expected} bytes of key material, got {actual}")]
    KeyLength {
        /// Required length.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },

    /// The device reported a HAP error code this port does not recognise.
    #[error("device reported unknown HAP error code {0:#04x}")]
    UnknownHapError(u8),

    /// A peer's SRP public value was zero modulo `N`, the RFC 5054 safeguard case.
    #[error("invalid SRP public value from {peer}")]
    SrpPublicKey {
        /// Which side sent it, `"accessory"` or `"controller"`.
        peer: &'static str,
    },

    /// A pairing step ran before the step it depends on.
    #[error("pairing step out of order: {0}")]
    OutOfOrder(&'static str),

    /// A PIN is required before pairing can continue.
    #[error("no PIN has been supplied")]
    MissingPin,

    /// Key material was structurally invalid: wrong length, or not a canonical curve point.
    #[error("invalid {kind} key material")]
    InvalidKey {
        /// Which key was rejected.
        kind: &'static str,
    },

    /// The accessory's Ed25519 signature over its pair-setup M6 payload did not verify.
    ///
    /// pyatv never performs this check — `pyatv/auth/hap_srp.py:229` is a literal
    /// `# TODO: verify signature here`. See [`crate::pairing`] for the divergence rationale.
    #[error("accessory signature in pair-setup M6 did not verify")]
    SetupSignature,

    /// The accessory's Ed25519 signature over its pair-verify M2 payload did not verify.
    #[error("accessory signature in pair-verify M2 did not verify")]
    VerifySignature,

    /// The accessory identified itself as a device other than the one the credentials name.
    #[error("accessory identifier mismatch: credentials name {expected}, device sent {actual}")]
    IdentifierMismatch {
        /// Identifier from the stored credentials, hex-encoded.
        expected: String,
        /// Identifier the device sent, hex-encoded.
        actual: String,
    },
}

impl From<Error> for pyatv_core::Error {
    /// Collapse a pairing error into the crate-wide one.
    ///
    /// The split that matters to callers is "the peer is not who the credentials say it is, or does
    /// not accept who we say we are" versus "the exchange broke down". Everything in the first
    /// group becomes [`pyatv_core::Error::Authentication`] so a caller can decide to re-pair
    /// instead of retrying: the two SRP/AEAD failures, both Ed25519 signature checks, the accessory
    /// identifier check, and the device's own `Authentication` HAP error code — which is exactly
    /// what a wrong PIN, or a controller the accessory has forgotten, comes back as.
    /// Everything else stays [`pyatv_core::Error::Pairing`], including the other HAP error codes,
    /// which describe a device state (busy, backing off, out of pairing slots) rather than a
    /// rejected identity.
    fn from(error: Error) -> Self {
        match error {
            Error::ProofMismatch
            | Error::Aead { .. }
            | Error::SetupSignature
            | Error::VerifySignature
            | Error::IdentifierMismatch { .. }
            | Error::HapError {
                code: crate::tlv8::ErrorCode::Authentication,
            } => Self::Authentication(error.to_string()),
            Error::InvalidCredentials(message) => Self::InvalidCredentials(message),
            other => Self::Pairing(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;
    use crate::tlv8::ErrorCode;

    fn mapped(error: Error) -> pyatv_core::Error {
        error.into()
    }

    /// Every identity failure has to land in `Authentication`, because that is the variant callers
    /// key "these credentials are dead, re-pair" off. Regressing one of these to `Pairing` would
    /// turn a permanent failure into an infinite retry loop.
    #[test]
    fn identity_failures_map_to_authentication() {
        let cases = [
            Error::ProofMismatch,
            Error::Aead {
                operation: "decrypt",
            },
            Error::SetupSignature,
            Error::VerifySignature,
            Error::IdentifierMismatch {
                expected: "aa".to_owned(),
                actual: "bb".to_owned(),
            },
            Error::HapError {
                code: ErrorCode::Authentication,
            },
        ];

        for case in cases {
            let rendered = case.to_string();
            assert!(
                matches!(mapped(case), pyatv_core::Error::Authentication(_)),
                "{rendered}"
            );
        }
    }

    /// The other HAP codes describe a device state, not a rejected identity.
    #[test]
    fn device_state_errors_stay_pairing_errors() {
        let cases = [
            Error::HapError {
                code: ErrorCode::Busy,
            },
            Error::HapError {
                code: ErrorCode::MaxPeers,
            },
            Error::UnknownHapError(0x42),
            Error::OutOfOrder("nothing has happened yet"),
            Error::MissingPin,
        ];

        for case in cases {
            let rendered = case.to_string();
            assert!(
                matches!(mapped(case), pyatv_core::Error::Pairing(_)),
                "{rendered}"
            );
        }
    }

    #[test]
    fn credential_parse_failures_keep_their_own_variant() {
        assert!(matches!(
            mapped(Error::InvalidCredentials("bad hex".to_owned())),
            pyatv_core::Error::InvalidCredentials(message) if message == "bad hex"
        ));
    }
}
