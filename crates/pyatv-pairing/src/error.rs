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

    /// An Ed25519 signature did not verify.
    #[error("signature verification failed")]
    SignatureMismatch,

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
    fn from(error: Error) -> Self {
        match error {
            Error::ProofMismatch | Error::SignatureMismatch | Error::Aead { .. } => {
                Self::Authentication(error.to_string())
            }
            Error::InvalidCredentials(message) => Self::InvalidCredentials(message),
            other => Self::Pairing(other.to_string()),
        }
    }
}
