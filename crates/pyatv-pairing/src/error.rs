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

    /// Key material had the wrong length.
    #[error("expected {expected} bytes of key material, got {actual}")]
    KeyLength {
        /// Required length.
        expected: usize,
        /// Length supplied.
        actual: usize,
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
