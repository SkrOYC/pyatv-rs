//! Companion errors.

/// Something went wrong on a Companion connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A frame header or payload was malformed.
    #[error("Companion framing error: {0}")]
    Framing(String),

    /// The OPACK body could not be decoded.
    #[error(transparent)]
    Opack(#[from] pyatv_opack::Error),

    /// Pairing or transport encryption failed.
    #[error(transparent)]
    Pairing(#[from] pyatv_pairing::Error),

    /// The device rejected a command.
    #[error("device rejected {command}: {reason}")]
    Rejected {
        /// The `_i` identifier of the command that was rejected.
        command: String,
        /// The `_em` error message the device returned.
        reason: String,
    },

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for pyatv_core::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Pairing(inner) => inner.into(),
            Error::Io(inner) => Self::Io(inner),
            Error::Rejected { command, reason } => Self::Command { command, reason },
            other => Self::InvalidResponse(other.to_string()),
        }
    }
}
