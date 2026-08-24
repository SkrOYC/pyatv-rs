//! AirPlay and RAOP errors.

/// Something went wrong on an AirPlay or RAOP connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A message could not be parsed off the wire.
    #[error("malformed RTSP/HTTP message: {0}")]
    Malformed(String),

    /// The device answered with a non-success status.
    #[error("device returned {status} {reason}")]
    Status {
        /// Numeric status code.
        status: u16,
        /// Reason phrase.
        reason: String,
    },

    /// A binary plist body could not be decoded.
    #[error("could not decode plist body: {0}")]
    Plist(String),

    /// Pairing or transport encryption failed.
    #[error(transparent)]
    Pairing(#[from] pyatv_pairing::Error),

    /// The device requires a password that was not supplied or was rejected.
    #[error("device requires a password")]
    PasswordRequired,

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for pyatv_core::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Pairing(inner) => inner.into(),
            Error::Io(inner) => Self::Io(inner),
            Error::PasswordRequired => {
                Self::Authentication("device requires a password".to_owned())
            }
            other => Self::InvalidResponse(other.to_string()),
        }
    }
}
