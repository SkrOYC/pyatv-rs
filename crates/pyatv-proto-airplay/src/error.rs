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

    /// The device rejected the request as unauthenticated.
    ///
    /// pyatv raises `AuthenticationError` for both `401` and `403`
    /// (`pyatv/support/http.py:482-489`); the status is kept so a caller can tell "wrong password"
    /// from "not paired".
    #[error("device rejected the request as unauthenticated ({status})")]
    NotAuthenticated {
        /// The status the device sent, `401` or `403`.
        status: u16,
    },

    /// A binary plist body could not be decoded.
    #[error("could not decode plist body: {0}")]
    Plist(String),

    /// Pairing or transport encryption failed.
    #[error(transparent)]
    Pairing(#[from] pyatv_pairing::Error),

    /// A pairing step ran before the step that starts it.
    #[error("{0} has not been started")]
    NotStarted(&'static str),

    /// Pair-setup was asked for with an authentication type that cannot be set up.
    ///
    /// There is nothing to establish for a null or an ephemeral pairing
    /// (`pyatv/protocols/airplay/auth/__init__.py:73-75`).
    #[error("authentication type {auth_type:?} does not support pair-setup")]
    UnsupportedAuthentication {
        /// The type that was asked for.
        auth_type: pyatv_pairing::AuthenticationType,
    },

    /// Transport keys were requested from an exchange that does not produce any.
    #[error("{0} derives no encryption keys")]
    NoEncryptionKeys(&'static str),

    /// The device requires a password that was not supplied or was rejected.
    #[error("device requires a password")]
    PasswordRequired,

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for pyatv_core::Error {
    fn from(error: Error) -> Self {
        // Rendered before the match so the arms that do not bind the value can still report it.
        let rendered = error.to_string();

        match error {
            Error::Pairing(inner) => inner.into(),
            Error::Io(inner) => Self::Io(inner),
            Error::PasswordRequired | Error::NotAuthenticated { .. } => {
                Self::Authentication(rendered)
            }
            Error::NotStarted(_) | Error::UnsupportedAuthentication { .. } => {
                Self::Pairing(rendered)
            }
            Error::NoEncryptionKeys(_) => Self::NotSupported(rendered),
            Error::Malformed(_) | Error::Status { .. } | Error::Plist(_) => {
                Self::InvalidResponse(rendered)
            }
        }
    }
}
