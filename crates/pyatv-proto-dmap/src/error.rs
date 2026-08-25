//! DMAP errors.
//!
//! pyatv distinguishes several exception classes across the DAAP request state machine
//! (`pyatv/exceptions.py:23-58`), and conflating them loses information a caller can act on:
//! `NotSupportedError` means "this device will never do this", `AuthenticationError` means "the
//! credentials no longer work", and `InvalidCredentialsError` means "the stored string is not even
//! shaped like a credential". Each gets its own variant, and each maps onto the closest
//! [`pyatv_core::Error`].

/// Something went wrong talking DMAP.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A DMAP payload was truncated or otherwise malformed.
    #[error("malformed DMAP payload: {0}")]
    Malformed(String),

    /// A tag's data did not match the type the tag table says it should carry.
    #[error("tag {tag} declared as {expected} could not be read from {length} bytes")]
    TypeMismatch {
        /// The four-character tag key.
        tag: String,
        /// The type the table expects.
        expected: &'static str,
        /// How many bytes the tag actually carried.
        length: usize,
    },

    /// The device's HTTP response could not be decoded.
    #[error("bad HTTP response: {0}")]
    Http(String),

    /// The device answered HTTP 500 to a command.
    ///
    /// `NotSupportedError` (`daap.py:139-141`), whose own source comment is "Seems to be the
    /// case?" — the mapping is pyatv's guess, kept because callers may have come to depend on it.
    /// Unlike every other failure this is terminal on the first attempt: no re-login, no retry.
    #[error("command not supported at this stage")]
    NotSupported,

    /// The retry budget was exhausted on a non-2xx response.
    ///
    /// `AuthenticationError(f"failed to login: {status}")` (`daap.py:152`). The message says
    /// "failed to login" even when the failing request was not a login, which is upstream's
    /// wording and is preserved so that a log line from either implementation greps the same.
    #[error("failed to login: {0}")]
    Authentication(u16),

    /// The stored credential string is neither a pairing GUID nor a Home Sharing ID.
    ///
    /// `InvalidCredentialsError` (`daap.py:165-167`).
    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),

    /// A `cmmk` value outside the table (`UnknownMediaKindError`, `daap.py:42`).
    #[error("unknown media kind: {0}")]
    UnknownMediaKind(u64),

    /// A `caps` value outside the table (`UnknownPlayStateError`, `daap.py:61`).
    #[error("unknown playstate: {0}")]
    UnknownPlayState(u64),

    /// Pairing failed.
    #[error("DMAP pairing failed: {0}")]
    Pairing(String),

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for pyatv_core::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Io(inner) => Self::Io(inner),
            Error::Pairing(message) => Self::Pairing(message),
            Error::NotSupported => {
                Self::NotSupported("DMAP: command not supported at this stage".to_owned())
            }
            Error::Authentication(status) => {
                Self::Authentication(format!("failed to login: {status}"))
            }
            Error::InvalidCredentials(credentials) => Self::InvalidCredentials(credentials),
            // Everything left is "the device said something we could not use": a malformed
            // payload, an out-of-table enum value, or a response this client could not frame.
            // A non-2xx status is not among them — it never reaches a caller as a status, because
            // `_do` turns it into `NotSupported` or `Authentication` first (`daap.py:130-152`).
            other => Self::InvalidResponse(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    /// The three variants that carry a distinct meaning must not collapse into `InvalidResponse`.
    #[test]
    fn the_distinguishable_failures_stay_distinguishable() {
        assert!(matches!(
            pyatv_core::Error::from(Error::NotSupported),
            pyatv_core::Error::NotSupported(_)
        ));
        assert!(matches!(
            pyatv_core::Error::from(Error::Authentication(403)),
            pyatv_core::Error::Authentication(_)
        ));
        assert!(matches!(
            pyatv_core::Error::from(Error::InvalidCredentials("nonsense".to_owned())),
            pyatv_core::Error::InvalidCredentials(_)
        ));
        assert!(matches!(
            pyatv_core::Error::from(Error::Pairing("no".to_owned())),
            pyatv_core::Error::Pairing(_)
        ));
    }

    /// Upstream's exact wording, kept so logs from either implementation match.
    #[test]
    fn the_authentication_message_matches_upstream() {
        assert_eq!(
            Error::Authentication(503).to_string(),
            "failed to login: 503"
        );
        assert_eq!(
            Error::NotSupported.to_string(),
            "command not supported at this stage"
        );
    }
}
