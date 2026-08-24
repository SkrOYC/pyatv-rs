//! DMAP errors.

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

    /// The device answered with a non-success HTTP status.
    #[error("device returned HTTP {0}")]
    HttpStatus(u16),

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
            other => Self::InvalidResponse(other.to_string()),
        }
    }
}
