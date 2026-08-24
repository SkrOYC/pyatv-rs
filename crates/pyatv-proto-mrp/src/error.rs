//! MRP errors.

/// Something went wrong on an MRP connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A frame could not be delimited.
    #[error("MRP framing error: {0}")]
    Framing(String),

    /// A protobuf message failed to decode.
    #[error("could not decode protobuf message: {0}")]
    Decode(String),

    /// The bytes of a `ProtocolMessage` are not a well-formed protobuf message.
    ///
    /// Raised by the extension extractor, which walks the top-level fields itself because `prost`
    /// discards everything it was not generated for. See `crate::protobuf::extensions`.
    #[error("malformed protobuf field at offset {offset}: {reason}")]
    WireFormat {
        /// Byte offset of the offending field key within the message.
        offset: usize,
        /// What was wrong with it.
        reason: &'static str,
    },

    /// The device sent a message type this client does not handle.
    #[error("unhandled MRP message type {0}")]
    UnhandledMessage(i32),

    /// Pairing or transport encryption failed.
    #[error(transparent)]
    Pairing(#[from] pyatv_pairing::Error),

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for pyatv_core::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::Pairing(inner) => inner.into(),
            Error::Io(inner) => Self::Io(inner),
            other => Self::InvalidResponse(other.to_string()),
        }
    }
}
