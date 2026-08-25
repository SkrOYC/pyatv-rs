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

    /// The device could not be reached.
    #[error("could not connect to {peer}: {source}")]
    Connect {
        /// Where the connection was attempted.
        peer: std::net::SocketAddr,
        /// The underlying socket failure.
        source: std::io::Error,
    },

    /// The device rejected a command, quoting its own `SendError`/`HandlerReturnStatus`.
    ///
    /// `MrpRemoteControl._send_command`'s failure branch
    /// (`pyatv/protocols/mrp/__init__.py:347-354`) — the one MRP command path with real
    /// device-side error reporting. HID presses have no response payload to fail on.
    #[error("{0}")]
    Command(String),

    /// The device answered with a non-zero `ProtocolMessage.errorCode`.
    #[error("device reported errorCode {code} for message type {message_type}")]
    ErrorCode {
        /// The `errorCode` field value.
        code: i32,
        /// The `type` of the message carrying it.
        message_type: i32,
    },

    /// The device did not answer within the deadline.
    #[error("timed out waiting for a response to {0}")]
    Timeout(String),

    /// The connection is gone: closed by the caller, dropped by the device, or never opened.
    #[error("the MRP connection is closed")]
    Closed,

    /// An operation was attempted in a state that does not allow it.
    #[error("invalid MRP protocol state: {0}")]
    InvalidState(&'static str),

    /// This transport cannot serve the request at all.
    #[error("not supported on this MRP transport: {0}")]
    NotSupported(&'static str),

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
            Error::Connect { peer, source } => Self::ConnectionFailed {
                address: peer.to_string(),
                reason: source.to_string(),
            },
            Error::Command(message) => Self::Command {
                command: "MRP".to_owned(),
                reason: message,
            },
            Error::Closed => Self::ConnectionLost("the MRP connection is closed".to_owned()),
            Error::Timeout(what) => Self::Command {
                command: what,
                reason: "the device did not answer".to_owned(),
            },
            Error::NotSupported(what) => Self::NotSupported(what.to_owned()),
            other => Self::InvalidResponse(other.to_string()),
        }
    }
}
