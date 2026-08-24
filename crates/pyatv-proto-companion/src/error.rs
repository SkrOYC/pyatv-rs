//! Companion errors.

use std::net::SocketAddr;

/// Something went wrong on a Companion connection.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A frame header or payload was malformed, or a frame exceeded
    /// [`crate::codec::MAX_FRAME_PAYLOAD`].
    #[error("Companion framing error: {0}")]
    Framing(String),

    /// The OPACK body could not be decoded, or was not the shape the envelope requires.
    #[error(transparent)]
    Opack(#[from] pyatv_opack::Error),

    /// A message envelope was well-formed OPACK but not a well-formed Companion message.
    #[error("malformed Companion message: {0}")]
    Envelope(String),

    /// Pairing or transport encryption failed.
    #[error(transparent)]
    Pairing(#[from] pyatv_pairing::Error),

    /// The device rejected a command, reporting `_em` and optionally `_ec`/`_ed`.
    #[error("device rejected {command}: {reason}")]
    Rejected {
        /// The `_i` identifier of the command that was rejected.
        command: String,
        /// The `_em` error message the device returned.
        reason: String,
        /// The `_ec` error code, if the device sent one.
        code: Option<u64>,
        /// The `_ed` error domain, if the device sent one.
        domain: Option<String>,
    },

    /// An exchange did not complete inside its deadline.
    #[error("no response to {what} within {millis}ms")]
    Timeout {
        /// What was being awaited.
        what: String,
        /// The deadline that elapsed.
        millis: u64,
    },

    /// A step was taken out of order, or before the connection was ready for it.
    #[error("Companion protocol is not ready: {0}")]
    NotReady(&'static str),

    /// The device closed the connection.
    #[error("the Companion connection was closed by the device{}", if *partial { " mid-frame" } else { "" })]
    Closed {
        /// Whether bytes of an incomplete frame were still buffered when the peer hung up.
        partial: bool,
    },

    /// The TCP connection could not be established.
    #[error("failed to connect to Companion at {peer}")]
    Connect {
        /// The address that was dialled.
        peer: SocketAddr,
        /// The underlying failure.
        source: std::io::Error,
    },

    /// Underlying I/O failure on an established connection.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl From<Error> for pyatv_core::Error {
    /// Collapse a Companion error into the crate-wide one.
    ///
    /// The mapping that matters to callers is which failures mean "re-pair" and which mean "retry":
    /// everything from [`pyatv_pairing`] keeps its own split between
    /// [`pyatv_core::Error::Authentication`] and [`pyatv_core::Error::Pairing`], and the transport
    /// failures map onto the connection variants so a caller can tell an unreachable device from a
    /// device that answered with nonsense.
    fn from(error: Error) -> Self {
        match error {
            Error::Pairing(inner) => inner.into(),
            Error::Io(inner) => Self::Io(inner),
            Error::Connect { peer, source } => Self::ConnectionFailed {
                address: peer.to_string(),
                reason: source.to_string(),
            },
            Error::Closed { .. } => Self::ConnectionLost(error.to_string()),
            Error::Timeout { millis, .. } => Self::Timeout { millis },
            Error::Rejected {
                command, reason, ..
            } => Self::Command { command, reason },
            other @ (Error::Framing(_)
            | Error::Opack(_)
            | Error::Envelope(_)
            | Error::NotReady(_)) => Self::InvalidResponse(other.to_string()),
        }
    }
}
