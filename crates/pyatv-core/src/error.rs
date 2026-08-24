//! The crate-wide error type.
//!
//! Modelled on `pyatv/exceptions.py`, flattened into a single non-exhaustive enum so callers can
//! match on failure kind without a Python-style exception hierarchy. Protocol crates define their
//! own leaf error enums and convert into this type at the public boundary.

use crate::consts::Protocol;

/// Convenience alias used throughout the workspace.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// Everything that can go wrong while discovering, pairing with, or controlling a device.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The requested protocol is not present on the device configuration.
    #[error("device has no service for protocol {0:?}")]
    NoService(Protocol),

    /// The protocol is known but this build cannot speak it.
    #[error("protocol {0:?} is not supported")]
    UnsupportedProtocol(Protocol),

    /// A capability was requested that no connected protocol implements.
    #[error("operation not supported by any connected protocol: {0}")]
    NotSupported(String),

    /// Establishing the transport failed.
    #[error("failed to connect to {address}: {reason}")]
    ConnectionFailed {
        /// Host and port that was dialled.
        address: String,
        /// Underlying cause, already rendered.
        reason: String,
    },

    /// An established connection went away mid-session.
    #[error("connection lost: {0}")]
    ConnectionLost(String),

    /// The pairing exchange failed or was rejected by the device.
    #[error("pairing failed: {0}")]
    Pairing(String),

    /// Stored credentials were rejected, or a proof did not verify.
    #[error("authentication failed: {0}")]
    Authentication(String),

    /// No credentials are stored for a protocol that requires them.
    #[error("no credentials stored for protocol {0:?}")]
    NoCredentials(Protocol),

    /// A credential string could not be parsed.
    #[error("invalid credentials: {0}")]
    InvalidCredentials(String),

    /// The device asked the client to back off before retrying.
    #[error("device asked to back off for {seconds}s")]
    BackOff {
        /// Seconds to wait before the next attempt.
        seconds: u64,
    },

    /// A device response could not be decoded.
    #[error("invalid response: {0}")]
    InvalidResponse(String),

    /// A command was rejected by the device.
    #[error("command {command} failed: {reason}")]
    Command {
        /// Command that was rejected.
        command: String,
        /// Device-supplied reason.
        reason: String,
    },

    /// An operation exceeded its deadline.
    #[error("operation timed out after {millis}ms")]
    Timeout {
        /// Deadline that elapsed, in milliseconds.
        millis: u64,
    },

    /// Persisted settings or credentials could not be read or written.
    #[error("storage error: {0}")]
    Storage(String),

    /// A device configuration carries no identifier, so it cannot be filed in storage.
    ///
    /// `DeviceIdMissingError` (`pyatv/exceptions.py`), raised by
    /// [`crate::storage::Storage::get_settings`]. Identifiers come from mDNS, so this means the
    /// device was hand-built rather than discovered.
    #[error("no identifier for device {0}")]
    DeviceIdMissing(String),

    /// Underlying I/O failure.
    #[error("i/o error")]
    Io(#[from] std::io::Error),
}
