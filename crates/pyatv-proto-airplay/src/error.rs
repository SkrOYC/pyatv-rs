//! AirPlay and RAOP errors.

/// Why an audio source could not be turned into the PCM a stream needs.
///
/// The two want different answers from a caller, which is why they are not one string. pyatv makes
/// no such distinction — it lets `miniaudio`'s and `requests`' own exceptions escape `open_source`
/// (`pyatv/protocols/raop/audio_source.py:727-739`) — so the split is this port's, and it exists
/// because [`crate::Error`]'s conversion into [`pyatv_core::Error`] has to choose a variant and
/// "this build cannot decode Opus" and "that URL 404s" are not the same answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AudioFailure {
    /// The bytes are not audio this build can decode, or the format the receiver negotiated cannot
    /// be produced from them.
    ///
    /// Retrying is pointless: a different file, a different build, or a different receiver is the
    /// only recovery. Becomes [`pyatv_core::Error::NotSupported`].
    Format,

    /// The source could not be obtained or held: a path that is not there, a host that does not
    /// resolve, a server that answered an error, a stream too large to decode into memory.
    ///
    /// Nothing is wrong with this build's decoders; the input never arrived. Becomes
    /// [`pyatv_core::Error::Command`], because it is the `stream_file` call that failed rather
    /// than a capability that is missing.
    Source,
}

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

    /// Playback could not be started, or the device reported an error while playing.
    ///
    /// `PlaybackError` (`pyatv/exceptions.py`), raised by `AirPlayPlayer` both when every `/play`
    /// attempt was refused with `500` and when `/playback-info` carries an `error` key
    /// (`pyatv/protocols/airplay/player.py:68,100-102`).
    #[error("{0}")]
    Playback(String),

    /// An audio source could not be opened, decoded or resampled.
    ///
    /// pyatv lets `miniaudio`'s own exceptions escape `open_source`
    /// (`pyatv/protocols/raop/audio_source.py:727-739`); this port names the failure instead, since
    /// "the file is not audio this build can decode" and "the device refused the stream" want
    /// different answers from a caller. [`AudioFailure`] is which of the two it was.
    #[error("audio source error: {message}")]
    Audio {
        /// Whether the input was undecodable or simply never arrived.
        kind: AudioFailure,
        /// What happened, already rendered.
        message: String,
    },

    /// An operation was attempted in a state that does not allow it.
    ///
    /// `exceptions.InvalidStateError` (`pyatv/protocols/raop/__init__.py:131-136`), raised when a
    /// second `stream_file` starts while one is already running.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl Error {
    /// An [`Error::Audio`] for input this build cannot decode or conform.
    #[must_use]
    pub fn audio_format(message: impl Into<String>) -> Self {
        Self::Audio {
            kind: AudioFailure::Format,
            message: message.into(),
        }
    }

    /// An [`Error::Audio`] for input that could not be obtained or held.
    #[must_use]
    pub fn audio_source(message: impl Into<String>) -> Self {
        Self::Audio {
            kind: AudioFailure::Source,
            message: message.into(),
        }
    }
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
            Error::NoEncryptionKeys(_)
            | Error::Audio {
                kind: AudioFailure::Format,
                ..
            } => Self::NotSupported(rendered),
            Error::InvalidState(_)
            | Error::Audio {
                kind: AudioFailure::Source,
                ..
            } => Self::Command {
                command: "stream_file".to_owned(),
                reason: rendered,
            },
            // `pyatv_core` has no playback variant; the command that failed names itself instead.
            Error::Playback(_) => Self::Command {
                command: "play_url".to_owned(),
                reason: rendered,
            },
            Error::Malformed(_) | Error::Status { .. } | Error::Plist(_) => {
                Self::InvalidResponse(rendered)
            }
        }
    }
}
