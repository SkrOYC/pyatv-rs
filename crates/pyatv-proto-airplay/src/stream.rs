//! Playing a video URL on a receiver — the implementation behind
//! [`pyatv_core::interface::Stream::play_url`].
//!
//! Port of `AirPlayPlayer` (`pyatv/protocols/airplay/player.py`) and the two `StreamProtocol`
//! implementations it drives, `AirPlayV1.play_url`
//! (`pyatv/protocols/raop/protocols/airplayv1.py:119-137`) and `AirPlayV2.play_url`
//! (`airplayv2.py:210-273`). The byte-level reference is
//! `docs/research/airplay-playurl-raop-port-spec.md` §1–§2.
//!
//! # Shape
//!
//! - [`bodies`] — the paths, header sets and property-list bodies, which are constants.
//! - [`control`] — the one TCP connection the session runs on.
//! - [`ap1`] / [`ap2`] — what one attempt sends, per protocol version.
//! - [`player`] — the retry loop and the `/playback-info` poll that outlive it.
//!
//! # What this deliberately does not do
//!
//! **Local files are not served.** Upstream rewrites a `url` that names an existing file into an
//! `http://<local-ip>:<port>/…` address served by a throwaway `StaticFileWebServer`
//! (`pyatv/protocols/airplay/__init__.py:115-121`). That is an HTTP *server*, not a wire-format
//! concern, and it belongs with whoever owns the process' listening sockets; this crate plays
//! whatever URL it is handed.
//!
//! **No connection is shared with the MRP tunnel.** Upstream opens a second AirPlay connection for
//! `play_url`, with its own pair-verify and its own event channel, even when a tunnel is already up
//! (`docs/research/airplay-playurl-raop-port-spec.md` §2.3.1), and so does this. The two `SETUP`
//! bodies genuinely differ, so unifying them would be wrong rather than merely wasteful.

pub mod ap1;
pub mod ap2;
pub mod bodies;
pub mod control;
pub mod player;

use std::net::SocketAddr;
use std::time::Duration;

use pyatv_core::airplay::AirPlayMajorVersion;
use pyatv_pairing::HapCredentials;

pub use ap1::AirPlayV1;
pub use ap2::AirPlayV2;
pub use control::PlayControl;
pub use player::{AirPlayPlayer, PLAY_RETRIES, WAIT_RETRIES};

/// The intervals the play sequence waits on.
///
/// Upstream's values are the defaults; the type exists so a test can run the same state machine
/// without spending real seconds in `asyncio.sleep`, which is what pyatv's own tests achieve by
/// stubbing the clock (`tests/utils.py::total_sleep_time`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlayTiming {
    /// Between a `500` and the next attempt (`player.py:60`), and between two refused
    /// event-channel connections (`airplayv2.py:101`). One second in both places upstream.
    pub retry_delay: Duration,
    /// Between two `/playback-info` polls (`player.py:118`).
    pub poll_interval: Duration,
    /// Between two `POST /feedback` keepalives (`airplayv2.py:25`).
    pub feedback_interval: Duration,
}

impl Default for PlayTiming {
    fn default() -> Self {
        Self {
            retry_delay: Duration::from_secs(1),
            poll_interval: Duration::from_secs(1),
            feedback_interval: Duration::from_secs(2),
        }
    }
}

/// Everything one play session needs to know before it connects.
#[derive(Debug, Clone)]
pub struct PlayOptions {
    /// The `AirPlay` service's address and port, from its SRV record.
    pub address: SocketAddr,
    /// What to pair-verify with. See [`crate::setup::play_credentials`] for how one is chosen.
    pub credentials: HapCredentials,
    /// Which protocol version to speak, from [`pyatv_core::airplay::get_protocol_version`].
    pub version: AirPlayMajorVersion,
    /// The intervals to use. [`PlayTiming::default`] is upstream's.
    pub timing: PlayTiming,
}

impl PlayOptions {
    /// A session with upstream's timings.
    #[must_use]
    pub fn new(
        address: SocketAddr,
        credentials: HapCredentials,
        version: AirPlayMajorVersion,
    ) -> Self {
        Self {
            address,
            credentials,
            version,
            timing: PlayTiming::default(),
        }
    }
}

/// A fresh lowercase UUID, the casing `str(uuid4())` renders.
///
/// [`crate::ap2::random_uuid`] produces the uppercase form the `SETUP` bodies want
/// (`str(uuid4()).upper()`); the `/play` bodies and the `X-Apple-Session-ID` header want the other
/// one (`airplayv1.py:127`, `airplayv2.py:31,49`).
#[must_use]
pub fn random_session_id() -> String {
    crate::ap2::random_uuid().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::{PlayTiming, random_session_id};

    /// The three intervals upstream uses (`player.py:60,118`, `airplayv2.py:25`).
    #[test]
    fn the_default_timings_match_upstream() {
        let timing = PlayTiming::default();

        assert_eq!(timing.retry_delay.as_secs(), 1);
        assert_eq!(timing.poll_interval.as_secs(), 1);
        assert_eq!(timing.feedback_interval.as_secs(), 2);
    }

    /// `str(uuid4())` is lowercase, unlike the `SETUP` bodies' `str(uuid4()).upper()`.
    #[test]
    fn session_identifiers_are_lowercase_and_unique() {
        let first = random_session_id();

        assert_eq!(first, first.to_lowercase());
        assert_eq!(first.len(), 36);
        assert_ne!(first, random_session_id());
    }
}
