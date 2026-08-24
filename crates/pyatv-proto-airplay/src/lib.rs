//! AirPlay 1 and 2, plus RAOP audio streaming.
//!
//! The largest of the protocol crates, and the one with the most unusual transport. Its details live in `docs/research/airplay-raop-dmap.md`, with the crypto in `docs/research/crypto-pairing.md` §5.4 and the MRP tunnel it hosts in `docs/research/mrp-companion.md` §3.
//!
//! ## Why this crate hand-rolls its HTTP layer
//!
//! `docs/research/rust-crates.md` §5 examined `reqwest`, `hyper`, `h2` and `httparse` and rejected all of them, for reasons that are structural rather than stylistic:
//!
//! - **Both roles on one socket.** pyatv implements and uses `parse_request` *and* `parse_response` on the same connection, because AirPlay receivers send requests back to the controller over the same TCP stream. Every HTTP client library assumes a strict client role talking to a server that only ever replies.
//! - **Not really HTTP.** The methods are RTSP's (`ANNOUNCE`, `SETUP`, `RECORD`, `FLUSH`, `TEARDOWN`, `SET_PARAMETER`, `GET_PARAMETER`), the version string is `RTSP/1.0` or `HTTP/1.1` depending on device generation, and bodies are routinely `application/x-apple-binary-plist`.
//! - **Framing is `Content-Length` only.** No chunked transfer encoding appears anywhere in pyatv's parser, which suits a `tokio_util::codec::Decoder` returning `Ok(None)` for a partial frame.
//!
//! So [`codec`] implements a small `Encoder`/`Decoder` pair that parses the first line permissively and yields a `Frame::Request | Frame::Response` enum, letting one `Framed` stream serve both directions.
//!
//! ## Audio
//!
//! pyatv's RAOP sender advertises `a=rtpmap:96 L16/44100/2` — raw linear PCM, not ALAC — and no ALAC encoding appears anywhere in its RAOP code. Whether ALAC is genuinely unnecessary for parity is an open question in `docs/research/rust-crates.md` §7 that wants a live capture to settle, so no audio codec dependency is taken here yet.

pub mod codec;
pub mod error;
pub mod raop;
pub mod rtsp;

pub use codec::{AirPlayCodec, Frame};
pub use error::Error;

/// Convenience alias for fallible AirPlay operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
