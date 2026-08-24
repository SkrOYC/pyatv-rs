//! OPACK: Apple's undocumented binary serialisation format.
//!
//! OPACK carries HAP pairing payloads and every Companion-link message, so it sits directly under
//! two protocol crates. There is no dependency worth taking here: the only crate on crates.io,
//! `apple-opack` 1.0.0, was published a month before this project started, has a single
//! maintainer, and documents a deliberate encoder/decoder asymmetry in its deduplication handling.
//! The format is small enough to own outright, so this crate is a hand-written port of pyatv's
//! `pyatv/support/opack.py` with that file treated as ground truth. Every doc comment that states
//! a wire rule cites the Python line numbers it came from, and
//! `tests/pyatv_vectors.rs` ports all 41 cases from pyatv's own
//! `tests/support/test_opack.py` with their exact byte fixtures.
//!
//! `docs/research/rust-crates.md` §6 covers why the format is vendored rather than depended on;
//! `docs/research/mrp-companion.md` §4.5 has the prose tag table and §4.6 covers how Companion
//! frames wrap these payloads.
//!
//! # Usage
//!
//! ```
//! use pyatv_opack::{opack, pack, unpack, Value};
//!
//! let message = opack! {
//!     "_i" => "_sessionStart",
//!     "_t" => 1u64,
//!     "_c" => opack! { "_srvT" => "com.apple.tvremoteservices", "_sid" => 42u64 },
//! };
//!
//! let bytes = pack(&message)?;
//! let (decoded, consumed) = unpack(&bytes)?;
//!
//! assert_eq!(consumed, bytes.len());
//! assert_eq!(decoded.get("_i").and_then(Value::as_str), Some("_sessionStart"));
//! # Ok::<(), pyatv_opack::Error>(())
//! ```
//!
//! # Deliberate gaps, inherited and otherwise
//!
//! * **Absolute time (`0x06`) decodes but does not encode.** pyatv says so in its own module
//!   docstring (`opack.py:4`) and raises `NotImplementedError` for a `datetime` (`opack.py:47`).
//!   [`Value::AbsoluteTime`] preserves the decoded timestamp, and packing one returns
//!   [`Error::UnpackOnlyTag`] rather than silently re-emitting it as a plain integer.
//! * **There are no signed integers.** OPACK has no signed encoding; pyatv's `pack(-1)` emits a
//!   byte no decoder accepts, which is why its Companion client casts negative values to `float`
//!   first (`pyatv/protocols/companion/__init__.py:372`). [`Value`] simply has no signed variant.
//! * **Back-references *are* emitted**, despite pyatv's stale docstring claim to the contrary,
//!   but over a slightly different set of values than pyatv's encoder chooses — pyatv's encoder
//!   and decoder disagree about which values get an index, so it can emit payloads it cannot
//!   itself parse, and this crate would too if it copied the encoder verbatim. [`ser`] has the
//!   summary; the full reasoning and the reproducing example live in the `objects` module source.
//! * **Integer tags wider than eight bytes are rejected**, and **nesting is capped** — see [`de`].
//!
//! This crate deliberately depends only on `bytes` and `thiserror` — it must stay usable from any
//! layer of the workspace without dragging in the runtime or the core types.

pub mod de;
pub mod error;
mod macros;
mod objects;
pub mod ser;
pub mod tags;
pub mod value;

pub use de::unpack;
pub use error::Error;
pub use ser::{encode, pack};
pub use value::{UintWidth, Value};

/// Convenience alias for fallible OPACK operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

/// How deeply arrays and dictionaries may nest before [`Error::DepthLimitExceeded`].
///
/// OPACK carries no depth or total-size field, so `0xD1` repeated a few hundred thousand times is
/// a one-line stack-overflow attack against a recursive decoder. The limit applies to both
/// directions so that anything this crate encodes, it can also decode.
///
/// 32 is chosen as roughly eight times the deepest structure pyatv is known to exchange: the
/// `_systemInfo` payload in `tests/support/test_opack.py:403-435` — the largest real Companion
/// message in pyatv's suite — nests four levels.
pub const MAX_DEPTH: usize = 32;
