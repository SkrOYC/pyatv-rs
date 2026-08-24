//! OPACK: Apple's undocumented binary serialisation format.
//!
//! OPACK carries HAP pairing payloads and every Companion-link message, so it sits directly under
//! two protocol crates. There is no dependency worth taking here: the only crate on crates.io,
//! `apple-opack` 1.0.0, was published a month before this project started, has a single maintainer,
//! and documents a deliberate encoder/decoder asymmetry in its deduplication handling. The format
//! is small enough to own outright, so this crate is a hand-written port of pyatv's
//! `pyatv/support/opack.py` with that file treated as ground truth.
//!
//! The tag table, the small-integer packing rule and pyatv's own documented gaps (absolute time
//! `0x06` can be unpacked but not packed; UID back-references are not emitted on the pack side) are
//! recorded in `docs/research/rust-crates.md` §6. `docs/research/mrp-companion.md` covers how
//! Companion frames wrap these payloads.
//!
//! This crate deliberately depends only on `bytes` and `thiserror` — it must stay usable from any
//! layer of the workspace without dragging in the runtime or the core types.

pub mod de;
pub mod error;
pub mod ser;
pub mod tags;
pub mod value;

pub use de::unpack;
pub use error::Error;
pub use ser::pack;
pub use value::Value;

/// Convenience alias for fallible OPACK operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
