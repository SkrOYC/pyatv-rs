//! MediaRemote Protocol (MRP).
//!
//! MRP is the protobuf-based protocol Apple TV generation 4 and later speak. It reaches the device over one of two completely different transports, and the single most important architectural fact about this crate is that everything above the transport is shared between them.
//!
//! - **Direct TCP**, for tvOS before 15 and for HomePod: varint-length-prefixed protobuf on a plain socket, with each message ChaCha20-Poly1305 sealed individually once pair-verify completes. See [`variant`] and `docs/research/mrp-companion.md` §1.
//! - **AirPlay tunnel**, mandatory on tvOS 15 and later: the same protobuf messages ride inside binary-plist payloads on an AirPlay 2 data-stream channel, which is itself wrapped in HAP session framing. See `docs/research/mrp-companion.md` §3.
//!
//! pyatv models this with one `AbstractMrpConnection` and two implementations, keeping the protocol state machine entirely transport-agnostic. [`transport::MrpTransport`] is the direct port of that idea, and the research report calls it out explicitly as the shape to copy.
//!
//! ## Protobuf codegen
//!
//! pyatv's 77 `.proto` files are vendored verbatim under `proto/` (see `proto/README.md`) and compiled at build time by `protox` — a pure-Rust protobuf compiler, so the crate builds offline with no `protoc` binary — feeding `prost-build`. The generated messages and enums live in [`protobuf`], keeping pyatv's names.
//!
//! The one thing `prost` cannot do is proto2 extensions, which is exactly how MRP nests every concrete message inside the `ProtocolMessage` envelope. [`protobuf::extensions`] supplies that layer: a generated typed handle per extension, reading and writing the field directly on the serialised envelope. `docs/research/mrp-protobuf-spike.md` records the two toolchains that were measured and why this shape was chosen.

pub mod error;
pub mod protobuf;
pub mod transport;
pub mod variant;

pub use error::Error;
pub use transport::{MrpTransport, TunnelTransport, direct::DirectTransport};

/// Convenience alias for fallible MRP operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
