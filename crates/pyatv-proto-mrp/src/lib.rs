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
//! pyatv carries 77 `.proto` files. They are not vendored yet, so there is no `build.rs`: `prost-build` and `protox` are declared as build dependencies and wired up in a later step. `docs/research/rust-crates.md` §3 selects `protox` over invoking `protoc` so the build stays pure Rust, while noting that protox does not claim full parity with every protoc extension and must be validated against the real corpus once it lands.

pub mod error;
pub mod transport;
pub mod variant;

pub use error::Error;
pub use transport::{MrpTransport, TunnelTransport, direct::DirectTransport};

/// Convenience alias for fallible MRP operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;

// TODO(step-1): vendor pyatv's `pyatv/protocols/mrp/protobuf/*.proto` (77 files) under `proto/`,
// add a `build.rs` that calls `protox::compile` and feeds `prost_build::compile_fds`, and expose
// the generated types from a `protobuf` module here. See docs/research/rust-crates.md §3 and
// docs/research/mrp-companion.md §1.3 for the message catalogue.
