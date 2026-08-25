//! MediaRemote Protocol (MRP).
//!
//! MRP is the protobuf-based protocol Apple TV generation 4 and later speak. It reaches the device over one of two completely different transports, and the single most important architectural fact about this crate is that everything above the transport is shared between them.
//!
//! - **Direct TCP**, for tvOS before 15 and for HomePod: varint-length-prefixed protobuf on a plain socket, with each message ChaCha20-Poly1305 sealed individually once pair-verify completes. See [`variant`] and [`transport::direct`].
//! - **AirPlay tunnel**, mandatory on tvOS 15 and later: the same protobuf messages ride inside binary-plist payloads on an AirPlay 2 data-stream channel, which is itself wrapped in HAP session framing. This crate owns only the innermost layer of that — see [`transport::tunnel`] for exactly where the seam is and why.
//!
//! pyatv models this with one `AbstractMrpConnection` and two implementations, keeping the protocol state machine entirely transport-agnostic. [`transport::MrpTransport`] is the direct port of that idea, and `docs/research/airplay-control-mrp-tunnel-port-spec.md` §7.1 calls it out explicitly as the shape to copy.
//!
//! ## Layering
//!
//! | Here | pyatv | Role |
//! |---|---|---|
//! | [`variant`] | `support/variant.py` | the length prefix on direct frames |
//! | [`transport`] | `mrp/connection.py`, `airplay/mrp_connection.py` | framing, encryption, the two transports |
//! | [`message`] + [`messages`] + [`hid`] | `mrp/messages.py` | the envelope and every outbound factory |
//! | [`protocol`] | `mrp/protocol.py` | bring-up, correlation, heartbeats, dispatch |
//! | [`player_state`] + [`playing`] | `mrp/player_state.py`, `mrp/__init__.py` | now-playing state and its derivation |
//! | [`state`] | — | the shared observation the facades read |
//! | [`facade`] | `mrp/__init__.py` | the [`pyatv_core::interface`] implementations |
//! | [`auth`] + [`pairing`] | `mrp/auth.py`, `mrp/pairing.py` | pair-setup and pair-verify |
//!
//! ## Protobuf codegen
//!
//! pyatv's 77 `.proto` files are vendored verbatim under `proto/` (see `proto/README.md`) and compiled at build time by `protox` — a pure-Rust protobuf compiler, so the crate builds offline with no `protoc` binary — feeding `prost-build`. The generated messages and enums live in [`protobuf`], keeping pyatv's names.
//!
//! The one thing `prost` cannot do is proto2 extensions, which is exactly how MRP nests every concrete message inside the `ProtocolMessage` envelope. [`protobuf::extensions`] supplies that layer: a generated typed handle per extension, reading and writing the field directly on the serialised envelope. `docs/research/mrp-protobuf-spike.md` records the two toolchains that were measured and why this shape was chosen. The consequence for callers is [`message::MrpMessage`], which carries the envelope and the serialised extension together because a bare `ProtocolMessage` is lossy.

pub mod auth;
pub mod error;
pub mod facade;
pub mod hid;
pub mod message;
pub mod messages;
pub mod pairing;
pub mod player_state;
pub mod playing;
pub mod protobuf;
pub mod protocol;
pub mod state;
pub mod transport;
pub mod variant;

pub use error::Error;
pub use facade::{MrpSetupOptions, setup};
pub use message::MrpMessage;
pub use pairing::{MrpPairingHandler, MrpPairingOptions};
pub use protocol::{MrpProtocol, MrpProtocolOptions};
pub use transport::{
    ByteChannel, DirectTransport, MrpTransport, TransportEncryption, TunnelTransport,
};

/// Convenience alias for fallible MRP operations.
pub type Result<T, E = Error> = core::result::Result<T, E>;
