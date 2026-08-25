//! Pure-Rust client for Apple TV and AirPlay devices.
//!
//! This is the crate applications depend on. It owns the three entry points pyatv exposes — [`scan`], [`pair`] and [`connect`] — and is the only place in the workspace that knows about every protocol at once. Everything else is either protocol-agnostic (`pyatv-core`) or knows about exactly one protocol.
//!
//! ```text
//! scan()    -> discovery finds devices and their services
//! pair()    -> one protocol's pairing exchange, credentials land in Storage
//! connect() -> each enabled protocol connects, registers into a FacadeAppleTV
//! ```
//!
//! The layering is deliberately one-directional: `pyatv-core` defines the traits, the protocol crates implement them, and this crate wires the implementations into `pyatv_core::facade::FacadeAppleTV`. No protocol crate depends on another, and none of them depend on this one, so a protocol can be developed and tested in isolation.
//!
//! That rule is also why [`tunnel`] exists here rather than in either crate it joins. On tvOS 15 and later an Apple TV stops advertising `_mediaremotetv._tcp` altogether and MRP is reachable only inside an AirPlay 2 data-stream channel — so somebody has to name both `pyatv-proto-airplay`'s channel and `pyatv-proto-mrp`'s transport in one place, and this is the only crate allowed to.
//!
//! See `docs/research/pyatv-architecture.md` for the upstream design this reproduces.

pub mod connect;
pub mod pair;
pub mod scan;
pub mod tunnel;

pub use connect::connect;
pub use pair::pair;
pub use scan::scan;

pub use pyatv_core::interface::{
    AppleTV, Apps, Audio, DeviceListener, Features, Keyboard, Metadata, PairingHandler,
    PlaybackListener, Power, PowerListener, PushUpdater, RemoteControl, Stream, TouchGestures,
    UserAccounts,
};
pub use pyatv_core::models::Playing;
pub use pyatv_core::storage::{
    AirPlaySettings, CompanionSettings, DmapSettings, FileStorage, InfoSettings, MemoryStorage,
    MrpSettings, MrpTunnel, ProtocolSettings, RaopSettings, Settings, Storage, StorageModel,
};
/// The curated public API, re-exported so callers need only depend on this crate.
pub use pyatv_core::{
    App, ArtworkInfo, BaseConfig, BaseService, DeviceInfo, DeviceModel, DeviceState, Error,
    FeatureInfo, FeatureName, FeatureState, InputAction, KeyboardFocusState, MediaType,
    OperatingSystem, PairingRequirement, PowerState, Protocol, RepeatState, Result, ShuffleState,
    TouchAction, UserAccount,
};
pub use pyatv_mdns::ScanOptions;
